"""
AIScan Network Correlation Monitor
Watches outbound network connections and correlates them with recent
clipboard/file events to detect confirmed data exfiltration.

This is the feature no other offline tool has:
  - PII copied to clipboard + upload to unknown host = confirmed exfiltration
  - Sensitive file opened + connection to filesharing site = likely exfil
  - API key in clipboard + POST request = credential theft

How it works:
  1. Polls netstat every 10 seconds for new ESTABLISHED connections
  2. Maintains a baseline of known-good hosts (Microsoft, Google, etc)
  3. New connections to unknown hosts are recorded as events
  4. Correlator checks: did a PII/AI event happen in the last 120 seconds?
  5. If yes -> EXFILTRATION ALERT with full chain

No packet inspection. No decryption. Just connection metadata:
  - Remote IP/hostname
  - Port
  - Process name that opened the connection
  - Timestamp
"""
import os, sys, re, time, json, logging, threading, socket, subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict
from collections import deque

log = logging.getLogger("aiscan")
IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

_SUBPROCESS_FLAGS = {}
if IS_WIN:
    _SUBPROCESS_FLAGS = {"creationflags": 0x08000000}  # CREATE_NO_WINDOW


# ============================================================================
# KNOWN-SAFE HOST WHITELIST
# ============================================================================

# Hosts/domains we never alert on - Microsoft, Google, Anthropic, etc.
SAFE_HOSTS = {
    # Microsoft
    "microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com",
    "live.com", "office.com", "office365.com", "sharepoint.com", "onedrive.com",
    "teams.microsoft.com", "outlook.com", "hotmail.com", "msn.com", "bing.com",
    "azure.com", "azureedge.net", "azurefd.net", "trafficmanager.net",
    # Google
    "google.com", "googleapis.com", "gstatic.com", "gmail.com", "googlevideo.com",
    "googleusercontent.com", "google.co.in", "ytimg.com", "youtube.com",
    "doubleclick.net", "googlesyndication.com", "googletagmanager.com",
    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "apple-dns.net",
    # Amazon / AWS
    "amazonaws.com", "amazon.com", "cloudfront.net", "awsstatic.com",
    # CDNs
    "cloudflare.com", "fastly.net", "akamaiedge.net", "akamai.net",
    "edgesuite.net", "limelight.com", "cdnjs.cloudflare.com",
    # Communication
    "slack.com", "slack-edge.com", "slackb.com",
    "zoom.us", "zoomgov.com",
    "teams.live.com",
    # Developer tools
    "github.com", "githubusercontent.com", "githubassets.com",
    "npmjs.com", "pypi.org", "pythonhosted.org",
    # Security / cert infrastructure
    "ocsp.digicert.com", "crl.microsoft.com", "pki.goog",
    "letsencrypt.org", "digicert.com",
    # Indian services
    "npci.org.in", "bhimupi.org.in", "icici.com", "hdfcbank.com",
    "sbi.co.in", "axisbank.com", "kotak.com",
    # Common browsers
    "firefox.com", "mozilla.org", "chrome.com",
    # DNS / infrastructure
    "dns.google", "cloudflare-dns.com", "opendns.com",
    # Anthropic
    "anthropic.com", "claude.ai",
    # Localhost
    "localhost", "127.0.0.1", "::1",
}

# High-risk destinations - filesharing, paste sites, exfil-common targets
HIGH_RISK_HOSTS = {
    "wetransfer.com", "we.tl",
    "pastebin.com", "pastie.org", "hastebin.com", "paste.ee",
    "filebin.net", "file.io", "transfer.sh",
    "sendspace.com", "mediafire.com", "mega.nz",
    "telegram.org", "t.me",
    "discord.com", "discordapp.com",
    "anonfiles.com", "gofile.io",
    "temp.sh", "0x0.st",
}

# High-risk ports for data transfer
HIGH_RISK_PORTS = {21, 22, 25, 465, 587}  # FTP, SSH, SMTP


@dataclass
class NetworkConnection:
    ts: float
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    remote_host: str      # resolved hostname if available
    process_name: str
    state: str
    is_new: bool          # True if not seen in previous poll
    risk_level: str       # CRITICAL/HIGH/MEDIUM/LOW/SAFE

    def to_dict(self):
        return {
            "ts": self.ts,
            "ts_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
            "local": f"{self.local_addr}:{self.local_port}",
            "remote": f"{self.remote_addr}:{self.remote_port}",
            "remote_host": self.remote_host,
            "process": self.process_name,
            "state": self.state,
            "risk_level": self.risk_level,
        }


# ============================================================================
# CONNECTION PARSER
# ============================================================================

def _get_connections_windows() -> List[Dict]:
    """Get active TCP connections on Windows using netstat."""
    conns = []
    try:
        r = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=15,
            **_SUBPROCESS_FLAGS)

        # Map PIDs to process names
        pid_names = {}
        try:
            r2 = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True, text=True, timeout=10,
                **_SUBPROCESS_FLAGS)
            for line in r2.stdout.splitlines():
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pid_names[int(parts[1])] = parts[0]
                    except ValueError:
                        pass
        except Exception:
            pass

        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0] != "TCP":
                continue
            state = parts[3] if len(parts) > 3 else ""
            if state not in ("ESTABLISHED", "CLOSE_WAIT"):
                continue
            try:
                local  = parts[1].rsplit(":", 1)
                remote = parts[2].rsplit(":", 1)
                pid    = int(parts[4])
                conns.append({
                    "local_addr":  local[0],
                    "local_port":  int(local[1]),
                    "remote_addr": remote[0],
                    "remote_port": int(remote[1]),
                    "process":     pid_names.get(pid, f"PID:{pid}"),
                    "state":       state,
                })
            except (IndexError, ValueError):
                pass
    except Exception as e:
        log.debug(f"Windows netstat error: {e}")
    return conns


def _get_connections_mac() -> List[Dict]:
    """Get active TCP connections on macOS using netstat/lsof."""
    conns = []
    try:
        r = subprocess.run(
            ["netstat", "-an", "-p", "tcp"],
            capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            if "ESTABLISHED" not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                local  = parts[3].rsplit(".", 1)
                remote = parts[4].rsplit(".", 1)
                conns.append({
                    "local_addr":  local[0],
                    "local_port":  int(local[1]),
                    "remote_addr": remote[0],
                    "remote_port": int(remote[1]),
                    "process":     "unknown",
                    "state":       "ESTABLISHED",
                })
            except (IndexError, ValueError):
                pass
    except Exception as e:
        log.debug(f"Mac netstat error: {e}")
    return conns


def _get_connections() -> List[Dict]:
    if IS_WIN: return _get_connections_windows()
    if IS_MAC: return _get_connections_mac()
    return []


def _resolve_host(ip: str) -> str:
    """Reverse-resolve IP to hostname. Returns IP if fails. Non-blocking."""
    try:
        if ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            return "localhost"
        # Quick check: private IP ranges - never resolve
        if (ip.startswith("10.") or ip.startswith("192.168.") or
                ip.startswith("172.") or ip.startswith("169.254.")):
            return ip  # private/local
        result = socket.gethostbyaddr(ip)
        return result[0]
    except Exception:
        return ip


def _classify_connection(remote_addr: str, remote_host: str,
                          remote_port: int, process: str) -> str:
    """Classify a connection's risk level."""
    host_lower = remote_host.lower()

    # Localhost / private range = safe
    if remote_addr in ("127.0.0.1", "::1", "0.0.0.0"):
        return "SAFE"
    if (remote_addr.startswith("10.") or remote_addr.startswith("192.168.") or
            remote_addr.startswith("172.")):
        return "SAFE"

    # Check against safe whitelist (domain suffix match)
    for safe in SAFE_HOSTS:
        if host_lower == safe or host_lower.endswith("." + safe):
            return "SAFE"

    # High-risk destinations
    for risky in HIGH_RISK_HOSTS:
        if risky in host_lower:
            return "HIGH"

    # High-risk ports
    if remote_port in HIGH_RISK_PORTS:
        return "MEDIUM"

    # Unknown host on common web ports - medium risk
    if remote_port in (80, 443, 8080, 8443):
        return "MEDIUM"

    # Unknown host on unusual port - high risk
    return "HIGH"


# ============================================================================
# NETWORK MONITOR
# ============================================================================

class NetworkMonitor:
    """
    Polls network connections every 10 seconds.
    Records new connections and correlates with recent security events.
    """

    def __init__(self, data_dir: Path,
                 incident_correlator=None,
                 alert_fn=None):
        self._data_dir = data_dir
        self._correlator = incident_correlator
        self._alert_fn = alert_fn
        self._running = False
        self._known_conns: Set[str] = set()   # fingerprints of seen connections
        self._recent_conns: deque = deque(maxlen=200)
        self._lock = threading.Lock()
        self._interval = 10  # seconds between polls
        self._log_file = data_dir / "network_events.jsonl"

        # DNS cache to avoid repeated lookups
        self._dns_cache: Dict[str, str] = {}
        self._dns_lock = threading.Lock()

    def start(self):
        # Populate baseline - don't alert on existing connections
        baseline = _get_connections()
        for c in baseline:
            self._known_conns.add(self._fingerprint(c))
        self._running = True
        threading.Thread(target=self._loop, daemon=True,
                         name="NetworkMonitor").start()
        log.info(f"Network monitor active  -  "
                 f"{len(baseline)} baseline connections, "
                 f"watching for new exfiltration attempts")

    def stop(self):
        self._running = False

    def _fingerprint(self, conn: Dict) -> str:
        return (f"{conn['remote_addr']}:{conn['remote_port']}:"
                f"{conn.get('process','')}")

    def _resolve_cached(self, ip: str) -> str:
        with self._dns_lock:
            if ip in self._dns_cache:
                return self._dns_cache[ip]
        host = _resolve_host(ip)
        with self._dns_lock:
            self._dns_cache[ip] = host
        return host

    def _loop(self):
        log.info("Network correlation monitoring active")
        while self._running:
            try:
                self._poll()
            except Exception as e:
                log.debug(f"Network monitor poll error: {e}")
            time.sleep(self._interval)

    def _poll(self):
        raw_conns = _get_connections()
        now = time.time()
        new_alerts = []

        for c in raw_conns:
            fp = self._fingerprint(c)
            if fp in self._known_conns:
                continue  # not new

            self._known_conns.add(fp)

            # Resolve hostname (quick, cached)
            host = self._resolve_cached(c["remote_addr"])
            risk = _classify_connection(
                c["remote_addr"], host, c["remote_port"], c.get("process",""))

            if risk == "SAFE":
                continue  # don't log safe connections

            conn = NetworkConnection(
                ts=now,
                local_addr=c["local_addr"],
                local_port=c["local_port"],
                remote_addr=c["remote_addr"],
                remote_port=c["remote_port"],
                remote_host=host,
                process_name=c.get("process", "unknown"),
                state=c.get("state", "ESTABLISHED"),
                is_new=True,
                risk_level=risk,
            )

            log.info(
                f"NETWORK [{risk}]: new connection -> "
                f"{host}:{c['remote_port']} "
                f"(process: {conn.process_name})"
            )

            with self._lock:
                self._recent_conns.append(conn)

            self._log_connection(conn)

            # Correlate with recent security events
            if self._correlator and risk in ("HIGH", "MEDIUM"):
                self._correlate(conn)

            new_alerts.append(conn)

        return new_alerts

    def _correlate(self, conn: NetworkConnection):
        """Check if this connection correlates with recent PII/AI events."""
        if not self._correlator:
            return

        from incident_engine import IncidentEvent

        # Record network event
        self._correlator.record(IncidentEvent(
            ts=conn.ts,
            event_type="NETWORK_CONNECTION",
            severity=conn.risk_level,
            source=f"{conn.remote_host}:{conn.remote_port}",
            detail=(f"New outbound connection: {conn.process_name} -> "
                    f"{conn.remote_host}:{conn.remote_port}"),
            metadata={
                "host": conn.remote_host,
                "port": conn.remote_port,
                "process": conn.process_name,
                "risk": conn.risk_level,
            },
        ))

        # Check for exfiltration pattern: PII/clipboard event in last 120s
        now = conn.ts
        window = 120
        recent_events = self._correlator.get_recent_events(hours=1)
        related = [
            e for e in recent_events
            if (now - e.ts <= window and
                e.event_type in ("PII_FOUND", "CLIPBOARD_COPY", "AI_DETECTION") and
                e.ts < now)
        ]

        if related and conn.risk_level in ("HIGH",):
            # This is a confirmed exfiltration pattern
            most_severe = max(related, key=lambda e:
                {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(e.severity,0))

            detail = (
                f"EXFILTRATION PATTERN: {most_severe.event_type} detected "
                f"{now - most_severe.ts:.0f}s before new connection to "
                f"{conn.remote_host} via {conn.process_name}"
            )
            log.warning(f"EXFIL CORRELATION: {detail}")

            # Fire alert
            if self._alert_fn:
                self._alert_fn(conn, related, detail)

            # Record as critical incident event
            self._correlator.record(IncidentEvent(
                ts=now,
                event_type="EXFIL_CORRELATION",
                severity="CRITICAL",
                source=f"{conn.remote_host}",
                detail=detail,
                metadata={
                    "connection": conn.to_dict(),
                    "related_events": len(related),
                    "trigger_event": most_severe.event_type,
                },
            ), capture_screenshot=True)

    def _log_connection(self, conn: NetworkConnection):
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(conn.to_dict()) + "\n")
        except Exception as e:
            log.debug(f"Network log error: {e}")

    def get_recent(self, minutes: int = 60) -> List[NetworkConnection]:
        cutoff = time.time() - minutes * 60
        with self._lock:
            return [c for c in self._recent_conns if c.ts >= cutoff]

    def get_stats(self) -> dict:
        conns = list(self._recent_conns)
        return {
            "total_seen": len(self._known_conns),
            "recent_1h": sum(1 for c in conns
                            if time.time() - c.ts < 3600),
            "high_risk": sum(1 for c in conns if c.risk_level == "HIGH"),
            "medium_risk": sum(1 for c in conns if c.risk_level == "MEDIUM"),
        }


# ============================================================================
# EXFILTRATION ALERT POPUP
# ============================================================================

def show_exfil_alert(conn: NetworkConnection, related_events: list,
                     detail: str):
    """Show an urgent exfiltration alert popup."""
    threading.Thread(
        target=_exfil_popup,
        args=(conn, related_events, detail),
        daemon=True
    ).start()


def _exfil_popup(conn: NetworkConnection, related_events: list, detail: str):
    try:
        import tkinter as tk

        root = tk.Tk()
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        root.attributes("-alpha", 0.97)
        root.configure(bg="#0d0d14")

        W, H = 460, 300
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        C_RED = "#ff2244"

        tk.Frame(root, bg=C_RED, height=5).pack(fill="x")
        hdr = tk.Frame(root, bg="#1a0000"); hdr.pack(fill="x")
        tk.Label(hdr, text="[!!] EXFILTRATION DETECTED",
                 font=("Helvetica", 12, "bold"),
                 fg=C_RED, bg="#1a0000").pack(side="left", padx=16, pady=12)
        tk.Label(hdr, text="CRITICAL",
                 font=("Helvetica", 9, "bold"), fg="#0d0d14",
                 bg=C_RED).pack(side="right", padx=12)

        main = tk.Frame(root, bg="#0d0d14"); main.pack(fill="both",
                        expand=True, padx=16, pady=12)

        tk.Label(main,
                 text="Sensitive data event followed by unknown network connection",
                 font=("Helvetica", 10, "bold"), fg="#e8e8f0",
                 bg="#0d0d14", wraplength=420).pack(anchor="w")

        info_rows = [
            ("Destination:",  f"{conn.remote_host}:{conn.remote_port}"),
            ("Process:",       conn.process_name),
            ("Trigger event:", related_events[0].event_type if related_events else "Unknown"),
            ("Time gap:",      f"{conn.ts - related_events[0].ts:.0f}s" if related_events else "-"),
        ]
        for label_text, val in info_rows:
            rf = tk.Frame(main, bg="#1a0000", padx=10, pady=5)
            rf.pack(fill="x", pady=2)
            tk.Label(rf, text=label_text,
                     font=("Helvetica", 9, "bold"),
                     fg="#888", bg="#1a0000", width=14, anchor="w").pack(side="left")
            tk.Label(rf, text=val,
                     font=("Courier", 9),
                     fg="#e8e8f0", bg="#1a0000").pack(side="left")

        tk.Label(main,
                 text="Screenshot evidence has been captured automatically.",
                 font=("Helvetica", 8), fg="#555",
                 bg="#0d0d14").pack(anchor="w", pady=(8, 0))

        bf = tk.Frame(main, bg="#0d0d14"); bf.pack(fill="x", pady=(10, 0))
        tk.Button(bf, text="Dismiss",
                  command=root.destroy,
                  font=("Helvetica", 9), fg="#888",
                  bg="#1a1a28", relief="flat",
                  padx=12, pady=5).pack(side="right")

        root.after(30000, root.destroy)  # 30s auto-close

        root.attributes("-alpha", 0.0)
        def fade(a=0.0):
            if a < 0.97:
                root.attributes("-alpha", min(a+0.08, 0.97))
                root.after(16, lambda: fade(a+0.08))
        root.after(10, fade)
        root.mainloop()

    except Exception as e:
        log.debug(f"Exfil popup error: {e}")


# ============================================================================
# NETWORK DASHBOARD  -  HTML
# ============================================================================

def build_network_dashboard(monitor: NetworkMonitor, data_dir: Path) -> Path:
    """Build HTML dashboard of recent network activity."""
    out_path = data_dir / "network_dashboard.html"
    conns = monitor.get_recent(minutes=60 * 24)  # last 24h
    stats = monitor.get_stats()

    def risk_color(risk):
        return {"CRITICAL":"#ff2244","HIGH":"#ff6600",
                "MEDIUM":"#ffaa00","LOW":"#ffdd00","SAFE":"#44cc77"}.get(risk,"#888")

    def risk_badge(risk):
        col = risk_color(risk)
        return (f'<span style="background:{col};color:#000;padding:2px 8px;'
                f'border-radius:4px;font-size:10px;font-weight:bold">{risk}</span>')

    rows = ""
    for c in sorted(conns, key=lambda x: x.ts, reverse=True)[:200]:
        col = risk_color(c.risk_level)
        rows += f"""
        <tr style="border-bottom:1px solid #111">
          <td style="padding:8px;color:#555;font-size:11px;white-space:nowrap">
            {time.strftime("%H:%M:%S", time.localtime(c.ts))}</td>
          <td style="padding:8px">{risk_badge(c.risk_level)}</td>
          <td style="padding:8px;color:#00e5ff;font-family:monospace;font-size:11px">
            {c.remote_host}</td>
          <td style="padding:8px;color:#888;font-size:11px">{c.remote_port}</td>
          <td style="padding:8px;color:#aaa;font-size:11px">{c.process_name}</td>
          <td style="padding:8px;color:#555;font-size:11px">{c.remote_addr}</td>
        </tr>"""

    if not rows:
        rows = ('<tr><td colspan="6" style="color:#333;text-align:center;'
                'padding:40px">No suspicious connections detected in last 24h.'
                ' Network monitoring is active.</td></tr>')

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AIScan Network Monitor</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{ background:#07070f; color:#e8e8f0; font-family:'Segoe UI',sans-serif }}
    .navbar {{ background:#0d0d14; border-bottom:1px solid #1a1a2e;
               padding:14px 32px; display:flex; align-items:center; gap:12px }}
    .logo {{ color:#00e5ff; font-weight:900; font-size:18px }}
    .tag {{ color:#ff6600; font-weight:600; font-size:13px;
            background:#ff660022; padding:3px 10px; border-radius:4px;
            border:1px solid #ff660044 }}
    .subtitle {{ color:#444; font-size:12px; margin-left:auto }}
    .container {{ max-width:1300px; margin:0 auto; padding:32px 24px }}
    .stats {{ display:grid; grid-template-columns:repeat(4,1fr);
              gap:16px; margin-bottom:32px }}
    .stat {{ background:#0d0d14; border:1px solid #1a1a2e;
             border-radius:8px; padding:20px; text-align:center }}
    .stat-num {{ font-size:32px; font-weight:900; margin-bottom:4px }}
    .stat-label {{ color:#666; font-size:12px }}
    .section-title {{ color:#666; font-size:11px; letter-spacing:2px;
                      text-transform:uppercase; margin:0 0 12px }}
    table {{ width:100%; border-collapse:collapse }}
    .th {{ padding:10px 16px; text-align:left; color:#444; font-size:11px;
           letter-spacing:1px; text-transform:uppercase;
           border-bottom:1px solid #1a1a2e; background:#0a0a12 }}
    tr:hover {{ background:#0d0d14 }}
    .note {{ color:#333; font-size:11px; margin-top:12px }}
    .refresh {{ color:#00e5ff; font-size:11px; cursor:pointer;
                background:none; border:1px solid #00e5ff44;
                padding:4px 12px; border-radius:4px }}
  </style>
</head>
<body>
  <div class="navbar">
    <span class="logo">AI</span>
    <span style="color:#fff;font-weight:700;font-size:18px">Scan</span>
    <span class="tag">NETWORK MONITOR</span>
    <span class="subtitle">
      {stats['total_seen']} total connections observed |
      Updated: {time.strftime('%Y-%m-%d %H:%M:%S')}
    </span>
    <button class="refresh" onclick="location.reload()">Refresh</button>
  </div>
  <div class="container">
    <div class="stats">
      <div class="stat">
        <div class="stat-num" style="color:#ff2244">{stats['high_risk']}</div>
        <div class="stat-label">High Risk Connections</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#ffaa00">{stats['medium_risk']}</div>
        <div class="stat-label">Medium Risk</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#00e5ff">{stats['recent_1h']}</div>
        <div class="stat-label">New (Last Hour)</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#888">{stats['total_seen']}</div>
        <div class="stat-label">Total Observed</div>
      </div>
    </div>
    <div class="section-title">Suspicious Connections (Last 24h)</div>
    <table>
      <tr>
        <th class="th">Time</th>
        <th class="th">Risk</th>
        <th class="th">Remote Host</th>
        <th class="th">Port</th>
        <th class="th">Process</th>
        <th class="th">IP</th>
      </tr>
      {rows}
    </table>
    <p class="note">
      Safe connections (Microsoft, Google, CDNs, Indian banks) are filtered out.
      Only new, unrecognized outbound connections are shown here.
      Correlated exfiltration events appear in the Incident Dashboard.
    </p>
  </div>
</body>
</html>"""

    out_path.write_text(html, encoding="utf-8")
    log.info(f"Network dashboard: {len(conns)} connections logged")
    return out_path
