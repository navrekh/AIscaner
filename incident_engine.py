"""
AIScan Incident Engine
Correlates events into incident chains, captures screenshot evidence,
monitors USB/removable media, tracks process anomalies.

Sprint 1 cybersecurity features:
  1. Incident timeline - correlates events within time windows
  2. Screenshot evidence - captures screen at moment of CRITICAL alert
  3. USB monitor - watches for removable media, scans copied files
  4. Process monitor - detects anomalous process spawning
"""
import os, sys, time, json, threading, hashlib, logging, subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from collections import deque

log = logging.getLogger("aiscan")
IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

_SUBPROCESS_FLAGS = {}
if IS_WIN:
    _SUBPROCESS_FLAGS = {"creationflags": 0x08000000}


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class IncidentEvent:
    """A single event that may be part of an incident chain."""
    ts: float
    event_type: str          # AI_DETECTION / PII_FOUND / CLIPBOARD_COPY / USB_COPY / PROCESS_ANOMALY / SCREENSHOT_TAKEN
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    source: str              # file path, clipboard, screen, usb
    detail: str              # human-readable description
    score: float = 0.0       # AI score if applicable
    screenshot_path: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "ts": self.ts,
            "ts_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "detail": self.detail,
            "score": self.score,
            "screenshot_path": self.screenshot_path,
            "metadata": self.metadata,
        }


@dataclass
class IncidentChain:
    """A correlated sequence of events that together indicate a threat."""
    chain_id: str
    started_at: float
    events: List[IncidentEvent]
    severity: str
    title: str
    description: str
    resolved: bool = False

    @property
    def duration_seconds(self):
        if len(self.events) < 2:
            return 0
        return self.events[-1].ts - self.events[0].ts

    def to_dict(self):
        return {
            "chain_id": self.chain_id,
            "started_at": self.started_at,
            "started_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at)),
            "events": [e.to_dict() for e in self.events],
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "resolved": self.resolved,
            "duration_seconds": self.duration_seconds,
            "event_count": len(self.events),
        }


# ============================================================================
# SCREENSHOT EVIDENCE CAPTURE
# ============================================================================

def capture_evidence_screenshot(data_dir: Path, reason: str) -> Optional[str]:
    """
    Capture full screen screenshot as evidence at moment of detection.
    Saves to data_dir/evidence/TIMESTAMP_reason.png
    Returns path to saved screenshot or None if failed.
    """
    try:
        evidence_dir = data_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_reason = re.sub(r'[^\w]', '_', reason)[:30]
        filename = f"{ts}_{safe_reason}.png"
        save_path = evidence_dir / filename

        # Method 1: mss (bundled, fastest)
        try:
            import mss
            from PIL import Image
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                shot = sct.grab(monitor)
                img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                img.save(str(save_path))
                log.info(f"EVIDENCE: screenshot saved -> {filename}")
                return str(save_path)
        except ImportError:
            pass

        # Method 2: PIL ImageGrab
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab()
            img.save(str(save_path))
            log.info(f"EVIDENCE: screenshot saved -> {filename}")
            return str(save_path)
        except Exception as e:
            log.debug(f"Screenshot ImageGrab failed: {e}")

        # Method 3: Windows snipping tool via PowerShell
        if IS_WIN:
            ps = f"""
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$bmp.Save('{str(save_path).replace(os.sep, "/")}')
"""
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=10,
                **_SUBPROCESS_FLAGS)
            if save_path.exists():
                log.info(f"EVIDENCE: screenshot saved via PS -> {filename}")
                return str(save_path)

    except Exception as e:
        log.debug(f"Evidence screenshot failed: {e}")

    return None


import re  # needed for safe_reason


# ============================================================================
# INCIDENT CORRELATOR
# ============================================================================

# Correlation window: events within this many seconds are grouped
CORRELATION_WINDOW = 120  # 2 minutes

# Chains that indicate exfiltration
CHAIN_RULES = [
    {
        "name": "Exfiltration Chain",
        "description": "PII found then clipboard copy detected - possible data exfiltration",
        "requires": ["PII_FOUND", "CLIPBOARD_COPY"],
        "window": 60,
        "severity": "CRITICAL",
    },
    {
        "name": "AI Content + Immediate Paste",
        "description": "AI content detected on screen then immediately saved to file",
        "requires": ["AI_DETECTION", "AI_DETECTION"],
        "window": 30,
        "severity": "HIGH",
    },
    {
        "name": "USB Exfiltration",
        "description": "Sensitive file copied to removable media",
        "requires": ["PII_FOUND", "USB_COPY"],
        "window": 300,
        "severity": "CRITICAL",
    },
    {
        "name": "Rapid Data Movement",
        "description": "Multiple high-risk events in short window",
        "requires": ["CLIPBOARD_COPY", "CLIPBOARD_COPY", "CLIPBOARD_COPY"],
        "window": 60,
        "severity": "HIGH",
    },
    {
        "name": "Suspicious Process + File Access",
        "description": "Anomalous process spawned then file accessed",
        "requires": ["PROCESS_ANOMALY", "AI_DETECTION"],
        "window": 120,
        "severity": "HIGH",
    },
]


class IncidentCorrelator:
    """
    Receives individual events and correlates them into incident chains.
    Runs continuously in background.
    """

    def __init__(self, data_dir: Path, alert_fn=None):
        self._data_dir = data_dir
        self._alert_fn = alert_fn
        self._events = deque(maxlen=500)   # recent events
        self._chains = []                   # detected incident chains
        self._chain_ids = set()             # prevent duplicate chains
        self._lock = threading.Lock()
        self._incidents_file = data_dir / "incidents.jsonl"
        self._evidence_dir = data_dir / "evidence"
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

    def record(self, event: IncidentEvent, capture_screenshot: bool = False):
        """Record a new event and check for chain correlations."""
        # Optionally capture screenshot evidence
        if capture_screenshot and event.severity in ("CRITICAL", "HIGH"):
            screenshot_path = capture_evidence_screenshot(
                self._data_dir, event.event_type)
            if screenshot_path:
                event.screenshot_path = screenshot_path

        with self._lock:
            self._events.append(event)

        # Check for chains
        self._check_chains(event)

        # Persist
        self._save_event(event)

    def _check_chains(self, new_event: IncidentEvent):
        """Check if new event completes any chain pattern."""
        now = new_event.ts

        with self._lock:
            recent = [e for e in self._events
                      if now - e.ts <= CORRELATION_WINDOW]

        for rule in CHAIN_RULES:
            window = rule["window"]
            required = rule["requires"]

            # Get events in window matching required types
            in_window = [e for e in recent if now - e.ts <= window]
            type_counts = {}
            for e in in_window:
                type_counts[e.event_type] = type_counts.get(e.event_type, 0) + 1

            # Check if all required types are present with needed counts
            req_counts = {}
            for t in required:
                req_counts[t] = req_counts.get(t, 0) + 1

            matched = all(type_counts.get(t, 0) >= c
                         for t, c in req_counts.items())

            if matched:
                # Create chain ID from sorted event hashes to prevent duplicates
                chain_key = f"{rule['name']}_{int(now // window)}"
                if chain_key not in self._chain_ids:
                    self._chain_ids.add(chain_key)
                    chain = IncidentChain(
                        chain_id=chain_key,
                        started_at=min(e.ts for e in in_window),
                        events=[e for e in in_window
                                if e.event_type in required],
                        severity=rule["severity"],
                        title=rule["name"],
                        description=rule["description"],
                    )
                    self._chains.append(chain)
                    log.info(
                        f"INCIDENT CHAIN: [{rule['severity']}] {rule['name']} "
                        f"({len(chain.events)} events in {chain.duration_seconds:.0f}s)"
                    )
                    self._save_chain(chain)
                    if self._alert_fn:
                        threading.Thread(
                            target=self._alert_fn,
                            args=(chain,),
                            daemon=True
                        ).start()

    def _save_event(self, event: IncidentEvent):
        try:
            with open(self._data_dir / "events.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            log.debug(f"Event save error: {e}")

    def _save_chain(self, chain: IncidentChain):
        try:
            with open(self._incidents_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(chain.to_dict()) + "\n")
        except Exception as e:
            log.debug(f"Chain save error: {e}")

    def get_recent_chains(self, hours=24) -> List[IncidentChain]:
        cutoff = time.time() - hours * 3600
        return [c for c in self._chains if c.started_at >= cutoff]

    def get_recent_events(self, hours=24) -> List[IncidentEvent]:
        cutoff = time.time() - hours * 3600
        with self._lock:
            return [e for e in self._events if e.ts >= cutoff]


# ============================================================================
# USB / REMOVABLE MEDIA MONITOR
# ============================================================================

class USBMonitor:
    """
    Watches for new removable drives being connected.
    Scans files copied to USB drives.
    Alerts when sensitive files are moved to removable media.
    """

    def __init__(self, scan_fn, alert_fn, incident_correlator=None):
        self._scan = scan_fn
        self._alert = alert_fn
        self._correlator = incident_correlator
        self._known_drives = set()
        self._running = False
        self._interval = 5  # check every 5 seconds

    def start(self):
        self._known_drives = self._get_drives()
        self._running = True
        threading.Thread(target=self._loop, daemon=True, name="USBMonitor").start()
        log.info(f"USB monitor active  -  watching for removable media")

    def stop(self):
        self._running = False

    def _get_drives(self) -> set:
        """Get current set of drive letters / mount points."""
        drives = set()
        if IS_WIN:
            try:
                import ctypes
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                    if bitmask & (1 << i):
                        drive = f"{letter}:\\"
                        # Check if removable (type 2 = DRIVE_REMOVABLE)
                        dtype = ctypes.windll.kernel32.GetDriveTypeW(drive)
                        if dtype == 2:  # DRIVE_REMOVABLE
                            drives.add(drive)
            except Exception as e:
                log.debug(f"USB drive detection error: {e}")
        elif IS_MAC:
            try:
                volumes = Path("/Volumes")
                if volumes.exists():
                    for vol in volumes.iterdir():
                        if vol.is_dir() and vol.name not in ("Macintosh HD", "."):
                            drives.add(str(vol))
            except Exception as e:
                log.debug(f"USB volume detection error: {e}")
        return drives

    def _loop(self):
        while self._running:
            try:
                current = self._get_drives()
                new_drives = current - self._known_drives
                removed = self._known_drives - current

                for drive in new_drives:
                    log.info(f"USB DETECTED: new drive -> {drive}")
                    self._on_drive_connected(drive)

                for drive in removed:
                    log.info(f"USB REMOVED: {drive}")

                self._known_drives = current

            except Exception as e:
                log.debug(f"USB monitor loop error: {e}")

            time.sleep(self._interval)

    def _on_drive_connected(self, drive: str):
        """Handle new drive connection - alert and start watching."""
        log.info(f"USB: scanning drive {drive}")

        if self._correlator:
            self._correlator.record(IncidentEvent(
                ts=time.time(),
                event_type="USB_COPY",
                severity="MEDIUM",
                source=drive,
                detail=f"Removable drive connected: {drive}",
            ), capture_screenshot=True)

        # Start watching this drive for file copies
        threading.Thread(
            target=self._watch_drive,
            args=(drive,),
            daemon=True
        ).start()

    def _watch_drive(self, drive: str):
        """Watch a USB drive for new files being copied to it."""
        try:
            from watchdog.observers.polling import PollingObserver
            from watchdog.events import FileSystemEventHandler

            correlator = self._correlator
            scan_fn = self._scan
            alert_fn = self._alert

            class USBHandler(FileSystemEventHandler):
                def on_created(self, event):
                    if event.is_directory:
                        return
                    path = Path(event.src_path)
                    ext = path.suffix.lower()
                    # Scan documents copied to USB
                    SCAN_EXTS = {".docx",".pdf",".xlsx",".txt",".csv",
                                 ".pptx",".py",".js",".ts",".java"}
                    if ext in SCAN_EXTS:
                        log.info(f"USB: file copied -> {path.name}")
                        threading.Thread(
                            target=_scan_usb_file,
                            args=(path, correlator, scan_fn, alert_fn),
                            daemon=True
                        ).start()

            obs = PollingObserver()
            obs.schedule(USBHandler(), str(drive), recursive=True)
            obs.start()
            log.info(f"USB: watching {drive} for file copies")

            # Watch until drive is removed
            while drive in self._known_drives and self._running:
                time.sleep(2)

            obs.stop()
            obs.join(timeout=3)
            log.info(f"USB: stopped watching {drive}")

        except Exception as e:
            log.debug(f"USB watch error for {drive}: {e}")


def _scan_usb_file(path: Path, correlator, scan_fn, alert_fn):
    """Scan a file copied to USB and alert if sensitive."""
    try:
        time.sleep(0.5)  # wait for write
        if not path.exists() or path.stat().st_size == 0:
            return

        text = scan_fn(path) if callable(scan_fn) else ""

        # Check for PII in the file
        from security_mode import scan_for_pii, SEVERITY_ORDER
        if text:
            sec = scan_for_pii(text, "usb")
            if sec.has_threats:
                log.info(
                    f"USB THREAT: {sec.severity} PII in file copied to USB: {path.name}"
                )
                if correlator:
                    correlator.record(IncidentEvent(
                        ts=time.time(),
                        event_type="USB_COPY",
                        severity=sec.severity,
                        source=str(path),
                        detail=f"Sensitive file copied to USB: {path.name} ({sec.summary})",
                        metadata={"pii_types": [m.pattern_name for m in sec.matches]},
                    ), capture_screenshot=True)
                if alert_fn:
                    alert_fn(path, sec)
    except Exception as e:
        log.debug(f"USB file scan error: {e}")


# ============================================================================
# PROCESS ANOMALY MONITOR
# ============================================================================

# Processes that are suspicious when spawned by documents
SUSPICIOUS_CHILD_PROCESSES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe",
}

# Processes that should never spawn from Office apps
OFFICE_PROCESSES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"
}


class ProcessMonitor:
    """
    Watches for anomalous process behavior:
    - Office apps spawning shell processes (macro attack)
    - Unusual processes at unusual times
    - Known malware process names
    """

    def __init__(self, incident_correlator=None):
        self._correlator = incident_correlator
        self._running = False
        self._known_pids = set()
        self._baseline_procs = set()
        self._interval = 10

    def start(self):
        if not IS_WIN:
            log.debug("Process monitor: Windows only")
            return
        self._baseline_procs = self._get_process_names()
        self._running = True
        threading.Thread(target=self._loop, daemon=True, name="ProcessMonitor").start()
        log.info(f"Process monitor active  -  watching {len(self._baseline_procs)} baseline processes")

    def stop(self):
        self._running = False

    def _get_processes(self) -> dict:
        """Get current processes as {pid: name} dict."""
        procs = {}
        if not IS_WIN:
            return procs
        try:
            r = subprocess.run(
                ["wmic", "process", "get", "ProcessId,Name,ParentProcessId",
                 "/format:csv"],
                capture_output=True, text=True, timeout=10,
                **_SUBPROCESS_FLAGS)
            for line in r.stdout.splitlines():
                parts = line.strip().split(",")
                if len(parts) >= 4:
                    try:
                        name = parts[1].strip().lower()
                        pid  = int(parts[2].strip())
                        ppid = int(parts[3].strip())
                        procs[pid] = {"name": name, "ppid": ppid}
                    except (ValueError, IndexError):
                        pass
        except Exception as e:
            log.debug(f"Process list error: {e}")
        return procs

    def _get_process_names(self) -> set:
        return {p["name"] for p in self._get_processes().values()}

    def _loop(self):
        while self._running:
            try:
                procs = self._get_processes()

                # Check for Office apps spawning suspicious children
                for pid, info in procs.items():
                    name = info["name"]
                    ppid = info["ppid"]

                    if name in SUSPICIOUS_CHILD_PROCESSES:
                        parent = procs.get(ppid, {}).get("name", "")
                        if parent in OFFICE_PROCESSES:
                            detail = (
                                f"MACRO ATTACK: {parent} spawned {name} "
                                f"(PID {pid}) - possible macro malware"
                            )
                            log.warning(f"PROCESS ANOMALY: {detail}")
                            if self._correlator:
                                self._correlator.record(IncidentEvent(
                                    ts=time.time(),
                                    event_type="PROCESS_ANOMALY",
                                    severity="CRITICAL",
                                    source=f"{parent} -> {name}",
                                    detail=detail,
                                    metadata={"parent": parent, "child": name, "pid": pid},
                                ), capture_screenshot=True)

            except Exception as e:
                log.debug(f"Process monitor error: {e}")

            time.sleep(self._interval)


# ============================================================================
# INCIDENT DASHBOARD  -  HTML report of all incidents
# ============================================================================

def build_incident_dashboard(data_dir: Path) -> Path:
    """
    Build a full HTML incident timeline dashboard.
    Shows all events correlated into chains, with screenshots.
    Returns path to saved HTML file.
    """
    incidents_file = data_dir / "incidents.jsonl"
    events_file    = data_dir / "events.jsonl"
    out_path       = data_dir / "incident_dashboard.html"

    chains = []
    if incidents_file.exists():
        for line in incidents_file.read_text(encoding="utf-8").splitlines():
            try:
                chains.append(json.loads(line))
            except:
                pass

    events = []
    if events_file.exists():
        for line in events_file.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except:
                pass

    # Sort most recent first
    chains.sort(key=lambda c: c.get("started_at", 0), reverse=True)
    events.sort(key=lambda e: e.get("ts", 0), reverse=True)

    SEV_COLOR = {
        "CRITICAL": "#ff2244", "HIGH": "#ff6600",
        "MEDIUM": "#ffaa00",   "LOW": "#ffdd00",
        "CLEAN": "#44cc77",
    }

    def sev_badge(sev):
        col = SEV_COLOR.get(sev, "#888")
        return (f'<span style="background:{col};color:#000;padding:2px 8px;'
                f'border-radius:4px;font-size:11px;font-weight:bold">{sev}</span>')

    def event_row(ev):
        sev = ev.get("severity", "LOW")
        col = SEV_COLOR.get(sev, "#888")
        ss  = ev.get("screenshot_path", "")
        ss_link = (f' <a href="file:///{ss}" style="color:#00e5ff;font-size:10px">'
                   f'[screenshot]</a>' if ss and Path(ss).exists() else "")
        return f"""
        <tr style="border-bottom:1px solid #1a1a2e">
          <td style="padding:8px;color:#888;font-size:11px;white-space:nowrap">
            {ev.get("ts_str","")}</td>
          <td style="padding:8px">{sev_badge(sev)}</td>
          <td style="padding:8px;color:#aaa;font-size:12px">
            {ev.get("event_type","")}</td>
          <td style="padding:8px;color:#e8e8f0;font-size:12px">
            {ev.get("detail","")}{ss_link}</td>
        </tr>"""

    def chain_card(ch):
        sev  = ch.get("severity", "LOW")
        col  = SEV_COLOR.get(sev, "#888")
        evs  = "".join(event_row(e) for e in ch.get("events", []))
        dur  = ch.get("duration_seconds", 0)
        return f"""
        <div style="background:#0d0d14;border:1px solid {col};border-radius:8px;
                    margin:16px 0;overflow:hidden">
          <div style="background:{col}22;padding:14px 20px;border-bottom:1px solid {col}44;
                      display:flex;align-items:center;gap:12px">
            <span style="color:{col};font-size:20px;font-weight:bold">[!]</span>
            <div style="flex:1">
              <div style="color:{col};font-weight:bold;font-size:14px">
                {ch.get("title","")}</div>
              <div style="color:#888;font-size:11px;margin-top:2px">
                {ch.get("started_str","")}  -  
                {ch.get("event_count",0)} events over {dur:.0f}s</div>
            </div>
            {sev_badge(sev)}
          </div>
          <div style="padding:12px 16px;color:#888;font-size:12px">
            {ch.get("description","")}</div>
          <table style="width:100%;border-collapse:collapse">{evs}</table>
        </div>"""

    chains_html = "".join(chain_card(c) for c in chains[:50]) or (
        '<div style="color:#444;text-align:center;padding:40px">'
        'No incident chains detected yet. Security mode is monitoring.</div>'
    )

    # Recent events table (last 100)
    recent_rows = "".join(event_row(e) for e in events[:100])

    stats_critical = sum(1 for c in chains if c.get("severity") == "CRITICAL")
    stats_high     = sum(1 for c in chains if c.get("severity") == "HIGH")
    stats_events   = len(events)

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AIScan Incident Dashboard</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #07070f; color: #e8e8f0; font-family: 'Segoe UI', sans-serif; }}
    .navbar {{ background: #0d0d14; border-bottom: 1px solid #1a1a2e;
               padding: 14px 32px; display: flex; align-items: center; gap: 12px; }}
    .logo {{ color: #00e5ff; font-weight: 900; font-size: 18px; letter-spacing: 1px; }}
    .subtitle {{ color: #444; font-size: 12px; margin-left: auto; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
    .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
    .stat {{ background: #0d0d14; border: 1px solid #1a1a2e; border-radius: 8px;
             padding: 20px; text-align: center; }}
    .stat-num {{ font-size: 36px; font-weight: 900; margin-bottom: 4px; }}
    .stat-label {{ color: #666; font-size: 12px; }}
    .section-title {{ color: #666; font-size: 11px; letter-spacing: 2px;
                      text-transform: uppercase; margin: 32px 0 12px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    tr:hover {{ background: #0d0d14; }}
    .empty {{ color: #333; text-align: center; padding: 40px; }}
    .refresh {{ color: #00e5ff; font-size: 11px; cursor: pointer;
                background: none; border: 1px solid #00e5ff44;
                padding: 4px 12px; border-radius: 4px; float: right; }}
  </style>
</head>
<body>
  <div class="navbar">
    <span class="logo">AI</span>
    <span style="color:#fff;font-weight:700;font-size:18px">Scan</span>
    <span style="color:#ff4455;font-weight:600;font-size:13px;
                 background:#ff445522;padding:3px 10px;border-radius:4px;
                 border:1px solid #ff445544">INCIDENT DASHBOARD</span>
    <span class="subtitle">
      Last updated: {time.strftime("%Y-%m-%d %H:%M:%S")}
    </span>
    <button class="refresh" onclick="location.reload()">Refresh</button>
  </div>

  <div class="container">
    <div class="stats">
      <div class="stat">
        <div class="stat-num" style="color:#ff2244">{stats_critical}</div>
        <div class="stat-label">Critical Incidents</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#ff6600">{stats_high}</div>
        <div class="stat-label">High Severity</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#00e5ff">{len(chains)}</div>
        <div class="stat-label">Total Chains</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#888">{stats_events}</div>
        <div class="stat-label">Total Events</div>
      </div>
    </div>

    <div class="section-title">Incident Chains</div>
    {chains_html}

    <div class="section-title">All Events (last 100)</div>
    <table>
      <tr style="border-bottom:1px solid #1a1a2e">
        <th style="padding:8px;text-align:left;color:#444;font-size:11px">TIME</th>
        <th style="padding:8px;text-align:left;color:#444;font-size:11px">SEV</th>
        <th style="padding:8px;text-align:left;color:#444;font-size:11px">TYPE</th>
        <th style="padding:8px;text-align:left;color:#444;font-size:11px">DETAIL</th>
      </tr>
      {recent_rows}
    </table>
  </div>
</body>
</html>"""

    out_path.write_text(html, encoding="utf-8")
    log.info(f"Incident dashboard updated: {len(chains)} chains, {len(events)} events")
    return out_path


# ============================================================================
# CHAIN ALERT POPUP
# ============================================================================

def show_chain_alert(chain: IncidentChain, dashboard_path: Path = None):
    """Show popup alert for a detected incident chain."""
    threading.Thread(
        target=_chain_popup,
        args=(chain, dashboard_path),
        daemon=True
    ).start()


def _chain_popup(chain: IncidentChain, dashboard_path: Path = None):
    try:
        import tkinter as tk

        SEV_COLORS = {
            "CRITICAL": "#ff2244", "HIGH": "#ff6600",
            "MEDIUM": "#ffaa00",   "LOW": "#ffdd00",
        }
        color = SEV_COLORS.get(chain.severity, "#ff4455")

        root = tk.Tk()
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        root.attributes("-alpha", 0.97)
        root.configure(bg="#0d0d14")

        W, H = 420, 260
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{sw-W-20}+{sh-H-60}")

        tk.Frame(root, bg=color, height=4).pack(fill="x")

        hdr = tk.Frame(root, bg="#0f0008"); hdr.pack(fill="x")
        tk.Label(hdr, text="[!!] INCIDENT CHAIN DETECTED",
                 font=("Helvetica", 11, "bold"), fg=color,
                 bg="#0f0008").pack(side="left", padx=16, pady=10)
        tk.Label(hdr, text=chain.severity,
                 font=("Helvetica", 9, "bold"), fg="#0d0d14",
                 bg=color).pack(side="right", padx=12, pady=10)

        main = tk.Frame(root, bg="#0d0d14"); main.pack(fill="both", expand=True, padx=16)

        tk.Label(main, text=chain.title,
                 font=("Helvetica", 12, "bold"), fg="#e8e8f0",
                 bg="#0d0d14").pack(anchor="w", pady=(12, 4))

        tk.Label(main, text=chain.description,
                 font=("Helvetica", 9), fg="#888",
                 bg="#0d0d14", wraplength=380).pack(anchor="w", pady=(0, 8))

        # Event count and duration
        info = (f"{chain.event_count} events  |  "
                f"{chain.duration_seconds:.0f}s window  |  "
                f"{time.strftime('%H:%M:%S', time.localtime(chain.started_at))}")
        tk.Label(main, text=info,
                 font=("Courier", 9), fg="#555",
                 bg="#0d0d14").pack(anchor="w", pady=(0, 12))

        # Screenshot indicator
        screenshots = [e.screenshot_path for e in chain.events if e.screenshot_path]
        if screenshots:
            tk.Label(main,
                     text=f"[camera] {len(screenshots)} screenshot(s) saved as evidence",
                     font=("Helvetica", 9), fg="#00e5ff",
                     bg="#0d0d14").pack(anchor="w", pady=(0, 8))

        bf = tk.Frame(main, bg="#0d0d14"); bf.pack(fill="x", pady=(4, 8))

        if dashboard_path and Path(dashboard_path).exists():
            import webbrowser
            tk.Button(bf, text="View Dashboard",
                      command=lambda: [webbrowser.open(
                          Path(dashboard_path).as_uri()), root.destroy()],
                      font=("Helvetica", 9, "bold"),
                      fg="#0d0d14", bg=color,
                      relief="flat", padx=12, pady=5,
                      cursor="hand2").pack(side="left")

        tk.Button(bf, text="Dismiss",
                  command=root.destroy,
                  font=("Helvetica", 9), fg="#888", bg="#1a1a28",
                  relief="flat", padx=12, pady=5,
                  cursor="hand2").pack(side="right")

        root.after(25000, root.destroy)

        root.attributes("-alpha", 0.0)
        def fade(a=0.0):
            if a < 0.97:
                root.attributes("-alpha", min(a + 0.08, 0.97))
                root.after(16, lambda: fade(a + 0.08))
        root.after(10, fade)
        root.mainloop()

    except Exception as e:
        log.debug(f"Chain popup error: {e}")
