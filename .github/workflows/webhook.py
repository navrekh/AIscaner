"""
AIScan Webhook & Email Digest
Sends alerts to external systems when critical events occur.
Supports:
  - Webhook POST (JSON) - works with Slack, Teams, Zapier, custom endpoints
  - Email digest (daily/weekly summary via SMTP)
  - In-app notification log

Zero dependencies beyond stdlib (urllib, smtplib).
"""
import json, logging, smtplib, ssl, threading, time, urllib.request, urllib.error
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("aiscan")


@dataclass
class WebhookConfig:
    url: str = ""
    enabled: bool = False
    min_severity: str = "HIGH"   # only send HIGH/CRITICAL
    include_entity: bool = True
    secret_header: str = ""      # optional X-AIScan-Secret header


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    sender: str = ""
    password: str = ""
    recipient: str = ""
    digest_frequency: str = "DAILY"  # DAILY / WEEKLY
    last_digest_sent: float = 0.0


def send_webhook(config: WebhookConfig, event: dict) -> bool:
    """
    POST a JSON event to the webhook URL.
    event should have: type, severity, title, detail, timestamp, file (optional)
    """
    if not config.enabled or not config.url:
        return False

    sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if sev_order.get(event.get("severity","LOW"), 1) < sev_order.get(config.min_severity, 3):
        return False

    payload = {
        "source": "AIScan",
        "version": "5.0",
        "timestamp": event.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ")),
        "event_type": event.get("type", "ALERT"),
        "severity": event.get("severity", "HIGH"),
        "title": event.get("title", "AIScan Alert"),
        "detail": event.get("detail", ""),
        "file": event.get("file", ""),
        "entity": event.get("entity", ""),
        "score": event.get("score", 0),
    }

    # Slack-compatible format (works with Slack incoming webhooks directly)
    slack_payload = {
        "text": f"*[AIScan {payload['severity']}]* {payload['title']}",
        "attachments": [{
            "color": {"CRITICAL":"#ff2244","HIGH":"#ff6600",
                     "MEDIUM":"#ffaa00","LOW":"#44cc77"}.get(payload["severity"],"#888"),
            "fields": [
                {"title": "Detail",  "value": payload["detail"],  "short": False},
                {"title": "File",    "value": payload["file"] or "N/A", "short": True},
                {"title": "Entity",  "value": payload["entity"] or "N/A", "short": True},
            ],
            "footer": f"AIScan v5 | {payload['timestamp']}",
        }],
        **payload,  # also include raw payload for non-Slack consumers
    }

    try:
        data = json.dumps(slack_payload).encode("utf-8")
        headers = {"Content-Type": "application/json",
                   "User-Agent": "AIScan/5.0"}
        if config.secret_header:
            headers["X-AIScan-Secret"] = config.secret_header

        req = urllib.request.Request(config.url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            if status < 300:
                log.info(f"Webhook sent: {payload['title']} ({status})")
                return True
            else:
                log.warning(f"Webhook HTTP {status}")
                return False
    except urllib.error.URLError as e:
        log.warning(f"Webhook failed (network): {e}")
        return False
    except Exception as e:
        log.warning(f"Webhook error: {e}")
        return False


def send_webhook_async(config: WebhookConfig, event: dict):
    """Non-blocking webhook send."""
    threading.Thread(
        target=send_webhook, args=(config, event), daemon=True).start()


def build_digest_html(events: list, period: str, org_name: str = "Your Organisation") -> str:
    """Build an HTML email digest from a list of events."""
    critical = [e for e in events if e.get("severity") == "CRITICAL"]
    high     = [e for e in events if e.get("severity") == "HIGH"]
    total    = len(events)

    def color(sev):
        return {"CRITICAL":"#ff2244","HIGH":"#ff6600","MEDIUM":"#ffaa00","LOW":"#888"}.get(sev,"#888")

    rows = ""
    for ev in events[-20:]:  # last 20 events
        col = color(ev.get("severity","LOW"))
        rows += f"""
        <tr style="border-bottom:1px solid #eee">
          <td style="padding:8px;color:#999;font-size:11px">{ev.get('timestamp','')[:16]}</td>
          <td style="padding:8px"><span style="color:{col};font-weight:bold;font-size:11px">
            {ev.get('severity','')}</span></td>
          <td style="padding:8px;font-size:12px">{ev.get('title','')}</td>
          <td style="padding:8px;color:#999;font-size:11px">{ev.get('file','')[:40]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:Helvetica,sans-serif;background:#f5f5f8;margin:0;padding:20px">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden">
    <div style="background:#07070f;padding:24px">
      <span style="color:#00e5ff;font-weight:900;font-size:20px">AI</span>
      <span style="color:#fff;font-weight:700;font-size:20px">Scan</span>
      <span style="color:#444;font-size:13px;margin-left:12px">{period} Digest</span>
    </div>
    <div style="padding:24px">
      <p style="color:#333;font-size:14px">Security digest for <b>{org_name}</b>.</p>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin:20px 0">
        <div style="background:#fff5f5;border:1px solid #fdd;border-radius:6px;padding:16px;text-align:center">
          <div style="font-size:28px;font-weight:900;color:#ff2244">{len(critical)}</div>
          <div style="font-size:11px;color:#999">Critical</div>
        </div>
        <div style="background:#fff8f0;border:1px solid #fde;border-radius:6px;padding:16px;text-align:center">
          <div style="font-size:28px;font-weight:900;color:#ff6600">{len(high)}</div>
          <div style="font-size:11px;color:#999">High</div>
        </div>
        <div style="background:#f5f5ff;border:1px solid #ddf;border-radius:6px;padding:16px;text-align:center">
          <div style="font-size:28px;font-weight:900;color:#444">{total}</div>
          <div style="font-size:11px;color:#999">Total Events</div>
        </div>
      </div>
      {'<p style="color:#ff2244;font-weight:bold">Action required: critical events detected.</p>' if critical else '<p style="color:#44cc77">No critical events this period.</p>'}
      <table style="width:100%;border-collapse:collapse;margin-top:16px">
        <tr style="background:#f5f5f8">
          <th style="padding:8px;text-align:left;font-size:11px;color:#999">TIME</th>
          <th style="padding:8px;text-align:left;font-size:11px;color:#999">SEV</th>
          <th style="padding:8px;text-align:left;font-size:11px;color:#999">EVENT</th>
          <th style="padding:8px;text-align:left;font-size:11px;color:#999">FILE</th>
        </tr>
        {rows}
      </table>
    </div>
    <div style="background:#f5f5f8;padding:16px;font-size:11px;color:#999;text-align:center">
      AIScan v5 | Generated {time.strftime('%Y-%m-%d %H:%M')} |
      <a href="file:///AIScan/incident_dashboard.html">View Dashboard</a>
    </div>
  </div>
</body></html>"""


def send_email_digest(config: EmailConfig, events: list,
                      org_name: str = "Your Organisation") -> bool:
    """Send email digest via SMTP."""
    if not config.enabled or not config.sender or not config.recipient:
        return False

    period = f"Weekly ({time.strftime('%b %d')})" if config.digest_frequency == "WEEKLY" \
        else f"Daily ({time.strftime('%b %d')})"

    html = build_digest_html(events, period, org_name)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"AIScan {period} Security Digest"
    msg["From"]    = config.sender
    msg["To"]      = config.recipient
    msg.attach(MIMEText(html, "html"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(config.smtp_host, config.smtp_port) as server:
            server.starttls(context=context)
            server.login(config.sender, config.password)
            server.sendmail(config.sender, config.recipient, msg.as_string())
        config.last_digest_sent = time.time()
        log.info(f"Email digest sent to {config.recipient} ({len(events)} events)")
        return True
    except smtplib.SMTPException as e:
        log.warning(f"Email digest SMTP error: {e}")
        return False
    except Exception as e:
        log.warning(f"Email digest error: {e}")
        return False


class NotificationManager:
    """
    Central notification hub.
    Fires webhooks and manages digest scheduling.
    """

    def __init__(self, data_dir: Path):
        self._data_dir = data_dir
        self._config_file = data_dir / "notification_config.json"
        self._event_log   = data_dir / "notification_events.jsonl"
        self.webhook = WebhookConfig()
        self.email   = EmailConfig()
        self._load_config()

    def _load_config(self):
        if self._config_file.exists():
            try:
                d = json.loads(self._config_file.read_text(encoding="utf-8"))
                for k, v in d.get("webhook", {}).items():
                    if hasattr(self.webhook, k): setattr(self.webhook, k, v)
                for k, v in d.get("email", {}).items():
                    if hasattr(self.email, k):   setattr(self.email, k, v)
            except Exception as e:
                log.debug(f"Notification config load error: {e}")

    def save_config(self):
        try:
            self._config_file.write_text(
                json.dumps({
                    "webhook": self.webhook.__dict__,
                    "email":   self.email.__dict__,
                }, indent=2), encoding="utf-8")
        except Exception as e:
            log.debug(f"Notification config save error: {e}")

    def notify(self, event_type: str, severity: str, title: str,
               detail: str, file: str = "", entity: str = "",
               score: float = 0):
        """Send notifications for an event."""
        event = {
            "type":      event_type,
            "severity":  severity,
            "title":     title,
            "detail":    detail,
            "file":      file,
            "entity":    entity,
            "score":     score,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        # Log event
        try:
            with open(self._event_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

        # Fire webhook
        if self.webhook.enabled:
            send_webhook_async(self.webhook, event)

    def get_recent_events(self, days: int = 7) -> list:
        cutoff = time.strftime("%Y-%m-%d",
            time.localtime(time.time() - days * 86400))
        events = []
        if self._event_log.exists():
            for line in self._event_log.read_text(encoding="utf-8").splitlines():
                try:
                    ev = json.loads(line)
                    if ev.get("timestamp","") >= cutoff:
                        events.append(ev)
                except Exception:
                    pass
        return events

    def send_digest_if_due(self, org_name: str = ""):
        """Send email digest if it's due."""
        if not self.email.enabled:
            return
        now = time.time()
        last = self.email.last_digest_sent
        freq = self.email.digest_frequency
        due_after = 86400 if freq == "DAILY" else 604800
        if now - last >= due_after:
            events = self.get_recent_events(1 if freq == "DAILY" else 7)
            if events:  # only send if there's something to report
                send_email_digest(self.email, events, org_name)
                self.save_config()


def show_notification_settings_ui(manager: NotificationManager):
    threading.Thread(target=_notification_ui, args=(manager,), daemon=True).start()


def _notification_ui(manager: NotificationManager):
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.title("AIScan - Notifications & Webhooks")
        root.configure(bg="#0d0d14")
        W, H = 560, 500
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        tk.Frame(root, bg="#00e5ff", height=3).pack(fill="x")
        hdr = tk.Frame(root, bg="#0a0a12"); hdr.pack(fill="x")
        tk.Label(hdr, text="Notifications & Webhooks",
                 font=("Helvetica",13,"bold"),
                 fg="#00e5ff", bg="#0a0a12").pack(side="left",padx=20,pady=14)

        main = tk.Frame(root, bg="#0d0d14"); main.pack(fill="both", expand=True, padx=24, pady=16)

        def labeled_entry(parent, label_text, default="", show=""):
            f = tk.Frame(parent, bg="#0d0d14"); f.pack(fill="x", pady=3)
            tk.Label(f, text=label_text, font=("Helvetica",9), fg="#888",
                     bg="#0d0d14", width=16, anchor="w").pack(side="left")
            var = tk.StringVar(value=default)
            tk.Entry(f, textvariable=var, show=show,
                     font=("Helvetica",9), bg="#1a1a2e", fg="#e8e8f0",
                     insertbackground="#fff", relief="flat",
                     width=32).pack(side="left", padx=(4,0))
            return var

        # Webhook section
        tk.Label(main, text="Webhook (Slack / Teams / Custom)",
                 font=("Helvetica",10,"bold"), fg="#e8e8f0",
                 bg="#0d0d14").pack(anchor="w", pady=(0,6))
        wh_enabled = tk.BooleanVar(value=manager.webhook.enabled)
        tk.Checkbutton(main, text="Enable webhook",
                       variable=wh_enabled, font=("Helvetica",9),
                       fg="#888", bg="#0d0d14", activebackground="#0d0d14",
                       selectcolor="#0d0d14").pack(anchor="w")
        wh_url  = labeled_entry(main, "Webhook URL:", manager.webhook.url)
        wh_sec  = labeled_entry(main, "Secret header:", manager.webhook.secret_header, show="*")
        sev_var = tk.StringVar(value=manager.webhook.min_severity)
        rf = tk.Frame(main, bg="#0d0d14"); rf.pack(fill="x", pady=3)
        tk.Label(rf, text="Min severity:", font=("Helvetica",9),
                 fg="#888", bg="#0d0d14", width=16, anchor="w").pack(side="left")
        for sev in ["MEDIUM","HIGH","CRITICAL"]:
            tk.Radiobutton(rf, text=sev, variable=sev_var, value=sev,
                           font=("Helvetica",9), fg="#888",
                           bg="#0d0d14", activebackground="#0d0d14",
                           selectcolor="#0d0d14").pack(side="left", padx=6)

        tk.Frame(main, bg="#1a1a2e", height=1).pack(fill="x", pady=12)

        # Email section
        tk.Label(main, text="Email Digest",
                 font=("Helvetica",10,"bold"), fg="#e8e8f0",
                 bg="#0d0d14").pack(anchor="w", pady=(0,6))
        em_enabled = tk.BooleanVar(value=manager.email.enabled)
        tk.Checkbutton(main, text="Enable email digest",
                       variable=em_enabled, font=("Helvetica",9),
                       fg="#888", bg="#0d0d14", activebackground="#0d0d14",
                       selectcolor="#0d0d14").pack(anchor="w")
        em_host  = labeled_entry(main, "SMTP host:", manager.email.smtp_host)
        em_from  = labeled_entry(main, "From (email):", manager.email.sender)
        em_pass  = labeled_entry(main, "Password:", manager.email.password, show="*")
        em_to    = labeled_entry(main, "Send to:", manager.email.recipient)
        freq_var = tk.StringVar(value=manager.email.digest_frequency)
        ff = tk.Frame(main, bg="#0d0d14"); ff.pack(fill="x", pady=3)
        tk.Label(ff, text="Frequency:", font=("Helvetica",9),
                 fg="#888", bg="#0d0d14", width=16, anchor="w").pack(side="left")
        for f in ["DAILY","WEEKLY"]:
            tk.Radiobutton(ff, text=f, variable=freq_var, value=f,
                           font=("Helvetica",9), fg="#888",
                           bg="#0d0d14", activebackground="#0d0d14",
                           selectcolor="#0d0d14").pack(side="left", padx=8)

        status_var = tk.StringVar()
        tk.Label(main, textvariable=status_var, font=("Helvetica",9),
                 fg="#44cc77", bg="#0d0d14").pack(anchor="w", pady=(8,0))

        def save():
            manager.webhook.enabled       = wh_enabled.get()
            manager.webhook.url           = wh_url.get()
            manager.webhook.secret_header = wh_sec.get()
            manager.webhook.min_severity  = sev_var.get()
            manager.email.enabled         = em_enabled.get()
            manager.email.smtp_host       = em_host.get()
            manager.email.sender          = em_from.get()
            manager.email.password        = em_pass.get()
            manager.email.recipient       = em_to.get()
            manager.email.digest_frequency = freq_var.get()
            manager.save_config()
            status_var.set("Settings saved.")

        def test_webhook():
            save()
            ok = send_webhook(manager.webhook, {
                "type": "TEST", "severity": "HIGH",
                "title": "AIScan Webhook Test",
                "detail": "This is a test notification from AIScan.",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            status_var.set("Test sent!" if ok else "Test failed - check URL and network.")

        bf = tk.Frame(root, bg="#0a0a12"); bf.pack(fill="x", side="bottom")
        tk.Frame(bf, bg="#1a1a2e", height=1).pack(fill="x")
        brow = tk.Frame(bf, bg="#0a0a12"); brow.pack(fill="x", padx=16, pady=8)
        tk.Button(brow, text="Save", command=save,
                  font=("Helvetica",10,"bold"), fg="#0d0d14", bg="#00e5ff",
                  relief="flat", padx=14, pady=6).pack(side="right", padx=(6,0))
        tk.Button(brow, text="Test Webhook", command=test_webhook,
                  font=("Helvetica",10), fg="#0d0d14", bg="#44cc77",
                  relief="flat", padx=14, pady=6).pack(side="right", padx=(6,0))
        tk.Button(brow, text="Close", command=root.destroy,
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=14, pady=6).pack(side="left")
        root.mainloop()
    except Exception as e:
        log.error(f"Notification UI error: {e}")
