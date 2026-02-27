"""
AIScan Security Mode
PII detection, data exfiltration alerts, credential monitoring,
phishing document detection, and sensitive data scanning.

Activates alongside AI detection when Security Mode is enabled in Settings.
"""
import re, os, sys, logging, time, threading, hashlib, zipfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("aiscan")

IS_WIN = sys.platform == "win32"


# ============================================================================
# PII PATTERNS  -  India-first, global second
# ============================================================================

PII_PATTERNS = {
    # India
    "Aadhaar Number": (
        r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
        "CRITICAL", "Aadhaar number exposed"
    ),
    "PAN Card": (
        r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "HIGH", "PAN card number exposed"
    ),
    "Indian Phone": (
        r"\b(?:\+91|91|0)?[6-9][0-9]{9}\b",
        "MEDIUM", "Indian phone number detected"
    ),
    "UPI ID": (
        r"\b[a-zA-Z0-9._-]+@(?:okicici|oksbi|okaxis|okhdfcbank|ybl|ibl|axl|"
        r"upi|paytm|phonepe|gpay|apl|waicici)\b",
        "HIGH", "UPI payment ID exposed"
    ),
    "Bank Account": (
        r"\b[0-9]{9,18}\b(?=.*(?:account|acc|bank|savings|current))",
        "HIGH", "Possible bank account number"
    ),
    "IFSC Code": (
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "MEDIUM", "IFSC code detected"
    ),
    # Global
    "Credit Card": (
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
        r"3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "CRITICAL", "Credit card number exposed"
    ),
    "Email Address": (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "LOW", "Email address detected"
    ),
    "IP Address": (
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "LOW", "IP address detected"
    ),
    # Credentials
    "API Key": (
        r"(?:sk-[a-zA-Z0-9]{15,}|"           # OpenAI (sk- + 15+ chars)
        r"AIza[0-9A-Za-z_-]{20,}|"           # Google
        r"ghp_[a-zA-Z0-9]{20,}|"             # GitHub
        r"AKIA[0-9A-Z]{16}|"                  # AWS Access Key
        r"xox[baprs]-[0-9a-zA-Z-]{10,})",    # Slack
        "CRITICAL", "API key or token exposed"
    ),
    "Password Pattern": (
        r"(?i)(?:password|passwd|pwd|secret|token|key)\s*[=:]\s*\S+",
        "CRITICAL", "Credential pattern detected"
    ),
    "Private Key": (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "CRITICAL", "Private key exposed"
    ),
    "Connection String": (
        r"(?i)(?:mongodb|mysql|postgres|redis|amqp|smtp)://[^\s]+",
        "CRITICAL", "Database connection string exposed"
    ),
    "JWT Token": (
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "HIGH", "JWT token exposed"
    ),
}

# Severity order
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class PIIMatch:
    pattern_name: str
    severity: str
    message: str
    sample: str       # redacted sample
    count: int = 1


@dataclass
class SecurityResult:
    has_threats: bool
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / CLEAN
    matches: List[PIIMatch]
    threat_count: int
    summary: str
    should_alert: bool
    block_clipboard: bool    # True for CRITICAL - clear clipboard


def scan_for_pii(text: str, context: str = "file") -> SecurityResult:
    """
    Scan text for PII, credentials, and sensitive data patterns.
    Returns SecurityResult with all matches and recommended actions.
    """
    if not text or len(text) < 5:
        return SecurityResult(False, "CLEAN", [], 0, "No threats", False, False)

    matches = []
    highest_severity = "CLEAN"

    for pattern_name, (pattern, severity, message) in PII_PATTERNS.items():
        try:
            found = re.findall(pattern, text)
            if found:
                # Redact the match for safe logging
                sample = found[0]
                if len(sample) > 4:
                    sample = sample[:2] + "*" * (len(sample) - 4) + sample[-2:]
                matches.append(PIIMatch(
                    pattern_name=pattern_name,
                    severity=severity,
                    message=message,
                    sample=sample,
                    count=len(found)
                ))
                if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest_severity, 0):
                    highest_severity = severity
        except re.error:
            continue

    if not matches:
        return SecurityResult(False, "CLEAN", [], 0, "No PII detected", False, False)

    # Build summary
    critical = [m for m in matches if m.severity == "CRITICAL"]
    high     = [m for m in matches if m.severity == "HIGH"]
    summary_parts = []
    if critical: summary_parts.append(f"{len(critical)} critical")
    if high:     summary_parts.append(f"{len(high)} high severity")
    summary = f"PII detected: {', '.join(summary_parts) or f'{len(matches)} patterns'}"

    should_alert   = highest_severity in ("CRITICAL", "HIGH")
    block_clipboard = highest_severity == "CRITICAL" and context == "clipboard"

    return SecurityResult(
        has_threats    = True,
        severity       = highest_severity,
        matches        = matches,
        threat_count   = len(matches),
        summary        = summary,
        should_alert   = should_alert,
        block_clipboard = block_clipboard,
    )


# ============================================================================
# DOCUMENT THREAT SCANNER  -  macros, executables, phishing patterns
# ============================================================================

PHISHING_PATTERNS = [
    r"(?i)verify your (?:account|identity|details)",
    r"(?i)click here (?:to )?(?:confirm|verify|update)",
    r"(?i)your account (?:will be )?(?:suspended|terminated|locked)",
    r"(?i)(?:urgent|immediate) (?:action|response) (?:required|needed)",
    r"(?i)(?:login|sign in) (?:to )?(?:confirm|verify|restore)",
    r"(?i)we (?:have )?(?:detected|noticed) (?:unusual|suspicious) (?:activity|access)",
    r"(?i)(?:update|confirm) your (?:payment|billing|credit card)",
    r"(?i)prize|winner|congratulations.*claim",
    r"(?i)(?:send|transfer|wire).{0,30}(?:money|funds|payment|bitcoin|crypto)",
]

MACRO_SIGNATURES = [
    b"VBA",
    b"AutoOpen",
    b"Document_Open",
    b"Auto_Open",
    b"Shell(",
    b"CreateObject",
    b"WScript.Shell",
    b"cmd.exe",
    b"powershell",
    b"MSXML2.XMLHTTP",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".scr",
    ".pif", ".com", ".msi", ".ps1", ".reg"
}


@dataclass
class DocumentThreat:
    threat_type: str
    severity: str
    detail: str


def scan_document_threats(file_path: Path, text: str = "") -> List[DocumentThreat]:
    """
    Scan a document for malware indicators, phishing content, and suspicious patterns.
    """
    threats = []
    ext = file_path.suffix.lower()

    # 1. Phishing text patterns
    if text:
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, text):
                threats.append(DocumentThreat(
                    "Phishing", "HIGH",
                    f"Phishing language: {pattern[6:40]}..."
                ))
                break  # one phishing alert per doc

    # 2. Macro scan for Office files
    if ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                names = z.namelist()
                # Check for VBA macro storage
                if any("vbaProject" in n or "xl/macrosheets" in n for n in names):
                    threats.append(DocumentThreat(
                        "Macro", "HIGH",
                        "Office document contains VBA macros - potential malware vector"
                    ))
                # Check macro content for suspicious calls
                for name in names:
                    if "vba" in name.lower() or "macro" in name.lower():
                        try:
                            data = z.read(name)
                            for sig in MACRO_SIGNATURES:
                                if sig in data:
                                    threats.append(DocumentThreat(
                                        "Suspicious Macro", "CRITICAL",
                                        f"Dangerous macro signature: {sig.decode('utf-8','ignore')}"
                                    ))
                                    break
                        except:
                            pass
        except:
            pass

    # 3. Disguised extension check
    name = file_path.name.lower()
    for bad_ext in SUSPICIOUS_EXTENSIONS:
        if bad_ext in name and ext in (".pdf", ".docx", ".txt"):
            threats.append(DocumentThreat(
                "Disguised File", "CRITICAL",
                f"File may be disguised executable: {file_path.name}"
            ))

    # 4. PDF with JavaScript
    if ext == ".pdf":
        try:
            data = file_path.read_bytes()
            if b"/JavaScript" in data or b"/JS " in data:
                threats.append(DocumentThreat(
                    "PDF JavaScript", "HIGH",
                    "PDF contains JavaScript - potential exploit"
                ))
            if b"/Launch" in data:
                threats.append(DocumentThreat(
                    "PDF Launch Action", "CRITICAL",
                    "PDF contains Launch action - known malware vector"
                ))
        except:
            pass

    return threats


# ============================================================================
# EXFILTRATION MONITOR  -  unusual data movement patterns
# ============================================================================

@dataclass
class ExfilAlert:
    alert_type: str
    severity: str
    detail: str
    timestamp: float = field(default_factory=time.time)


class ExfiltrationMonitor:
    """
    Watches for behavioral patterns that indicate data exfiltration:
    - Large clipboard copies
    - Rapid successive copies
    - PII copied multiple times
    - Large files saved to unusual locations
    """

    def __init__(self):
        self._clipboard_history = []   # (timestamp, word_count, has_pii)
        self._copy_times = []          # timestamps of recent copies
        self._alerts = []
        self._lock = threading.Lock()

    def record_clipboard_copy(self, text: str, has_pii: bool):
        """Call every time clipboard content changes."""
        now = time.time()
        word_count = len(text.split())

        with self._lock:
            self._clipboard_history.append((now, word_count, has_pii))
            self._copy_times.append(now)

            # Keep only last 5 minutes
            cutoff = now - 300
            self._clipboard_history = [(t,w,p) for t,w,p in self._clipboard_history if t > cutoff]
            self._copy_times = [t for t in self._copy_times if t > cutoff]

        return self._check_exfil_patterns(now, word_count, has_pii)

    def _check_exfil_patterns(self, now, word_count, has_pii) -> Optional[ExfilAlert]:
        with self._lock:
            recent = self._copy_times

            # Pattern 1: Rapid copying (10+ copies in 60 seconds)
            last_60s = [t for t in recent if now - t < 60]
            if len(last_60s) >= 10:
                return ExfilAlert(
                    "Rapid Copying", "HIGH",
                    f"{len(last_60s)} clipboard copies in 60 seconds - possible bulk data exfil"
                )

            # Pattern 2: Very large copy (2000+ words)
            if word_count >= 2000:
                return ExfilAlert(
                    "Large Copy", "MEDIUM",
                    f"{word_count} words copied to clipboard at once"
                )

            # Pattern 3: PII copied multiple times
            if has_pii:
                pii_copies = [(t,w,p) for t,w,p in self._clipboard_history if p]
                if len(pii_copies) >= 3:
                    return ExfilAlert(
                        "Repeated PII Copy", "HIGH",
                        f"PII content copied {len(pii_copies)} times in 5 minutes"
                    )

        return None


# ============================================================================
# SECURITY POPUP  -  different visual style from AI detection popup
# ============================================================================

def show_security_popup(sec_result: SecurityResult, context: str, clear_clipboard_fn=None):
    """Show security alert popup. Red-themed, more urgent than AI popup."""
    threading.Thread(
        target=_security_popup,
        args=(sec_result, context, clear_clipboard_fn),
        daemon=True
    ).start()


def _security_popup(sec_result: SecurityResult, context: str, clear_clipboard_fn=None):
    try:
        import tkinter as tk
        import tkinter.ttk as ttk

        SEV_COLORS = {
            "CRITICAL": "#ff2244",
            "HIGH":     "#ff6600",
            "MEDIUM":   "#ffaa00",
            "LOW":      "#ffdd00",
        }
        color = SEV_COLORS.get(sec_result.severity, "#ff4455")

        root = tk.Tk()
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        root.attributes("-alpha", 0.97)
        root.configure(bg="#0d0d14")

        W, H = 400, 220 + len(sec_result.matches) * 28
        H = min(H, 420)
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{sw-W-20}+{sh-H-60}")

        # Header bar - red accent for security
        tk.Frame(root, bg=color, height=4).pack(fill="x")
        hdr = tk.Frame(root, bg="#110a0a"); hdr.pack(fill="x", padx=0)

        # Shield icon + title
        tk.Label(hdr, text="[!] SECURITY ALERT",
                 font=("Helvetica", 11, "bold"), fg=color,
                 bg="#110a0a").pack(side="left", padx=16, pady=10)
        tk.Label(hdr, text=f"[{sec_result.severity}]",
                 font=("Helvetica", 9, "bold"), fg="#0d0d14",
                 bg=color).pack(side="right", padx=12, pady=10)

        main = tk.Frame(root, bg="#0d0d14"); main.pack(fill="both", expand=True, padx=16)

        # Context
        tk.Label(main, text=context, font=("Helvetica", 9),
                 fg="#666", bg="#0d0d14").pack(anchor="w", pady=(8, 2))

        # Summary
        tk.Label(main, text=sec_result.summary,
                 font=("Helvetica", 10, "bold"), fg="#e8e8f0",
                 bg="#0d0d14", wraplength=360).pack(anchor="w", pady=(0, 8))

        # Matches
        for match in sec_result.matches[:5]:
            mf = tk.Frame(main, bg="#1a0a0a", padx=10, pady=6)
            mf.pack(fill="x", pady=2)
            sev_col = SEV_COLORS.get(match.severity, color)
            tk.Label(mf, text=f"  {match.pattern_name}",
                     font=("Helvetica", 9, "bold"),
                     fg=sev_col, bg="#1a0a0a").pack(side="left")
            tk.Label(mf, text=f"  {match.sample}",
                     font=("Courier", 8),
                     fg="#888", bg="#1a0a0a").pack(side="left")
            tk.Label(mf, text=f"x{match.count}",
                     font=("Helvetica", 8),
                     fg="#555", bg="#1a0a0a").pack(side="right")

        # Action buttons
        bf = tk.Frame(main, bg="#0d0d14"); bf.pack(fill="x", pady=(12, 8))

        if sec_result.block_clipboard and clear_clipboard_fn:
            tk.Button(bf, text="Clear Clipboard",
                      command=lambda: [clear_clipboard_fn(), root.destroy()],
                      font=("Helvetica", 9, "bold"), fg="#0d0d14", bg=color,
                      relief="flat", padx=12, pady=5, cursor="hand2").pack(side="left")

        tk.Button(bf, text="Dismiss",
                  command=root.destroy,
                  font=("Helvetica", 9), fg="#888", bg="#1a1a28",
                  relief="flat", padx=12, pady=5, cursor="hand2").pack(side="right")

        # Auto-close
        duration = 20000 if sec_result.severity == "CRITICAL" else 12000
        root.after(duration, root.destroy)

        # Fade in
        root.attributes("-alpha", 0.0)
        def fade(alpha=0.0):
            if alpha < 0.97:
                root.attributes("-alpha", min(alpha + 0.08, 0.97))
                root.after(16, lambda: fade(alpha + 0.08))
        root.after(10, fade)
        root.mainloop()

    except Exception as e:
        log.debug(f"Security popup error: {e}")


# ============================================================================
# SECURITY SETTINGS
# ============================================================================

@dataclass
class SecuritySettings:
    enabled: bool = False
    scan_pii: bool = True
    scan_credentials: bool = True
    scan_macros: bool = True
    scan_phishing: bool = True
    monitor_exfiltration: bool = True
    alert_on_low: bool = False       # LOW severity = log only by default
    alert_on_medium: bool = True
    block_critical_clipboard: bool = True
    min_severity_alert: str = "HIGH"  # CRITICAL/HIGH/MEDIUM/LOW


# ============================================================================
# MAIN SECURITY SCANNER  -  called from agent
# ============================================================================

class SecurityScanner:
    """
    Main entry point. Called by agent for every scan event.
    Runs PII + document threat checks in parallel with AI detection.
    """

    def __init__(self, settings: SecuritySettings = None):
        self.settings = settings or SecuritySettings()
        self.exfil = ExfiltrationMonitor()
        self._alerts_today = 0

    def scan_text(self, text: str, context: str = "file") -> Optional[SecurityResult]:
        """Scan text for PII and sensitive patterns."""
        if not self.settings.enabled:
            return None
        result = scan_for_pii(text, context)
        if result.has_threats:
            log.info(
                f"SECURITY [{context.upper()}]: {result.severity}  -  "
                f"{result.summary}"
            )
        return result if result.has_threats else None

    def scan_file(self, path: Path, text: str = "") -> List[DocumentThreat]:
        """Scan file for document-level threats (macros, phishing, etc)."""
        if not self.settings.enabled:
            return []
        threats = scan_document_threats(path, text)
        for t in threats:
            log.info(f"SECURITY [FILE]: {t.severity}  -  {t.threat_type}: {t.detail}")
        return threats

    def on_clipboard_change(self, text: str) -> tuple:
        """
        Called on every clipboard change.
        Returns (SecurityResult or None, ExfilAlert or None)
        """
        if not self.settings.enabled:
            return None, None

        sec_result = self.scan_text(text, "clipboard")
        exfil_alert = self.exfil.record_clipboard_copy(
            text,
            has_pii=bool(sec_result and sec_result.has_threats)
        )
        return sec_result, exfil_alert

    def should_alert(self, result: SecurityResult) -> bool:
        if not result or not result.has_threats:
            return False
        min_order = SEVERITY_ORDER.get(self.settings.min_severity_alert, 3)
        result_order = SEVERITY_ORDER.get(result.severity, 0)
        return result_order >= min_order
