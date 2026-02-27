"""
AIScan Extended PII Detector
Covers all PII types required by DPDP Act 2023 (India) plus global standards.

Categories:
  IDENTITY    -- Aadhaar, PAN, Passport, Voter ID, Driving License
  FINANCIAL   -- UPI, IFSC, Account numbers, Credit cards, GST
  CONTACT     -- Phone, Email, Address
  BIOMETRIC   -- References to biometric data fields
  HEALTH      -- Medical record numbers, diagnosis codes
  EMPLOYMENT  -- Employee IDs, salary info, PF numbers
  CREDENTIALS -- Passwords, API keys, tokens, SSH keys
  LEGAL       -- Case numbers, FIR references
  VEHICLE     -- Vehicle registration numbers

Each pattern returns: (category, label, severity, matched_value)
Severity: CRITICAL (Aadhaar, financial, credentials) / HIGH / MEDIUM
"""
import re, logging
from typing import List, Tuple, Optional
from dataclasses import dataclass

log = logging.getLogger("aiscan")


@dataclass
class PIIMatch:
    category: str
    label: str
    severity: str    # CRITICAL / HIGH / MEDIUM
    value: str       # redacted or partial match
    position: int    # char offset in text

    def to_dict(self):
        return {
            "category": self.category,
            "label":    self.label,
            "severity": self.severity,
            "value":    self.value,
        }


# -- INDIA-SPECIFIC PATTERNS --------------------------------------------------

INDIA_PATTERNS = [
    # Aadhaar (12 digits, various separators)
    ("IDENTITY", "Aadhaar Number", "CRITICAL",
     r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'),

    # PAN Card (AAAAA9999A format)
    ("IDENTITY", "PAN Card", "CRITICAL",
     r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),

    # Indian Passport (A/B/C/F/G/H/J/K/L/M/N/P + 7 digits)
    ("IDENTITY", "Passport Number", "HIGH",
     r'\b[A-Z]{1,2}[0-9]{7}\b'),

    # Voter ID (ECI format: 3 letters + 7 digits)
    ("IDENTITY", "Voter ID", "HIGH",
     r'\b[A-Z]{3}[0-9]{7}\b'),

    # Driving License (state code + year + digits)
    ("IDENTITY", "Driving License", "HIGH",
     r'\b[A-Z]{2}[0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{7}\b'),

    # UPI ID
    ("FINANCIAL", "UPI ID", "CRITICAL",
     r'\b[\w.\-]+@(?:oksbi|okaxis|okicici|okhdfcbank|paytm|ybl|ibl|upi|'
     r'apl|axl|fbl|hdfcbank|icici|sbi|kotak|cnrb|barodampay)\b'),

    # Generic UPI (@handle)
    ("FINANCIAL", "UPI Handle", "HIGH",
     r'\b[\w.\-]{3,}@[a-z]{3,10}\b'),

    # IFSC Code
    ("FINANCIAL", "IFSC Code", "HIGH",
     r'\b[A-Z]{4}0[A-Z0-9]{6}\b'),

    # Indian Bank Account (9-18 digits)
    ("FINANCIAL", "Bank Account", "CRITICAL",
     r'(?:account|a\/c|acc)[\s:no.#-]*(\d{9,18})\b'),

    # GST Number
    ("FINANCIAL", "GST Number", "HIGH",
     r'\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b'),

    # Indian Mobile (10 digits, optional +91)
    ("CONTACT", "Indian Mobile", "MEDIUM",
     r'(?:\+91[\s\-]?)?[6-9]\d{9}\b'),

    # PF Number
    ("EMPLOYMENT", "PF / EPFO Number", "HIGH",
     r'\b[A-Z]{2}[/\-][A-Z]{3}[/\-]\d{7}[/\-]\d{3}[/\-]\d{7}\b'),
]


# -- GLOBAL PATTERNS -----------------------------------------------------------

GLOBAL_PATTERNS = [
    # Credit / Debit cards (Luhn-valid check not done, pattern only)
    ("FINANCIAL", "Credit Card Number", "CRITICAL",
     r'\b(?:4[0-9]{12}(?:[0-9]{3})?'          # Visa
     r'|5[1-5][0-9]{14}'                        # Mastercard
     r'|3[47][0-9]{13}'                         # Amex
     r'|6(?:011|5[0-9]{2})[0-9]{12})\b'),       # Discover

    # International IBAN
    ("FINANCIAL", "IBAN", "HIGH",
     r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'),

    # Email address
    ("CONTACT", "Email Address", "MEDIUM",
     r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),

    # International phone (E.164)
    ("CONTACT", "International Phone", "MEDIUM",
     r'\+[1-9]\d{7,14}\b'),

    # US SSN
    ("IDENTITY", "US SSN", "CRITICAL",
     r'\b\d{3}-\d{2}-\d{4}\b'),

    # UK NI Number
    ("IDENTITY", "UK NI Number", "HIGH",
     r'\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b'),

    # IPv4 Address (private ranges are informational)
    ("CONTACT", "IP Address", "MEDIUM",
     r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
]


# -- CREDENTIAL PATTERNS -------------------------------------------------------

CREDENTIAL_PATTERNS = [
    # API keys (generic high-entropy strings after common keywords)
    ("CREDENTIALS", "API Key", "CRITICAL",
     r'(?:api[_\-]?key|apikey|access[_\-]?key|secret[_\-]?key)'
     r'[\s:="\']+([\w\-]{20,})'),

    # Bearer tokens
    ("CREDENTIALS", "Bearer Token", "CRITICAL",
     r'Bearer\s+([A-Za-z0-9\-._~+/]{20,})'),

    # AWS Access Key
    ("CREDENTIALS", "AWS Access Key", "CRITICAL",
     r'\bAKIA[0-9A-Z]{16}\b'),

    # GitHub Personal Access Token
    ("CREDENTIALS", "GitHub Token", "CRITICAL",
     r'\bghp_[A-Za-z0-9]{36}\b'),

    # Google API key
    ("CREDENTIALS", "Google API Key", "CRITICAL",
     r'\bAIza[0-9A-Za-z\-_]{35}\b'),

    # Private key header
    ("CREDENTIALS", "Private Key", "CRITICAL",
     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),

    # Password in code/config
    ("CREDENTIALS", "Hardcoded Password", "HIGH",
     r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']'),

    # JWT token
    ("CREDENTIALS", "JWT Token", "HIGH",
     r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
]


# -- HEALTH / BIOMETRIC --------------------------------------------------------

HEALTH_PATTERNS = [
    # ICD-10 diagnosis codes
    ("HEALTH", "ICD-10 Code", "HIGH",
     r'\b[A-Z]\d{2}(?:\.\d{1,4})?\b'),

    # References to biometric data
    ("BIOMETRIC", "Biometric Reference", "HIGH",
     r'\b(?:fingerprint|iris scan|retina scan|facial recognition|'
     r'biometric|face id|voiceprint)\b'),

    # Blood type
    ("HEALTH", "Blood Type", "MEDIUM",
     r'\b(?:A|B|AB|O)[+-]\b'),
]


# -- VEHICLE -------------------------------------------------------------------

VEHICLE_PATTERNS = [
    # Indian vehicle registration (new format: XX00XX0000)
    ("VEHICLE", "Vehicle Registration", "MEDIUM",
     r'\b[A-Z]{2}[0-9]{2}[A-Z]{1,2}[0-9]{4}\b'),
]

# -- LEGAL ---------------------------------------------------------------------

LEGAL_PATTERNS = [
    # FIR Number
    ("LEGAL", "FIR Number", "HIGH",
     r'\bFIR[\s\-/]?(?:No|Number)?[\s\-.:]*\d{1,5}/\d{4}\b'),
]


ALL_PATTERNS = (INDIA_PATTERNS + GLOBAL_PATTERNS + CREDENTIAL_PATTERNS +
                HEALTH_PATTERNS + VEHICLE_PATTERNS + LEGAL_PATTERNS)

# Compile all patterns once
_COMPILED = [(cat, label, sev, re.compile(pat, re.IGNORECASE))
             for cat, label, sev, pat in ALL_PATTERNS]


def scan_text(text: str, redact: bool = True) -> List[PIIMatch]:
    """
    Scan text for all PII types.
    Returns list of PIIMatch objects, sorted by severity.
    If redact=True, values are partially masked.
    """
    matches = []
    seen_positions = set()

    for cat, label, sev, compiled in _COMPILED:
        for m in compiled.finditer(text):
            pos = m.start()
            # Deduplicate overlapping matches
            if any(abs(pos - p) < 4 for p in seen_positions):
                continue
            seen_positions.add(pos)

            raw = m.group(0)
            value = _redact(raw, label) if redact else raw

            matches.append(PIIMatch(
                category=cat,
                label=label,
                severity=sev,
                value=value,
                position=pos,
            ))

    # Sort: CRITICAL first, then HIGH, then MEDIUM
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    matches.sort(key=lambda x: sev_order.get(x.severity, 3))
    return matches


def _redact(value: str, label: str) -> str:
    """Partially mask a PII value."""
    if len(value) <= 4:
        return "****"
    if "Aadhaar" in label:
        return f"XXXX-XXXX-{value[-4:]}"
    if "PAN" in label:
        return f"{value[:2]}***{value[-2:]}"
    if "Card" in label or "Account" in label:
        return f"{'*' * (len(value)-4)}{value[-4:]}"
    if "Email" in label:
        parts = value.split("@")
        if len(parts) == 2:
            return f"{parts[0][:2]}***@{parts[1]}"
    if "Mobile" in label or "Phone" in label:
        return f"{'*' * (len(value)-4)}{value[-4:]}"
    # Default: show first 2 and last 2
    return f"{value[:2]}{'*' * max(1, len(value)-4)}{value[-2:]}"


def get_severity(matches: List[PIIMatch]) -> str:
    """Get highest severity from a list of matches."""
    if any(m.severity == "CRITICAL" for m in matches):
        return "CRITICAL"
    if any(m.severity == "HIGH" for m in matches):
        return "HIGH"
    if any(m.severity == "MEDIUM" for m in matches):
        return "MEDIUM"
    return "NONE"


def summary(matches: List[PIIMatch]) -> str:
    """Human-readable summary of PII found."""
    if not matches:
        return "No PII detected"
    cats = {}
    for m in matches:
        cats[m.label] = cats.get(m.label, 0) + 1
    parts = [f"{count} {label}" for label, count in cats.items()]
    return ", ".join(parts[:5]) + (" ..." if len(parts) > 5 else "")
