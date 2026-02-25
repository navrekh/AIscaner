"""
AIScan License System
- 14 day free trial from first launch
- After trial: shows upgrade screen, app pauses
- User enters license key from Razorpay purchase
- Key validated locally using HMAC — no server needed
"""
import hmac, hashlib, json, time, base64
from pathlib import Path
import sys, os

# ── Secret known only to you — NEVER share this ──────────────────────────
# This is what makes keys impossible to fake
LICENSE_SECRET = "aiscan-2026-navrekh-secret-xK9mP2qR"

# ── Where trial/license data is stored on user's machine ─────────────────
if sys.platform == "win32":
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AIScan"
elif sys.platform == "darwin":
    DATA_DIR = Path.home() / "Library" / "Application Support" / "AIScan"
else:
    DATA_DIR = Path.home() / ".aiscan"

DATA_DIR.mkdir(parents=True, exist_ok=True)
LICENSE_FILE = DATA_DIR / "license.json"

TRIAL_DAYS = 14


def _load():
    if LICENSE_FILE.exists():
        try:
            return json.loads(LICENSE_FILE.read_text())
        except:
            pass
    return {}


def _save(data):
    LICENSE_FILE.write_text(json.dumps(data))


def _make_key(email: str) -> str:
    """Generate a valid license key for an email. You run this after payment."""
    raw = f"AISCAN-{email.lower().strip()}"
    sig = hmac.new(LICENSE_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:24].upper()
    # Format as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
    return "-".join(sig[i:i+4] for i in range(0, 24, 4))


def _verify_key(key: str, email: str) -> bool:
    """Check if a license key is valid for an email."""
    expected = _make_key(email)
    return key.strip().upper() == expected


def get_status():
    """
    Returns dict with:
      status: 'trial' | 'active' | 'expired'
      days_left: int (only for trial)
      email: str (only for active)
    """
    data = _load()

    # Already licensed
    if data.get("licensed"):
        return {"status": "active", "email": data.get("email", "")}

    # First launch — record trial start
    if "trial_start" not in data:
        data["trial_start"] = time.time()
        _save(data)

    days_used = (time.time() - data["trial_start"]) / 86400
    days_left  = max(0, int(TRIAL_DAYS - days_used))

    if days_left > 0:
        return {"status": "trial", "days_left": days_left}
    else:
        return {"status": "expired"}


def activate(email: str, key: str) -> tuple[bool, str]:
    """
    Try to activate with email + key.
    Returns (success, message)
    """
    email = email.strip().lower()
    if not email or "@" not in email:
        return False, "Please enter a valid email address."
    if not key.strip():
        return False, "Please enter your license key."
    if _verify_key(key, email):
        data = _load()
        data["licensed"] = True
        data["email"] = email
        data["activated_at"] = time.time()
        _save(data)
        return True, "License activated! Thank you."
    else:
        return False, "Invalid license key. Please check your email and key and try again."


def reset_for_testing():
    """Dev only — resets trial so you can test expiry."""
    if LICENSE_FILE.exists():
        LICENSE_FILE.unlink()


# ── Key generator — you run this to give a customer their key ────────────
if __name__ == "__main__":
    if len(sys.argv) == 2:
        email = sys.argv[1]
        key = _make_key(email)
        print(f"\nLicense key for {email}:")
        print(f"  {key}\n")
    else:
        print("Usage: python license.py customer@email.com")
