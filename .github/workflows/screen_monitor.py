"""
AIScan Screen Monitor v3
Real-time screen reading - detects AI content in ANY open app.
No file locks. Works while documents are open and being edited.

Fixes in v3:
- PowerShell path uses forward slashes (backslashes broke OCR silently)
- UIA skips AIScan's own tray window, tracks last user window
- Full debug logging on every tick so failures are visible
- min_words lowered to 20
- clean_ocr_text is less aggressive
"""
import sys, time, threading, hashlib, logging, re, subprocess, os
from pathlib import Path
from collections import deque

log = logging.getLogger("aiscan")
IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

# Windows: hide console window for all subprocess calls
_SUBPROCESS_FLAGS = {}
if IS_WIN:
    _SUBPROCESS_FLAGS = {"creationflags": 0x08000000}  # CREATE_NO_WINDOW

# Track last known user-facing window (not AIScan's tray)
_last_user_hwnd = None
_AISCAN_CLASSES = {"Shell_TrayWnd", "TrayNotifyWnd", "tooltips_class32"}


# ============================================================================
# FAST PATH: Windows UI Automation - reads text directly, no OCR
# ============================================================================

def read_foreground_window_text() -> str:
    """
    Read text directly from the user's focused window.
    Skips AIScan's own tray/popup windows.
    Returns None to trigger OCR fallback.
    """
    if not IS_WIN:
        return None

    try:
        import ctypes
        import ctypes.wintypes as wt
        global _last_user_hwnd

        hwnd = ctypes.windll.user32.GetForegroundWindow()
        if not hwnd:
            return None

        class_buf = ctypes.create_unicode_buffer(256)
        ctypes.windll.user32.GetClassNameW(hwnd, class_buf, 256)
        win_class = class_buf.value

        title_buf = ctypes.create_unicode_buffer(512)
        ctypes.windll.user32.GetWindowTextW(hwnd, title_buf, 512)
        win_title = title_buf.value

        # Skip AIScan's own windows - use last known user window
        is_aiscan = (
            win_class in _AISCAN_CLASSES or
            win_class.startswith("Tk") or
            "AIScan" in win_title or
            win_title == ""
        )

        if is_aiscan:
            if _last_user_hwnd:
                hwnd = _last_user_hwnd
                ctypes.windll.user32.GetClassNameW(hwnd, class_buf, 256)
                win_class = class_buf.value
                ctypes.windll.user32.GetWindowTextW(hwnd, title_buf, 512)
                win_title = title_buf.value
            else:
                return None
        else:
            _last_user_hwnd = hwnd

        log.debug(f"UIA: reading '{win_title}' class='{win_class}'")

        # Find edit control (Notepad, WordPad, text editors)
        edit_hwnd = ctypes.windll.user32.FindWindowExW(hwnd, None, "Edit", None)
        if not edit_hwnd:
            edit_hwnd = ctypes.windll.user32.FindWindowExW(hwnd, None, "RichEditD2DPT", None)
        if not edit_hwnd:
            edit_hwnd = ctypes.windll.user32.FindWindowExW(hwnd, None, "RICHEDIT50W", None)
        if not edit_hwnd:
            edit_hwnd = hwnd

        WM_GETTEXTLENGTH = 0x000E
        WM_GETTEXT = 0x000D
        text_len = ctypes.windll.user32.SendMessageW(edit_hwnd, WM_GETTEXTLENGTH, 0, 0)

        if text_len > 10:
            text_buf = ctypes.create_unicode_buffer(min(text_len + 1, 50000))
            ctypes.windll.user32.SendMessageW(edit_hwnd, WM_GETTEXT, len(text_buf), text_buf)
            text = text_buf.value.strip()
            if len(text.split()) >= 5:
                log.debug(f"UIA: got {len(text.split())} words from '{win_class}'")
                return text

    except Exception as e:
        log.debug(f"UIA error: {e}")

    return None


# ============================================================================
# OCR BACKENDS
# ============================================================================

def _ocr_pytesseract(img) -> str:
    import pytesseract
    from PIL import Image
    w, h = img.size
    img2 = img.resize((w * 2, h * 2), Image.LANCZOS)
    return pytesseract.image_to_string(img2, config='--psm 6 --oem 3')


def _ocr_windows_builtin(img) -> str:
    """
    Windows 10/11 built-in OCR via PowerShell WinRT.
    CRITICAL: use forward slashes in path - backslashes break PowerShell f-strings.
    """
    import tempfile
    # Forward slashes work on Windows and don't break PowerShell strings
    tmp_raw = tempfile.mktemp(suffix='.png')
    tmp_fwd = tmp_raw.replace(os.sep, '/')  # forward slashes for PowerShell
    try:
        img.save(tmp_raw)

        ps = """
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Runtime.WindowsRuntime

function Await($Task) {
    $t = [System.WindowsRuntimeSystemExtensions]::AsTask($Task)
    $t.Wait(-1) | Out-Null
    $t.Result
}

try {
    $p = '""" + tmp_fwd + """'
    $f = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($p))
    $s = Await ($f.OpenAsync([Windows.Storage.FileAccessMode]::Read))
    $d = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($s))
    $b = Await ($d.GetSoftwareBitmapAsync())
    $e = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    if ($null -eq $e) { Write-Error 'OCR engine unavailable'; exit 1 }
    $r = Await ($e.RecognizeAsync($b))
    $r.Lines | ForEach-Object { $_.Text }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""
        r = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive',
             '-OutputFormat', 'Text', '-Command', ps],
            capture_output=True, text=True, timeout=20,
            **_SUBPROCESS_FLAGS)

        if r.returncode != 0:
            log.info(f"OCR PowerShell stderr: {r.stderr.strip()[:150]}")
            return ""

        return r.stdout.strip()

    except Exception as e:
        log.info(f"Windows OCR exception: {e}")
        return ""
    finally:
        try:
            os.unlink(tmp_raw)
        except:
            pass


def _ocr_mac_vision(img) -> str:
    import tempfile
    tmp = tempfile.mktemp(suffix='.png')
    try:
        img.save(tmp)
        script = f"""
import Vision, AppKit, sys
url = AppKit.NSURL.fileURLWithPath_('{tmp}')
handler = Vision.VNImageRequestHandler.alloc().initWithURL_options_(url, {{}})
req = Vision.VNRecognizeTextRequest.alloc().init()
req.setRecognitionLevel_(1)
handler.performRequests_error_([req], None)
results = req.results() or []
print(' '.join([r.topCandidates_(1)[0].string() for r in results if r.topCandidates_(1)]))
"""
        r = subprocess.run(['python3', '-c', script],
                           capture_output=True, text=True, timeout=15)
        return r.stdout if r.returncode == 0 else ""
    except Exception as e:
        log.debug(f"Mac Vision error: {e}")
        return ""
    finally:
        try:
            os.unlink(tmp)
        except:
            pass


def detect_ocr_backend() -> tuple:
    # 1. Tesseract
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        log.info("OCR backend: pytesseract [OK]")
        return "pytesseract", _ocr_pytesseract, True, ""
    except Exception as e:
        log.debug(f"pytesseract not available: {e}")

    # 2. Windows built-in
    if IS_WIN:
        try:
            r = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 '[Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]; echo ok'],
                capture_output=True, text=True, timeout=8,
                **_SUBPROCESS_FLAGS)
            if 'ok' in r.stdout:
                log.info("OCR backend: Windows built-in OCR [OK]")
                return "windows-ocr", _ocr_windows_builtin, True, ""
        except Exception as e:
            log.debug(f"Windows OCR check: {e}")

        hint = (
            "Screen monitoring needs Tesseract OCR.\n\n"
            "Install from:\nhttps://github.com/UB-Mannheim/tesseract/wiki\n\n"
            "Choose 64-bit installer, use default settings.\nThen restart AIScan."
        )
        return "none", None, False, hint

    # 3. Mac Vision
    if IS_MAC:
        try:
            r = subprocess.run(['python3', '-c', 'import Vision; print("ok")'],
                               capture_output=True, text=True, timeout=5)
            if 'ok' in r.stdout:
                log.info("OCR backend: Mac Vision [OK]")
                return "mac-vision", _ocr_mac_vision, True, ""
        except:
            pass
        hint = "Screen monitoring needs Tesseract:\nbrew install tesseract\n\nThen restart AIScan."
        return "none", None, False, hint

    return "none", None, False, "Screen monitoring needs Tesseract OCR."


# ============================================================================
# SCREENSHOT CAPTURE
# ============================================================================

def capture_screen():
    """Full screen capture using mss (bundled, fast, no display driver needed)."""
    try:
        import mss
        from PIL import Image
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            shot = sct.grab(monitor)
            img = Image.frombytes('RGB', shot.size, shot.bgra, 'raw', 'BGRX')
            w, h = img.size
            return img.crop((0, 0, w, int(h * 0.92)))  # crop taskbar
    except ImportError:
        pass

    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        w, h = img.size
        return img.crop((0, 0, w, int(h * 0.92)))
    except Exception as e:
        log.debug(f"Screenshot failed: {e}")
        return None


# ============================================================================
# TEXT CLEANING
# ============================================================================

def clean_ocr_text(text: str) -> str:
    """
    Remove obvious UI chrome, keep document content.
    Conservative - only strip things we're sure are not content.
    """
    if not text:
        return ""

    lines = text.split("\n")
    cleaned = []

    ui_exact = {
        "file", "edit", "view", "insert", "format", "tools", "help",
        "window", "ok", "cancel", "save", "open", "close", "yes", "no",
        "print", "undo", "redo", "cut", "copy", "paste", "find", "replace",
        "untitled", "untitled - notepad", "notepad", "microsoft word",
    }

    for line in lines:
        line = line.strip()
        if not line:
            continue
        words = line.split()
        if len(words) < 2:
            continue
        if line.replace(" ", "").isdigit():
            continue
        if all(not c.isalnum() for c in line):
            continue
        if line.lower().strip() in ui_exact:
            continue
        digit_ratio = sum(c.isdigit() for c in line) / max(1, len(line))
        if digit_ratio > 0.6:
            continue
        cleaned.append(line)

    result = " ".join(cleaned)
    log.debug(f"OCR clean: {len(lines)} lines -> {len(result.split())} words")
    return result


# ============================================================================
# MAIN SCREEN MONITOR
# ============================================================================

class ScreenMonitor:
    def __init__(self, detect_fn, alert_fn, interval_seconds=4):
        self._detect   = detect_fn
        self._alert    = alert_fn
        self._interval = interval_seconds
        self._running  = False
        self._paused   = False
        self._last_hash = ""
        self._alerted  = deque(maxlen=100)
        self._min_words = 20
        self._ocr_fn   = None
        self._ocr_name = "none"
        self._errors   = 0
        self._scans    = 0

    def setup(self) -> tuple:
        name, fn, ok, hint = detect_ocr_backend()
        self._ocr_name = name
        self._ocr_fn   = fn
        return ok, name, hint

    def start(self):
        if not self._ocr_fn:
            ok, name, hint = self.setup()
            if not ok:
                log.warning(f"Screen monitor: OCR not available")
                return False
        self._running = True
        threading.Thread(target=self._loop, daemon=True, name="ScreenMonitor").start()
        log.info(f"Screen monitor running via {self._ocr_name} (every {self._interval}s)")
        return True

    def stop(self):
        self._running = False

    def pause(self):
        self._paused = True
        log.info("Screen monitor paused")

    def resume(self):
        self._paused = False
        log.info("Screen monitor resumed")

    @property
    def is_active(self):
        return self._running and not self._paused

    def _loop(self):
        log.info(f"Screen monitoring active  -  checking every {self._interval}s")
        tick = 0

        while self._running:
            try:
                if self._paused:
                    time.sleep(1)
                    continue

                tick += 1
                text = ""

                # Step 1: Try UI Automation (instant, no OCR, works for Notepad)
                direct = read_foreground_window_text()
                if direct and len(direct.split()) >= self._min_words:
                    text = direct
                    log.info(f"SCREEN tick={tick}: UIA read {len(text.split())} words")
                else:
                    if direct:
                        log.info(f"SCREEN tick={tick}: UIA read {len(direct.split())} words (need {self._min_words}), trying OCR")

                    # Step 2: Screenshot + OCR fallback
                    img = capture_screen()
                    if img is None:
                        log.info(f"SCREEN tick={tick}: screenshot failed")
                        self._errors += 1
                        time.sleep(self._interval)
                        continue

                    raw = self._ocr_fn(img)
                    if not raw or not raw.strip():
                        log.info(f"SCREEN tick={tick}: OCR returned empty")
                        time.sleep(self._interval)
                        continue

                    text = clean_ocr_text(raw)
                    log.info(f"SCREEN tick={tick}: OCR {len(raw.split())} raw -> {len(text.split())} clean words")

                words = text.split()
                if len(words) < self._min_words:
                    log.info(f"SCREEN tick={tick}: only {len(words)} words (need {self._min_words}), skipping")
                    time.sleep(self._interval)
                    continue

                # Deduplication
                content_hash = hashlib.md5(text.encode()).hexdigest()
                if content_hash == self._last_hash:
                    log.info(f"SCREEN tick={tick}: content unchanged, skipping")
                    time.sleep(self._interval)
                    continue
                self._last_hash = content_hash
                self._scans += 1

                if content_hash in self._alerted:
                    log.info(f"SCREEN tick={tick}: already alerted")
                    time.sleep(self._interval)
                    continue

                # Detect
                result = self._detect(text)
                log.info(
                    f"SCREEN [{self._scans}]: {result.ai_score:.0f}%"
                    f" [{result.risk_level}]  -  {len(words)} words"
                )

                if result.ai_score >= 35:
                    self._alerted.append(content_hash)
                    log.info(f"  AI content on screen  -  alerting user")
                    self._alert(result, "Screen  -  live content")

            except Exception as e:
                self._errors += 1
                log.warning(f"SCREEN tick={tick} error: {e}")
                if self._errors > 10:
                    log.warning("Screen monitor: too many errors, slowing down")
                    time.sleep(self._interval * 3)
                    self._errors = 0
                    continue

            time.sleep(self._interval)

    def get_status(self) -> dict:
        return {
            "running":  self._running,
            "paused":   self._paused,
            "backend":  self._ocr_name,
            "scans":    self._scans,
            "errors":   self._errors,
        }


def check_ocr_available() -> tuple:
    name, fn, ok, hint = detect_ocr_backend()
    return ok, name, hint


def install_tesseract_guide() -> str:
    if IS_WIN:
        return (
            "Install Tesseract OCR for screen monitoring:\n\n"
            "1. Go to: https://github.com/UB-Mannheim/tesseract/wiki\n"
            "2. Download: tesseract-ocr-w64-setup-5.x.x.exe\n"
            "3. Run installer (use default path C:\\Program Files\\Tesseract-OCR)\n"
            "4. Restart AIScan\n\n"
            "Takes 2 minutes. AIScan will auto-detect it."
        )
    elif IS_MAC:
        return (
            "Install Tesseract OCR for screen monitoring:\n\n"
            "Run in Terminal:\n"
            "  brew install tesseract\n\n"
            "Then restart AIScan."
        )
    return "Install tesseract-ocr from your package manager."
