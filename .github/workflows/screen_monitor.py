"""
AIScan Screen Monitor v2
Real-time screen reading  -  detects AI content in ANY open app.
No file locks. Works while documents are open and being edited.

Requirements:
  Windows: pip install pillow pytesseract mss
           + Tesseract from https://github.com/UB-Mannheim/tesseract/wiki
  Mac:     pip install pillow pytesseract mss
           + brew install tesseract
  
  OR: Windows 10/11 built-in OCR (no install needed)  -  auto-detected.
"""
import sys, time, threading, hashlib, logging, re, subprocess, os

# Windows: hide console window for all subprocess calls
_SUBPROCESS_FLAGS = {}
if sys.platform == "win32":
    _SUBPROCESS_FLAGS = {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
from pathlib import Path
from collections import deque

log = logging.getLogger("aiscan")
IS_WIN  = sys.platform == "win32"
IS_MAC  = sys.platform == "darwin"


# ============================================================================
# OCR BACKENDS  -  tries each in order, uses best available
# ============================================================================

def _ocr_pytesseract(img) -> str:
    """Best quality OCR using Tesseract."""
    import pytesseract
    # 2x upscale dramatically improves accuracy on screen text
    from PIL import Image
    w, h = img.size
    img2 = img.resize((w * 2, h * 2), Image.LANCZOS)
    return pytesseract.image_to_string(img2, config='--psm 6 --oem 3')


def _ocr_windows_builtin(img) -> str:
    """
    Windows 10/11 built-in OCR  -  no install needed.
    Uses Windows.Media.Ocr via PowerShell.
    """
    import tempfile
    tmp = tempfile.mktemp(suffix='.png')
    try:
        img.save(tmp)
        ps = f"""
$path = '{tmp}'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asms = [System.AppDomain]::CurrentDomain.GetAssemblies()

function Await($WinRtTask, $ResultType) {{
    $asTask = [System.WindowsRuntimeSystemExtensions]::AsTask($WinRtTask)
    $asTask.Wait(-1) | Out-Null
    $asTask.Result
}}

$storageFile = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($path)) ([Windows.Storage.StorageFile])
$stream = Await ($storageFile.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$bitmap  = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
$result = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
$result.Lines | ForEach-Object {{ $_.Text }} | Out-String
"""
        r = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps],
            capture_output=True, text=True, timeout=15,
            **_SUBPROCESS_FLAGS)
        return r.stdout if r.returncode == 0 else ""
    except Exception as e:
        log.debug(f"Windows OCR error: {e}")
        return ""
    finally:
        try: os.unlink(tmp)
        except: pass


def _ocr_mac_vision(img) -> str:
    """
    Mac Vision framework OCR  -  built-in, no install.
    Available on macOS 10.15+.
    """
    import tempfile
    tmp = tempfile.mktemp(suffix='.png')
    try:
        img.save(tmp)
        script = f"""
import Vision
import AppKit
import sys

url = NSURL.fileURLWithPath_('{tmp}')
handler = Vision.VNImageRequestHandler.alloc().initWithURL_options_(url, {{}})
request = Vision.VNRecognizeTextRequest.alloc().init()
request.setRecognitionLevel_(1)  # accurate
handler.performRequests_error_([request], None)
results = request.results() or []
print(' '.join([r.topCandidates_(1)[0].string() for r in results if r.topCandidates_(1)]))
"""
        r = subprocess.run(['python3', '-c', script],
                          capture_output=True, text=True, timeout=15)
        return r.stdout if r.returncode == 0 else ""
    except Exception as e:
        log.debug(f"Mac Vision OCR error: {e}")
        return ""
    finally:
        try: os.unlink(tmp)
        except: pass


def detect_ocr_backend() -> tuple:
    """
    Auto-detect the best available OCR backend.
    Returns (backend_name, backend_fn, is_available, install_hint)
    """
    # 1. Try pytesseract (best, cross-platform)
    try:
        import pytesseract
        from PIL import Image
        pytesseract.get_tesseract_version()
        log.info("OCR backend: pytesseract [OK]")
        return "pytesseract", _ocr_pytesseract, True, ""
    except Exception as e:
        log.debug(f"pytesseract not available: {e}")

    # 2. Windows built-in OCR (Windows 10+, no install needed)
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
            "Choose 64-bit installer, use default settings.\n"
            "Then restart AIScan."
        )
        return "none", None, False, hint

    # 3. Mac Vision (macOS 10.15+)
    if IS_MAC:
        try:
            r = subprocess.run(['python3', '-c', 'import Vision; print(\"ok\")'],
                              capture_output=True, text=True, timeout=5)
            if 'ok' in r.stdout:
                log.info("OCR backend: Mac Vision [OK]")
                return "mac-vision", _ocr_mac_vision, True, ""
        except: pass

        hint = "Screen monitoring needs Tesseract:\nbrew install tesseract\n\nThen restart AIScan."
        return "none", None, False, hint

    hint = "Screen monitoring needs Tesseract OCR."
    return "none", None, False, hint


# ============================================================================
# FAST PATH: Windows UI Automation (reads text directly, no OCR needed)
# Works for Notepad, WordPad, most text editors - instant, no screenshot
# ============================================================================

def read_foreground_window_text() -> str:
    """
    Read text directly from the focused window using Windows UI Automation.
    No screenshot, no OCR - reads the actual text buffer directly.
    Works for: Notepad, WordPad, most text editors, browser address bars.
    Falls back to None if not supported (then OCR is used).
    """
    if not IS_WIN:
        return None

    try:
        import ctypes
        import ctypes.wintypes as wt

        # Get foreground window
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        if not hwnd:
            return None

        # Get window class to identify app type
        class_buf = ctypes.create_unicode_buffer(256)
        ctypes.windll.user32.GetClassNameW(hwnd, class_buf, 256)
        win_class = class_buf.value

        title_buf = ctypes.create_unicode_buffer(512)
        ctypes.windll.user32.GetWindowTextW(hwnd, title_buf, 512)
        win_title = title_buf.value

        log.debug(f"SCREEN: foreground window = '{win_title}' class='{win_class}'")

        # Method 1: For Notepad and simple edit controls - use WM_GETTEXT
        # Find the edit control inside the window
        edit_hwnd = ctypes.windll.user32.FindWindowExW(hwnd, None, "Edit", None)
        if not edit_hwnd:
            # Notepad on Windows 11 uses a different structure
            edit_hwnd = ctypes.windll.user32.FindWindowExW(hwnd, None, "RichEditD2DPT", None)
        if not edit_hwnd:
            edit_hwnd = ctypes.windll.user32.FindWindowExW(hwnd, None, "RICHEDIT50W", None)
        if not edit_hwnd:
            edit_hwnd = hwnd  # try the window itself

        # Get text length
        WM_GETTEXTLENGTH = 0x000E
        WM_GETTEXT = 0x000D
        text_len = ctypes.windll.user32.SendMessageW(edit_hwnd, WM_GETTEXTLENGTH, 0, 0)

        if text_len > 10:
            text_buf = ctypes.create_unicode_buffer(min(text_len + 1, 50000))
            ctypes.windll.user32.SendMessageW(edit_hwnd, WM_GETTEXT, len(text_buf), text_buf)
            text = text_buf.value.strip()
            if len(text.split()) >= 5:
                log.debug(f"SCREEN: UIA read {len(text.split())} words from '{win_class}'")
                return text

    except Exception as e:
        log.debug(f"UIA text read failed: {e}")

    return None  # Fall back to OCR


# ============================================================================
# SCREENSHOT CAPTURE
# ============================================================================

def capture_screen():
    """Capture the primary screen. Returns PIL Image or None."""
    # Method 1: mss (fastest, cross-platform)
    try:
        import mss
        from PIL import Image
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # primary monitor
            shot = sct.grab(monitor)
            img = Image.frombytes('RGB', shot.size, shot.bgra, 'raw', 'BGRX')
            # Crop out taskbar (bottom 8%)
            w, h = img.size
            return img.crop((0, 0, w, int(h * 0.92)))
    except ImportError:
        pass

    # Method 2: PIL ImageGrab (Windows/Mac)
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        w, h = img.size
        return img.crop((0, 0, w, int(h * 0.92)))
    except Exception as e:
        log.debug(f"Screenshot failed: {e}")
        return None


def capture_active_window():
    """
    Capture full screen using mss (most reliable on Windows).
    mss is bundled in the exe and works without display drivers.
    We capture full screen because:
    - The foreground window when AIScan tray scans is not Notepad
    - Full screen OCR catches whatever the user is working in
    - clean_ocr_text() strips UI chrome anyway
    """
    return capture_screen()


def capture_foreground_window():
    """
    Capture only the currently focused window.
    Only used when explicitly requested (e.g. right-click scan on screen).
    """
    if IS_WIN:
        try:
            import ctypes, ctypes.wintypes as wt
            import mss
            from PIL import Image

            hwnd = ctypes.windll.user32.GetForegroundWindow()
            rect = wt.RECT()
            ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))

            if rect.right - rect.left > 100 and rect.bottom - rect.top > 100:
                with mss.mss() as sct:
                    region = {
                        "left":   rect.left,
                        "top":    rect.top,
                        "width":  rect.right - rect.left,
                        "height": rect.bottom - rect.top,
                    }
                    shot = sct.grab(region)
                    return Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        except Exception as e:
            log.debug(f"Foreground window capture failed: {e}")

    return capture_screen()


# ============================================================================
# TEXT CLEANING  -  Remove UI chrome, keep document text
# ============================================================================

def clean_ocr_text(text: str) -> str:
    """
    Clean OCR output - remove UI chrome, keep document text.
    Conservative approach: only strip obvious UI elements, keep content.
    """
    if not text:
        return ""

    lines = text.split("\n")
    cleaned = []

    # Only strip these exact UI strings - nothing else
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

        # Skip very short lines (1 word) that are just UI noise
        words = line.split()
        if len(words) < 2:
            continue

        # Skip pure number lines (page numbers, line counts)
        if line.replace(" ", "").isdigit():
            continue

        # Skip pure symbol lines
        if all(not c.isalnum() for c in line):
            continue

        # Skip exact UI matches (case insensitive)
        if line.lower().strip() in ui_exact:
            continue

        # Skip lines that are >60% digits (timestamps, phone numbers etc)
        digit_ratio = sum(c.isdigit() for c in line) / max(1, len(line))
        if digit_ratio > 0.6:
            continue

        cleaned.append(line)

    result = " ".join(cleaned)  # join as single text block for better detection
    log.debug(f"SCREEN: OCR cleaned to {len(result.split())} words from {len(lines)} lines")
    return result


# ============================================================================
# MAIN SCREEN MONITOR
# ============================================================================

class ScreenMonitor:
    """
    Captures screen every N seconds, OCRs it, detects AI content.
    Works in any app  -  Word, Chrome, Notepad, Teams, anything.
    True real-time detection while document is open and being edited.
    """

    def __init__(self, detect_fn, alert_fn, interval_seconds=4):
        self._detect    = detect_fn
        self._alert     = alert_fn
        self._interval  = interval_seconds
        self._running   = False
        self._paused    = False
        self._last_hash = ""
        self._alerted   = deque(maxlen=100)   # content hashes already alerted
        self._min_words = 20  # lowered from 35 - catches short Notepad content
        self._ocr_fn    = None
        self._ocr_name  = "none"
        self._errors    = 0
        self._scans     = 0

    def setup(self) -> tuple:
        """Initialize OCR backend. Returns (success, method, hint)."""
        name, fn, ok, hint = detect_ocr_backend()
        self._ocr_name = name
        self._ocr_fn   = fn
        return ok, name, hint

    def start(self):
        if not self._ocr_fn:
            ok, name, hint = self.setup()
            if not ok:
                log.warning(f"Screen monitor: OCR not available  -  {hint}")
                return False

        self._running = True
        threading.Thread(target=self._loop, daemon=True, name="ScreenMonitor").start()
        log.info(f"Screen monitor running via {self._ocr_name} (every {self._interval}s)")
        return True

    def stop(self):
        self._running = False
        log.info("Screen monitor stopped")

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
        """Main monitoring loop."""
        log.info(f"Screen monitoring active  -  checking every {self._interval}s")
        tick = 0

        while self._running:
            try:
                if self._paused:
                    time.sleep(1)
                    continue

                tick += 1
                text = ""

                # --- Step 1: Try direct UI Automation read (instant, no OCR) ---
                # Works for Notepad, WordPad, most text editors
                direct_text = read_foreground_window_text()
                if direct_text and len(direct_text.split()) >= 5:
                    text = direct_text
                    log.info(f"SCREEN tick={tick}: UIA read {len(text.split())} words")
                else:
                    # --- Step 2: Screenshot + OCR fallback ---
                    img = capture_screen()
                    if img is None:
                        log.info(f"SCREEN tick={tick}: screenshot failed")
                        self._errors += 1
                        time.sleep(self._interval)
                        continue

                    raw_text = self._ocr_fn(img)
                    if not raw_text or not raw_text.strip():
                        log.info(f"SCREEN tick={tick}: OCR returned empty")
                        time.sleep(self._interval)
                        continue

                    text = clean_ocr_text(raw_text)
                    log.info(f"SCREEN tick={tick}: OCR got {len(raw_text.split())} raw -> {len(text.split())} clean words")

                words = text.split()

                # --- Step 3: Word count check ---
                if len(words) < self._min_words:
                    log.info(f"SCREEN tick={tick}: only {len(words)} words (need {self._min_words}), skipping")
                    time.sleep(self._interval)
                    continue

                # --- Step 4: Deduplication ---
                content_hash = hashlib.md5(text.encode()).hexdigest()
                if content_hash == self._last_hash:
                    log.info(f"SCREEN tick={tick}: content unchanged, skipping")
                    time.sleep(self._interval)
                    continue
                self._last_hash = content_hash
                self._scans += 1

                if content_hash in self._alerted:
                    log.info(f"SCREEN tick={tick}: already alerted for this content")
                    time.sleep(self._interval)
                    continue

                # --- Step 5: Detect ---
                result = self._detect(text)
                log.info(
                    f"SCREEN [{self._scans}]: {result.ai_score:.0f}% "
                    f"[{result.risk_level}]  -  {len(words)} words"
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
            "running": self._running,
            "paused": self._paused,
            "backend": self._ocr_name,
            "scans": self._scans,
            "errors": self._errors,
        }


def check_ocr_available() -> tuple:
    """Public API  -  check if OCR is available."""
    name, fn, ok, hint = detect_ocr_backend()
    return ok, name, hint


def install_tesseract_guide() -> str:
    """Return OS-specific install instructions."""
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
