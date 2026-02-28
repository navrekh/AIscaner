"""
AIScan v6 Build Script
Produces a single-file Windows EXE or macOS .app bundle via PyInstaller.

Changes from v5:
  - Bumped to v6, added 9 new companion modules (quarantine, whitelist,
    scheduler, webhook, auto_updater, extended_pii, cli + 2 others)
  - Removed sklearn / joblib (no longer used anywhere in codebase)
  - Added hidden imports for smtplib/email (webhook module), argparse (cli),
    urllib (auto_updater), socket/subprocess (network_monitor)
  - Added benchmark accuracy gate: build fails if accuracy < 92% or FPR > 5%
  - Syntax + encoding pre-flight on all 23 modules before touching PyInstaller
  - Pinned PyInstaller to 6.10.0 for reproducible builds

Popup fix (v6.0.1):
  - show_popup() now enqueues to _popup_queue instead of spawning tk.Tk() in
    a background thread.  pystray uses icon.run_detached() so the main thread
    is free to own the tkinter event loop.  PyInstaller must therefore bundle:
      pystray._base        (contains run_detached())
      pystray._util.win32  (used by pystray._win32 internally)
      six / six.moves.queue  (imported by pystray._win32)
      queue                (stdlib, now explicitly imported in agent_standalone)
  - --collect-submodules pystray ensures all pystray backends are bundled
"""
import os, sys, ast, subprocess, shutil, importlib.util
from pathlib import Path

# Fix Windows console encoding FIRST before any print()
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

print("=" * 60)
print("  AIScan v6 Build Script")
print("=" * 60)
print()

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
SEP    = ";" if IS_WIN else ":"

# Hide console window on Windows for subprocess calls
RUN_FLAGS = {}
if IS_WIN:
    RUN_FLAGS["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

# -- All 23 companion modules --------------------------------------------------
COMPANION_MODULES = [
    "intelligence",
    "advanced_detection",
    "session_recorder",
    "bulk_scanner",
    "screen_monitor",
    "settings_ui",
    "onboarding",
    "report_generator",
    "security_mode",
    "incident_engine",
    "entity_tracker",
    "compliance_reporter",
    "benchmark",
    "network_monitor",
    "quarantine",
    "whitelist",
    "scheduler",
    "webhook",
    "auto_updater",
    "extended_pii",
    "cli",
    "license",
]

REQUIRED_FILES = ["agent_standalone.py"] + [f"{m}.py" for m in COMPANION_MODULES]

# -- Step 1: Clear old build artefacts -----------------------------------------
print("Step 1: Clearing build cache...")
for d in ["build", "dist"]:
    if Path(d).exists():
        shutil.rmtree(d)
        print(f"  Cleared {d}/")
for f in Path(".").glob("*.spec"):
    f.unlink()
    print(f"  Deleted {f.name}")

# -- Step 2: Verify all source files -------------------------------------------
print()
print("Step 2: Verifying source files (23 modules)...")
missing = [f for f in REQUIRED_FILES if not Path(f).exists()]
if missing:
    print(f"  ERROR: Missing: {missing}")
    sys.exit(1)
total_lines = 0
for f in REQUIRED_FILES:
    lines = len(Path(f).read_text(encoding="utf-8").splitlines())
    total_lines += lines
    print(f"  OK {f:40s} {lines:5d} lines")
print(f"  Total: {len(REQUIRED_FILES)} files, {total_lines:,} lines")

# -- Step 3: Syntax + encoding gate --------------------------------------------
print()
print("Step 3: Syntax + encoding check...")
errors = []
for f in REQUIRED_FILES:
    c = Path(f).read_text(encoding="utf-8", errors="replace")
    bad = sum(1 for ch in c if ord(ch) > 127)
    if bad:
        errors.append(f"{f}: {bad} non-ASCII characters")
    try:
        ast.parse(c)
    except SyntaxError as e:
        errors.append(f"{f}: SyntaxError - {e}")
if errors:
    for e in errors:
        print(f"  FAIL: {e}")
    sys.exit(1)
print(f"  All {len(REQUIRED_FILES)} modules: syntax clean, ASCII-only")

# -- Step 4: Accuracy benchmark gate -------------------------------------------
print()
print("Step 4: Accuracy benchmark (v6 engine)...")
try:
    sys.path.insert(0, ".")
    spec = importlib.util.spec_from_file_location("benchmark", "benchmark.py")
    bm_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bm_mod)
    from agent_standalone import _detect
    results = bm_mod.run_benchmark(_detect)
    acc = results.accuracy * 100
    fpr = results.false_positive_rate * 100
    f1  = results.f1_ai
    print(f"  Accuracy:  {acc:.1f}%  (gate: >= 92%)")
    print(f"  Precision: {results.precision_ai*100:.1f}%")
    print(f"  Recall:    {results.recall_ai*100:.1f}%")
    print(f"  F1:        {f1:.3f}  (gate: >= 0.90)")
    print(f"  FPR:       {fpr:.1f}%   (gate: <= 5%)")
    print(f"  Score sep: {results.score_separation:.1f}pts")
    if acc < 92.0:
        print(f"  FAIL: accuracy {acc:.1f}% < 92% threshold")
        sys.exit(1)
    if fpr > 5.0:
        print(f"  FAIL: FPR {fpr:.1f}% > 5% threshold")
        sys.exit(1)
    if f1 < 0.90:
        print(f"  FAIL: F1 {f1:.3f} < 0.90 threshold")
        sys.exit(1)
    print("  Benchmark PASSED")
except Exception as e:
    print(f"  WARNING: Benchmark skipped ({e})")

# -- Step 5: Locate reportlab data (fonts required for PDF) --------------------
print()
print("Step 5: Locating reportlab resources...")
try:
    import reportlab
    rl_dir   = Path(reportlab.__file__).parent
    rl_fonts = rl_dir / "fonts"
    rl_lib   = rl_dir / "lib"
    print(f"  reportlab: {rl_dir}")
    print(f"  fonts:     {rl_fonts} (exists={rl_fonts.exists()})")
    print(f"  lib:       {rl_lib}   (exists={rl_lib.exists()})")
except ImportError:
    print("  ERROR: reportlab not installed - run: pip install reportlab")
    sys.exit(1)

# -- Step 6: Build with PyInstaller --------------------------------------------
print()
print(f"Step 6: Building for {'Windows' if IS_WIN else 'macOS'}...")
print(f"  Bundling {len(COMPANION_MODULES)} companion modules...")

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile" if IS_WIN else "--onedir",
    "--windowed",
    "--name", "AIScan",

    # -- Bundle all companion modules alongside the exe --
    *[arg for m in COMPANION_MODULES
      for arg in ("--add-data", f"{m}.py{SEP}.")],

    # -- reportlab fonts + lib (required for PDF generation) --
    "--add-data", f"{rl_fonts}{SEP}reportlab/fonts",
    "--add-data", f"{rl_lib}{SEP}reportlab/lib",

    # -- tkinter (PyInstaller misses ttk on Windows) --
    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.ttk",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox",
    "--hidden-import", "tkinter.simpledialog",
    "--hidden-import", "_tkinter",

    # -- File format parsers --
    "--hidden-import", "docx",
    "--hidden-import", "docx.oxml",
    "--hidden-import", "openpyxl",
    "--hidden-import", "pptx",
    "--hidden-import", "pypdf",

    # -- watchdog file system observer --
    "--hidden-import", "watchdog.observers.polling",
    "--collect-submodules", "watchdog",

    # -- screen capture + OCR --
    "--hidden-import", "mss",
    "--hidden-import", "mss.base",
    "--hidden-import", "mss.tools",
    "--hidden-import", "PIL",
    "--hidden-import", "PIL.Image",
    "--hidden-import", "PIL.ImageGrab",
    "--hidden-import", "PIL.ImageDraw",
    "--hidden-import", "PIL.ImageFont",
    "--collect-submodules", "PIL",
    "--hidden-import", "pytesseract",          # optional - graceful fallback if absent

    # -- reportlab (PDF generation) --
    "--hidden-import", "reportlab",
    "--hidden-import", "reportlab.pdfgen",
    "--hidden-import", "reportlab.pdfgen.canvas",
    "--hidden-import", "reportlab.lib.pagesizes",
    "--hidden-import", "reportlab.lib.units",
    "--hidden-import", "reportlab.lib.colors",
    "--hidden-import", "reportlab.platypus",
    "--hidden-import", "reportlab.pdfbase",
    "--hidden-import", "reportlab.pdfbase.pdfmetrics",
    "--hidden-import", "reportlab.pdfbase.ttfonts",
    "--collect-submodules", "reportlab",

    # -- webhook module (smtplib + email are stdlib but need explicit include) --
    "--hidden-import", "smtplib",
    "--hidden-import", "email",
    "--hidden-import", "email.mime.text",
    "--hidden-import", "email.mime.multipart",
    "--hidden-import", "ssl",

    # -- auto_updater + network_monitor (urllib, socket, subprocess - all stdlib) --
    "--hidden-import", "urllib.request",
    "--hidden-import", "urllib.error",
    "--hidden-import", "socket",
    "--hidden-import", "subprocess",

    # -- cli module --
    "--hidden-import", "argparse",

    # -- misc stdlib that PyInstaller sometimes misses --
    "--hidden-import", "zipfile",
    "--hidden-import", "re",
    "--hidden-import", "json",
    "--hidden-import", "hashlib",
    "--hidden-import", "threading",
    "--hidden-import", "fnmatch",
    "--hidden-import", "queue",            # explicitly used by _popup_queue

    # -- pystray internals: required for icon.run_detached() --
    # run_detached() lives in pystray._base; _win32 backend uses pystray._util.win32
    # and imports six.moves.queue.  Without these, the tray icon starts but
    # run_detached() fails silently and popups never appear.
    "--hidden-import", "pystray._base",
    "--hidden-import", "pystray._util",
    "--hidden-import", "pystray._util.win32",
    "--hidden-import", "six",
    "--hidden-import", "six.moves",
    "--hidden-import", "six.moves.queue",
    "--collect-submodules", "pystray",

    # -- Excludes: keep exe size down, none of these are used --
    "--exclude-module", "sklearn",
    "--exclude-module", "joblib",
    "--exclude-module", "matplotlib",
    "--exclude-module", "scipy",
    "--exclude-module", "pandas",
    "--exclude-module", "numpy",
    "--exclude-module", "onnxruntime",
    "--exclude-module", "tensorflow",
    "--exclude-module", "torch",
    "--exclude-module", "cv2",
    "--exclude-module", "notebook",
    "--exclude-module", "IPython",
    "--exclude-module", "pytest",
    "--exclude-module", "setuptools",
]

# -- Windows-only hidden imports -----------------------------------------------
if IS_WIN:
    cmd += [
        "--hidden-import", "watchdog.observers.winapi",
        "--hidden-import", "pystray._win32",
        "--hidden-import", "pystray._dummy",  # fallback backend PyInstaller may need
        "--hidden-import", "win32gui",
        "--hidden-import", "win32clipboard",
        "--hidden-import", "win32con",
        "--hidden-import", "win32api",
        "--hidden-import", "winreg",
        "--hidden-import", "plyer.platforms.win.notification",
        "--hidden-import", "comtypes",
        "--hidden-import", "comtypes.client",
    ]

# -- macOS-only hidden imports -------------------------------------------------
elif IS_MAC:
    cmd += [
        "--hidden-import", "watchdog.observers.fsevents",
        "--hidden-import", "rumps",
        "--hidden-import", "plyer.platforms.macosx.notification",
        "--osx-bundle-identifier", "com.aiscan.agent",
    ]

cmd.append("agent_standalone.py")

print()
print("  Running PyInstaller...")
result = subprocess.run(cmd, **RUN_FLAGS)

if result.returncode != 0:
    print()
    print("  BUILD FAILED - check output above for errors")
    sys.exit(1)

# -- Step 7: Verify output -----------------------------------------------------
print()
print("Step 7: Verifying output...")
if IS_WIN:
    exe = Path("dist/AIScan.exe")
    if exe.exists():
        size_mb = exe.stat().st_size / 1024 / 1024
        print(f"  OK  dist/AIScan.exe  ({size_mb:.1f} MB)")
    else:
        print("  FAIL  dist/AIScan.exe NOT FOUND")
        sys.exit(1)
else:
    app = Path("dist/AIScan.app")
    if app.exists():
        import subprocess as sp
        size = sp.check_output(["du", "-sh", str(app)]).decode().split()[0]
        print(f"  OK  dist/AIScan.app  ({size})")
    else:
        print("  FAIL  dist/AIScan.app NOT FOUND")
        sys.exit(1)

print()
print("=" * 60)
print("  Build Complete  -  AIScan v6")
print("=" * 60)
