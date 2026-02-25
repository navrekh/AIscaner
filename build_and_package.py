"""
AIScan v5 Build Script
Run this locally or via GitHub Actions to produce the installer.
Fixes applied:
  - Windows console encoding (cp1252 -> utf-8)
  - tkinter.ttk hidden imports
  - reportlab fonts bundled (required for PDF reports)
  - CREATE_NO_WINDOW for subprocess calls
  - All 8 companion modules bundled
"""
import os, sys, subprocess, shutil
from pathlib import Path

# Fix Windows console encoding FIRST before any print()
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

print("=== AIScan v5 Build ===")
print()

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
SEP    = ";" if IS_WIN else ":"

# Subprocess flags - hide console window on Windows
RUN_FLAGS = {}
if IS_WIN:
    RUN_FLAGS["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

# -- Step 1: Clear old build cache -----------------------------------------
print("Clearing build cache...")
for d in ["build", "dist"]:
    if Path(d).exists():
        shutil.rmtree(d)
        print(f"  Cleared {d}/")
for f in Path(".").glob("*.spec"):
    f.unlink()
    print(f"  Deleted {f}")

# -- Step 2: Verify all source files exist ---------------------------------
print()
print("Verifying source files...")
required_files = [
    "agent_standalone.py",
    "intelligence.py",
    "advanced_detection.py",
    "session_recorder.py",
    "bulk_scanner.py",
    "screen_monitor.py",
    "settings_ui.py",
    "onboarding.py",
    "report_generator.py",
    "license.py",
]
missing = [f for f in required_files if not Path(f).exists()]
if missing:
    print(f"ERROR: Missing files: {missing}")
    sys.exit(1)
for f in required_files:
    size = Path(f).stat().st_size
    print(f"  OK {f} ({size} bytes)")

# -- Step 3: Find reportlab data path (fonts required for PDF) -------------
print()
print("Locating reportlab fonts...")
try:
    import reportlab
    rl_dir = Path(reportlab.__file__).parent
    rl_fonts  = rl_dir / "fonts"
    rl_lib    = rl_dir / "lib"
    print(f"  reportlab: {rl_dir}")
    print(f"  fonts:     {rl_fonts} (exists={rl_fonts.exists()})")
except ImportError:
    print("  ERROR: reportlab not installed - run: pip install reportlab")
    sys.exit(1)

# -- Step 4: Build with PyInstaller ----------------------------------------
print()
print(f"Building for: {'Windows' if IS_WIN else 'macOS'}")

companion_modules = [
    "intelligence",
    "advanced_detection",
    "session_recorder",
    "bulk_scanner",
    "screen_monitor",
    "settings_ui",
    "onboarding",
    "report_generator",
]
print(f"Bundling {len(companion_modules)} companion modules...")

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile" if IS_WIN else "--onedir",
    "--windowed",
    "--name", "AIScan",

    # Bundle all companion modules
    *[arg for m in companion_modules
      for arg in ("--add-data", f"{m}.py{SEP}.")],

    # Bundle reportlab fonts and lib (required for PDF generation)
    "--add-data", f"{rl_fonts}{SEP}reportlab/fonts",
    "--add-data", f"{rl_lib}{SEP}reportlab/lib",

    # Hidden imports - tkinter (PyInstaller misses ttk on Windows)
    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.ttk",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox",
    "--hidden-import", "tkinter.simpledialog",
    "--hidden-import", "_tkinter",

    # Hidden imports - watchdog + sklearn
    "--hidden-import", "watchdog.observers.polling",
    "--hidden-import", "sklearn.ensemble._forest",
    "--hidden-import", "sklearn.utils._cython_blas",
    "--hidden-import", "sklearn.neighbors.typedefs",
    "--hidden-import", "sklearn.neighbors._partition_nodes",

    # Hidden imports - screen capture
    "--hidden-import", "mss",
    "--hidden-import", "mss.base",
    "--hidden-import", "mss.tools",

    # Hidden imports - PDF reports
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

    # Collect all reportlab subpackages
    "--collect-submodules", "reportlab",

    # Excludes (keep exe size down)
    "--exclude-module", "matplotlib",
    "--exclude-module", "scipy",
    "--exclude-module", "pandas",
    "--exclude-module", "onnxruntime",
    "--exclude-module", "tensorflow",
    "--exclude-module", "torch",
    "--exclude-module", "cv2",
    "--exclude-module", "notebook",
    "--exclude-module", "IPython",
]

# Platform-specific hidden imports
if IS_WIN:
    cmd += [
        "--hidden-import", "watchdog.observers.winapi",
        "--hidden-import", "pystray._win32",
        "--hidden-import", "win32gui",
        "--hidden-import", "win32clipboard",
        "--hidden-import", "win32con",
        "--hidden-import", "plyer.platforms.win.notification",
        "--hidden-import", "comtypes",
        "--hidden-import", "comtypes.client",
    ]
elif IS_MAC:
    cmd += [
        "--hidden-import", "watchdog.observers.fsevents",
        "--hidden-import", "rumps",
        "--hidden-import", "plyer.platforms.macosx.notification",
        "--osx-bundle-identifier", "com.aiscan.agent",
    ]

cmd.append("agent_standalone.py")

print()
print("Running PyInstaller...")
result = subprocess.run(cmd, **RUN_FLAGS)

if result.returncode != 0:
    print()
    print("BUILD FAILED - check output above for errors")
    sys.exit(1)

# -- Step 5: Verify output -------------------------------------------------
print()
print("Verifying output...")
if IS_WIN:
    exe = Path("dist/AIScan.exe")
    if exe.exists():
        size_mb = exe.stat().st_size / 1024 / 1024
        print(f"  OK dist/AIScan.exe ({size_mb:.1f} MB)")
    else:
        print("  FAIL dist/AIScan.exe NOT FOUND")
        sys.exit(1)
else:
    app = Path("dist/AIScan.app")
    if app.exists():
        print(f"  OK dist/AIScan.app")
    else:
        print("  FAIL dist/AIScan.app NOT FOUND")
        sys.exit(1)

print()
print("=== Build Complete ===")
