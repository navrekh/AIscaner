"""
AIScan v5 Build Script
Run this locally or via GitHub Actions to produce the installer.
"""
import os, sys, subprocess, shutil
from pathlib import Path

# Fix Windows console encoding (prevents UnicodeEncodeError on cp1252)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

print("=== AIScan v5 Build ===")
print()

# -- Step 1: Clear old build cache ----------------------------------------
print("Clearing build cache...")
for d in ["build", "dist"]:
    if Path(d).exists():
        shutil.rmtree(d)
        print(f"  Cleared {d}/")
for f in Path(".").glob("*.spec"):
    f.unlink()
    print(f"  Deleted {f}")

# -- Step 2: Verify all source files exist --------------------------------
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

# -- Step 3: PyInstaller build ---------------------------------------------
print()
is_windows = sys.platform == "win32"
is_mac     = sys.platform == "darwin"
sep        = ";" if is_windows else ":"

# All companion modules to bundle
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

print(f"Building for: {'Windows' if is_windows else 'macOS'}")
print(f"Bundling {len(companion_modules)} modules...")

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile" if is_windows else "--onedir",
    "--windowed",
    "--name", "AIScan",

    # Bundle all companion modules
    *[arg for m in companion_modules
      for arg in ("--add-data", f"{m}.py{sep}.")],

    # Hidden imports - detection + watchdog
    "--hidden-import", "watchdog.observers.polling",
    "--hidden-import", "sklearn.ensemble._forest",
    "--hidden-import", "sklearn.utils._cython_blas",
    "--hidden-import", "sklearn.neighbors.typedefs",
    "--hidden-import", "sklearn.neighbors._partition_nodes",

    # Hidden imports - tkinter (PyInstaller misses ttk on Windows)
    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.ttk",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox",
    "--hidden-import", "tkinter.simpledialog",
    "--hidden-import", "_tkinter",

    # Hidden imports - screen capture
    "--hidden-import", "mss",
    "--hidden-import", "mss.base",
    "--hidden-import", "mss.tools",

    # Hidden imports - PDF reports
    "--hidden-import", "reportlab.pdfgen",
    "--hidden-import", "reportlab.lib.pagesizes",
    "--hidden-import", "reportlab.lib.units",
    "--hidden-import", "reportlab.lib.colors",
    "--hidden-import", "reportlab.platypus",

    # Excludes (keep exe size down)
    "--exclude-module", "matplotlib",
    "--exclude-module", "scipy",
    "--exclude-module", "pandas",
    "--exclude-module", "onnxruntime",
    "--exclude-module", "tensorflow",
    "--exclude-module", "torch",
    "--exclude-module", "cv2",
]

# Platform-specific
if is_windows:
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
elif is_mac:
    cmd += [
        "--hidden-import", "watchdog.observers.fsevents",
        "--hidden-import", "rumps",
        "--hidden-import", "plyer.platforms.macosx.notification",
        "--osx-bundle-identifier", "com.aiscan.agent",
    ]

cmd.append("agent_standalone.py")

print()
print("Running PyInstaller...")
result = subprocess.run(cmd)

if result.returncode != 0:
    print()
    print("BUILD FAILED")
    sys.exit(1)

# -- Step 4: Verify output -------------------------------------------------
print()
print("Verifying output...")
if is_windows:
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
