import os, sys, subprocess, shutil
from pathlib import Path

# Clear any cached builds
print("=== Clearing cache ===")
for d in ["build", "dist"]:
    if Path(d).exists():
        shutil.rmtree(d)
        print(f"  Cleared {d}/")
for f in Path(".").glob("*.spec"):
    f.unlink()
    print(f"  Deleted {f}")
print("=== Cache cleared ===")

# Run PyInstaller
print("=== Building AIScan ===")
is_windows = sys.platform == "win32"

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile" if is_windows else "--onedir",
    "--windowed",
    "--name", "AIScan",
    "--hidden-import", "sklearn.ensemble._forest",
    "--hidden-import", "watchdog.observers.polling",
    "--hidden-import", "watchdog.observers.winapi" if is_windows else "watchdog.observers.fsevents",
    "--exclude-module", "matplotlib",
    "--exclude-module", "scipy",
    "--exclude-module", "pandas",
    "--exclude-module", "onnxruntime",
    "agent_standalone.py",
]

if is_windows:
    cmd += [
        "--hidden-import", "pystray._win32",
        "--hidden-import", "win32gui",
        "--hidden-import", "win32clipboard",
        "--hidden-import", "plyer.platforms.win.notification",
    ]
else:
    cmd += [
        "--hidden-import", "rumps",
        "--hidden-import", "plyer.platforms.macosx.notification",
        "--osx-bundle-identifier", "com.aiscan.agent",
    ]

result = subprocess.run(cmd)
sys.exit(result.returncode)
