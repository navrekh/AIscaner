import os, sys, subprocess, shutil
from pathlib import Path

print("=== Clearing cache ===")
for d in ["build", "dist"]:
    if Path(d).exists():
        shutil.rmtree(d)
        print(f"  Cleared {d}/")
for f in Path(".").glob("*.spec"):
    f.unlink()
print("=== Cache cleared ===")

is_windows = sys.platform == "win32"
sep = ";" if is_windows else ":"

# Bundle all companion modules
add_data = [
    f"intelligence.py{sep}.",
    f"advanced_detection.py{sep}.",
    f"session_recorder.py{sep}.",
    f"bulk_scanner.py{sep}.",
]

print("=== Building AIScan v4 ===")
cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile" if is_windows else "--onedir",
    "--windowed",
    "--name", "AIScan",
    "--exclude-module", "matplotlib",
    "--exclude-module", "scipy",
    "--exclude-module", "pandas",
    "--exclude-module", "onnxruntime",
    "--hidden-import", "watchdog.observers.polling",
    "--hidden-import", "watchdog.observers.winapi" if is_windows else "watchdog.observers.fsevents",
    "--hidden-import", "sklearn.ensemble._forest",
]

for d in add_data:
    cmd += ["--add-data", d]

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

cmd.append("agent_standalone.py")
result = subprocess.run(cmd)
sys.exit(result.returncode)
