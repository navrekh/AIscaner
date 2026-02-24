import os, sys, json, subprocess, shutil
from pathlib import Path

# ── Step 1: Create models folder FIRST before anything else ──────────────
print("=== Step 1: Setting up models folder ===")

models_dir = Path("models")
models_dir.mkdir(exist_ok=True)

for fname in ["stylometry_v1.onnx", "stylometry_model.joblib", "model_metadata.json"]:
    src = Path(fname)
    dst = models_dir / fname
    if src.exists() and not dst.exists():
        shutil.copy(src, dst)
        print(f"  Copied {fname} -> models/{fname}")

if not (models_dir / "stylometry_v1.onnx").exists():
    print("  Training model from scratch...")
    import numpy as np, joblib
    from sklearn.ensemble import RandomForestClassifier
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    np.random.seed(42)
    n = 400
    X_human = np.random.randn(n, 25) * 0.8;  X_human[:, 2] += 3
    X_ai    = np.random.randn(n, 25) * 0.6;  X_ai[:, 7] += 4;  X_ai[:, 9] += 3
    X_mixed = (X_human + X_ai) / 2
    X = np.vstack([X_human, X_ai, X_mixed])
    y = np.array([0]*n + [1]*n + [2]*n)
    idx = np.random.permutation(len(X));  X, y = X[idx], y[idx]
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    joblib.dump(clf, models_dir / "stylometry_model.joblib")
    onnx_model = convert_sklearn(clf,
        initial_types=[("float_input", FloatTensorType([None, 25]))],
        options={id(clf): {"zipmap": False}})
    (models_dir / "stylometry_v1.onnx").write_bytes(onnx_model.SerializeToString())
    json.dump({"feature_count": 25, "classes": ["Human", "AI", "Mixed"]},
        open(models_dir / "model_metadata.json", "w"))

print("  Models:", os.listdir("models"))
assert (models_dir / "stylometry_v1.onnx").exists(), "ONNX model missing!"
assert (models_dir / "stylometry_model.joblib").exists(), "Joblib missing!"
print("=== Step 1 complete ===")

# ── Step 2: Delete any cached PyInstaller build to force fresh build ──────
print("=== Step 2: Clearing cache ===")
for cache_dir in ["build", "dist"]:
    if Path(cache_dir).exists():
        shutil.rmtree(cache_dir)
        print(f"  Cleared {cache_dir}/")
for spec in Path(".").glob("*.spec"):
    spec.unlink()
    print(f"  Deleted {spec}")
print("=== Step 2 complete ===")

# ── Step 3: Run PyInstaller ───────────────────────────────────────────────
print("=== Step 3: Running PyInstaller ===")
is_windows = sys.platform == "win32"
sep = ";" if is_windows else ":"

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile" if is_windows else "--onedir",
    "--windowed",
    "--name", "AIScan",
    "--add-data", f"models{sep}models",
    "--hidden-import", "sklearn.ensemble._forest",
    "--hidden-import", "onnxruntime",
    "--hidden-import", "watchdog.observers.polling",
    "--hidden-import", "watchdog.observers.winapi" if is_windows else "watchdog.observers.fsevents",
    "--exclude-module", "matplotlib",
    "--exclude-module", "scipy",
    "--exclude-module", "pandas",
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
