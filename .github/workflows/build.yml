"""
AIScan build script.
Trains the model, then calls PyInstaller.
Run: python build_and_package.py
"""
import os, sys, json, subprocess
from pathlib import Path

# ── Step 1: Train model and write models folder ───────────────────────────
print("=== Training model ===")

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

models_dir = Path("models")
models_dir.mkdir(exist_ok=True)

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

onnx_model = convert_sklearn(
    clf,
    initial_types=[("float_input", FloatTensorType([None, 25]))],
    options={id(clf): {"zipmap": False}}
)
(models_dir / "stylometry_v1.onnx").write_bytes(onnx_model.SerializeToString())
json.dump(
    {"feature_count": 25, "classes": ["Human", "AI", "Mixed"]},
    open(models_dir / "model_metadata.json", "w")
)

print("Models folder contents:", list(models_dir.iterdir()))
assert (models_dir / "stylometry_v1.onnx").exists(), "ONNX model missing!"
assert (models_dir / "stylometry_model.joblib").exists(), "Joblib model missing!"
print("=== Model training complete ===")

# ── Step 2: Run PyInstaller ───────────────────────────────────────────────
print("=== Running PyInstaller ===")

is_windows = sys.platform == "win32"
sep = ";" if is_windows else ":"

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile",
    "--windowed",
    "--name", "AIScan",
    "--add-data", f"models{sep}models",
    "--hidden-import", "sklearn.ensemble._forest",
    "--hidden-import", "sklearn.ensemble._gb",
    "--hidden-import", "onnxruntime",
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
