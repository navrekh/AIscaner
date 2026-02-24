"""
AIScan — AI Document Detection Agent
Single-file standalone version. Bundles all detection logic.
User installs once, runs forever. Zero configuration.
"""
import sys, os, time, json, threading, logging, hashlib, re, math
from pathlib import Path
from collections import Counter, deque
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass, field

# ── Platform detection ────────────────────────────────────────────────────
IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

# ── Data directory (auto-created) ─────────────────────────────────────────
if IS_WIN:
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AIScan"
elif IS_MAC:
    DATA_DIR = Path.home() / "Library" / "Application Support" / "AIScan"
else:
    DATA_DIR = Path.home() / ".aiscan"

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(LOG_DIR / "aiscan.log", maxBytes=5*1024*1024, backupCount=3),
        logging.StreamHandler(sys.stdout),
    ])
log = logging.getLogger("aiscan")

# ── Find bundled model (works both frozen and unfrozen) ───────────────────
if getattr(sys, "frozen", False):
    _BASE = Path(sys._MEIPASS)
else:
    _BASE = Path(__file__).parent

MODELS_DIR = _BASE / "models"

# ════════════════════════════════════════════════════════════════════════════
# DETECTION ENGINE — 100% offline, no network calls
# ════════════════════════════════════════════════════════════════════════════

AI_PHRASES = [
    "furthermore","moreover","additionally","in conclusion",
    "it is important to note","it is worth noting","notably",
    "in summary","to summarize","in essence","as a result",
    "consequently","therefore","thus","this highlights",
    "this demonstrates","cutting-edge","robust framework",
    "paradigm shift","leverage","utilize","facilitate",
    "in today's fast-paced","delve into","navigate",
]

@dataclass
class ScanResult:
    ai_score: float = 0.0
    risk_level: str = "Low"
    classification: str = "Human"
    llm_suspected: str = "None"
    confidence: str = "Low"

def _detect(text: str) -> ScanResult:
    """Pure heuristic + ONNX detection. No network. No config."""
    text = text.strip()
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if len(s.split()) >= 3]
    words = text.lower().split()

    if len(sentences) < 2 or len(words) < 15:
        return ScanResult()

    # ── Stylometry features ───────────────────────────────────────────────
    sl = [len(s.split()) for s in sentences]
    mean_sl = sum(sl) / len(sl)
    std_sl = math.sqrt(sum((l - mean_sl)**2 for l in sl) / len(sl))
    burstiness = (std_sl / mean_sl * 100) if mean_sl > 0 else 50
    burstiness_score = max(0, 100 - burstiness * 1.5)   # low burstiness = AI

    freq = Counter(words)
    n = len(words)
    entropy = -sum((c/n)*math.log2(c/n) for c in freq.values() if c > 0)
    vocab_score = max(0, min(100, (12 - entropy) * 12))  # low entropy = AI

    text_lower = text.lower()
    hits = sum(1 for p in AI_PHRASES if p in text_lower)
    phrase_score = min(100, hits * 18)

    # Hedging words
    hedging = len(re.findall(r'\b(may|might|could|would|perhaps|possibly|likely|suggests?|indicates?|appears?|seems?)\b', text_lower))
    hedge_score = min(100, hedging / max(1, n) * 800)

    # Passive voice
    passive = len(re.findall(r'\b(is|are|was|were|be|been|being)\s+\w+ed\b', text_lower))
    passive_score = min(100, passive / max(1, len(sentences)) * 40)

    # Comma density (AI writes long complex sentences)
    commas = text.count(",")
    comma_score = min(100, commas / max(1, len(sentences)) * 25)

    # Repetition (AI reuses phrases)
    bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words)-1)]
    bigram_rep = len(bigrams) - len(set(bigrams))
    rep_score = min(100, bigram_rep / max(1, len(bigrams)) * 300)

    # ── Try ONNX model if available ───────────────────────────────────────
    ml_score = 0.0
    ml_confidence = "Low"
    onnx_path = MODELS_DIR / "stylometry_v1.onnx"
    if onnx_path.exists():
        try:
            import onnxruntime as ort, numpy as np, joblib
            meta_path = MODELS_DIR / "model_metadata.json"
            meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
            feature_names = meta.get("feature_names", [])

            sess = ort.InferenceSession(str(onnx_path))
            input_name = sess.get_inputs()[0].name

            # Build feature vector matching training
            features = _extract_features(text, sentences, words, freq)
            X = np.array([features], dtype=np.float32)
            proba = sess.run(None, {input_name: X})[1][0]
            # class order: 0=Human, 1=AI, 2=Mixed
            ai_prob = float(proba[1]) + float(proba[2]) * 0.5
            ml_score = ai_prob * 100
            max_p = max(proba)
            ml_confidence = "High" if max_p > 0.8 else "Medium" if max_p > 0.6 else "Low"
        except Exception as e:
            log.debug(f"ONNX inference failed: {e}")

    # ── Blend scores ──────────────────────────────────────────────────────
    heuristic = (
        0.25 * burstiness_score +
        0.20 * phrase_score +
        0.15 * vocab_score +
        0.15 * hedge_score +
        0.10 * passive_score +
        0.10 * comma_score +
        0.05 * rep_score
    )

    if ml_score > 0:
        w = {"High": 0.80, "Medium": 0.65, "Low": 0.45}.get(ml_confidence, 0.5)
        final = w * ml_score + (1 - w) * heuristic
    else:
        final = heuristic

    final = round(min(100, max(0, final)), 1)

    # ── Classify ──────────────────────────────────────────────────────────
    if final < 25:   classification = "Human";        risk = "Low"
    elif final < 50: classification = "AI-assisted";   risk = "Low" if final < 35 else "Medium"
    elif final < 75: classification = "Mixed";          risk = "Medium"
    else:            classification = "AI-generated";  risk = "High"

    conf = "High" if final < 20 or final > 80 else "Medium" if final < 35 or final > 65 else "Low"

    # ── LLM suspicion ─────────────────────────────────────────────────────
    if final >= 40:
        if burstiness < 15 and hedge_score > 30:   llm = "Likely ChatGPT"
        elif phrase_score > 50 and comma_score > 40: llm = "Likely Claude"
        elif vocab_score > 50:                        llm = "Likely Gemini"
        else:                                          llm = "Unknown LLM"
    else:
        llm = "None"

    return ScanResult(ai_score=final, risk_level=risk,
                      classification=classification, llm_suspected=llm, confidence=conf)


def _extract_features(text, sentences, words, freq):
    """Extract the same 25 features used in training."""
    n = max(1, len(words))
    ns = max(1, len(sentences))
    sl = [len(s.split()) for s in sentences]
    mean_sl = sum(sl)/ns
    std_sl = math.sqrt(sum((l-mean_sl)**2 for l in sl)/ns)

    entropy = -sum((c/n)*math.log2(c/n) for c in freq.values() if c > 0)
    text_lower = text.lower()
    trans = sum(1 for p in AI_PHRASES[:12] if p in text_lower)
    hedge = len(re.findall(r'\b(may|might|could|would|perhaps|possibly|likely|suggests?|indicates?)\b', text_lower))
    passive = len(re.findall(r'\b(is|are|was|were|be|been|being)\s+\w+ed\b', text_lower))
    commas = text.count(",")
    colons = text.count(":")
    dashes = text.count("—") + text.count(" - ")
    bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words)-1)]
    bigram_rep = (len(bigrams)-len(set(bigrams)))/max(1,len(bigrams))
    trigrams = [f"{words[i]} {words[i+1]} {words[i+2]}" for i in range(len(words)-2)]
    trigram_rep = (len(trigrams)-len(set(trigrams)))/max(1,len(trigrams)) if trigrams else 0
    starters = Counter(s.split()[0].lower() if s.split() else "" for s in sentences)
    st_entropy = -sum((c/ns)*math.log2(c/ns) for c in starters.values() if c > 0)
    paras = [p for p in text.split("\n\n") if p.strip()]
    pl = [len(p.split()) for p in paras] if len(paras) > 1 else [n]
    pm = sum(pl)/len(pl); pl_cv = math.sqrt(sum((l-pm)**2 for l in pl)/len(pl))/max(1,pm)
    wl = [len(w) for w in words]
    avg_wl = sum(wl)/n
    word_entropy = -sum((c/n)*math.log2(c/n) for c in freq.values() if c > 0)
    vocab_rich = len(freq)/n

    filler_phrases = ["it is important","it is worth","as a result","in conclusion",
                      "furthermore","moreover","additionally","in summary"]
    filler_count = sum(text_lower.count(p) for p in filler_phrases)
    filler_density = filler_count / max(1, ns)

    return [
        mean_sl, std_sl, max(0,100-std_sl/max(1,mean_sl)*100)/100,
        ns, vocab_rich, 1-vocab_rich,
        avg_wl, trans/ns, hedge/n*100, filler_density,
        passive/ns, commas/ns, colons/n*10, dashes/n*10,
        bigram_rep, trigram_rep, st_entropy, pl_cv,
        word_entropy, entropy,
        min(1, filler_count/10), min(1, hedge/10), min(1, trans/10),
        min(1, passive/5), filler_count,
    ]


# ════════════════════════════════════════════════════════════════════════════
# CONTENT EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════

def extract_text(path: Path) -> str:
    """Extract text from any supported file type."""
    ext = path.suffix.lower()
    try:
        if ext == ".txt" or ext == ".md" or ext == ".csv":
            return path.read_text(encoding="utf-8", errors="ignore")
        elif ext == ".docx":
            from docx import Document
            doc = Document(str(path))
            return "\n".join(p.text for p in doc.paragraphs if p.text.strip())
        elif ext == ".xlsx":
            import openpyxl
            wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
            parts = []
            for ws in wb.worksheets:
                for row in ws.iter_rows(values_only=True):
                    parts.extend(str(c) for c in row if c and str(c).strip())
            return " ".join(parts)
        elif ext == ".pptx":
            from pptx import Presentation
            prs = Presentation(str(path))
            parts = []
            for slide in prs.slides:
                for shape in slide.shapes:
                    if hasattr(shape, "text"): parts.append(shape.text)
            return "\n".join(parts)
        elif ext == ".pdf":
            try:
                import pypdf
                reader = pypdf.PdfReader(str(path))
                return "\n".join(p.extract_text() or "" for p in reader.pages)
            except Exception:
                return ""
    except Exception as e:
        log.debug(f"Extract failed {path.name}: {e}")
    return ""


# ════════════════════════════════════════════════════════════════════════════
# HISTORY — local HTML viewer
# ════════════════════════════════════════════════════════════════════════════

HISTORY_FILE = DATA_DIR / "scan_log.jsonl"
HISTORY_HTML  = DATA_DIR / "scan_history.html"

def save_result(path: Path, result: ScanResult):
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "file": path.name,
        "score": result.ai_score,
        "risk": result.risk_level,
        "class": result.classification,
        "llm": result.llm_suspected,
    }
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    _rebuild_html()

def _rebuild_html():
    events = []
    if HISTORY_FILE.exists():
        for line in HISTORY_FILE.read_text(encoding="utf-8").strip().splitlines()[-500:]:
            try: events.append(json.loads(line))
            except: pass
    events.reverse()
    risk_color = {"High":"#ff4455","Medium":"#ffaa00","Low":"#44cc77"}
    rows = "".join(
        f'<tr><td class="ts">{e["ts"]}</td>'
        f'<td class="fn">{e["file"]}</td>'
        f'<td style="color:{risk_color.get(e["risk"],"#aaa")};font-weight:700">{e["risk"]}</td>'
        f'<td style="color:{risk_color.get(e["risk"],"#aaa")};font-size:1.2em;font-weight:900">{e["score"]:.0f}%</td>'
        f'<td>{e["class"]}</td>'
        f'<td class="llm">{e["llm"]}</td></tr>'
        for e in events
    ) or '<tr><td colspan="6" class="empty">No scans yet — save a document to get started</td></tr>'

    HISTORY_HTML.write_text(f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>AIScan History</title>
<meta http-equiv="refresh" content="10">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:#0d0d14;color:#e8e8f0;padding:32px 40px}}
h1{{color:#00e5ff;font-size:1.5em;margin-bottom:4px}}
.sub{{color:#555;font-size:0.82em;margin-bottom:28px}}
table{{width:100%;border-collapse:collapse;font-size:0.875em}}
th{{background:#141420;color:#666;font-weight:600;text-transform:uppercase;
    letter-spacing:1px;font-size:0.72em;padding:10px 14px;text-align:left}}
td{{padding:11px 14px;border-bottom:1px solid #1a1a28}}
tr:hover td{{background:#141420}}
.ts{{color:#444;font-size:0.85em}}.fn{{font-weight:600}}
.llm{{color:#555;font-size:0.9em}}
.empty{{text-align:center;padding:60px;color:#333}}
.count{{color:#555;font-size:0.82em;margin-top:16px}}
</style></head>
<body>
<h1>🤖 AIScan — Scan History</h1>
<p class="sub">Auto-refreshes every 10s · All processing is local · Nothing sent to internet</p>
<table>
<thead><tr><th>Time</th><th>File</th><th>Risk</th><th>AI Score</th><th>Classification</th><th>Suspected LLM</th></tr></thead>
<tbody>{rows}</tbody></table>
<p class="count">{len(events)} total scans · Stored at {DATA_DIR}</p>
</body></html>""", encoding="utf-8")


# ════════════════════════════════════════════════════════════════════════════
# POPUP NOTIFICATIONS
# ════════════════════════════════════════════════════════════════════════════

def show_popup(result: ScanResult, filename: str):
    """Show native popup. Non-blocking."""
    threading.Thread(target=_popup, args=(result, filename), daemon=True).start()

def _test_scan(test_path=None):
    """Run a test scan to verify everything is working."""
    import tempfile
    log.info("Running test scan to verify detection is working...")
    test_text = "Furthermore it is important to note that leveraging robust AI frameworks plays a crucial role in achieving paradigm shifts. Moreover cutting-edge solutions enable organizations to optimize their workflows and facilitate seamless integration across multiple touchpoints."
    result = _detect(test_text)
    log.info(f"Test scan result: {result.ai_score:.0f}% [{result.risk_level}] — {'WORKING ✓' if result.ai_score > 20 else 'WARNING: low score, check model'}")
    return result

def _popup(result: ScanResult, filename: str):
    score = result.ai_score
    risk  = result.risk_level
    color = {"High":"#ff4455","Medium":"#ffaa00","Low":"#44cc77"}.get(risk,"#aaa")

    # Try system notification first (least intrusive)
    if IS_MAC:
        try:
            import subprocess
            msg = f"AI Score: {score:.0f}% — {result.classification}"
            subprocess.run(["osascript","-e",
                f'display notification "{msg}" with title "AIScan" subtitle "{filename}"'],
                timeout=3, capture_output=True)
            return
        except Exception: pass

    # Tkinter window (works on both platforms)
    try:
        import tkinter as tk
        root = tk.Tk()
        root.title("AIScan")
        root.configure(bg="#0d0d14")
        root.resizable(False, False)
        root.attributes("-topmost", True)

        W, H = 400, 220
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{sw-W-20}+{sh-H-60}")

        tk.Frame(root, bg=color, height=3).pack(fill="x")

        tf = tk.Frame(root, bg="#0d0d14", pady=10)
        tf.pack(fill="x", padx=16)
        tk.Label(tf, text="🤖  AIScan", font=("Helvetica",12,"bold"),
                 fg="#00e5ff", bg="#0d0d14").pack(side="left")
        tk.Label(tf, text=f"● {risk}", font=("Helvetica",10),
                 fg=color, bg="#0d0d14").pack(side="right")

        tk.Label(root, text=f"📄  {filename}", font=("Helvetica",9),
                 fg="#555", bg="#0d0d14", anchor="w", padx=16).pack(fill="x")

        cf = tk.Frame(root, bg="#141420", padx=12, pady=10,
                      highlightbackground=color, highlightthickness=1)
        cf.pack(fill="x", padx=14, pady=8)
        tk.Label(cf, text=f"{score:.0f}%", font=("Courier",30,"bold"),
                 fg=color, bg="#141420").pack(side="left")
        df = tk.Frame(cf, bg="#141420", padx=10)
        df.pack(side="left")
        tk.Label(df, text=result.classification, font=("Helvetica",11,"bold"),
                 fg="#e8e8f0", bg="#141420").pack(anchor="w")
        tk.Label(df, text=f"Suspected: {result.llm_suspected}",
                 font=("Courier",9), fg="#555", bg="#141420").pack(anchor="w")

        bf = tk.Frame(root, bg="#0d0d14", pady=6)
        bf.pack(fill="x", padx=14)
        tk.Button(bf, text="Dismiss", command=root.destroy,
                  font=("Helvetica",9,"bold"), fg="#0d0d14", bg="#00e5ff",
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(side="left", padx=(0,8))
        tk.Button(bf, text="View History",
                  command=lambda: [__import__("webbrowser").open(HISTORY_HTML.as_uri()), root.destroy()],
                  font=("Helvetica",9), fg="#888", bg="#1a1a28",
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(side="left")

        root.after(12000, root.destroy)
        root.mainloop()
    except Exception as e:
        log.debug(f"Popup failed: {e}")


# ════════════════════════════════════════════════════════════════════════════
# FILE WATCHER
# ════════════════════════════════════════════════════════════════════════════

SUPPORTED = {".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".md"}

class _Handler:
    def __init__(self): self._debounce = {}
    def dispatch(self, event):
        if event.is_directory: return
        if not hasattr(event, "src_path"): return
        path = Path(event.src_path)
        if path.suffix.lower() not in SUPPORTED: return
        if path.name.startswith(("~$",".",".~")): return
        now = time.time()
        if now - self._debounce.get(str(path), 0) < 1.0: return
        self._debounce[str(path)] = now
        threading.Thread(target=self._scan, args=(path,), daemon=True).start()

    def _scan(self, path: Path):
        try:
            log.info(f"Starting scan: {path.name}")
            text = extract_text(path)
            if not text:
                log.info(f"No text extracted from {path.name}")
                return
            word_count = len(text.split())
            log.info(f"Extracted {word_count} words from {path.name}")
            if word_count < 15:
                log.info(f"Too short to scan ({word_count} words), skipping")
                return
            result = _detect(text)
            log.info(f"SCAN RESULT: {path.name} → {result.ai_score:.0f}% [{result.risk_level}] {result.classification}")
            save_result(path, result)
            # Show popup for ALL results so user knows it's working
            show_popup(result, path.name)
        except Exception as e:
            log.error(f"Scan error {path.name}: {e}", exc_info=True)

def _watch_paths():
    home = Path.home()
    paths = []
    for name in ["Documents", "Desktop", "Downloads"]:
        p = home / name
        p.mkdir(exist_ok=True)
        paths.append(p)
    if IS_WIN:
        od = os.environ.get("ONEDRIVE")
        if od:
            for sub in ["Documents", "Desktop"]:
                p = Path(od) / sub
                if p.exists(): paths.append(p)
    return paths

def start_watcher(paths):
    from watchdog.events import FileSystemEventHandler

    # Use PollingObserver on Windows - actively checks every 2 seconds
    # Much more reliable than default WinAPI observer especially with OneDrive
    if IS_WIN:
        from watchdog.observers.polling import PollingObserver
        obs = PollingObserver(timeout=2)
        log.info("Using PollingObserver for Windows")
    else:
        from watchdog.observers import Observer
        obs = Observer()

    handler = _Handler()

    class WDHandler(FileSystemEventHandler):
        def on_created(self, e): handler.dispatch(e)
        def on_modified(self, e): handler.dispatch(e)

    for p in paths:
        obs.schedule(WDHandler(), str(p), recursive=True)
        log.info(f"Watching: {p}")
    obs.start()
    return obs


# ════════════════════════════════════════════════════════════════════════════
# SYSTEM TRAY
# ════════════════════════════════════════════════════════════════════════════

def _make_icon():
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64,64), (0,0,0,0))
    d = ImageDraw.Draw(img)
    d.ellipse([2,2,62,62], fill=(13,13,20), outline=(0,229,255), width=2)
    d.ellipse([8,22,56,42], fill=(0,229,255))
    d.ellipse([20,26,44,38], fill=(245,245,255))
    d.ellipse([26,28,38,36], fill=(13,13,20))
    d.ellipse([30,30,34,34], fill=(255,255,255))
    return img

def run_tray(obs):
    import webbrowser

    if IS_WIN:
        import pystray
        _paused = [False]

        def toggle_pause(icon, item):
            if _paused[0]:
                obs.start(); _paused[0] = False; icon.title = "AIScan — Active"
            else:
                obs.stop(); _paused[0] = True; icon.title = "AIScan — Paused"

        menu = pystray.Menu(
            pystray.MenuItem("AIScan — Active", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("View Scan History", lambda *_: webbrowser.open(HISTORY_HTML.as_uri())),
            pystray.MenuItem("Pause / Resume",    toggle_pause),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", lambda *_: (obs.stop(), icon.stop(), sys.exit(0))),
        )
        icon = pystray.Icon("AIScan", _make_icon(), "AIScan — Active", menu)
        icon.run()

    elif IS_MAC:
        try:
            import rumps
            app = rumps.App("🔍", quit_button=None)
            _paused = [False]

            @rumps.clicked("View Scan History")
            def view_history(_): webbrowser.open(HISTORY_HTML.as_uri())

            @rumps.clicked("Pause / Resume")
            def toggle(sender):
                if _paused[0]: obs.start(); _paused[0]=False; app.title="🔍"
                else: obs.stop(); _paused[0]=True; app.title="⏸"

            @rumps.clicked("Quit AIScan")
            def quit(_): obs.stop(); rumps.quit_application()

            app.menu = ["View Scan History", "Pause / Resume", None, "Quit AIScan"]
            app.run()
        except ImportError:
            while True: time.sleep(60)


# ════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════


# ════════════════════════════════════════════════════════════════════════════
# LICENSE SYSTEM
# ════════════════════════════════════════════════════════════════════════════

import hmac, hashlib

LICENSE_SECRET = "aiscan-2026-navrekh-secret-xK9mP2qR"
LICENSE_FILE   = DATA_DIR / "license.json"
TRIAL_DAYS     = 14
RAZORPAY_URL   = "https://rzp.io/rzp/sdbqn0r"  

def _lic_load():
    if LICENSE_FILE.exists():
        try: return json.loads(LICENSE_FILE.read_text())
        except: pass
    return {}

def _lic_save(data):
    LICENSE_FILE.write_text(json.dumps(data))

def _make_key(email):
    raw = f"AISCAN-{email.lower().strip()}"
    sig = hmac.new(LICENSE_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:24].upper()
    return "-".join(sig[i:i+4] for i in range(0, 24, 4))

def get_license_status():
    data = _lic_load()
    if data.get("licensed"):
        return {"status": "active", "email": data.get("email", "")}
    if "trial_start" not in data:
        data["trial_start"] = time.time()
        _lic_save(data)
    days_left = max(0, int(TRIAL_DAYS - (time.time() - data["trial_start"]) / 86400))
    return {"status": "trial", "days_left": days_left} if days_left > 0 else {"status": "expired"}

def activate_license(email, key):
    email = email.strip().lower()
    if not email or "@" not in email:
        return False, "Please enter a valid email address."
    if _make_key(email) == key.strip().upper():
        data = _lic_load()
        data.update({"licensed": True, "email": email, "activated_at": time.time()})
        _lic_save(data)
        return True, "License activated! Thank you."
    return False, "Invalid key. Please check your email and key."

def show_trial_banner(days_left):
    """Show a small non-blocking trial reminder."""
    try:
        import tkinter as tk
        root = tk.Tk(); root.withdraw()
        from tkinter import messagebox
        messagebox.showinfo("AIScan Trial",
            f"You have {days_left} day{'s' if days_left != 1 else ''} left in your free trial.\n\n"
            f"Upgrade at:\n{RAZORPAY_URL}")
        root.destroy()
    except: pass

def show_expired_screen():
    """Blocking upgrade screen shown when trial expires."""
    import tkinter as tk
    from tkinter import messagebox
    import webbrowser

    root = tk.Tk()
    root.title("AIScan — Trial Expired")
    root.configure(bg="#0d0d14")
    root.geometry("460x420")
    root.resizable(False, False)
    root.attributes("-topmost", True)

    # Center on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth()  - 460) // 2
    y = (root.winfo_screenheight() - 420) // 2
    root.geometry(f"460x420+{x}+{y}")

    tk.Frame(root, bg="#c8401a", height=4).pack(fill="x")

    tk.Label(root, text="⏰  Trial Expired",
             font=("Helvetica", 18, "bold"), fg="#ff6644", bg="#0d0d14"
             ).pack(pady=(28, 4))
    tk.Label(root, text="Your 14-day free trial has ended.",
             font=("Helvetica", 11), fg="#888", bg="#0d0d14").pack()
    tk.Label(root, text="Upgrade to keep using AIScan.",
             font=("Helvetica", 11), fg="#888", bg="#0d0d14").pack(pady=(0, 20))

    # Upgrade button
    tk.Button(root, text="Upgrade Now  —  ₹499/month",
              font=("Helvetica", 12, "bold"), fg="#000", bg="#00e5ff",
              relief="flat", padx=20, pady=10, cursor="hand2",
              command=lambda: webbrowser.open(RAZORPAY_URL)
              ).pack(pady=(0, 20))

    # License key entry
    tk.Label(root, text="Already purchased? Enter your license key:",
             font=("Helvetica", 10), fg="#666", bg="#0d0d14").pack()

    email_var = tk.StringVar()
    key_var   = tk.StringVar()
    msg_var   = tk.StringVar()

    ef = tk.Frame(root, bg="#0d0d14"); ef.pack(pady=(8,0))
    tk.Label(ef, text="Email:", font=("Helvetica",10), fg="#888", bg="#0d0d14",
             width=8, anchor="e").pack(side="left")
    tk.Entry(ef, textvariable=email_var, font=("Courier",10),
             bg="#1a1a28", fg="#e8e8f0", insertbackground="#fff",
             relief="flat", width=28).pack(side="left", padx=4)

    kf = tk.Frame(root, bg="#0d0d14"); kf.pack(pady=4)
    tk.Label(kf, text="Key:", font=("Helvetica",10), fg="#888", bg="#0d0d14",
             width=8, anchor="e").pack(side="left")
    tk.Entry(kf, textvariable=key_var, font=("Courier",10),
             bg="#1a1a28", fg="#e8e8f0", insertbackground="#fff",
             relief="flat", width=28).pack(side="left", padx=4)

    tk.Label(root, textvariable=msg_var, font=("Helvetica",9),
             fg="#ff6644", bg="#0d0d14").pack(pady=4)

    def try_activate():
        ok, msg = activate_license(email_var.get(), key_var.get())
        if ok:
            msg_var.set("✓ " + msg)
            root.after(1500, root.destroy)
        else:
            msg_var.set("✗ " + msg)

    tk.Button(root, text="Activate License",
              font=("Helvetica", 10, "bold"), fg="#000", bg="#44cc77",
              relief="flat", padx=14, pady=6, cursor="hand2",
              command=try_activate).pack(pady=(0, 16))

    root.mainloop()

def main():
    log.info(f"AIScan starting. Data: {DATA_DIR}")

    # ── License check ─────────────────────────────────────────────────────
    lic = get_license_status()
    log.info(f"License status: {lic['status']}")

    if lic["status"] == "expired":
        log.info("Trial expired — showing upgrade screen")
        show_expired_screen()
        # Re-check after they may have activated
        lic = get_license_status()
        if lic["status"] != "active":
            sys.exit(0)  # exit if still not activated

    elif lic["status"] == "trial" and lic["days_left"] <= 3:
        # Warn when 3 or fewer days left
        threading.Thread(target=show_trial_banner,
                         args=(lic["days_left"],), daemon=True).start()

    # Initialise history page
    if not HISTORY_HTML.exists():
        _rebuild_html()

    # Start watching
    paths = _watch_paths()
    obs = start_watcher(paths)

    log.info("AIScan is running. Watching: " + ", ".join(str(p) for p in paths))

    # Run test scan on startup to verify detection works
    threading.Thread(target=_test_scan, daemon=True).start()

    # Show startup notification
    if IS_WIN:
        try:
            from plyer import notification
            notification.notify(title="AIScan", message="AI monitoring active.",
                                app_name="AIScan", timeout=4)
        except Exception: pass

    # Run tray (blocks until exit)
    try:
        run_tray(obs)
    except KeyboardInterrupt:
        obs.stop()

if __name__ == "__main__":
    main()
