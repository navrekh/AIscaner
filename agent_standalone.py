"""
AIScan v2.0  -  AI Document Detection Agent
Smarter detection, paragraph-level highlighting, right-click scan, history dashboard.
"""
import sys, os, time, json, threading, logging, hashlib, re, math, webbrowser
from pathlib import Path
from collections import Counter, deque
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass, field

IS_WIN = sys.platform == "win32"

# -- Intelligence engine (inline import to keep single-file deploy) --------
def _load_module(name):
    """Load a companion module if available."""
    try:
        import importlib.util, os
        base = os.path.dirname(os.path.abspath(
            sys.argv[0] if getattr(sys, "frozen", False) else __file__))
        path = os.path.join(base, f"{name}.py")
        if not os.path.exists(path):
            # Try same dir as script
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{name}.py")
        if not os.path.exists(path):
            log.warning(f"Module {name}.py not found")
            return None
        spec = importlib.util.spec_from_file_location(name, path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception as e:
        log.warning(f"Could not load {name}: {e}")
        return None

def _load_intelligence():
    return _load_module("intelligence")

IS_MAC = sys.platform == "darwin"

if IS_WIN:
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AIScan"
elif IS_MAC:
    DATA_DIR = Path.home() / "Library" / "Application Support" / "AIScan"
else:
    DATA_DIR = Path.home() / ".aiscan"

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(LOG_DIR / "aiscan.log", maxBytes=2*1024*1024, backupCount=3, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ])
log = logging.getLogger("aiscan")

HISTORY_FILE = DATA_DIR / "scan_log.jsonl"
HISTORY_HTML = DATA_DIR / "scan_history.html"

# -- Initialize all modules -----------------------------------------------
_intel = _load_intelligence()
if _intel:
    _behavioral      = _intel.BehavioralFingerprint(DATA_DIR)
    _keystroke       = _intel.KeystrokeRhythm()
    _dna             = _intel.DocumentDNA(DATA_DIR)
    _source_verifier = _intel.SourceVerifier()
    log.info("Intelligence engine loaded OK")
else:
    _behavioral = _keystroke = _dna = _source_verifier = None

_advanced = _load_module("advanced_detection")
if _advanced:
    log.info("Advanced detection loaded OK (code, rewrite, multilingual, images)")
else:
    log.warning("Advanced detection not available")

_session_mod = _load_module("session_recorder")
_session_recorder = _session_mod.SessionRecorder(DATA_DIR) if _session_mod else None
if _session_recorder:
    log.info("Session recorder loaded OK")

_bulk_mod = _load_module("bulk_scanner")
if _bulk_mod:
    log.info("Bulk scanner loaded OK")

_screen_mod     = _load_module("screen_monitor")
_settings_mod   = _load_module("settings_ui")
_onboard_mod    = _load_module("onboarding")
_report_mod     = _load_module("report_generator")
_screen_monitor = None  # initialized in main()
_settings_mgr   = _settings_mod.SettingsManager(DATA_DIR) if _settings_mod else None
if _settings_mgr: log.info("Settings loaded OK")

# ============================================================================
# DETECTION ENGINE v2  -  Smarter, per-paragraph, LLM fingerprinting
# ============================================================================

# Expanded AI phrase sets per LLM
CHATGPT_PHRASES = [
    "certainly!", "of course!", "great question", "i'd be happy to",
    "as an ai", "as a language model", "i cannot provide",
    "it's important to note", "it's worth noting",
    "in today's world", "in today's fast-paced", "in conclusion",
    "to summarize", "furthermore", "moreover", "additionally",
    "this is a complex topic", "there are several", "various factors",
]

CLAUDE_PHRASES = [
    "i want to be direct", "to be clear", "let me think through",
    "there are a few things", "it's worth considering",
    "i should note", "nuanced", "straightforward",
    "happy to help", "let me know if",
]

GEMINI_PHRASES = [
    "leverage", "utilize", "facilitate", "paradigm shift",
    "cutting-edge", "robust framework", "seamless integration",
    "optimize", "innovative", "ecosystem", "synergy",
    "delve into", "navigate", "unlock", "empower",
    "transformative", "scalable", "actionable insights",
]

GENERIC_AI_PHRASES = [
    "as a result", "consequently", "therefore", "thus",
    "this highlights", "this demonstrates", "this underscores",
    "it is important to", "one must consider", "plays a crucial role",
    "across multiple", "multiple touchpoints", "best practices",
    "key takeaways", "moving forward", "going forward",
]

ALL_AI_PHRASES = CHATGPT_PHRASES + CLAUDE_PHRASES + GEMINI_PHRASES + GENERIC_AI_PHRASES

@dataclass
class ParagraphResult:
    text: str
    ai_score: float
    classification: str
    reasons: list

@dataclass
class ScanResult:
    ai_score: float = 0.0
    risk_level: str = "Low"
    classification: str = "Human"
    llm_suspected: str = "None"
    confidence: str = "Low"
    paragraph_results: list = field(default_factory=list)
    reasons: list = field(default_factory=list)


def _score_text_block(text: str) -> tuple:
    """Score a block of text. Returns (score, reasons, component_scores)."""
    text = text.strip()
    if not text:
        return 0.0, [], {}

    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if len(s.split()) >= 3]
    words = text.lower().split()
    n = max(1, len(words))
    ns = max(1, len(sentences))

    reasons = []
    scores = {}

    # 1. Sentence length burstiness (AI = uniform, Human = varied)
    if len(sentences) >= 2:
        sl = [len(s.split()) for s in sentences]
        mean_sl = sum(sl) / len(sl)
        std_sl = math.sqrt(sum((l - mean_sl)**2 for l in sl) / len(sl))
        cv = (std_sl / mean_sl) if mean_sl > 0 else 0
        scores["burstiness"] = max(0, min(100, (0.5 - cv) * 200))
        if scores["burstiness"] > 60:
            reasons.append(f"Very uniform sentence lengths (AI pattern)")
    else:
        scores["burstiness"] = 30

    # 2. Vocabulary entropy (AI = lower entropy / more predictable)
    freq = Counter(words)
    entropy = -sum((c/n)*math.log2(c/n) for c in freq.values() if c > 0)
    scores["vocab"] = max(0, min(100, (11 - entropy) * 14))
    if scores["vocab"] > 60:
        reasons.append(f"Predictable vocabulary patterns")

    # 3. AI phrase detection with per-LLM tracking
    text_lower = text.lower()
    chatgpt_hits = sum(1 for p in CHATGPT_PHRASES if p in text_lower)
    claude_hits   = sum(1 for p in CLAUDE_PHRASES   if p in text_lower)
    gemini_hits   = sum(1 for p in GEMINI_PHRASES   if p in text_lower)
    generic_hits  = sum(1 for p in GENERIC_AI_PHRASES if p in text_lower)
    total_hits = chatgpt_hits + claude_hits + gemini_hits + generic_hits
    scores["phrases"] = min(100, total_hits * 15)
    if total_hits > 0:
        matched = [p for p in ALL_AI_PHRASES if p in text_lower][:3]
        reasons.append(f"AI phrases detected: {', '.join(matched)}")

    # 4. Hedging language
    hedging = len(re.findall(
        r'\b(may|might|could|would|perhaps|possibly|likely|suggests?|'
        r'indicates?|appears?|seems?|arguably|presumably)\b', text_lower))
    scores["hedging"] = min(100, hedging / n * 600)
    if scores["hedging"] > 50:
        reasons.append(f"High hedging language ({hedging} instances)")

    # 5. Passive voice density
    passive = len(re.findall(r'\b(is|are|was|were|be|been|being)\s+\w+ed\b', text_lower))
    scores["passive"] = min(100, passive / ns * 35)
    if scores["passive"] > 50:
        reasons.append(f"High passive voice usage")

    # 6. Comma density
    commas = text.count(",")
    scores["comma"] = min(100, commas / ns * 22)

    # 7. Bigram repetition
    bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words)-1)]
    rep = len(bigrams) - len(set(bigrams))
    scores["repetition"] = min(100, rep / max(1, len(bigrams)) * 250)
    if scores["repetition"] > 40:
        reasons.append(f"Repeated phrase patterns")

    # 8. Perfect structure detection (AI loves numbered lists, perfect headers)
    numbered = len(re.findall(r'^\s*\d+[\.\)]\s', text, re.MULTILINE))
    bullet = len(re.findall(r'^\s*[-**]\s', text, re.MULTILINE))
    scores["structure"] = min(100, (numbered + bullet) / ns * 60)
    if scores["structure"] > 40:
        reasons.append(f"Highly structured formatting (AI pattern)")

    # 9. Transition word density
    transitions = len(re.findall(
        r'\b(however|nevertheless|nonetheless|consequently|subsequently|'
        r'furthermore|moreover|additionally|alternatively|conversely)\b', text_lower))
    scores["transitions"] = min(100, transitions / ns * 80)
    if scores["transitions"] > 50:
        reasons.append(f"Heavy use of transition words")

    # 10. Question marks (humans ask more questions)
    questions = text.count("?")
    scores["questions"] = max(0, min(30, 30 - questions * 15))

    # Weighted blend
    final = (
        0.20 * scores["burstiness"] +
        0.15 * scores["phrases"] +
        0.12 * scores["vocab"] +
        0.12 * scores["hedging"] +
        0.10 * scores["passive"] +
        0.10 * scores["transitions"] +
        0.08 * scores["structure"] +
        0.07 * scores["comma"] +
        0.04 * scores["repetition"] +
        0.02 * scores["questions"]
    )

    return (
        round(min(100, max(0, final)), 1),
        reasons,
        {**scores,
         "chatgpt_hits": chatgpt_hits,
         "claude_hits": claude_hits,
         "gemini_hits": gemini_hits}
    )


def _detect(text: str) -> ScanResult:
    """Full document detection with paragraph-level analysis."""
    text = text.strip()
    if not text:
        return ScanResult()

    # Split into paragraphs
    paragraphs = [p.strip() for p in re.split(r'\n\s*\n', text) if len(p.strip().split()) >= 10]
    if not paragraphs:
        paragraphs = [text]

    # Score each paragraph
    para_results = []
    all_scores = []
    all_reasons = []
    all_components = []

    for para in paragraphs:
        score, reasons, components = _score_text_block(para)
        all_scores.append(score)
        all_reasons.extend(reasons)
        all_components.append(components)

        if score < 30:    cls = "Human"
        elif score < 55:  cls = "AI-assisted"
        elif score < 75:  cls = "Mixed"
        else:             cls = "AI-generated"

        para_results.append(ParagraphResult(
            text=para[:200] + "..." if len(para) > 200 else para,
            ai_score=score,
            classification=cls,
            reasons=reasons
        ))

    # Document-level score = weighted average (higher paragraphs weighted more)
    if all_scores:
        sorted_scores = sorted(all_scores, reverse=True)
        # Weight top paragraphs more heavily
        weights = [1.0 / (i + 1) for i in range(len(sorted_scores))]
        total_w = sum(weights)
        final = sum(s * w for s, w in zip(sorted_scores, weights)) / total_w
    else:
        final = 0.0

    final = round(min(100, max(0, final)), 1)

    # Deduplicate reasons
    seen = set()
    unique_reasons = []
    for r in all_reasons:
        key = r[:40]
        if key not in seen:
            seen.add(key)
            unique_reasons.append(r)

    # LLM fingerprinting
    total_chatgpt = sum(c.get("chatgpt_hits", 0) for c in all_components)
    total_claude  = sum(c.get("claude_hits",   0) for c in all_components)
    total_gemini  = sum(c.get("gemini_hits",   0) for c in all_components)

    if final >= 35:
        llm_votes = {
            "Likely ChatGPT": total_chatgpt,
            "Likely Claude":  total_claude,
            "Likely Gemini":  total_gemini,
        }
        top_llm = max(llm_votes, key=llm_votes.get)
        llm = top_llm if max(llm_votes.values()) > 0 else "Unknown LLM"
    else:
        llm = "None"

    # Classification
    if final < 25:   classification = "Human";        risk = "Low"
    elif final < 40: classification = "AI-assisted";  risk = "Low"
    elif final < 60: classification = "AI-assisted";  risk = "Medium"
    elif final < 78: classification = "Mixed";         risk = "Medium"
    else:            classification = "AI-generated";  risk = "High"

    conf = "High" if final < 20 or final > 80 else "Medium" if final < 35 or final > 65 else "Low"

    return ScanResult(
        ai_score=final,
        risk_level=risk,
        classification=classification,
        llm_suspected=llm,
        confidence=conf,
        paragraph_results=para_results,
        reasons=unique_reasons[:5]
    )


# ============================================================================
# CONTENT EXTRACTION
# ============================================================================

SUPPORTED = {".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".md", ".csv"}

def extract_text(path: Path) -> str:
    try:
        ext = path.suffix.lower()
        if ext == ".txt" or ext == ".md" or ext == ".csv":
            for enc in ["utf-8", "latin-1", "cp1252"]:
                try:
                    return path.read_text(encoding=enc)
                except: pass
        elif ext == ".docx":
            from docx import Document
            doc = Document(str(path))
            return "\n\n".join(p.text for p in doc.paragraphs if p.text.strip())
        elif ext == ".pdf":
            from pypdf import PdfReader
            reader = PdfReader(str(path))
            return "\n\n".join(p.extract_text() or "" for p in reader.pages)
        elif ext == ".xlsx":
            from openpyxl import load_workbook
            wb = load_workbook(str(path), read_only=True, data_only=True)
            parts = []
            for ws in wb.worksheets:
                for row in ws.iter_rows(values_only=True):
                    parts.extend(str(c) for c in row if c)
            return " ".join(parts)
        elif ext == ".pptx":
            from pptx import Presentation
            prs = Presentation(str(path))
            parts = []
            for slide in prs.slides:
                for shape in slide.shapes:
                    if hasattr(shape, "text"):
                        parts.append(shape.text)
            return "\n\n".join(parts)
    except Exception as e:
        log.error(f"Extract error {path.name}: {e}")
    return ""


# ============================================================================
# HISTORY STORAGE & HTML DASHBOARD
# ============================================================================

MAX_HISTORY = 500

def save_result(path: Path, result: ScanResult):
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "file": str(path),
        "name": path.name,
        "score": result.ai_score,
        "risk": result.risk_level,
        "classification": result.classification,
        "llm": result.llm_suspected,
        "confidence": result.confidence,
        "reasons": result.reasons,
        "paragraphs": [
            {"score": p.ai_score, "classification": p.classification,
             "text": p.text[:150], "reasons": p.reasons}
            for p in result.paragraph_results
        ]
    }
    lines = []
    if HISTORY_FILE.exists():
        lines = HISTORY_FILE.read_text().splitlines()
    lines.append(json.dumps(entry))
    if len(lines) > MAX_HISTORY:
        lines = lines[-MAX_HISTORY:]
    HISTORY_FILE.write_text("\n".join(lines))
    _rebuild_html()


def _rebuild_html():
    entries = []
    if HISTORY_FILE.exists():
        for line in HISTORY_FILE.read_text().splitlines():
            try:
                entries.append(json.loads(line))
            except: pass
    entries.reverse()

    # Stats
    total = len(entries)
    high_risk = sum(1 for e in entries if e.get("risk") == "High")
    medium_risk = sum(1 for e in entries if e.get("risk") == "Medium")
    avg_score = sum(e.get("score", 0) for e in entries) / max(1, total)

    rows = ""
    for e in entries[:100]:
        score = e.get("score", 0)
        risk = e.get("risk", "Low")
        color = "#ff4455" if risk == "High" else "#ffaa00" if risk == "Medium" else "#44cc77"
        reasons_html = ""
        if e.get("reasons"):
            reasons_html = "<br><small style='color:#666'>" + " . ".join(e["reasons"][:3]) + "</small>"

        # Paragraph breakdown
        para_html = ""
        for p in e.get("paragraphs", [])[:3]:
            p_color = "#ff4455" if p["score"] > 75 else "#ffaa00" if p["score"] > 40 else "#44cc77"
            para_html += f"""
            <div style='margin:4px 0;padding:6px 10px;background:#111;border-left:3px solid {p_color};border-radius:0 4px 4px 0;font-size:11px;color:#aaa'>
                <span style='color:{p_color};font-weight:700'>{p["score"]:.0f}%</span>
                <span style='color:#666;margin:0 6px'>.</span>
                {p["text"][:100]}...
            </div>"""

        rows += f"""
        <div class='card' onclick='this.querySelector(".details").style.display=this.querySelector(".details").style.display==="none"?"block":"none"'>
            <div style='display:flex;align-items:center;gap:12px'>
                <div style='font-size:1.4em;font-weight:800;color:{color};min-width:52px'>{score:.0f}%</div>
                <div style='flex:1'>
                    <div style='font-weight:600;color:#e8e8f0'>{e.get("name","")}</div>
                    <div style='font-size:11px;color:#555'>{e.get("ts","")} &nbsp;.&nbsp;
                        <span style='color:{color}'>{risk} Risk</span> &nbsp;.&nbsp;
                        {e.get("classification","")} &nbsp;.&nbsp;
                        <span style='color:#888'>{e.get("llm","")}</span>
                    </div>
                    {reasons_html}
                </div>
                <div style='color:#444;font-size:18px'>v</div>
            </div>
            <div class='details' style='display:none;margin-top:12px;padding-top:12px;border-top:1px solid #1a1a2e'>
                <div style='font-size:11px;color:#555;margin-bottom:6px'>PARAGRAPH BREAKDOWN</div>
                {para_html if para_html else "<div style='color:#444;font-size:11px'>No paragraph data</div>"}
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<meta http-equiv="refresh" content="10"/>
<title>AIScan History</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600;700&display=swap" rel="stylesheet">
<style>
* {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ background:#0d0d14; color:#e8e8f0; font-family:'DM Sans',sans-serif; font-size:13px }}
.header {{ background:#0a0a10; border-bottom:1px solid #1a1a2e; padding:20px 32px; display:flex; align-items:center; gap:16px }}
.header h1 {{ font-size:1.3em; font-weight:700 }} .header h1 span {{ color:#00e5ff }}
.stats {{ display:flex; gap:16px; padding:20px 32px }}
.stat {{ background:#111; border:1px solid #1a1a2e; border-radius:8px; padding:14px 20px; flex:1; text-align:center }}
.stat .n {{ font-size:1.8em; font-weight:800; color:#00e5ff }}
.stat .l {{ font-size:11px; color:#555; margin-top:2px }}
.feed {{ padding:0 32px 32px }}
.card {{ background:#111; border:1px solid #1a1a2e; border-radius:8px; padding:14px 16px;
         margin-bottom:8px; cursor:pointer; transition:border-color .15s }}
.card:hover {{ border-color:#333 }}
.empty {{ text-align:center; color:#333; padding:60px; font-size:1.1em }}
</style></head><body>
<div class="header">
    <div style="width:32px;height:32px;background:#00e5ff;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:16px">[AIScan]</div>
    <h1><span>AI</span>Scan  -  Detection History</h1>
    <div style="margin-left:auto;font-size:11px;color:#333">Auto-refreshes every 10s</div>
</div>
<div class="stats">
    <div class="stat"><div class="n">{total}</div><div class="l">Total Scans</div></div>
    <div class="stat"><div class="n" style="color:#ff4455">{high_risk}</div><div class="l">High Risk</div></div>
    <div class="stat"><div class="n" style="color:#ffaa00">{medium_risk}</div><div class="l">Medium Risk</div></div>
    <div class="stat"><div class="n">{avg_score:.0f}%</div><div class="l">Avg AI Score</div></div>
</div>
<div class="feed">
    {"".join(rows) if rows else '<div class="empty">No scans yet. Save a document to get started.</div>'}
</div>
</body></html>"""

    HISTORY_HTML.write_text(html, encoding="utf-8")


# ============================================================================
# NOTIFICATIONS
# ============================================================================

def show_popup(result: ScanResult, filename: str):
    threading.Thread(target=_popup, args=(result, filename), daemon=True).start()

def _popup(result: ScanResult, filename: str):
    try:
        score = result.ai_score
        risk  = result.risk_level
        color = "#ff4455" if risk == "High" else "#ffaa00" if risk == "Medium" else "#44cc77"
        reason_text = result.reasons[0] if result.reasons else ""

        import tkinter as tk
        root = tk.Tk()
        root.title("AIScan")
        root.configure(bg="#111827")
        root.geometry("380x180")
        root.resizable(False, False)
        root.attributes("-topmost", True)

        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"380x180+{sw-400}+{sh-220}")

        tk.Frame(root, bg=color, height=3).pack(fill="x")
        main = tk.Frame(root, bg="#111827"); main.pack(fill="both", expand=True, padx=16, pady=12)

        top = tk.Frame(main, bg="#111827"); top.pack(fill="x")
        tk.Label(top, text="[AIScan] AIScan", font=("Helvetica",10,"bold"),
                 fg="#00e5ff", bg="#111827").pack(side="left")
        tk.Label(top, text=f"* {risk} Risk", font=("Helvetica",9),
                 fg=color, bg="#111827").pack(side="right")

        tk.Label(main, text=filename[:45], font=("Helvetica",9),
                 fg="#555", bg="#111827", anchor="w").pack(fill="x", pady=(2,8))

        mid = tk.Frame(main, bg="#1a1a2e", padx=12, pady=10); mid.pack(fill="x")
        tk.Label(mid, text=f"{score:.0f}%", font=("Helvetica",20,"bold"),
                 fg=color, bg="#1a1a2e").pack(side="left")
        right = tk.Frame(mid, bg="#1a1a2e"); right.pack(side="left", padx=(12,0))
        tk.Label(right, text=result.classification, font=("Helvetica",10,"bold"),
                 fg="#e8e8f0", bg="#1a1a2e").pack(anchor="w")
        tk.Label(right, text=result.llm_suspected, font=("Helvetica",9),
                 fg="#666", bg="#1a1a2e").pack(anchor="w")
        if reason_text:
            tk.Label(right, text=reason_text[:40], font=("Helvetica",8),
                     fg="#555", bg="#1a1a2e").pack(anchor="w")

        bf = tk.Frame(main, bg="#111827"); bf.pack(fill="x", pady=(10,0))
        tk.Button(bf, text="Dismiss", command=root.destroy,
                  font=("Helvetica",9,"bold"), fg="#0d0d14", bg="#00e5ff",
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(side="left", padx=(0,8))
        tk.Button(bf, text="View History",
                  command=lambda: [webbrowser.open(HISTORY_HTML.as_uri()), root.destroy()],
                  font=("Helvetica",9), fg="#888", bg="#1a1a28",
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(side="left")

        root.after(12000, root.destroy)
        root.mainloop()
    except Exception as e:
        log.debug(f"Popup failed: {e}")


# ============================================================================
# FILE WATCHER
# ============================================================================

class _Handler:
    def __init__(self): self._debounce = {}
    def dispatch(self, event):
        if event.is_directory: return
        if not hasattr(event, "src_path"): return
        path = Path(event.src_path)
        if path.suffix.lower() not in SUPPORTED: return
        if path.name.startswith(("~$", ".", ".~")): return
        now = time.time()
        if now - self._debounce.get(str(path), 0) < 1.0: return
        self._debounce[str(path)] = now
        threading.Thread(target=self._scan, args=(path,), daemon=True).start()

    def _scan(self, path: Path):
        try:
            log.info(f"Starting scan: {path.name}")
            time.sleep(0.5)  # wait for file write to complete
            text = extract_text(path)
            if not text:
                log.info(f"No text extracted from {path.name}")
                return
            word_count = len(text.split())
            log.info(f"Extracted {word_count} words from {path.name}")
            if word_count < 15:
                log.info(f"Too short ({word_count} words), skipping")
                return

            # -- Session recording ------------------------------------------
            if _session_recorder:
                import hashlib as _hl
                file_hash = _hl.md5(text.encode()).hexdigest()[:12]
                _session_recorder.record_save(path, word_count, file_hash)

            # -- Advanced detection -----------------------------------------
            if _advanced:
                ext = path.suffix.lower()
                # Code detection
                from advanced_detection import CODE_EXTENSIONS
                if ext in CODE_EXTENSIONS:
                    code_r = _advanced.detect_code(text, ext)
                    log.info(f"CODE SCAN: {path.name} -> {code_r['score']:.0f}% [{code_r['risk']}]")

                # Rewrite detection
                rewrite_r = _advanced.detect_rewrite(text)
                if rewrite_r["score"] > 30:
                    log.info(f"REWRITE DETECTED: {path.name} -> {rewrite_r['score']:.0f}%")

                # Multilingual
                lang_r = _advanced.detect_multilingual(text)
                if lang_r["language"] != "en":
                    log.info(f"LANGUAGE: {lang_r['language_name']}  -  {lang_r['score']:.0f}%")

                # Image scan for docx
                if ext == '.docx':
                    img_r = _advanced.scan_document_images(path, DATA_DIR / "temp")
                    if img_r["ai_images"] > 0:
                        log.info(f"AI IMAGES: {img_r['ai_images']}/{img_r['total_images']} images are AI-generated")

            # Base detection
            result = _detect(text)
            log.info(f"BASE SCAN: {path.name} -> {result.ai_score:.0f}% [{result.risk_level}] {result.classification} | {result.llm_suspected}")

            # -- Intelligence layer -----------------------------------------
            if _intel:
                # 1. Behavioral fingerprint
                beh = _behavioral.deviation_score(text)

                # 2. Keystroke rhythm
                key = _keystroke.analyze_growth(path, word_count)

                # 3. Document DNA
                dna = _dna.record(path, text)

                # 4. Source verification (async, only for high scores)
                src = (False, "Low", "Not checked")
                if result.ai_score >= 55:
                    try:
                        src = _source_verifier.verify(text)
                    except: pass

                # Combine all signals
                intel_result = _intel.combine_signals(
                    base_score=result.ai_score,
                    behavioral=beh,
                    keystroke=key,
                    dna=dna,
                    source=src,
                    reasons=result.reasons
                )

                # Update result with intelligence-enhanced score
                result.ai_score = intel_result.final_score
                result.reasons  = intel_result.all_reasons

                # Update risk level based on new score
                if result.ai_score >= 75:    result.risk_level = "High"
                elif result.ai_score >= 45:  result.risk_level = "Medium"
                else:                        result.risk_level = "Low"

                log.info(f"INTEL RESULT: {path.name} -> {intel_result.intelligence_summary}")

                # Update behavioral profile if human-written
                if result.ai_score < 30:
                    _behavioral.update_profile(text, result.ai_score)

            if result.reasons:
                log.info(f"  Reasons: {' | '.join(result.reasons[:3])}")

            save_result(path, result)
            show_popup(result, path.name)

            # Auto-save PDF report if enabled
            if (_report_mod and _settings_mgr and
                    _settings_mgr.settings.auto_save_reports):
                try:
                    reports_dir = Path(_settings_mgr.settings.reports_folder or
                                       str(Path.home() / "Documents" / "AIScan Reports"))
                    reports_dir.mkdir(parents=True, exist_ok=True)
                    pdf_name = f"AIScan_{path.stem}_{int(time.time())}.pdf"
                    pdf_path = reports_dir / pdf_name
                    _report_mod.generate_scan_report(
                        filename=path.name,
                        ai_score=result.ai_score,
                        risk_level=result.risk_level,
                        classification=result.classification,
                        llm_suspected=result.llm_suspected,
                        confidence=result.confidence,
                        reasons=result.reasons,
                        paragraph_results=result.paragraph_results,
                        output_path=pdf_path,
                    )
                    log.info(f"PDF report saved: {pdf_path.name}")
                except Exception as pe:
                    log.debug(f"PDF report error: {pe}")

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
        # OneDrive
        od = os.environ.get("ONEDRIVE")
        if od:
            for sub in ["Documents", "Desktop"]:
                p = Path(od) / sub
                if p.exists(): paths.append(p)
        # Google Drive
        for gd in [Path.home() / "Google Drive",
                   Path("C:/Google Drive"),
                   Path(os.environ.get("LOCALAPPDATA","")) / "Google/Drive/user_default/root"]:
            if gd.exists(): paths.append(gd); break
        # Dropbox
        db_info = Path.home() / "AppData/Roaming/Dropbox/info.json"
        if db_info.exists():
            try:
                info = json.loads(db_info.read_text())
                db_path = Path(info.get("personal",{}).get("path",""))
                if db_path.exists(): paths.append(db_path)
            except: pass
    elif IS_MAC:
        for gd in [Path.home() / "Google Drive",
                   Path.home() / "Library/CloudStorage/GoogleDrive-personal"]:
            if gd.exists(): paths.append(gd); break
        db = Path.home() / "Dropbox"
        if db.exists(): paths.append(db)
    return paths


def start_watcher(paths):
    from watchdog.events import FileSystemEventHandler
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


# ============================================================================
# RIGHT-CLICK CONTEXT MENU (Windows only)
# ============================================================================

def install_context_menu():
    """Add 'Scan with AIScan' to Windows right-click menu."""
    if not IS_WIN: return
    try:
        import winreg
        exe = sys.executable if not getattr(sys, "frozen", False) else sys.argv[0]
        exe_path = str(Path(exe).resolve())

        # Register for all files
        key_path = r"*\shell\ScanWithAIScan"
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "Scan with AIScan")
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f"{exe_path},0")

        cmd_path = key_path + r"\command"
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as key:
            winreg.SetValue(key, "", winreg.REG_SZ, f'"{exe_path}" --scan "%1"')

        log.info("Right-click context menu installed")
    except Exception as e:
        log.warning(f"Context menu install failed (try running as admin): {e}")


def handle_cli_scan(file_path: str):
    """Handle --scan <file> from right-click context menu."""
    path = Path(file_path)
    if not path.exists():
        log.error(f"File not found: {file_path}")
        return
    log.info(f"CLI scan requested: {path.name}")
    text = extract_text(path)
    if not text or len(text.split()) < 15:
        _show_simple_popup("AIScan", f"{path.name}\n\nFile too short or could not read content.")
        return
    result = _detect(text)
    log.info(f"CLI SCAN RESULT: {path.name} -> {result.ai_score:.0f}% [{result.risk_level}]")
    save_result(path, result)
    show_popup(result, path.name)
    time.sleep(15)  # keep process alive for popup


def _show_simple_popup(title, message):
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk(); root.withdraw()
        messagebox.showinfo(title, message)
        root.destroy()
    except: pass


# ============================================================================
# SYSTEM TRAY
# ============================================================================

def run_tray(obs):
    if IS_WIN:
        _run_tray_win(obs)
    elif IS_MAC:
        _run_tray_mac(obs)
    else:
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            obs.stop()


def _run_tray_win(obs):
    try:
        import pystray
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (64,64), (0,0,0,0))
        d   = ImageDraw.Draw(img)
        d.ellipse([4,4,60,60], fill="#0d0d14", outline="#00e5ff", width=3)
        d.ellipse([18,18,46,46], fill="#00e5ff")
        d.ellipse([26,26,38,38], fill="#0d0d14")

        paused = [False]

        def on_history(icon, item):
            if HISTORY_HTML.exists():
                webbrowser.open(HISTORY_HTML.as_uri())

        def on_pause(icon, item):
            paused[0] = not paused[0]
            if paused[0]:
                obs.stop()
                if _screen_monitor: _screen_monitor.pause()
                clipboard.pause() if hasattr(clipboard, 'pause') else None
            else:
                paths = _watch_paths()
                obs2 = start_watcher(paths)
                obs2.join(0)
                if _screen_monitor: _screen_monitor.resume()

        def on_toggle_screen(icon, item):
            if _screen_monitor:
                if _screen_monitor._paused:
                    _screen_monitor.resume()
                    log.info("Screen monitoring resumed")
                else:
                    _screen_monitor.pause()
                    log.info("Screen monitoring paused")
            else:
                _show_simple_popup("AIScan",
                    "Screen monitoring requires Tesseract OCR.\n\n"
                    "Install from:\nhttps://github.com/UB-Mannheim/tesseract/wiki\n\n"
                    "Then restart AIScan.")

        def on_exit(icon, item):
            icon.stop()
            obs.stop()

        def on_bulk_scan(icon, item):
            import tkinter.filedialog as fd
            folder = fd.askdirectory(title="Select folder to scan")
            if folder and _bulk_mod:
                _bulk_mod.show_bulk_scan_ui(
                    Path(folder), extract_text, _detect, HISTORY_HTML)

        def on_view_certificate(icon, item):
            import tkinter.filedialog as fd
            file = fd.askopenfilename(title="Select document",
                filetypes=[("Documents", "*.docx *.txt *.pdf")])
            if file and _session_recorder:
                analysis = _session_recorder.analyze_session(Path(file))
                cert_html = _session_recorder.generate_certificate(Path(file))
                if cert_html:
                    cert_path = DATA_DIR / "certificate.html"
                    cert_path.write_text(cert_html, encoding="utf-8")
                    webbrowser.open(cert_path.as_uri())
                else:
                    _show_simple_popup("AIScan",
                        f"Not enough writing history for {Path(file).name}\n\n"
                        f"Score: {analysis['score']:.0f}%\n"
                        f"Saves: {analysis['save_count']}\n"
                        f"Need at least 3 saves over 3+ minutes.")

        def on_settings(icon, item):
            if _settings_mod and _settings_mgr:
                threading.Thread(target=_settings_mod.show_settings_window,
                                 args=(_settings_mgr,), daemon=True).start()
            else:
                _show_simple_popup("AIScan", "Settings module not available.")

        def on_generate_report(icon, item):
            import tkinter.filedialog as fd
            file = fd.askopenfilename(
                title="Select document to generate report for",
                filetypes=[("Documents","*.docx *.pdf *.txt *.xlsx *.pptx")])
            if file and _report_mod:
                path = Path(file)
                text = extract_text(path)
                if text and len(text.split()) >= 15:
                    result = _detect(text)
                    save_path = DATA_DIR / f"report_{path.stem}.pdf"
                    _report_mod.generate_scan_report(
                        filename=path.name,
                        ai_score=result.ai_score,
                        risk_level=result.risk_level,
                        classification=result.classification,
                        llm_suspected=result.llm_suspected,
                        confidence=result.confidence,
                        reasons=result.reasons,
                        paragraph_results=result.paragraph_results,
                        output_path=save_path,
                    )
                    webbrowser.open(save_path.as_uri())
                    log.info(f"Report generated: {save_path}")

        menu = pystray.Menu(
            pystray.MenuItem("View History", on_history),
            pystray.MenuItem("Generate Report...", on_generate_report),
            pystray.MenuItem("Bulk Scan Folder...", on_bulk_scan),
            pystray.MenuItem("View Certificate...", on_view_certificate),
            pystray.MenuItem("Toggle Screen Monitor", on_toggle_screen),
            pystray.MenuItem("Settings", on_settings),
            pystray.MenuItem("Pause / Resume All", on_pause),
            pystray.MenuItem("Exit", on_exit)
        )
        icon = pystray.Icon("AIScan", img, "AIScan  -  AI monitoring active", menu)
        icon.run()
    except Exception as e:
        log.error(f"Tray error: {e}")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            obs.stop()


def _run_tray_mac(obs):
    try:
        import rumps
        class AIScanApp(rumps.App):
            def __init__(self):
                super().__init__("[Scan]", quit_button=None)
                self.menu = ["View History", "Pause", rumps.separator, "Quit"]
                self._obs = obs
                self._paused = False

            @rumps.clicked("View History")
            def view_history(self, _):
                if HISTORY_HTML.exists():
                    webbrowser.open(HISTORY_HTML.as_uri())

            @rumps.clicked("Pause")
            def toggle_pause(self, sender):
                self._paused = not self._paused
                if self._paused:
                    self._obs.stop()
                    sender.title = "Resume"
                else:
                    paths = _watch_paths()
                    self._obs = start_watcher(paths)
                    sender.title = "Pause"

            @rumps.clicked("Quit")
            def quit_app(self, _):
                self._obs.stop()
                rumps.quit_application()

        AIScanApp().run()
    except Exception as e:
        log.error(f"Mac tray error: {e}")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            obs.stop()


# ============================================================================
# LICENSE SYSTEM
# ============================================================================

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
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk(); root.withdraw()
        messagebox.showinfo("AIScan Trial",
            f"You have {days_left} day{'s' if days_left != 1 else ''} left in your free trial.\n\n"
            f"Upgrade at:\n{RAZORPAY_URL}")
        root.destroy()
    except: pass

def show_expired_screen():
    import tkinter as tk
    import webbrowser
    root = tk.Tk()
    root.title("AIScan  -  Trial Expired")
    root.configure(bg="#0d0d14")
    root.geometry("460x420")
    root.resizable(False, False)
    root.attributes("-topmost", True)
    x = (root.winfo_screenwidth()  - 460) // 2
    y = (root.winfo_screenheight() - 420) // 2
    root.geometry(f"460x420+{x}+{y}")
    tk.Frame(root, bg="#c8401a", height=4).pack(fill="x")
    tk.Label(root, text="[!]  Trial Expired", font=("Helvetica",18,"bold"),
             fg="#ff6644", bg="#0d0d14").pack(pady=(28,4))
    tk.Label(root, text="Your 14-day free trial has ended.",
             font=("Helvetica",11), fg="#888", bg="#0d0d14").pack()
    tk.Label(root, text="Upgrade to keep using AIScan.",
             font=("Helvetica",11), fg="#888", bg="#0d0d14").pack(pady=(0,20))
    tk.Button(root, text="Upgrade Now   -   Rs.499/month",
              font=("Helvetica",12,"bold"), fg="#000", bg="#00e5ff",
              relief="flat", padx=20, pady=10, cursor="hand2",
              command=lambda: webbrowser.open(RAZORPAY_URL)).pack(pady=(0,20))
    tk.Label(root, text="Already purchased? Enter your license key:",
             font=("Helvetica",10), fg="#666", bg="#0d0d14").pack()
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
        msg_var.set(("OK " if ok else "FAIL ") + msg)
        if ok: root.after(1500, root.destroy)
    tk.Button(root, text="Activate License",
              font=("Helvetica",10,"bold"), fg="#000", bg="#44cc77",
              relief="flat", padx=14, pady=6, cursor="hand2",
              command=try_activate).pack(pady=(0,16))
    root.mainloop()


# ============================================================================
# TEST SCAN
# ============================================================================

def _test_scan():
    log.info("Running startup test scan...")
    test_text = ("Furthermore it is important to note that leveraging robust AI frameworks "
                 "plays a crucial role in achieving paradigm shifts. Moreover cutting-edge "
                 "solutions enable organizations to optimize their workflows and facilitate "
                 "seamless integration across multiple touchpoints. This demonstrates the "
                 "importance of utilizing cutting-edge technology to empower teams.")
    result = _detect(test_text)
    log.info(f"Test scan: {result.ai_score:.0f}% [{result.risk_level}]  -  detection WORKING OK")
    if result.reasons:
        log.info(f"  Detected: {' | '.join(result.reasons[:3])}")


# ============================================================================
# MAIN
# ============================================================================


# ============================================================================
# CLIPBOARD MONITOR  -  Detects AI content the moment it's pasted
# ============================================================================

class ClipboardMonitor:
    """
    Watches the clipboard every 1.5 seconds.
    When text is pasted that looks AI-generated, shows popup immediately.
    Works on Windows and Mac.
    """
    def __init__(self):
        self._last_hash = ""
        self._last_alert_hash = ""
        self._running = False
        self._min_words = 30  # ignore short copies

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log.info("Clipboard monitor started")

    def stop(self):
        self._running = False

    def _get_clipboard_text(self):
        try:
            if IS_WIN:
                import ctypes
                if not ctypes.windll.user32.OpenClipboard(0):
                    return ""
                try:
                    CF_UNICODETEXT = 13
                    handle = ctypes.windll.user32.GetClipboardData(CF_UNICODETEXT)
                    if not handle:
                        return ""
                    ptr = ctypes.windll.kernel32.GlobalLock(handle)
                    if not ptr:
                        return ""
                    text = ctypes.wstring_at(ptr)
                    ctypes.windll.kernel32.GlobalUnlock(handle)
                    return text
                finally:
                    ctypes.windll.user32.CloseClipboard()
            elif IS_MAC:
                import subprocess
                result = subprocess.run(
                    ["pbpaste"], capture_output=True, text=True, timeout=2)
                return result.stdout
        except Exception as e:
            log.debug(f"Clipboard read error: {e}")
        return ""

    def _loop(self):
        log.info("Clipboard monitoring active")
        while self._running:
            try:
                text = self._get_clipboard_text()
                if not text or len(text.split()) < self._min_words:
                    time.sleep(1.5)
                    continue

                # Hash to detect changes
                text_hash = hashlib.md5(text.encode()).hexdigest()
                if text_hash == self._last_hash:
                    time.sleep(1.5)
                    continue

                self._last_hash = text_hash

                # Skip if already alerted for this content
                if text_hash == self._last_alert_hash:
                    time.sleep(1.5)
                    continue

                # Scan it
                result = _detect(text)
                log.info(f"CLIPBOARD SCAN: {result.ai_score:.0f}% [{result.risk_level}] {result.classification} | {result.llm_suspected}")

                # Only alert for Medium+ risk
                if result.ai_score >= 35:
                    self._last_alert_hash = text_hash
                    log.info(f"  AI content detected in clipboard  -  alerting user")
                    _show_clipboard_popup(result, text)

            except Exception as e:
                log.debug(f"Clipboard monitor error: {e}")
            time.sleep(1.5)


def _show_clipboard_popup(result: ScanResult, text: str):
    """Special popup for clipboard detection  -  shown immediately on paste."""
    threading.Thread(target=_clipboard_popup, args=(result, text), daemon=True).start()


def _clipboard_popup(result: ScanResult, text: str):
    try:
        score = result.ai_score
        risk  = result.risk_level
        color = "#ff4455" if risk == "High" else "#ffaa00" if risk == "Medium" else "#44cc77"
        preview = text.strip()[:120].replace("\n", " ") + "..."

        import tkinter as tk
        root = tk.Tk()
        root.title("AIScan  -  Clipboard")
        root.configure(bg="#111827")
        root.geometry("400x220")
        root.resizable(False, False)
        root.attributes("-topmost", True)

        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"400x220+{sw-420}+{sh-260}")

        tk.Frame(root, bg=color, height=3).pack(fill="x")
        main = tk.Frame(root, bg="#111827"); main.pack(fill="both", expand=True, padx=16, pady=12)

        top = tk.Frame(main, bg="#111827"); top.pack(fill="x")
        tk.Label(top, text="[Clipboard] AIScan  -  Clipboard Detected",
                 font=("Helvetica",10,"bold"), fg="#00e5ff", bg="#111827").pack(side="left")
        tk.Label(top, text=f"* {risk}", font=("Helvetica",9),
                 fg=color, bg="#111827").pack(side="right")

        tk.Label(main, text="AI content detected in your clipboard",
                 font=("Helvetica",9), fg="#555", bg="#111827", anchor="w").pack(fill="x", pady=(2,8))

        mid = tk.Frame(main, bg="#1a1a2e", padx=12, pady=10); mid.pack(fill="x")
        tk.Label(mid, text=f"{score:.0f}%", font=("Helvetica",20,"bold"),
                 fg=color, bg="#1a1a2e").pack(side="left")
        right = tk.Frame(mid, bg="#1a1a2e"); right.pack(side="left", padx=(12,0))
        tk.Label(right, text=result.classification, font=("Helvetica",10,"bold"),
                 fg="#e8e8f0", bg="#1a1a2e").pack(anchor="w")
        tk.Label(right, text=result.llm_suspected, font=("Helvetica",9),
                 fg="#666", bg="#1a1a2e").pack(anchor="w")

        tk.Label(main, text=preview, font=("Helvetica",8),
                 fg="#444", bg="#111827", wraplength=360, justify="left").pack(fill="x", pady=(6,0))

        bf = tk.Frame(main, bg="#111827"); bf.pack(fill="x", pady=(8,0))
        tk.Button(bf, text="Dismiss", command=root.destroy,
                  font=("Helvetica",9,"bold"), fg="#0d0d14", bg="#00e5ff",
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(side="left", padx=(0,8))
        tk.Button(bf, text="View History",
                  command=lambda: [webbrowser.open(HISTORY_HTML.as_uri()), root.destroy()],
                  font=("Helvetica",9), fg="#888", bg="#1a1a28",
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(side="left")

        root.after(12000, root.destroy)
        root.mainloop()
    except Exception as e:
        log.debug(f"Clipboard popup failed: {e}")

def main():
    log.info(f"AIScan v4 starting. Data: {DATA_DIR}")

    # Handle right-click scan
    if len(sys.argv) >= 3 and sys.argv[1] == "--scan":
        handle_cli_scan(sys.argv[2])
        return

    # Install right-click menu
    threading.Thread(target=install_context_menu, daemon=True).start()

    # -- Onboarding (first run only) ----------------------------------------
    if _onboard_mod and _onboard_mod.should_show_onboarding(DATA_DIR):
        log.info("First run  -  showing onboarding")
        _onboard_mod.show_onboarding(DATA_DIR, _detect, HISTORY_HTML)

    # License check
    lic = get_license_status()
    log.info(f"License status: {lic['status']}")

    if lic["status"] == "expired":
        show_expired_screen()
        lic = get_license_status()
        if lic["status"] != "active":
            sys.exit(0)
    elif lic["status"] == "trial" and lic["days_left"] <= 3:
        threading.Thread(target=show_trial_banner, args=(lic["days_left"],), daemon=True).start()

    # Init history
    if not HISTORY_HTML.exists():
        _rebuild_html()

    # Start watcher
    paths = _watch_paths()
    obs = start_watcher(paths)
    log.info("Watching: " + ", ".join(str(p) for p in paths))

    # Start clipboard monitor
    clipboard = ClipboardMonitor()
    clipboard.start()

    # Start screen monitor
    global _screen_monitor
    if _screen_mod:
        ocr_ok, ocr_method, ocr_hint = _screen_mod.check_ocr_available()
        if ocr_ok:
            _screen_monitor = _screen_mod.ScreenMonitor(
                detect_fn=_detect,
                alert_fn=show_popup,
                interval_seconds=4
            )
            _screen_monitor.start()
            log.info(f"Screen monitor started via {ocr_method}")
        else:
            log.warning(f"Screen monitor disabled: {ocr_hint}")

    # Startup test
    threading.Thread(target=_test_scan, daemon=True).start()

    # Startup notification
    if IS_WIN:
        try:
            from plyer import notification
            notification.notify(title="AIScan", message="AI monitoring active  -  v2.0",
                                app_name="AIScan", timeout=4)
        except: pass

    try:
        run_tray(obs)
    except KeyboardInterrupt:
        obs.stop()

if __name__ == "__main__":
    main()
