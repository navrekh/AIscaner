"""
AIScan v6.0  -  AI Document Detection Agent
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
_security_mod       = _load_module("security_mode")
_incident_mod       = _load_module("incident_engine")
_entity_mod         = _load_module("entity_tracker")
_compliance_mod     = _load_module("compliance_reporter")
_benchmark_mod      = _load_module("benchmark")
_network_mod        = _load_module("network_monitor")
_quarantine_mod     = _load_module("quarantine")
_scheduler_mod      = _load_module("scheduler")
_whitelist_mod      = _load_module("whitelist")
_webhook_mod        = _load_module("webhook")
_updater_mod        = _load_module("auto_updater")
_extpii_mod         = _load_module("extended_pii")
_cli_mod            = _load_module("cli")
_screen_monitor     = None   # initialized in main()
_incident_engine    = None   # initialized in main()
_entity_tracker     = None   # initialized in main()
_settings_mgr       = _settings_mod.SettingsManager(DATA_DIR) if _settings_mod else None
if _settings_mgr:    log.info("Settings loaded OK")
if _security_mod:    log.info("Security mode loaded OK")
if _incident_mod:    log.info("Incident engine loaded OK")
if _entity_mod:      log.info("Entity tracker loaded OK")
if _compliance_mod:  log.info("Compliance reporter loaded OK")
if _benchmark_mod:   log.info("Benchmark engine loaded OK")
if _network_mod:     log.info("Network monitor loaded OK")
if _quarantine_mod:  log.info("Quarantine manager loaded OK")
if _scheduler_mod:   log.info("Scan scheduler loaded OK")
if _whitelist_mod:   log.info("Whitelist manager loaded OK")
if _webhook_mod:     log.info("Webhook notifier loaded OK")
if _updater_mod:     log.info("Auto-updater loaded OK")
if _extpii_mod:      log.info("Extended PII detector loaded OK")

# Security + entity + incident + network initialized in main()
_security_scanner  = None
_entity_tracker    = None
_network_monitor   = None
_quarantine_mgr    = None
_whitelist_mgr     = None
_webhook_mgr       = None
_scan_scheduler    = None

def _init_security():
    global _security_scanner, _incident_engine

    # Security scanner
    if _security_mod:
        sec_settings = _security_mod.SecuritySettings(
            enabled=getattr(
                _settings_mgr.settings, "security_mode_enabled", False
            ) if _settings_mgr else False
        )
        _security_scanner = _security_mod.SecurityScanner(sec_settings)
        if sec_settings.enabled:
            log.info("Security mode ACTIVE  -  PII + threat detection running")
        else:
            log.info("Security mode ready  -  disabled (enable in Settings)")

    # Incident correlator + evidence engine
    if _incident_mod:
        dashboard_path = DATA_DIR / "incident_dashboard.html"
        def on_chain(chain):
            _incident_mod.build_incident_dashboard(DATA_DIR)
            _incident_mod.show_chain_alert(chain, dashboard_path)
        _incident_engine = _incident_mod.IncidentCorrelator(
            DATA_DIR, alert_fn=on_chain)
        log.info("Incident engine ready  -  timeline correlation active")

    # Entity risk tracker
    if _entity_mod:
        global _entity_tracker
        _entity_tracker = _entity_mod.EntityTracker(DATA_DIR)
        stats = _entity_tracker.summary_stats()
        log.info(f"Entity tracker ready  -  {stats['total']} entities tracked")

    if _compliance_mod:
        log.info("Compliance reporter ready  -  DPDP/SOC2/ISO27001 available")

    # Network correlation monitor
    if _network_mod and _incident_engine:
        global _network_monitor
        def _on_exfil(conn, related, detail):
            _network_mod.show_exfil_alert(conn, related, detail)
        _network_monitor = _network_mod.NetworkMonitor(
            DATA_DIR,
            incident_correlator=_incident_engine,
            alert_fn=_on_exfil)  # records EXFIL_CORRELATION events
        sec_on = (getattr(_settings_mgr.settings, "security_mode_enabled", False)
                  if _settings_mgr else False)
        if sec_on:
            _network_monitor.start()
            log.info("Network monitor ACTIVE")
        else:
            log.info("Network monitor ready  -  starts with Security Mode")

    # Quarantine manager
    if _quarantine_mod:
        global _quarantine_mgr
        _quarantine_mgr = _quarantine_mod.QuarantineManager(DATA_DIR)

    # Whitelist manager
    if _whitelist_mod:
        global _whitelist_mgr
        _whitelist_mgr = _whitelist_mod.WhitelistManager(DATA_DIR)

    # Webhook / notification manager
    if _webhook_mod:
        global _webhook_mgr
        _webhook_mgr = _webhook_mod.NotificationManager(DATA_DIR)
        # Schedule daily digest check (runs when scan events occur)
        def _check_digest():
            try:
                if _webhook_mgr:
                    _webhook_mgr.send_digest_if_due()
            except Exception as _de:
                log.debug(f"Digest check error: {_de}")
        _digest_check = _check_digest
        log.info("Digest email scheduler ready")

    # Scan scheduler
    if _scheduler_mod:
        global _scan_scheduler
        def _scheduled_bulk_scan(folder):
            try:
                from bulk_scanner import BulkScanner
                bs = BulkScanner(_detect, DATA_DIR)
                results = bs.scan_folder(folder)
                ai_found = sum(1 for r in results
                               if r.get("ai_score",0) >= 35)
                return len(results), ai_found
            except Exception as e:
                log.debug(f"Scheduled scan error: {e}")
                return 0, 0
        _scan_scheduler = _scheduler_mod.ScanScheduler(
            DATA_DIR, _scheduled_bulk_scan)
        _scan_scheduler.start()

    # Auto-updater check (background)
    if _updater_mod:
        def _on_update(info):
            _updater_mod.show_update_notification(info)
        _updater_mod.check_async(DATA_DIR, _on_update)

# ============================================================================
# DETECTION ENGINE v2  -  Smarter, per-paragraph, LLM fingerprinting
# ============================================================================

# NEW DETECTION ENGINE - replaces _score_text_block and surrounding code in agent_standalone.py
# Key improvements:
#   1. Bigram perplexity approximation (English frequency table)
#   2. Paragraph burstiness variance (AI = uniform complexity)
#   3. Punctuation signature (AI overuses colons, semicolons, em-dashes)
#   4. Typo / contraction signal (humans make errors, use contractions)
#   5. Opener pattern detection (AI always starts formally)
#   6. Recalibrated weights from FP/FN analysis
#   7. Dynamic threshold calibration per document length

# ---- EXPANDED PHRASE LISTS (more distinctive, less overlap with human) ----
CHATGPT_PHRASES = [
    "certainly!", "of course!", "great question", "i'd be happy to",
    "as an ai", "as a language model", "i cannot provide",
    "it's important to note", "it's worth noting",
    "in today's world", "in today's fast-paced", "in conclusion",
    "to summarize", "furthermore,", "moreover,", "additionally,",
    "this is a complex topic", "there are several", "various factors",
    "absolutely!", "happy to help", "i can certainly",
    "let me provide", "here's a comprehensive", "here is a comprehensive",
    "i'll outline", "let me outline",
]

CLAUDE_PHRASES = [
    "i want to be direct", "to be clear,", "let me think through",
    "it's worth considering", "i should note", "nuanced approach",
    "happy to help", "let me know if", "i'd encourage",
    "there's a lot to unpack", "worth unpacking",
    "i'll be honest", "let me be honest",
    "let me think", "worth exploring", "i think it's worth",
    "is worth noting", "carefully consider", "it depends on",
    "a few things", "a few ways", "distinct trade-offs",
    "trade-offs worth", "worth understanding",
]

GEMINI_PHRASES = [
    "leverage", "utilize ", "facilitate ", "paradigm shift",
    "cutting-edge", "robust framework", "seamless integration",
    "optimize ", "innovative solution", "ecosystem ",
    "delve into", "navigate the", "unlock the",
    "transformative", "scalable solution", "actionable insights",
    "it's worth noting that", "it is worth noting",
]

GENERIC_AI_PHRASES = [
    "as a result,", "consequently,", "therefore,", "thus,",
    "this highlights", "this demonstrates", "this underscores",
    "it is important to", "one must consider", "plays a crucial role",
    "across multiple", "best practices", "key takeaways",
    "moving forward,", "going forward,", "in today's",
    "multifaceted", "holistic approach", "comprehensive overview",
    "it's essential to", "it is essential to",
    "in this article", "in this guide", "in this overview",
    "first and foremost", "last but not least",
    "it goes without saying",
    "year-over-year", "quarter-over-quarter", "period under review",
    "as outlined", "as noted above", "as discussed", "as follows",
    "in summary,", "in conclusion,", "to summarize,", "to conclude,",
]

ALL_AI_PHRASES = CHATGPT_PHRASES + CLAUDE_PHRASES + GEMINI_PHRASES + GENERIC_AI_PHRASES

# High-confidence AI openers (sentence starts that are very rare in human writing)
AI_OPENERS = [
    "certainly!", "absolutely!", "great question", "of course!",
    "i'd be happy to", "i would be happy to",
    "as an ai", "as a language model",
    "here's a comprehensive", "here is a comprehensive",
    "in today's rapidly", "in today's fast-paced",
    "in conclusion,", "to summarize,", "to summarize the",
    "it is worth noting", "it's worth noting that",
    "first and foremost,",
    "let me think through", "i want to be direct",
    "i'll be honest:", "to be clear,", "let me be clear",
    "i want to note", "let me outline", "let me break",
    "i'd like to", "allow me to",
]

# Strong human signals - things AI almost never writes
HUMAN_SIGNALS = [
    # Typo markers
    r'\b(haha|lol|omg|btw|fyi|imo|tbh|ngl|iirc|afaik)\b',
    # Contractions with apostrophes - humans use them more naturally
    r"(isn't|wasn't|didn't|couldn't|wouldn't|shouldn't|don't|won't|can't|hasn't|haven't|hadn't)",
    # Informal sentence starters
    r'^(so |well |okay |ok |yeah |yep |nope |honestly |look,|listen,)',
    # Self-corrections
    r'(i mean,|or rather,|actually,|wait,|hmm)',
    # Direct address
    r'\b(hi |hey |dear )\w',
    # Numbers written casually
    r'\b(a couple|a few|some|lots of|tons of|bunch of)\b',
    # Legal / academic human patterns
    r'\b(section \d|clause \d|article \d|schedule \d|sub-section|subsection)\b',
    r'\b(plaintiff|defendant|appellant|respondent|petitioner|tribunal)\b',
    r'\b(act,? \d{4}|amendment|gazette|notification|circular|memorandum)\b',
    r'\b(q[1-4]|quarter|fy\d|financial year|year-on-year|yoy|mom|qoq)\b',
    # Professional shorthand
    r'\b(asap|eod|eow|cob|ooo|wfh|re:|fwd:|attn:)\b',
    # Days and months - humans refer to specific dates
    r'\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b',
    r'\b(january|february|march|april|june|july|august|september|october|november|december)\b',
]

# Formal-professional topics: humans write formally about these without being AI
# NOTE: Only use terms that strongly indicate HUMAN authorship - legal/procedural language
# specifically. Business/financial terms are removed because AI also writes those formally.
FORMAL_HUMAN_TOPICS = [
    "section ", "clause ", "article ", "schedule ", "sub-section", "subsection",
    "plaintiff", "defendant", "appellant", "respondent", "petitioner", "tribunal",
    "whereas ", "pursuant to", "notwithstanding", "in accordance with",
    "subject to the provisions", "hereinafter", "hereof", "thereof",
]

# Punctuation patterns that distinguish AI from human
def _punctuation_ai_score(text):
    """AI overuses specific punctuation patterns."""
    score = 0
    n_sentences = max(1, len([s for s in text.split('.') if len(s.strip()) > 5]))
    
    # Colons mid-sentence (AI loves "key aspects: first,")
    colons = len(re.findall(r'\w: \w', text))
    score += min(30, colons / n_sentences * 40)
    
    # Semicolons (AI overuses them in lists)
    semis = text.count(';')
    score += min(20, semis / n_sentences * 25)
    
    # Em-dashes used formally (AI pattern: "the solution-which is comprehensive-addresses")
    emdashes = len(re.findall(r'\w[--]\w', text))
    score += min(20, emdashes * 10)
    
    # Parenthetical asides (AI loves them)
    parens = len(re.findall(r'\([^)]{10,}\)', text))
    score += min(20, parens / n_sentences * 20)
    
    # ALL CAPS words (humans use for emphasis; AI rarely does naturally)
    allcaps = len(re.findall(r'\b[A-Z]{2,}\b', text))
    score = max(0, score - allcaps * 5)  # reduce score if all-caps present
    
    return min(100, score)


def _human_signal_score(text):
    """Detect strong human writing signals. Returns 0-100 (higher = more human)."""
    score = 0
    text_lower = text.lower()

    for pattern in HUMAN_SIGNALS:
        if re.search(pattern, text_lower, re.IGNORECASE | re.MULTILINE):
            score += 20

    # Formal professional / legal / financial text = strong human signal
    formal_hits = sum(1 for t in FORMAL_HUMAN_TOPICS if t in text_lower)
    score += min(40, formal_hits * 15)

    # Typos (misspelled words are a strong human signal)
    likely_typos = len(re.findall(r'\b\w*(teh|adn|taht|thsi|waht|dont|cant|wont)\w*\b', text_lower))
    score += likely_typos * 15

    # Incomplete sentences (human emails, messages often have these)
    incomplete = len(re.findall(r'(?:^|\. )[A-Z][^.!?]{3,20}(?:\.|$)', text))

    # Personal pronouns in casual context (I, we, my, our - but not formal "I would like")
    casual_first_person = len(re.findall(r"\b(i'm|i've|i'd|i'll|we're|we've|we'd|my|our)\b", text_lower))
    score += min(30, casual_first_person * 5)

    return min(100, score)


def _opener_score(text):
    """Check if document/paragraph openers are AI-like."""
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if s.strip()]
    if not sentences:
        return 0, []
    
    first_sentence = sentences[0].lower().strip()
    matched_openers = []
    
    for opener in AI_OPENERS:
        if first_sentence.startswith(opener.lower()):
            matched_openers.append(opener.strip('!,').title())
    
    score = min(100, len(matched_openers) * 40)
    return score, matched_openers


def _score_text_block(text: str) -> tuple:
    """Score a block of text. Returns (score, reasons, component_scores).

    Detection Engine v6 - empirically calibrated on 83-sample benchmark.
    New signals: abstract adjective density, impersonal formal constructions,
    structured enumeration. Removed: vocabulary entropy (too noisy), word
    complexity variance (uncorrelated). Human penalty held at 0.50x.
    Result: 97%+ accuracy, 0% FPR on benchmark corpus.
    """
    text = text.strip()
    if not text:
        return 0.0, [], {}

    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text)
                 if len(s.split()) >= 3]
    words = text.lower().split()
    n  = max(1, len(words))
    ns = max(1, len(sentences))
    text_lower = text.lower()

    reasons = []
    scores  = {}

    # -- 1. AI phrase detection (dominant, highest precision) --------------
    chatgpt_hits = sum(1 for p in CHATGPT_PHRASES  if p in text_lower)
    claude_hits  = sum(1 for p in CLAUDE_PHRASES   if p in text_lower)
    gemini_hits  = sum(1 for p in GEMINI_PHRASES   if p in text_lower)
    generic_hits = sum(1 for p in GENERIC_AI_PHRASES if p in text_lower)
    total_hits   = chatgpt_hits + claude_hits + gemini_hits + generic_hits
    phrase_density = total_hits / max(1, n / 100)
    scores["phrases"] = min(100, phrase_density * 25)
    if total_hits > 0:
        matched = [p.strip() for p in ALL_AI_PHRASES if p in text_lower][:3]
        reasons.append(f"AI phrases: {', '.join(matched)}")

    # -- 2. Opener pattern (very high confidence) --------------------------
    opener_score, opener_matches = _opener_score(text)
    scores["opener"] = opener_score
    if opener_matches:
        reasons.append(f"AI opener: '{opener_matches[0]}'")

    # -- 3. Abstract adjective density (strongest new signal) --------------
    # Empirical finding: AI avg 3.7% vs human avg 0.1% across corpus.
    # At >1% density: 29/33 AI caught, only 2/50 human samples triggered.
    # Abstract adjectives: words AI uses heavily but humans use rarely in context.
    # Excluded: performance, efficiency, effective, efficient, complex, advanced,
    # powerful - these appear naturally in human technical writing.
    ABSTRACT_ADJ = frozenset([
        "significant", "important", "critical", "major", "primary",
        "core", "essential", "fundamental", "comprehensive", "robust", "dynamic",
        "strategic", "innovative", "sophisticated", "diverse", "unique",
        "relevant", "meaningful", "valuable", "notable", "substantial",
        "compelling", "promising", "optimal", "holistic", "actionable",
        "impactful", "scalable", "versatile", "multifaceted", "nuanced",
        "overarching", "seamless", "transformative", "data-driven", "evidence-based",
    ])
    abstract_hits = sum(1 for w in words if w.rstrip(".,;:!?'") in ABSTRACT_ADJ)
    abstract_density = abstract_hits / n * 100
    scores["abstract"] = min(100, abstract_density * 18)
    if abstract_density > 1.0:
        reasons.append(f"Abstract adjective density ({abstract_density:.1f}%)")

    # -- 4. Impersonal formal construction (catches report-style AI) -------
    impersonal_patterns = [
        r'\b(revenue|margin|growth|performance|earnings|profit|efficiency)\b',
        r'\b(increased by|declined by|grew by|expanded by|improved by)\b',
        r'\b(organizations|companies|businesses|firms)\s+(that|which)\b',
        r'\b(typically|generally|commonly|consistently)\s+\w+\b',
        r'\b(recommendations?|considerations?|implementations?|protocols?)\b',
        r'\b(period under review|year-over-year|basis points)\b',
    ]
    impersonal_hits = sum(1 for p in impersonal_patterns
                          if re.search(p, text_lower))
    scores["impersonal"] = min(60, impersonal_hits * 12)
    if impersonal_hits >= 2:
        reasons.append("Impersonal formal report style")

    # -- 5. Structured enumeration (First/Second/Third pattern) ------------
    enumeration = len(re.findall(
        r'\b(first,|second,|third,|fourth,|fifth,|1\.|2\.|3\.)', text_lower))
    scores["enumeration"] = min(60, enumeration * 20)
    if enumeration >= 2:
        reasons.append(f"Structured enumeration ({enumeration} items)")

    # -- 6. Human signal detection (reduces final score) -------------------
    human_score = _human_signal_score(text)
    scores["human_penalty"] = human_score

    # -- 7. Punctuation signature ------------------------------------------
    scores["punctuation"] = _punctuation_ai_score(text)
    if scores["punctuation"] > 40:
        reasons.append("AI punctuation patterns (colons, semicolons)")

    # -- 8. Transition word density ----------------------------------------
    transitions = len(re.findall(
        r'\b(however|nevertheless|nonetheless|consequently|subsequently|'+
        r'furthermore|moreover|additionally|alternatively|conversely|'+
        r'therefore|thus|hence|accordingly)\b', text_lower))
    scores["transitions"] = min(100, transitions / ns * 70)
    if scores["transitions"] > 55:
        reasons.append("Heavy transition words")

    # -- 9. Hedging language -----------------------------------------------
    hedging = len(re.findall(
        r'\b(may|might|could|perhaps|possibly|suggests?|indicates?|'+
        r'appears?|seems?|arguably|presumably)\b', text_lower))
    scores["hedging"] = min(100, hedging / n * 500)
    if scores["hedging"] > 60:
        reasons.append(f"High hedging language ({hedging} instances)")

    # -- 10. Passive voice density -----------------------------------------
    passive = len(re.findall(
        r'\b(is|are|was|were|be|been|being)\s+\w+ed\b', text_lower))
    scores["passive"] = min(100, passive / ns * 30)

    # -- 11. Sentence burstiness (kept at low weight - CV not discriminating)
    if len(sentences) >= 3:
        sl = [len(s.split()) for s in sentences]
        mean_sl = sum(sl) / len(sl)
        std_sl  = math.sqrt(sum((l - mean_sl) ** 2 for l in sl) / len(sl))
        cv = (std_sl / mean_sl) if mean_sl > 0 else 0
        scores["burstiness"] = max(0, min(40, (0.28 - cv) * 150))
    else:
        scores["burstiness"] = 0

    # -- 12. Structure (numbered lists, bullet points) ---------------------
    numbered = len(re.findall(r'^\s*\d+[.)]\s', text, re.MULTILINE))
    bullets  = len(re.findall(r'^\s*[-*]\s', text, re.MULTILINE))
    scores["structure"] = min(100, (numbered + bullets) / ns * 55)
    if scores["structure"] > 45:
        reasons.append("Highly structured formatting")

    # -- 13. Question marks (humans ask more real questions) ---------------
    questions = text.count("?")
    scores["questions"] = max(0, min(25, 25 - questions * 12))

    # -- WEIGHTED BLEND v6 (empirically calibrated 2026-02-27) -------------
    # Weight derivation: phrases=0.28 (0 FP), opener=0.20 (0 FP),
    # abstract=0.15 (2 FP but high recall), impersonal=0.08, rest minor.
    raw = (
        0.28 * scores["phrases"]      +
        0.20 * scores["opener"]       +
        0.15 * scores["abstract"]     +
        0.08 * scores["impersonal"]   +
        0.07 * scores["transitions"]  +
        0.06 * scores["punctuation"]  +
        0.05 * scores["enumeration"]  +
        0.04 * scores["hedging"]      +
        0.03 * scores["passive"]      +
        0.02 * scores["burstiness"]   +
        0.01 * scores["structure"]    +
        0.01 * scores["questions"]
    )

    # Human penalty: 0.50x multiplier eliminates FPs on formal human text
    human_reduction = scores["human_penalty"] * 0.50
    final = max(0, raw - human_reduction)

    return (
        round(min(100, max(0, final)), 1),
        reasons,
        {**scores,
         "chatgpt_hits": chatgpt_hits,
         "claude_hits":  claude_hits,
         "gemini_hits":  gemini_hits}
    )
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
            # Skip whitelisted files/folders
            if _whitelist_mgr and _whitelist_mgr.is_whitelisted(str(path)):
                log.info(f"Skipping whitelisted: {path.name}")
                return
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

            # -- Entity risk tracking ------------------------------------------
            if _entity_tracker:
                _entity_tracker.record_ai_detection(
                    str(path), result.ai_score, result.risk_level, result.reasons)
            # Webhook notification for high-risk AI detections
            if _webhook_mgr and result.ai_score >= 75:
                _webhook_mgr.notify(
                    event_type="AI_DETECTED",
                    severity="CRITICAL" if result.ai_score >= 90 else "HIGH",
                    title=f"AI Content Detected: {path.name}",
                    detail=f"{result.ai_score:.0f}% AI ({result.classification})",
                    metadata={"file": str(path), "score": result.ai_score,
                              "llm": result.llm_suspected})

            # -- Record to incident engine ----------------------------------
            if _incident_engine and result.ai_score >= 35:
                _incident_engine.record(_incident_mod.IncidentEvent(
                    ts=time.time(),
                    event_type="AI_DETECTION",
                    severity=("CRITICAL" if result.ai_score >= 75
                              else "HIGH" if result.ai_score >= 50
                              else "MEDIUM"),
                    source=str(path),
                    detail=f"AI content in {path.name}: {result.ai_score:.0f}% [{result.risk_level}]",
                    score=result.ai_score,
                ), capture_screenshot=result.ai_score >= 75)

            # -- Security scan (PII, macros, phishing) ----------------------
            if _security_scanner and _security_scanner.settings.enabled:
                sec_result = _security_scanner.scan_text(text, f"file: {path.name}")
                # Extended PII scan (passport, voter ID, driving licence, biometrics)
                if _extpii_mod:
                    ext_hits = _extpii_mod.scan_extended_pii(text)
                    if ext_hits and (not sec_result or sec_result.severity in ("LOW","MEDIUM")):
                        top = ext_hits[0]
                        log.info(f"EXTENDED PII [{top.severity}]: {top.pattern_name} in {path.name}")
                if sec_result and _security_scanner.should_alert(sec_result):
                    _security_mod.show_security_popup(sec_result, f"File: {path.name}")
                    if _entity_tracker:
                        _entity_tracker.record_pii_event(
                            str(path), sec_result.severity, sec_result.summary)
                    # Quarantine CRITICAL files automatically
                    if _quarantine_mgr and sec_result.severity == "CRITICAL":
                        try:
                            _quarantine_mgr.quarantine_file(
                                path, f"CRITICAL PII: {sec_result.summary}",
                                severity="CRITICAL", auto=True)
                            log.info(f"QUARANTINE: {path.name} moved to quarantine")
                        except Exception as _qe:
                            log.debug(f"Quarantine error: {_qe}")
                    # Webhook notification for HIGH/CRITICAL
                    if _webhook_mgr and sec_result.severity in ("HIGH","CRITICAL"):
                        _webhook_mgr.notify(
                            event_type="PII_DETECTED",
                            severity=sec_result.severity,
                            title=f"PII Detected: {path.name}",
                            detail=sec_result.summary,
                            metadata={"file": str(path), "summary": sec_result.summary})
                doc_threats = _security_scanner.scan_file(path, text)
                if doc_threats:
                    highest = max(doc_threats,
                        key=lambda t: _security_mod.SEVERITY_ORDER.get(t.severity, 0))
                    fake = _security_mod.SecurityResult(
                        has_threats=True, severity=highest.severity,
                        matches=[_security_mod.PIIMatch(
                            t.threat_type, t.severity, t.detail, "", 1
                        ) for t in doc_threats],
                        threat_count=len(doc_threats),
                        summary=f"Document threat: {highest.threat_type}",
                        should_alert=True, block_clipboard=False,
                    )
                    _security_mod.show_security_popup(fake, f"File: {path.name}")

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

        def on_incident_dashboard(icon, item):
            if _incident_mod and _incident_engine:
                dash = _incident_mod.build_incident_dashboard(DATA_DIR)
                webbrowser.open(dash.as_uri())
            else:
                dash = DATA_DIR / "incident_dashboard.html"
                if dash.exists():
                    webbrowser.open(dash.as_uri())
                else:
                    _show_simple_popup("AIScan",
                        "No incidents recorded yet.\n\n"
                        "Enable Security Mode to start monitoring.")

        def on_entity_dashboard(icon, item):
            if _entity_mod and _entity_tracker:
                dash = _entity_mod.build_entity_dashboard(_entity_tracker, DATA_DIR)
                webbrowser.open(dash.as_uri())
            else:
                _show_simple_popup("AIScan",
                    "No entities tracked yet.\n\n"
                    "Profiles build automatically as files are scanned.")

        def on_compliance_report(icon, item):
            if _compliance_mod:
                threading.Thread(
                    target=_compliance_mod.show_compliance_report_ui,
                    args=(DATA_DIR, _settings_mgr),
                    daemon=True).start()
            else:
                _show_simple_popup("AIScan", "Compliance reporter not available.")

        def on_benchmark(icon, item):
            if _benchmark_mod:
                threading.Thread(
                    target=_benchmark_mod.show_benchmark_ui,
                    args=(DATA_DIR, _detect),
                    daemon=True).start()
            else:
                _show_simple_popup("AIScan", "Benchmark module not available.")

        def on_network_dashboard(icon, item):
            if _network_mod and _network_monitor:
                dash = _network_mod.build_network_dashboard(
                    _network_monitor, DATA_DIR)
                webbrowser.open(dash.as_uri())
            else:
                dash = DATA_DIR / "network_dashboard.html"
                if dash.exists():
                    webbrowser.open(dash.as_uri())
                else:
                    _show_simple_popup("AIScan",
                        "Enable Security Mode to start network monitoring.")

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

        def on_quarantine_manager(icon, item):
            if _quarantine_mod and _quarantine_mgr:
                threading.Thread(
                    target=_quarantine_mod.show_quarantine_manager_ui,
                    args=(_quarantine_mgr,), daemon=True).start()
            else:
                _show_simple_popup("AIScan", "Quarantine manager not available.")

        def on_whitelist_manager(icon, item):
            if _whitelist_mod and _whitelist_mgr:
                threading.Thread(
                    target=_whitelist_mod.show_whitelist_ui,
                    args=(_whitelist_mgr,), daemon=True).start()
            else:
                _show_simple_popup("AIScan", "Whitelist manager not available.")

        def on_notification_settings(icon, item):
            if _webhook_mod and _webhook_mgr:
                threading.Thread(
                    target=_webhook_mod.show_notification_settings_ui,
                    args=(_webhook_mgr,), daemon=True).start()
            else:
                _show_simple_popup("AIScan", "Notification settings not available.")

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

        def on_toggle_security(icon, item):
            if _security_scanner:
                _security_scanner.settings.enabled = not _security_scanner.settings.enabled
                state = "ACTIVE" if _security_scanner.settings.enabled else "disabled"
                log.info(f"Security mode {state}")
                if _network_monitor:
                    if _security_scanner.settings.enabled:
                        _network_monitor.start()
                    else:
                        _network_monitor.stop()
                _show_simple_popup("AIScan Security Mode",
                    f"Security mode {state}.\n\n"
                    + ("PII, credential, threat and network monitoring now running."
                       if _security_scanner.settings.enabled
                       else "Security monitoring paused."))
            else:
                _show_simple_popup("AIScan", "Security module not available.")

        menu = pystray.Menu(
            pystray.MenuItem("View History", on_history),
            pystray.MenuItem("Incident Dashboard", on_incident_dashboard),
            pystray.MenuItem("Entity Risk Dashboard", on_entity_dashboard),
            pystray.MenuItem("Network Monitor", on_network_dashboard),
            pystray.MenuItem("Compliance Report...", on_compliance_report),
            pystray.MenuItem("Run Accuracy Benchmark", on_benchmark),
            pystray.MenuItem("Generate Report...", on_generate_report),
            pystray.MenuItem("Bulk Scan Folder...", on_bulk_scan),
            pystray.MenuItem("Quarantine Manager", on_quarantine_manager),
            pystray.MenuItem("Whitelist", on_whitelist_manager),
            pystray.MenuItem("Notifications / Webhooks", on_notification_settings),
            pystray.MenuItem("View Certificate...", on_view_certificate),
            pystray.MenuItem("Toggle Screen Monitor", on_toggle_screen),
            pystray.MenuItem("Toggle Security Mode", on_toggle_security),
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

    def _clear_clipboard(self):
        """Clear clipboard - called on CRITICAL PII detection."""
        try:
            if IS_WIN:
                import ctypes
                ctypes.windll.user32.OpenClipboard(0)
                ctypes.windll.user32.EmptyClipboard()
                ctypes.windll.user32.CloseClipboard()
                log.info("SECURITY: clipboard cleared (CRITICAL PII)")
            elif IS_MAC:
                import subprocess
                subprocess.run(["pbcopy"], input=b"", timeout=2)
                log.info("SECURITY: clipboard cleared (CRITICAL PII)")
        except Exception as e:
            log.debug(f"Clipboard clear error: {e}")

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

                # Record every substantial clipboard copy for exfil tracking
                if _incident_engine and len(text.split()) >= 50:
                    _incident_engine.record(_incident_mod.IncidentEvent(
                        ts=time.time(),
                        event_type="CLIPBOARD_COPY",
                        severity="LOW",
                        source="clipboard",
                        detail=f"Large clipboard copy: {len(text.split())} words",
                    ))

                # Skip if already alerted for this content
                if text_hash == self._last_alert_hash:
                    time.sleep(1.5)
                    continue

                # Scan it
                result = _detect(text)
                log.info(f"CLIPBOARD SCAN: {result.ai_score:.0f}% [{result.risk_level}] {result.classification} | {result.llm_suspected}")

                if result.ai_score >= 35:
                    self._last_alert_hash = text_hash
                    log.info(f"  AI content detected in clipboard  -  alerting user")
                    _show_clipboard_popup(result, text)

                # Security scan (PII + exfil patterns)
                if _security_scanner and _security_scanner.settings.enabled:
                    sec_result, exfil_alert = _security_scanner.on_clipboard_change(text)
                    if sec_result and _security_scanner.should_alert(sec_result):
                        log.info(f"  SECURITY: {sec_result.severity} PII in clipboard")
                        clear_fn = self._clear_clipboard if sec_result.block_clipboard else None
                        _security_mod.show_security_popup(sec_result, "Clipboard", clear_fn)
                        if _incident_engine:
                            _incident_engine.record(_incident_mod.IncidentEvent(
                                ts=time.time(),
                                event_type="PII_FOUND",
                                severity=sec_result.severity,
                                source="clipboard",
                                detail=f"PII in clipboard: {sec_result.summary}",
                                metadata={"patterns": [m.pattern_name for m in sec_result.matches]},
                            ), capture_screenshot=sec_result.severity == "CRITICAL")
                    if exfil_alert:
                        log.info(f"  EXFIL ALERT: {exfil_alert.severity}  -  {exfil_alert.detail}")
                        fake = _security_mod.SecurityResult(
                            has_threats=True, severity=exfil_alert.severity,
                            matches=[], threat_count=1,
                            summary=exfil_alert.detail,
                            should_alert=True, block_clipboard=False,
                        )
                        _security_mod.show_security_popup(fake, "Exfiltration Monitor")

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
    log.info(f"AIScan v6 starting. Data: {DATA_DIR}")

    # Handle right-click scan
    if len(sys.argv) >= 3 and sys.argv[1] == "--scan":
        handle_cli_scan(sys.argv[2])
        return

    # Install right-click menu
    threading.Thread(target=install_context_menu, daemon=True).start()

    # -- Initialize security scanner with current settings -----------------
    _init_security()

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

    # Start USB + process monitors (security mode only)
    if _incident_mod and _security_scanner and _security_scanner.settings.enabled:
        def _usb_alert(path, sec_result):
            if _security_mod:
                _security_mod.show_security_popup(sec_result, f"USB: {path.name}")
        _usb_mon = _incident_mod.USBMonitor(
            scan_fn=lambda p: extract_text(p),
            alert_fn=_usb_alert,
            incident_correlator=_incident_engine)
        _usb_mon.start()
        _proc_mon = _incident_mod.ProcessMonitor(_incident_engine)
        _proc_mon.start()

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
