"""
AIScan Intelligence Engine v3
4 advanced detection systems:
1. Behavioral Fingerprinting — learns each user's writing style
2. Keystroke Rhythm — detects paste vs typing  
3. Document DNA — tracks file growth patterns
4. Source Verification — searches web for exact AI phrases
"""
import json, time, math, re, hashlib, threading, logging
from pathlib import Path
from collections import Counter, deque
from dataclasses import dataclass, field

log = logging.getLogger("aiscan")


# ════════════════════════════════════════════════════════════════════════════
# 1. BEHAVIORAL FINGERPRINTING
# Learns each user's personal writing style over time.
# Alerts when a document deviates from THEIR normal baseline.
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class WritingProfile:
    """Personal writing baseline for one user."""
    sample_count: int = 0
    avg_sentence_length: float = 15.0
    avg_word_length: float = 4.5
    vocabulary_richness: float = 0.7      # unique words / total words
    comma_per_sentence: float = 1.2
    question_ratio: float = 0.05          # questions / sentences
    exclamation_ratio: float = 0.02
    avg_paragraph_length: float = 4.0    # sentences per paragraph
    common_words: dict = field(default_factory=dict)  # top 50 personal words
    transition_rate: float = 0.05        # transition words per sentence
    contraction_rate: float = 0.08       # contractions per word


class BehavioralFingerprint:
    """
    Builds a personal writing profile from human-scored documents.
    Detects when new text deviates significantly from the user's baseline.
    """
    TRANSITIONS = ["however","nevertheless","furthermore","moreover",
                   "additionally","consequently","therefore","thus"]
    CONTRACTIONS = ["i'm","it's","don't","can't","won't","isn't",
                    "aren't","wasn't","weren't","they're","we're"]

    def __init__(self, data_dir: Path):
        self.profile_file = data_dir / "writing_profile.json"
        self.profile = self._load()

    def _load(self) -> WritingProfile:
        if self.profile_file.exists():
            try:
                d = json.loads(self.profile_file.read_text())
                return WritingProfile(**d)
            except: pass
        return WritingProfile()

    def _save(self):
        d = {k: v for k, v in self.profile.__dict__.items()}
        self.profile_file.write_text(json.dumps(d))

    def _extract_features(self, text: str) -> dict:
        sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if len(s.split()) >= 2]
        words = text.lower().split()
        n_words = max(1, len(words))
        n_sent  = max(1, len(sentences))

        sl = [len(s.split()) for s in sentences]
        wl = [len(w.strip('.,!?;:')) for w in words if w.strip('.,!?;:')]

        paragraphs = [p.strip() for p in re.split(r'\n\s*\n', text) if p.strip()]
        para_lengths = [len(re.split(r'(?<=[.!?])\s+', p)) for p in paragraphs]

        vocab_richness = len(set(words)) / n_words
        commas = text.count(',')
        questions = sum(1 for s in sentences if s.strip().endswith('?'))
        exclamations = sum(1 for s in sentences if s.strip().endswith('!'))
        transitions = sum(1 for w in self.TRANSITIONS if w in text.lower())
        contractions = sum(1 for c in self.CONTRACTIONS if c in text.lower())

        top_words = dict(Counter(w for w in words if len(w) > 4).most_common(50))

        return {
            "avg_sentence_length": sum(sl)/len(sl) if sl else 15,
            "avg_word_length": sum(wl)/len(wl) if wl else 4.5,
            "vocabulary_richness": vocab_richness,
            "comma_per_sentence": commas / n_sent,
            "question_ratio": questions / n_sent,
            "exclamation_ratio": exclamations / n_sent,
            "avg_paragraph_length": sum(para_lengths)/len(para_lengths) if para_lengths else 4,
            "common_words": top_words,
            "transition_rate": transitions / n_sent,
            "contraction_rate": contractions / n_words,
        }

    def update_profile(self, text: str, ai_score: float):
        """Update profile with a document confirmed as human-written (score < 30)."""
        if ai_score >= 30:
            return  # Only learn from likely-human content
        if len(text.split()) < 20:
            return  # Too short to learn from

        features = self._extract_features(text)
        n = self.profile.sample_count

        def update_avg(old, new, n):
            return (old * n + new) / (n + 1)

        p = self.profile
        p.avg_sentence_length  = update_avg(p.avg_sentence_length,  features["avg_sentence_length"],  n)
        p.avg_word_length       = update_avg(p.avg_word_length,       features["avg_word_length"],       n)
        p.vocabulary_richness   = update_avg(p.vocabulary_richness,   features["vocabulary_richness"],   n)
        p.comma_per_sentence    = update_avg(p.comma_per_sentence,    features["comma_per_sentence"],    n)
        p.question_ratio        = update_avg(p.question_ratio,        features["question_ratio"],        n)
        p.exclamation_ratio     = update_avg(p.exclamation_ratio,     features["exclamation_ratio"],     n)
        p.avg_paragraph_length  = update_avg(p.avg_paragraph_length,  features["avg_paragraph_length"],  n)
        p.transition_rate       = update_avg(p.transition_rate,       features["transition_rate"],       n)
        p.contraction_rate      = update_avg(p.contraction_rate,      features["contraction_rate"],      n)

        # Merge common words
        for word, count in features["common_words"].items():
            p.common_words[word] = p.common_words.get(word, 0) + 1
        # Keep top 100
        p.common_words = dict(sorted(p.common_words.items(), key=lambda x: -x[1])[:100])

        p.sample_count += 1
        self._save()
        log.info(f"Writing profile updated — {p.sample_count} samples")

    def deviation_score(self, text: str) -> tuple:
        """
        Returns (deviation_score 0-100, reasons).
        High score = text is very different from user's normal writing.
        Only meaningful after 5+ profile samples.
        """
        if self.profile.sample_count < 5:
            return 0.0, []  # Not enough data yet

        features = self._extract_features(text)
        p = self.profile
        deviations = []
        reasons = []

        def pct_diff(actual, baseline):
            if baseline == 0: return 0
            return abs(actual - baseline) / baseline * 100

        # Sentence length deviation
        sl_dev = pct_diff(features["avg_sentence_length"], p.avg_sentence_length)
        if sl_dev > 40:
            deviations.append(min(100, sl_dev))
            reasons.append(f"Sentence length unusual for you ({features['avg_sentence_length']:.0f} vs your avg {p.avg_sentence_length:.0f} words)")

        # Vocabulary richness
        vr_dev = pct_diff(features["vocabulary_richness"], p.vocabulary_richness)
        if vr_dev > 30:
            deviations.append(min(100, vr_dev))
            reasons.append(f"Vocabulary pattern differs from your style")

        # Contraction rate (AI rarely uses contractions)
        if p.contraction_rate > 0.03 and features["contraction_rate"] < 0.01:
            deviations.append(60)
            reasons.append(f"You normally use contractions — this text doesn't")

        # Transition rate
        tr_dev = pct_diff(features["transition_rate"], p.transition_rate)
        if tr_dev > 100 and features["transition_rate"] > p.transition_rate:
            deviations.append(min(100, tr_dev * 0.5))
            reasons.append(f"Much more transition words than you normally use")

        # Vocabulary overlap with user's common words
        text_words = set(text.lower().split())
        user_words = set(p.common_words.keys())
        if len(user_words) > 20:
            overlap = len(text_words & user_words) / max(1, len(text_words)) * 100
            if overlap < 5:
                deviations.append(50)
                reasons.append(f"Almost no overlap with your personal vocabulary")

        score = sum(deviations) / max(1, len(deviations)) if deviations else 0
        return round(min(100, score), 1), reasons


# ════════════════════════════════════════════════════════════════════════════
# 2. KEYSTROKE RHYTHM ANALYSIS
# Detects paste events by measuring how fast content appears in a file.
# A human typing 500 words takes minutes. Paste takes milliseconds.
# ════════════════════════════════════════════════════════════════════════════

class KeystrokeRhythm:
    """
    Tracks file size growth over time.
    If a file jumps from small to large instantly — it was pasted, not typed.
    """
    def __init__(self):
        self._snapshots = {}  # path -> deque of (timestamp, word_count)

    def record_snapshot(self, path: Path, word_count: int):
        key = str(path)
        if key not in self._snapshots:
            self._snapshots[key] = deque(maxlen=20)
        self._snapshots[key].append((time.time(), word_count))

    def analyze_growth(self, path: Path, current_words: int) -> tuple:
        """
        Returns (paste_probability 0-100, reason).
        Compare current word count against the PREVIOUS snapshot.
        """
        key = str(path)
        snaps = self._snapshots.get(key, deque())
        now = time.time()

        if not snaps:
            # First time seeing this file
            self.record_snapshot(path, current_words)
            return 0.0, ""

        # Read previous snapshot BEFORE recording new one
        prev_time, prev_words = snaps[-1]
        elapsed = max(0.1, now - prev_time)
        growth = current_words - prev_words

        # Record new snapshot
        self.record_snapshot(path, current_words)

        if growth <= 30:
            return 0.0, ""

        # Words per minute
        wpm = (growth / elapsed) * 60

        # Average human typing: 40-80 WPM
        # Fast typist: up to 120 WPM  
        # Paste event: 10,000+ WPM
        reason = ""
        score = 0.0

        if wpm > 400 and growth > 30:
            score = min(100, 40 + (wpm - 400) / 200 * 60)
            reason = f"Content appeared too fast to type ({growth} words in {elapsed:.1f}s = {wpm:.0f} WPM — likely pasted)"
            log.info(f"KEYSTROKE ANOMALY: {path.name} grew {growth} words in {elapsed:.1f}s ({wpm:.0f} WPM)")

        return round(score, 1), reason


# ════════════════════════════════════════════════════════════════════════════
# 3. DOCUMENT DNA
# Tracks how documents evolve over multiple saves.
# AI docs appear fully formed. Human docs grow incrementally.
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class DocumentSnapshot:
    timestamp: float
    word_count: int
    hash: str
    change_size: int = 0  # words added/removed since last save


class DocumentDNA:
    """
    Tracks document evolution across saves.
    Flags documents that appear fully formed (AI pattern) vs grow incrementally (human pattern).
    """
    def __init__(self, data_dir: Path):
        self.dna_file = data_dir / "document_dna.json"
        self._dna = self._load()

    def _load(self):
        if self.dna_file.exists():
            try: return json.loads(self.dna_file.read_text())
            except: pass
        return {}

    def _save(self):
        # Keep only last 200 documents
        if len(self._dna) > 200:
            keys = sorted(self._dna.keys(),
                         key=lambda k: self._dna[k][-1]["timestamp"] if self._dna[k] else 0)
            for k in keys[:-200]: del self._dna[k]
        self.dna_file.write_text(json.dumps(self._dna))

    def record(self, path: Path, text: str) -> tuple:
        """
        Record a document snapshot and analyze growth pattern.
        Returns (dna_score 0-100, reason).
        """
        key = str(path)
        word_count = len(text.split())
        text_hash = hashlib.md5(text.encode()).hexdigest()[:12]
        now = time.time()

        if key not in self._dna:
            self._dna[key] = []

        history = self._dna[key]

        # Add snapshot
        change = word_count - (history[-1]["word_count"] if history else 0)
        history.append({
            "timestamp": now,
            "word_count": word_count,
            "hash": text_hash,
            "change_size": change
        })

        # Keep last 50 snapshots per doc
        if len(history) > 50:
            history = history[-50:]
        self._dna[key] = history
        self._save()

        # Need at least 2 snapshots to analyze
        if len(history) < 2:
            return 0.0, ""

        # Analyze pattern
        changes = [abs(s["change_size"]) for s in history[1:] if s["change_size"] != 0]
        if not changes:
            return 0.0, ""

        total_words = history[-1]["word_count"]
        first_words = history[0]["word_count"]
        total_growth = total_words - first_words
        n_saves = len(history)

        # AI pattern: document appears large on first save, few changes after
        # Human pattern: document grows steadily over multiple saves
        score = 0.0
        reason = ""

        # Large document appeared in very few saves
        if total_words > 200 and n_saves <= 2 and first_words > 150:
            score = min(100, total_words / 3)
            reason = f"Document appeared fully formed ({total_words} words in {n_saves} save)"

        # Single massive change
        max_change = max(changes) if changes else 0
        if max_change > 200 and max_change / max(1, total_words) > 0.7:
            score = max(score, min(100, max_change / 3))
            reason = f"Single large addition of {max_change} words (AI paste pattern)"

        return round(min(100, score), 1), reason


# ════════════════════════════════════════════════════════════════════════════
# 4. SOURCE VERIFICATION
# Searches for exact phrases from the document online.
# If found verbatim — confirms AI generation.
# ════════════════════════════════════════════════════════════════════════════

class SourceVerifier:
    """
    Extracts distinctive phrases and searches for them online.
    Confirms AI content by finding verbatim matches.
    Rate-limited to avoid spam.
    """
    def __init__(self):
        self._cache = {}        # phrase -> (result, timestamp)
        self._last_search = 0
        self._min_interval = 3  # seconds between searches

    def _extract_search_phrases(self, text: str) -> list:
        """Extract 2-3 distinctive phrases (6-10 words each) to search for."""
        sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text)
                    if 8 <= len(s.split()) <= 20]
        if not sentences:
            return []

        # Prefer sentences with AI indicator phrases
        ai_indicators = ["furthermore","moreover","leverage","utilize",
                        "cutting-edge","paradigm","seamless","optimize"]
        scored = []
        for s in sentences:
            s_lower = s.lower()
            indicator_count = sum(1 for w in ai_indicators if w in s_lower)
            scored.append((indicator_count, s))

        scored.sort(reverse=True)
        # Return top 2 phrases, as 6-8 word snippets
        phrases = []
        for _, s in scored[:2]:
            words = s.split()
            if len(words) >= 6:
                # Take middle portion (most distinctive)
                start = len(words) // 4
                phrase = " ".join(words[start:start+7])
                phrases.append(phrase)
        return phrases

    def verify(self, text: str) -> tuple:
        """
        Returns (verified_ai: bool, confidence: str, details: str)
        Searches web for distinctive phrases from the text.
        """
        # Rate limiting
        now = time.time()
        if now - self._last_search < self._min_interval:
            return False, "Low", "Rate limited"

        phrases = self._extract_search_phrases(text)
        if not phrases:
            return False, "Low", "No distinctive phrases found"

        try:
            import urllib.request, urllib.parse
            results = []

            for phrase in phrases[:2]:
                # Check cache
                if phrase in self._cache:
                    cached_result, cached_time = self._cache[phrase]
                    if now - cached_time < 3600:  # 1 hour cache
                        results.append(cached_result)
                        continue

                self._last_search = time.time()
                query = urllib.parse.quote(f'"{phrase}"')
                url = f"https://www.google.com/search?q={query}&num=5"

                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })

                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        html = resp.read().decode("utf-8", errors="ignore")

                    # Simple check: did the phrase appear in results?
                    phrase_lower = phrase.lower()
                    found = phrase_lower in html.lower()
                    result_data = {
                        "phrase": phrase,
                        "found_online": found,
                        "url": url
                    }
                    self._cache[phrase] = (result_data, time.time())
                    results.append(result_data)
                    time.sleep(0.5)

                except Exception as e:
                    log.debug(f"Search failed for phrase: {e}")

            if not results:
                return False, "Low", "Could not verify"

            found_count = sum(1 for r in results if r.get("found_online"))

            if found_count == len(results) and len(results) >= 2:
                return True, "High", f"All {len(results)} phrases found verbatim online"
            elif found_count > 0:
                return True, "Medium", f"{found_count}/{len(results)} phrases found online"
            else:
                return False, "Low", "Phrases not found online (may be original AI content)"

        except Exception as e:
            log.debug(f"Source verification error: {e}")
            return False, "Low", f"Verification unavailable"


# ════════════════════════════════════════════════════════════════════════════
# COMBINED INTELLIGENCE SCORE
# Merges all 4 signals into one enhanced result
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class IntelligenceResult:
    base_score: float           # from heuristic detection
    final_score: float          # after intelligence boost
    behavioral_score: float     # how different from user's style
    keystroke_score: float      # paste detection
    dna_score: float            # document growth pattern
    source_verified: bool       # found online
    source_confidence: str
    all_reasons: list
    intelligence_summary: str   # human readable explanation


def combine_signals(
    base_score: float,
    behavioral: tuple,
    keystroke: tuple,
    dna: tuple,
    source: tuple,
    reasons: list
) -> IntelligenceResult:
    """Combine all intelligence signals into a final enhanced score."""

    beh_score, beh_reasons = behavioral
    key_score, key_reason  = keystroke
    dna_score, dna_reason  = dna
    src_verified, src_conf, src_detail = source

    all_reasons = list(reasons)
    if beh_reasons: all_reasons.extend(beh_reasons)
    if key_reason:  all_reasons.append(key_reason)
    if dna_reason:  all_reasons.append(dna_reason)
    if src_verified: all_reasons.append(f"Source verified: {src_detail}")

    # Intelligence boost
    boost = 0.0
    if beh_score > 50:  boost += (beh_score - 50) * 0.3
    if key_score > 60:  boost += (key_score - 60) * 0.4
    if dna_score > 50:  boost += (dna_score - 50) * 0.2
    if src_verified:
        boost += 15 if src_conf == "High" else 8

    final = min(100, base_score + boost)

    # Build summary
    signals = []
    if beh_score > 30:  signals.append(f"style deviation {beh_score:.0f}%")
    if key_score > 30:  signals.append(f"paste detected")
    if dna_score > 30:  signals.append(f"appeared fully formed")
    if src_verified:    signals.append(f"found online ({src_conf} confidence)")

    summary = f"Base: {base_score:.0f}%"
    if signals:
        summary += f" + Intelligence signals: {', '.join(signals)} → Final: {final:.0f}%"

    return IntelligenceResult(
        base_score=base_score,
        final_score=round(final, 1),
        behavioral_score=beh_score,
        keystroke_score=key_score,
        dna_score=dna_score,
        source_verified=src_verified,
        source_confidence=src_conf,
        all_reasons=all_reasons[:6],
        intelligence_summary=summary
    )
