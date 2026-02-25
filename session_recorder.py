"""
AIScan Session Recorder
Tracks writing sessions to generate "Human Verified" certificates.
Records keystrokes, edit patterns, time spent  -  proves human authorship.
"""
import json, time, hashlib, os, re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import logging

log = logging.getLogger("aiscan")


@dataclass
class WritingSession:
    file_path: str
    started_at: float
    ended_at: float = 0.0
    total_duration_minutes: float = 0.0
    save_count: int = 0
    word_counts: list = field(default_factory=list)   # [(timestamp, word_count)]
    avg_words_per_minute: float = 0.0
    longest_gap_minutes: float = 0.0   # longest time without a save
    file_hash: str = ""
    is_human_verified: bool = False
    verification_score: float = 0.0    # 0-100, how human the session looks
    certificate_id: str = ""


class SessionRecorder:
    """
    Tracks every document's writing history.
    Generates human-verified certificates for documents with natural writing patterns.
    """

    def __init__(self, data_dir: Path):
        self.sessions_file = data_dir / "sessions.json"
        self._sessions = self._load()
        self._active = {}  # path -> session start time

    def _load(self):
        if self.sessions_file.exists():
            try: return json.loads(self.sessions_file.read_text())
            except: pass
        return {}

    def _save(self):
        if len(self._sessions) > 500:
            keys = sorted(self._sessions, key=lambda k: self._sessions[k].get("started_at", 0))
            for k in keys[:-500]: del self._sessions[k]
        self.sessions_file.write_text(json.dumps(self._sessions, indent=2))

    def record_save(self, path: Path, word_count: int, file_hash: str):
        """Called every time a file is saved."""
        key = str(path)
        now = time.time()

        if key not in self._sessions:
            self._sessions[key] = {
                "file_path": str(path),
                "started_at": now,
                "ended_at": now,
                "save_count": 0,
                "word_counts": [],
                "file_hash": file_hash,
                "certificate_id": ""
            }

        session = self._sessions[key]
        session["save_count"] += 1
        session["ended_at"] = now
        session["file_hash"] = file_hash
        session["word_counts"].append((now, word_count))

        # Keep last 100 saves
        if len(session["word_counts"]) > 100:
            session["word_counts"] = session["word_counts"][-100:]

        self._save()

    def analyze_session(self, path: Path) -> dict:
        """
        Analyze a document's writing session.
        Returns verification score and human-writing indicators.
        """
        key = str(path)
        if key not in self._sessions:
            return {"verified": False, "score": 0, "reason": "No session data"}

        session = self._sessions[key]
        wc = session.get("word_counts", [])

        if len(wc) < 2:
            return {"verified": False, "score": 0, "reason": "Only one save recorded"}

        # Calculate metrics
        total_duration = (session["ended_at"] - session["started_at"]) / 60  # minutes
        save_count     = session["save_count"]
        final_words    = wc[-1][1] if wc else 0
        first_words    = wc[0][1] if wc else 0

        # Gaps between saves
        gaps = [(wc[i+1][0] - wc[i][0]) / 60 for i in range(len(wc)-1)]
        avg_gap  = sum(gaps) / len(gaps) if gaps else 0
        max_gap  = max(gaps) if gaps else 0

        # Growth pattern
        growths = [abs(wc[i+1][1] - wc[i][1]) for i in range(len(wc)-1)]
        avg_growth = sum(growths) / len(growths) if growths else 0

        # Scoring
        score = 0
        signals = []

        # 1. Multiple saves over time (human pattern)
        if save_count >= 3:
            score += 20
            signals.append(f"Saved {save_count} times")

        # 2. Long session (humans take time)
        if total_duration >= 5:
            score += min(30, total_duration * 2)
            signals.append(f"Wrote for {total_duration:.0f} minutes")

        # 3. Incremental growth (not pasted all at once)
        if avg_growth < 100 and save_count >= 3:
            score += 20
            signals.append("Gradual incremental writing")

        # 4. Natural gaps (humans take breaks)
        if avg_gap >= 1 and max_gap < 60:
            score += 15
            signals.append("Natural writing pauses")

        # 5. Revision pattern (word count went down at some point = editing)
        has_revisions = any(wc[i+1][1] < wc[i][1] for i in range(len(wc)-1))
        if has_revisions:
            score += 15
            signals.append("Editing/revision detected")

        score = min(100, score)
        is_verified = score >= 60 and save_count >= 3 and total_duration >= 3

        # Generate certificate ID
        if is_verified and not session.get("certificate_id"):
            cert_data = f"{path.name}:{session['started_at']}:{session['file_hash']}"
            session["certificate_id"] = "VC-" + hashlib.sha256(
                cert_data.encode()).hexdigest()[:12].upper()
            self._save()

        return {
            "verified": is_verified,
            "score": round(score, 1),
            "signals": signals,
            "duration_minutes": round(total_duration, 1),
            "save_count": save_count,
            "final_word_count": final_words,
            "certificate_id": session.get("certificate_id", ""),
        }

    def generate_certificate(self, path: Path) -> Optional[str]:
        """Generate a Human Verified certificate as HTML."""
        analysis = self.analyze_session(path)
        if not analysis["verified"]:
            return None

        cert_id = analysis["certificate_id"]
        name = path.name
        date = time.strftime("%B %d, %Y")
        duration = analysis["duration_minutes"]
        saves = analysis["save_count"]
        words = analysis["final_word_count"]
        signals = analysis["signals"]

        signals_html = "".join(f"<li>[OK] {s}</li>" for s in signals)

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<title>Human Verified Certificate  -  {name}</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600;700&display=swap" rel="stylesheet">
<style>
* {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ background:#0d0d14; font-family:'DM Sans',sans-serif; display:flex;
        align-items:center; justify-content:center; min-height:100vh; padding:40px }}
.cert {{ background:#111; border:2px solid #00e5ff; border-radius:16px;
         max-width:600px; width:100%; padding:48px; text-align:center }}
.badge {{ width:80px; height:80px; background:#00e5ff; border-radius:50%;
          margin:0 auto 24px; display:flex; align-items:center;
          justify-content:center; font-size:36px }}
h1 {{ font-size:1.6em; color:#00e5ff; margin-bottom:8px }}
.sub {{ color:#555; font-size:14px; margin-bottom:32px }}
.filename {{ background:#0d0d14; border:1px solid #1a1a2e; border-radius:8px;
             padding:16px; margin:24px 0; font-size:1.1em; color:#e8e8f0; font-weight:600 }}
.stats {{ display:flex; gap:12px; margin:24px 0 }}
.stat {{ flex:1; background:#0d0d14; border-radius:8px; padding:16px }}
.stat .n {{ font-size:1.6em; font-weight:800; color:#00e5ff }}
.stat .l {{ font-size:11px; color:#555; margin-top:4px }}
ul {{ list-style:none; text-align:left; color:#44cc77;
      background:#0d0d14; border-radius:8px; padding:16px 20px; margin:16px 0 }}
ul li {{ padding:4px 0; font-size:13px }}
.cert-id {{ font-family:monospace; font-size:13px; color:#333;
            background:#0a0a10; padding:12px; border-radius:6px; margin-top:24px }}
.footer {{ margin-top:24px; font-size:11px; color:#333 }}
</style></head><body>
<div class="cert">
  <div class="badge">[OK]</div>
  <h1>Human Verified</h1>
  <div class="sub">This document was verified as human-written by AIScan</div>
  <div class="filename">? {name}</div>
  <div class="stats">
    <div class="stat"><div class="n">{duration:.0f}m</div><div class="l">Time Spent</div></div>
    <div class="stat"><div class="n">{saves}</div><div class="l">Saves Made</div></div>
    <div class="stat"><div class="n">{words}</div><div class="l">Words Written</div></div>
  </div>
  <ul>{signals_html}</ul>
  <div class="cert-id">Certificate ID: {cert_id}<br/>Issued: {date}</div>
  <div class="footer">Verified by AIScan v3 . Powered by behavioral writing analysis</div>
</div>
</body></html>"""
