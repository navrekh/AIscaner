"""
AIScan Entity Risk Tracker
Tracks people/sources over time and builds cumulative risk profiles.

"Show me which employees are highest risk" - the question every HR director asks.

An entity is identified by:
  - Folder path (C:/Users/rahul/Documents -> entity "rahul")
  - Username extracted from path
  - Custom label if assigned

Risk score accumulates over time:
  - Each AI detection adds to entity risk
  - PII events add more
  - Security incidents add most
  - Score decays over time (old events matter less)
"""
import os, sys, json, time, logging, threading, re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from collections import defaultdict

log = logging.getLogger("aiscan")

# Risk points per event type
RISK_WEIGHTS = {
    "AI_HIGH":        15,   # AI score >= 75%
    "AI_MEDIUM":      8,    # AI score 50-75%
    "AI_LOW":         3,    # AI score 35-50%
    "PII_CRITICAL":   25,   # Aadhaar, credit card, private key
    "PII_HIGH":       15,   # PAN, JWT, UPI
    "PII_MEDIUM":     5,    # Phone, IFSC
    "INCIDENT_CHAIN": 30,   # Correlated incident
    "USB_SENSITIVE":  20,   # Sensitive file on USB
    "MACRO_ATTACK":   40,   # Office macro spawning shell
}

# Risk decay: score halves every N days
DECAY_HALF_LIFE_DAYS = 14

# Risk levels
def risk_level(score: float) -> str:
    if score >= 80:  return "CRITICAL"
    if score >= 50:  return "HIGH"
    if score >= 25:  return "MEDIUM"
    if score >= 10:  return "LOW"
    return "CLEAN"

def risk_color(level: str) -> str:
    return {
        "CRITICAL": "#ff2244", "HIGH": "#ff6600",
        "MEDIUM": "#ffaa00",   "LOW": "#ffdd00",
        "CLEAN": "#44cc77",
    }.get(level, "#888")


@dataclass
class RiskEvent:
    ts: float
    event_type: str      # AI_HIGH / PII_CRITICAL / INCIDENT_CHAIN etc
    points: int
    detail: str
    file: str = ""
    decayed_points: float = 0.0  # computed at query time

    def to_dict(self):
        return {
            "ts": self.ts,
            "ts_str": time.strftime("%Y-%m-%d %H:%M", time.localtime(self.ts)),
            "event_type": self.event_type,
            "points": self.points,
            "detail": self.detail,
            "file": self.file,
        }


@dataclass
class EntityProfile:
    entity_id: str           # normalized identifier
    display_name: str        # human-readable name
    folder_paths: List[str]  # known associated folders
    events: List[RiskEvent]  # all risk events
    first_seen: float        # timestamp
    last_seen: float         # timestamp
    label: str = ""          # custom label (e.g. "HR Team", "Engineering")
    notes: str = ""

    @property
    def current_score(self) -> float:
        """Risk score with time decay applied."""
        now = time.time()
        half_life_seconds = DECAY_HALF_LIFE_DAYS * 86400
        total = 0.0
        for ev in self.events:
            age_seconds = now - ev.ts
            decay = 0.5 ** (age_seconds / half_life_seconds)
            total += ev.points * decay
        return min(total, 100.0)

    @property
    def raw_score(self) -> float:
        return min(sum(e.points for e in self.events), 100.0)

    @property
    def risk_level(self) -> str:
        return risk_level(self.current_score)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def ai_detections(self) -> int:
        return sum(1 for e in self.events if e.event_type.startswith("AI_"))

    @property
    def pii_events(self) -> int:
        return sum(1 for e in self.events if e.event_type.startswith("PII_"))

    @property
    def last_event_str(self) -> str:
        if not self.events:
            return "Never"
        last = max(e.ts for e in self.events)
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(last))

    def to_dict(self):
        return {
            "entity_id": self.entity_id,
            "display_name": self.display_name,
            "folder_paths": self.folder_paths,
            "current_score": round(self.current_score, 1),
            "raw_score": round(self.raw_score, 1),
            "risk_level": self.risk_level,
            "event_count": self.event_count,
            "ai_detections": self.ai_detections,
            "pii_events": self.pii_events,
            "first_seen": time.strftime("%Y-%m-%d", time.localtime(self.first_seen)),
            "last_seen": time.strftime("%Y-%m-%d", time.localtime(self.last_seen)),
            "last_event": self.last_event_str,
            "label": self.label,
            "notes": self.notes,
            "events": [e.to_dict() for e in self.events[-20:]],  # last 20
        }


# ============================================================================
# ENTITY EXTRACTOR  -  who owns this file?
# ============================================================================

# Common username path patterns
_USER_PATTERNS = [
    r"[/\\]Users[/\\]([^/\\]+)[/\\]",           # Windows: C:\Users\rahul\
    r"[/\\]home[/\\]([^/\\]+)[/\\]",             # Linux: /home/rahul/
    r"[/\\]OneDrive - ([^/\\]+)[/\\]",           # OneDrive business
    r"[/\\]([^/\\]+)'s ",                         # Possessive: "Rahul's Documents"
]

_SYSTEM_NAMES = {
    "users", "documents", "desktop", "downloads", "appdata", "local",
    "roaming", "temp", "tmp", "public", "default", "all users",
    "program files", "windows", "system32", "administrator", "admin",
}

def extract_entity_from_path(file_path: str) -> Optional[str]:
    """
    Extract a likely username/entity from a file path.
    Returns normalized entity ID or None if not identifiable.
    """
    path_str = str(file_path).replace("\\", "/")

    for pattern in _USER_PATTERNS:
        m = re.search(pattern, path_str, re.IGNORECASE)
        if m:
            name = m.group(1).strip().lower()
            if name not in _SYSTEM_NAMES and len(name) >= 2:
                return name

    return None


def normalize_entity_id(raw: str) -> str:
    """Normalize entity name to consistent ID."""
    return re.sub(r'[^\w]', '_', raw.lower().strip())


# ============================================================================
# ENTITY TRACKER
# ============================================================================

class EntityTracker:
    """
    Maintains risk profiles for all entities (users) observed by AIScan.
    Persists to data_dir/entities.json.
    Thread-safe.
    """

    def __init__(self, data_dir: Path):
        self._data_dir = data_dir
        self._file = data_dir / "entities.json"
        self._entities: Dict[str, EntityProfile] = {}
        self._lock = threading.Lock()
        self._load()
        log.info(f"Entity tracker loaded: {len(self._entities)} entities")

    def _load(self):
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text(encoding="utf-8"))
                for eid, ed in data.items():
                    events = [RiskEvent(**e) for e in ed.get("_events_raw", [])]
                    self._entities[eid] = EntityProfile(
                        entity_id=eid,
                        display_name=ed.get("display_name", eid),
                        folder_paths=ed.get("folder_paths", []),
                        events=events,
                        first_seen=ed.get("first_seen", time.time()),
                        last_seen=ed.get("last_seen", time.time()),
                        label=ed.get("label", ""),
                        notes=ed.get("notes", ""),
                    )
            except Exception as e:
                log.debug(f"Entity load error: {e}")

    def _save(self):
        try:
            data = {}
            for eid, ep in self._entities.items():
                d = ep.to_dict()
                d["_events_raw"] = [e.to_dict() for e in ep.events]
                data[eid] = d
            self._file.write_text(
                json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            log.debug(f"Entity save error: {e}")

    def _get_or_create(self, entity_id: str, file_path: str,
                       display_name: str = "") -> EntityProfile:
        if entity_id not in self._entities:
            self._entities[entity_id] = EntityProfile(
                entity_id=entity_id,
                display_name=display_name or entity_id.replace("_", " ").title(),
                folder_paths=[str(Path(file_path).parent)],
                events=[],
                first_seen=time.time(),
                last_seen=time.time(),
            )
        ep = self._entities[entity_id]
        ep.last_seen = time.time()
        folder = str(Path(file_path).parent)
        if folder not in ep.folder_paths:
            ep.folder_paths.append(folder)
        return ep

    def record_ai_detection(self, file_path: str, ai_score: float,
                            risk_level_str: str, reasons: List[str]):
        """Record an AI detection event for the entity owning this file."""
        entity_raw = extract_entity_from_path(file_path)
        if not entity_raw:
            return

        entity_id = normalize_entity_id(entity_raw)

        if ai_score >= 75:
            etype, pts = "AI_HIGH", RISK_WEIGHTS["AI_HIGH"]
        elif ai_score >= 50:
            etype, pts = "AI_MEDIUM", RISK_WEIGHTS["AI_MEDIUM"]
        else:
            etype, pts = "AI_LOW", RISK_WEIGHTS["AI_LOW"]

        reason_str = " | ".join(reasons[:2]) if reasons else ""
        detail = f"AI {ai_score:.0f}% [{risk_level_str}] in {Path(file_path).name}"
        if reason_str:
            detail += f" - {reason_str}"

        with self._lock:
            ep = self._get_or_create(entity_id, file_path)
            ep.events.append(RiskEvent(
                ts=time.time(), event_type=etype, points=pts,
                detail=detail, file=file_path))
            self._save()

        log.info(f"ENTITY [{entity_id}]: +{pts}pts ({etype}) "
                 f"-> score={self._entities[entity_id].current_score:.0f} "
                 f"[{self._entities[entity_id].risk_level}]")

    def record_pii_event(self, file_path: str, severity: str,
                         pii_summary: str):
        """Record a PII detection event."""
        entity_raw = extract_entity_from_path(file_path)
        if not entity_raw:
            return

        entity_id = normalize_entity_id(entity_raw)
        etype = f"PII_{severity}"
        pts = RISK_WEIGHTS.get(etype, 5)

        with self._lock:
            ep = self._get_or_create(entity_id, file_path)
            ep.events.append(RiskEvent(
                ts=time.time(), event_type=etype, points=pts,
                detail=f"PII [{severity}]: {pii_summary} in {Path(file_path).name}",
                file=file_path))
            self._save()

    def record_incident(self, entity_id: str, incident_title: str,
                        severity: str):
        """Record a correlated incident chain."""
        entity_id = normalize_entity_id(entity_id)
        pts = RISK_WEIGHTS["INCIDENT_CHAIN"]

        with self._lock:
            if entity_id in self._entities:
                ep = self._entities[entity_id]
                ep.events.append(RiskEvent(
                    ts=time.time(), event_type="INCIDENT_CHAIN", points=pts,
                    detail=f"Incident: {incident_title} [{severity}]"))
                self._save()

    def get_all(self) -> List[EntityProfile]:
        with self._lock:
            return sorted(self._entities.values(),
                          key=lambda e: e.current_score, reverse=True)

    def get_high_risk(self, min_score: float = 25.0) -> List[EntityProfile]:
        return [e for e in self.get_all() if e.current_score >= min_score]

    def get_entity(self, entity_id: str) -> Optional[EntityProfile]:
        return self._entities.get(normalize_entity_id(entity_id))

    def set_label(self, entity_id: str, label: str):
        eid = normalize_entity_id(entity_id)
        with self._lock:
            if eid in self._entities:
                self._entities[eid].label = label
                self._save()

    def summary_stats(self) -> dict:
        entities = self.get_all()
        return {
            "total": len(entities),
            "critical": sum(1 for e in entities if e.risk_level == "CRITICAL"),
            "high": sum(1 for e in entities if e.risk_level == "HIGH"),
            "medium": sum(1 for e in entities if e.risk_level == "MEDIUM"),
            "low": sum(1 for e in entities if e.risk_level in ("LOW", "CLEAN")),
            "top_entity": entities[0].display_name if entities else None,
            "top_score": round(entities[0].current_score, 1) if entities else 0,
        }


# ============================================================================
# ENTITY RISK DASHBOARD  -  HTML
# ============================================================================

def build_entity_dashboard(tracker: EntityTracker, data_dir: Path) -> Path:
    """
    Build a ranked entity risk dashboard HTML.
    Shows all entities sorted by risk score with drill-down event history.
    """
    out_path = data_dir / "entity_dashboard.html"
    entities = tracker.get_all()
    stats = tracker.summary_stats()

    def sev_badge(level):
        col = risk_color(level)
        return (f'<span style="background:{col};color:#000;padding:2px 8px;'
                f'border-radius:4px;font-size:11px;font-weight:bold">{level}</span>')

    def score_bar(score):
        col = risk_color(risk_level(score))
        pct = min(score, 100)
        return (f'<div style="background:#1a1a2e;border-radius:4px;'
                f'height:6px;width:120px;display:inline-block;vertical-align:middle">'
                f'<div style="background:{col};width:{pct}%;height:100%;'
                f'border-radius:4px"></div></div>')

    def entity_row(ep: EntityProfile):
        col = risk_color(ep.risk_level)
        label_badge = (f' <span style="background:#1a1a2e;color:#888;'
                       f'padding:1px 6px;border-radius:3px;font-size:10px">'
                       f'{ep.label}</span>' if ep.label else "")
        return f"""
        <tr style="border-bottom:1px solid #1a1a2e;cursor:pointer"
            onclick="toggleEvents('{ep.entity_id}')">
          <td style="padding:12px 16px">
            <div style="color:#e8e8f0;font-weight:600">{ep.display_name}{label_badge}</div>
            <div style="color:#444;font-size:11px;margin-top:2px">
              {ep.folder_paths[0] if ep.folder_paths else ''}</div>
          </td>
          <td style="padding:12px;text-align:center">
            <span style="color:{col};font-size:20px;font-weight:900">
              {ep.current_score:.0f}</span>
            <div style="margin-top:4px">{score_bar(ep.current_score)}</div>
          </td>
          <td style="padding:12px;text-align:center">{sev_badge(ep.risk_level)}</td>
          <td style="padding:12px;text-align:center;color:#888">{ep.ai_detections}</td>
          <td style="padding:12px;text-align:center;color:#888">{ep.pii_events}</td>
          <td style="padding:12px;text-align:center;color:#888">{ep.event_count}</td>
          <td style="padding:12px;color:#555;font-size:11px">{ep.last_event_str}</td>
        </tr>
        <tr id="events_{ep.entity_id}" style="display:none">
          <td colspan="7" style="padding:0 16px 12px;background:#080810">
            <table style="width:100%;border-collapse:collapse">
              {''.join(f"""
              <tr style="border-bottom:1px solid #111">
                <td style="padding:6px 8px;color:#555;font-size:11px;
                           white-space:nowrap">{ev['ts_str']}</td>
                <td style="padding:6px 8px">
                  <span style="color:{risk_color(risk_level(ev['points'] * 3))};
                        font-size:11px">{ev['event_type']}</span></td>
                <td style="padding:6px 8px;color:#888;font-size:11px">
                  {ev['detail']}</td>
                <td style="padding:6px 8px;color:#444;font-size:11px;
                           text-align:right">+{ev['points']}pts</td>
              </tr>""" for ev in ep.to_dict()['events'])}
            </table>
          </td>
        </tr>"""

    rows = "".join(entity_row(ep) for ep in entities) or (
        '<tr><td colspan="7" style="color:#333;text-align:center;padding:40px">'
        'No entities tracked yet. Scans will appear as files are detected.</td></tr>')

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AIScan Entity Risk Dashboard</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{ background:#07070f; color:#e8e8f0;
            font-family:'Segoe UI',sans-serif; min-height:100vh }}
    .navbar {{ background:#0d0d14; border-bottom:1px solid #1a1a2e;
               padding:14px 32px; display:flex; align-items:center; gap:12px }}
    .logo {{ color:#00e5ff; font-weight:900; font-size:18px }}
    .tag {{ color:#ff6600; font-weight:600; font-size:13px;
            background:#ff660022; padding:3px 10px; border-radius:4px;
            border:1px solid #ff660044 }}
    .subtitle {{ color:#444; font-size:12px; margin-left:auto }}
    .container {{ max-width:1300px; margin:0 auto; padding:32px 24px }}
    .stats {{ display:grid; grid-template-columns:repeat(5,1fr);
              gap:16px; margin-bottom:32px }}
    .stat {{ background:#0d0d14; border:1px solid #1a1a2e;
             border-radius:8px; padding:20px; text-align:center }}
    .stat-num {{ font-size:36px; font-weight:900; margin-bottom:4px }}
    .stat-label {{ color:#666; font-size:12px }}
    .section-title {{ color:#666; font-size:11px; letter-spacing:2px;
                      text-transform:uppercase; margin:0 0 12px }}
    table {{ width:100%; border-collapse:collapse }}
    .th {{ padding:10px 16px; text-align:left; color:#444;
           font-size:11px; letter-spacing:1px; text-transform:uppercase;
           border-bottom:1px solid #1a1a2e; background:#0a0a12 }}
    tr:hover {{ background:#0d0d14 }}
    .refresh {{ color:#00e5ff; font-size:11px; cursor:pointer;
                background:none; border:1px solid #00e5ff44;
                padding:4px 12px; border-radius:4px }}
    .decay-note {{ color:#333; font-size:11px; margin-top:8px }}
  </style>
  <script>
    function toggleEvents(id) {{
      var el = document.getElementById('events_' + id);
      el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
    }}
  </script>
</head>
<body>
  <div class="navbar">
    <span class="logo">AI</span>
    <span style="color:#fff;font-weight:700;font-size:18px">Scan</span>
    <span class="tag">ENTITY RISK DASHBOARD</span>
    <span class="subtitle">
      {len(entities)} entities tracked  |
      Updated: {time.strftime('%Y-%m-%d %H:%M:%S')}
    </span>
    <button class="refresh" onclick="location.reload()">Refresh</button>
  </div>

  <div class="container">
    <div class="stats">
      <div class="stat">
        <div class="stat-num" style="color:#ff2244">{stats['critical']}</div>
        <div class="stat-label">Critical Risk</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#ff6600">{stats['high']}</div>
        <div class="stat-label">High Risk</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#ffaa00">{stats['medium']}</div>
        <div class="stat-label">Medium Risk</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#44cc77">{stats['low']}</div>
        <div class="stat-label">Low / Clean</div>
      </div>
      <div class="stat">
        <div class="stat-num" style="color:#00e5ff">{stats['total']}</div>
        <div class="stat-label">Total Entities</div>
      </div>
    </div>

    <div class="section-title">Entity Risk Rankings</div>
    <p class="decay-note">
      Scores decay over time (half-life: {DECAY_HALF_LIFE_DAYS} days).
      Click any row to expand event history.
    </p>
    <br>
    <table>
      <tr>
        <th class="th">Entity / Path</th>
        <th class="th" style="text-align:center">Risk Score</th>
        <th class="th" style="text-align:center">Level</th>
        <th class="th" style="text-align:center">AI Detections</th>
        <th class="th" style="text-align:center">PII Events</th>
        <th class="th" style="text-align:center">Total Events</th>
        <th class="th">Last Event</th>
      </tr>
      {rows}
    </table>
  </div>
</body>
</html>"""

    out_path.write_text(html, encoding="utf-8")
    log.info(f"Entity dashboard: {len(entities)} entities, "
             f"{stats['critical']} critical")
    return out_path
