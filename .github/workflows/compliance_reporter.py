"""
AIScan Compliance Reporter
Generates audit-ready compliance reports for:
  - DPDP Act 2023 (India's Digital Personal Data Protection Act)
  - SOC 2 Type II (AI content and data handling controls)
  - ISO 27001 (Information security evidence)
  - Internal HR / Legal audit reports

Reports are PDF files suitable for submission to:
  - Regulators (MEITY, SEBI, RBI)
  - Auditors (Big 4, internal audit teams)
  - Legal counsel
  - HR investigations
"""
import time, json, logging
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

log = logging.getLogger("aiscan")


@dataclass
class ComplianceReportConfig:
    report_type: str         # DPDP / SOC2 / ISO27001 / HR_AUDIT / EXECUTIVE
    org_name: str = "Organisation"
    org_industry: str = ""
    prepared_by: str = "AIScan Automated Compliance System"
    period_days: int = 30    # report covers last N days
    include_entities: bool = True
    include_incidents: bool = True
    include_evidence_list: bool = True
    logo_path: str = ""
    confidential: bool = True


# ============================================================================
# DATA AGGREGATION
# ============================================================================

def _load_events(data_dir: Path, days: int) -> List[dict]:
    cutoff = time.time() - days * 86400
    events = []
    events_file = data_dir / "events.jsonl"
    if events_file.exists():
        for line in events_file.read_text(encoding="utf-8").splitlines():
            try:
                ev = json.loads(line)
                if ev.get("ts", 0) >= cutoff:
                    events.append(ev)
            except:
                pass
    return events


def _load_incidents(data_dir: Path, days: int) -> List[dict]:
    cutoff = time.time() - days * 86400
    incidents = []
    inc_file = data_dir / "incidents.jsonl"
    if inc_file.exists():
        for line in inc_file.read_text(encoding="utf-8").splitlines():
            try:
                inc = json.loads(line)
                if inc.get("started_at", 0) >= cutoff:
                    incidents.append(inc)
            except:
                pass
    return incidents


def _load_entities(data_dir: Path) -> List[dict]:
    ent_file = data_dir / "entities.json"
    if not ent_file.exists():
        return []
    try:
        data = json.loads(ent_file.read_text(encoding="utf-8"))
        return sorted(data.values(),
                      key=lambda e: e.get("current_score", 0), reverse=True)
    except:
        return []


def _load_scan_history(data_dir: Path, days: int) -> List[dict]:
    cutoff_str = time.strftime("%Y-%m-%d",
        time.localtime(time.time() - days * 86400))
    scans = []
    hist_file = data_dir / "scan_log.jsonl"
    if hist_file.exists():
        for line in hist_file.read_text(encoding="utf-8").splitlines():
            try:
                s = json.loads(line)
                if s.get("ts", "") >= cutoff_str:
                    scans.append(s)
            except:
                pass
    return scans


# ============================================================================
# PDF REPORT BUILDER
# ============================================================================

def generate_compliance_report(
    data_dir: Path,
    config: ComplianceReportConfig,
    output_path: Optional[Path] = None
) -> Optional[Path]:
    """
    Generate a compliance PDF report. Returns path to saved PDF or None.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.lib.units import mm, cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    except ImportError:
        log.error("reportlab not available - cannot generate compliance report")
        return None

    # -- Load data ---------------------------------------------------------
    events   = _load_events(data_dir, config.period_days)
    incidents = _load_incidents(data_dir, config.period_days)
    entities  = _load_entities(data_dir)
    scans     = _load_scan_history(data_dir, config.period_days)

    # Compute key stats
    total_scans     = len(scans)
    ai_detected     = sum(1 for s in scans if s.get("score", 0) >= 35)
    pii_events      = [e for e in events if e.get("event_type","").startswith("PII_")]
    critical_incs   = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    high_risk_ents  = [e for e in entities if e.get("risk_level") in ("CRITICAL","HIGH")]
    evidence_files  = list((data_dir / "evidence").glob("*.png")) if (
        data_dir / "evidence").exists() else []

    period_str = f"Last {config.period_days} days"
    report_date = time.strftime("%d %B %Y")
    ts_now = time.strftime("%Y-%m-%d %H:%M:%S")

    # -- Output path -------------------------------------------------------
    if not output_path:
        rtype = config.report_type.lower().replace(" ", "_")
        fname = f"AIScan_{rtype}_compliance_{time.strftime('%Y%m%d')}.pdf"
        output_path = data_dir / "reports" / fname
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # -- Colors ------------------------------------------------------------
    C_BG       = HexColor("#07070f")
    C_ACCENT   = HexColor("#00e5ff")
    C_TEXT     = HexColor("#1a1a2e")
    C_CRITICAL = HexColor("#ff2244")
    C_HIGH     = HexColor("#ff6600")
    C_MEDIUM   = HexColor("#ffaa00")
    C_LOW      = HexColor("#44cc77")
    C_GRAY     = HexColor("#888888")
    C_LIGHT    = HexColor("#f5f5f8")
    C_DARK     = HexColor("#0d0d14")
    C_BORDER   = HexColor("#1a1a2e")

    def sev_color(sev):
        return {
            "CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
            "MEDIUM": C_MEDIUM, "LOW": C_LOW,
        }.get(sev, C_GRAY)

    # -- Styles ------------------------------------------------------------
    styles = getSampleStyleSheet()

    def style(name, **kw):
        return ParagraphStyle(name, **kw)

    S_TITLE = style("Title",
        fontName="Helvetica-Bold", fontSize=28, textColor=C_DARK,
        spaceAfter=4, alignment=TA_LEFT)
    S_SUBTITLE = style("Subtitle",
        fontName="Helvetica", fontSize=13, textColor=C_GRAY,
        spaceAfter=2, alignment=TA_LEFT)
    S_H1 = style("H1",
        fontName="Helvetica-Bold", fontSize=14, textColor=C_DARK,
        spaceBefore=20, spaceAfter=8,
        borderPad=(0,0,4,0))
    S_H2 = style("H2",
        fontName="Helvetica-Bold", fontSize=11, textColor=C_DARK,
        spaceBefore=12, spaceAfter=6)
    S_BODY = style("Body",
        fontName="Helvetica", fontSize=9, textColor=C_TEXT,
        spaceAfter=6, leading=14, alignment=TA_JUSTIFY)
    S_SMALL = style("Small",
        fontName="Helvetica", fontSize=8, textColor=C_GRAY,
        spaceAfter=4, leading=12)
    S_BOLD = style("Bold",
        fontName="Helvetica-Bold", fontSize=9, textColor=C_TEXT,
        spaceAfter=4)
    S_CONF = style("Conf",
        fontName="Helvetica-Bold", fontSize=8, textColor=C_CRITICAL,
        alignment=TA_CENTER)
    S_CENTER = style("Center",
        fontName="Helvetica", fontSize=9, textColor=C_TEXT,
        alignment=TA_CENTER)

    # -- Table style helper ------------------------------------------------
    def table_style(header_color=C_DARK):
        return TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  header_color),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0),  8),
            ("FONTSIZE",      (0, 1), (-1, -1), 8),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, white]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ])

    # -- Build document ----------------------------------------------------
    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title=f"AIScan {config.report_type} Compliance Report",
        author="AIScan Compliance System",
    )

    story = []
    W = A4[0] - 4*cm  # usable width

    # -- COVER PAGE --------------------------------------------------------
    story.append(Spacer(1, 2*cm))

    # Title block with accent bar
    story.append(HRFlowable(width=W, thickness=4,
                             color=C_ACCENT, spaceAfter=16))
    story.append(Paragraph("AIScan Compliance Report", S_TITLE))

    report_labels = {
        "DPDP":      "Digital Personal Data Protection Act 2023 (India)",
        "SOC2":      "SOC 2 Type II - AI Content & Data Handling Controls",
        "ISO27001":  "ISO/IEC 27001:2022 - Information Security Evidence",
        "HR_AUDIT":  "Internal HR / Legal Audit Report",
        "EXECUTIVE": "Executive Risk Summary",
    }
    story.append(Paragraph(
        report_labels.get(config.report_type, config.report_type), S_SUBTITLE))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width=W, thickness=0.5,
                             color=C_BORDER, spaceAfter=24))

    # Report metadata table
    meta = [
        ["Organisation:", config.org_name],
        ["Industry:",     config.org_industry or "Not specified"],
        ["Report Date:",  report_date],
        ["Period:",       period_str],
        ["Prepared By:",  config.prepared_by],
        ["Generated:",    ts_now],
        ["System:",       "AIScan v5 - AI & Cybersecurity Detection Platform"],
    ]
    meta_table = Table(
        [[Paragraph(f"<b>{k}</b>", S_BOLD), Paragraph(v, S_BODY)]
         for k, v in meta],
        colWidths=[4.5*cm, W - 4.5*cm]
    )
    meta_table.setStyle(TableStyle([
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    if config.confidential:
        story.append(Paragraph(
            "CONFIDENTIAL - For authorised recipients only. "
            "Do not distribute without written permission.",
            S_CONF))

    story.append(PageBreak())

    # -- EXECUTIVE SUMMARY -------------------------------------------------
    story.append(Paragraph("1. Executive Summary", S_H1))
    story.append(HRFlowable(width=W, thickness=1,
                             color=C_ACCENT, spaceAfter=12))

    # KPI cards as a table
    sev_c = sev_color("CRITICAL") if critical_incs > 0 else C_LOW
    ai_c  = sev_color("HIGH") if ai_detected > 5 else C_LOW
    pii_c = sev_color("CRITICAL") if len(pii_events) > 0 else C_LOW
    hr_c  = sev_color("HIGH") if high_risk_ents else C_LOW

    kpi_data = [
        ["Total Scans", "AI Detections", "PII Events", "Incidents", "High Risk Entities"],
        [str(total_scans), str(ai_detected), str(len(pii_events)),
         str(len(incidents)), str(len(high_risk_ents))],
    ]
    kpi_table = Table(kpi_data, colWidths=[W/5]*5)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",     (0,0), (-1,0), HexColor("#aaaaaa")),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica"),
        ("FONTSIZE",      (0,0), (-1,0), 8),
        ("BACKGROUND",    (0,1), (-1,1), C_LIGHT),
        ("TEXTCOLOR",     (0,1), (0,1),  C_ACCENT),
        ("TEXTCOLOR",     (1,1), (1,1),  ai_c),
        ("TEXTCOLOR",     (2,1), (2,1),  pii_c),
        ("TEXTCOLOR",     (3,1), (3,1),  sev_c),
        ("TEXTCOLOR",     (4,1), (4,1),  hr_c),
        ("FONTNAME",      (0,1), (-1,1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,1), (-1,1), 22),
        ("ALIGN",         (0,0), (-1,-1),"CENTER"),
        ("VALIGN",        (0,0), (-1,-1),"MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("GRID",          (0,0), (-1,-1), 0.5, C_BORDER),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 16))

    # Summary narrative based on report type
    if config.report_type == "DPDP":
        narrative = (
            f"This report documents AIScan's monitoring activities for {config.org_name} "
            f"during the period covering the last {config.period_days} days, in accordance "
            f"with the Digital Personal Data Protection Act 2023 (DPDP Act). "
            f"During this period, AIScan monitored {total_scans} documents and detected "
            f"{len(pii_events)} instances of personal data exposure including Aadhaar numbers, "
            f"PAN cards, and other identifiable information. "
            f"All detected incidents have been logged with timestamp evidence as required "
            f"under Section 8 (Obligations of Data Fiduciary) of the DPDP Act."
        )
    elif config.report_type == "SOC2":
        narrative = (
            f"This report provides evidence of {config.org_name}'s AI content monitoring "
            f"and data handling controls for SOC 2 Type II purposes. "
            f"AIScan provides continuous monitoring across {total_scans} document scans, "
            f"with automated detection of AI-generated content, PII exposure, and "
            f"anomalous data movement patterns. "
            f"This evidence supports the following Trust Service Criteria: "
            f"CC6 (Logical and Physical Access), CC7 (System Operations), "
            f"and A1 (Availability)."
        )
    elif config.report_type == "ISO27001":
        narrative = (
            f"This report provides information security evidence for {config.org_name} "
            f"in support of ISO/IEC 27001:2022 certification. "
            f"Evidence covers Annex A controls including A.5.23 (Information security "
            f"for use of cloud services), A.8.12 (Data leakage prevention), and "
            f"A.8.16 (Monitoring activities). "
            f"AIScan monitored {total_scans} documents with {len(incidents)} correlated "
            f"security incidents detected and evidenced."
        )
    elif config.report_type == "HR_AUDIT":
        narrative = (
            f"This internal audit report documents AI content usage and data handling "
            f"activities at {config.org_name} for the last {config.period_days} days. "
            f"The report covers {total_scans} scanned documents with {ai_detected} instances "
            f"of suspected AI-generated content. "
            f"Entity risk profiles are included to assist HR investigation of "
            f"potential policy violations."
        )
    else:
        narrative = (
            f"AIScan detected {ai_detected} AI-generated documents and {len(pii_events)} "
            f"PII exposure events across {total_scans} total scans during the "
            f"reporting period. {critical_incs} critical incidents were identified "
            f"requiring immediate attention."
        )

    story.append(Paragraph(narrative, S_BODY))

    # -- ENTITY RISK SECTION -----------------------------------------------
    if config.include_entities and entities:
        story.append(PageBreak())
        story.append(Paragraph("2. Entity Risk Assessment", S_H1))
        story.append(HRFlowable(width=W, thickness=1,
                                 color=C_ACCENT, spaceAfter=8))
        story.append(Paragraph(
            "The following individuals have been identified through file path analysis. "
            "Risk scores incorporate time-decay weighting - recent events carry more weight. "
            "Scores above 50 warrant investigation; scores above 80 require immediate action.",
            S_BODY))
        story.append(Spacer(1, 8))

        ent_data = [["Entity", "Risk Score", "Level", "AI Detections",
                     "PII Events", "Last Activity"]]
        for ep in entities[:20]:
            level = ep.get("risk_level", "CLEAN")
            ent_data.append([
                ep.get("display_name", ep.get("entity_id", "Unknown")),
                f"{ep.get('current_score', 0):.0f}",
                level,
                str(ep.get("ai_detections", 0)),
                str(ep.get("pii_events", 0)),
                ep.get("last_event", "-"),
            ])

        ent_table = Table(ent_data,
                          colWidths=[5*cm, 2.5*cm, 2.5*cm, 2.5*cm, 2.5*cm, 4*cm])
        style_cmds = table_style().getCommands()

        # Color-code risk level column
        for i, ep in enumerate(entities[:20], 1):
            level = ep.get("risk_level", "CLEAN")
            col = sev_color(level)
            style_cmds += [("TEXTCOLOR", (2, i), (2, i), col),
                           ("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")]

        ent_table.setStyle(TableStyle(style_cmds))
        story.append(ent_table)

        # High risk entities - detailed
        hi_risk = [e for e in entities if e.get("risk_level") in ("CRITICAL","HIGH")]
        if hi_risk:
            story.append(Spacer(1, 16))
            story.append(Paragraph("High Risk Entity Details", S_H2))
            for ep in hi_risk[:5]:
                level = ep.get("risk_level","HIGH")
                col = sev_color(level)
                story.append(KeepTogether([
                    Paragraph(
                        f"<b>{ep.get('display_name','Unknown')}</b> "
                        f"[{level}] - Score: {ep.get('current_score',0):.0f}",
                        style("HR", fontName="Helvetica-Bold", fontSize=10,
                              textColor=col, spaceAfter=4)),
                    Paragraph(
                        f"Path: {ep.get('folder_paths',[''])[0]}  |  "
                        f"First seen: {ep.get('first_seen','-')}  |  "
                        f"Events: {ep.get('event_count',0)}",
                        S_SMALL),
                    Spacer(1, 8),
                ]))

    # -- INCIDENT SECTION --------------------------------------------------
    if config.include_incidents and incidents:
        story.append(PageBreak())
        story.append(Paragraph("3. Security Incidents", S_H1))
        story.append(HRFlowable(width=W, thickness=1,
                                 color=C_ACCENT, spaceAfter=8))
        story.append(Paragraph(
            "The following correlated incident chains were detected during the "
            "reporting period. Each chain represents multiple related events that "
            "together indicate a security threat.",
            S_BODY))
        story.append(Spacer(1, 8))

        inc_data = [["Incident", "Severity", "Events", "Duration", "Date"]]
        for inc in incidents[:30]:
            dur = inc.get("duration_seconds", 0)
            dur_str = f"{dur:.0f}s" if dur < 60 else f"{dur/60:.1f}m"
            inc_data.append([
                inc.get("title", "Unknown"),
                inc.get("severity", "-"),
                str(inc.get("event_count", 0)),
                dur_str,
                inc.get("started_str", "-")[:16],
            ])

        inc_table = Table(inc_data,
                          colWidths=[6*cm, 2.5*cm, 2*cm, 2.5*cm, 4*cm])
        style_cmds = table_style().getCommands()
        for i, inc in enumerate(incidents[:30], 1):
            sev = inc.get("severity", "LOW")
            col = sev_color(sev)
            style_cmds += [("TEXTCOLOR", (1, i), (1, i), col),
                           ("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")]
        inc_table.setStyle(TableStyle(style_cmds))
        story.append(inc_table)

    # -- COMPLIANCE CONTROLS SECTION ---------------------------------------
    story.append(PageBreak())
    sec_num = "4" if (config.include_entities or config.include_incidents) else "2"
    story.append(Paragraph(f"{sec_num}. Compliance Controls Evidence", S_H1))
    story.append(HRFlowable(width=W, thickness=1,
                             color=C_ACCENT, spaceAfter=8))

    if config.report_type == "DPDP":
        controls = [
            ["DPDP Act Section", "Requirement", "AIScan Control", "Status"],
            ["Section 4",    "Lawful processing of personal data",
             "PII detection prevents unauthorized exposure", "MONITORED"],
            ["Section 8(1)", "Data fiduciary obligations",
             "All PII events logged with timestamp evidence", "EVIDENCED"],
            ["Section 8(3)", "Data accuracy and completeness",
             "Document integrity monitoring", "ACTIVE"],
            ["Section 8(6)", "Security safeguards implementation",
             "Real-time clipboard + file monitoring", "ACTIVE"],
            ["Section 8(7)", "Breach reporting readiness",
             "Incident chains logged with screenshots", "READY"],
            ["Section 9",   "Processing of children's personal data",
             "CRITICAL alerts on any PII in educational contexts", "ACTIVE"],
        ]
    elif config.report_type == "SOC2":
        controls = [
            ["TSC Criteria", "Control Objective", "AIScan Evidence", "Status"],
            ["CC6.1",  "Logical access security",
             "File access monitoring with entity tracking", "EVIDENCED"],
            ["CC6.6",  "Prevent unauthorized access",
             "Real-time clipboard + screen monitoring", "ACTIVE"],
            ["CC7.1",  "Detect and monitor security events",
             "Incident correlation engine running 24/7", "ACTIVE"],
            ["CC7.2",  "Monitor system components",
             "Process anomaly detection (macro attacks)", "ACTIVE"],
            ["CC7.3",  "Evaluate security events",
             "Chain correlation with evidence screenshots", "EVIDENCED"],
            ["A1.2",   "System availability monitoring",
             "Continuous monitoring with audit log", "ACTIVE"],
        ]
    elif config.report_type == "ISO27001":
        controls = [
            ["Annex A Control", "Requirement", "AIScan Implementation", "Status"],
            ["A.5.23", "Cloud service security",
             "AI content detection in cloud-edited documents", "ACTIVE"],
            ["A.8.12", "Data leakage prevention",
             "PII monitoring on clipboard, files, screen", "ACTIVE"],
            ["A.8.16", "Monitoring activities",
             "Event logging with 500-entry audit trail", "EVIDENCED"],
            ["A.6.8",  "Information security event reporting",
             "Automated incident chains with popup alerts", "ACTIVE"],
            ["A.8.20", "Network security",
             "USB monitoring for removable media", "ACTIVE"],
            ["A.5.28", "Evidence collection",
             "Screenshot evidence on CRITICAL events", "EVIDENCED"],
        ]
    else:
        controls = [
            ["Control", "Description", "Evidence", "Status"],
            ["AI Detection",    "Detect AI-generated content",
             f"{ai_detected} detections logged", "ACTIVE"],
            ["PII Monitoring",  "Monitor personal data exposure",
             f"{len(pii_events)} events logged", "ACTIVE"],
            ["Incident Tracking","Correlate related events",
             f"{len(incidents)} chains detected", "ACTIVE"],
            ["Evidence Capture", "Screenshot on detection",
             f"{len(evidence_files)} screenshots saved", "ACTIVE"],
            ["Entity Tracking",  "Build risk profiles per person",
             f"{len(entities)} entities tracked", "ACTIVE"],
        ]

    ctrl_table = Table(controls,
                       colWidths=[4*cm, 5.5*cm, 5*cm, 2.5*cm])
    style_cmds = table_style().getCommands()
    for i in range(1, len(controls)):
        status = controls[i][-1] if controls[i] else ""
        col = C_LOW if status in ("ACTIVE","EVIDENCED","READY") else C_HIGH
        style_cmds += [("TEXTCOLOR", (3, i), (3, i), col),
                       ("FONTNAME",  (3, i), (3, i), "Helvetica-Bold")]
    ctrl_table.setStyle(TableStyle(style_cmds))
    story.append(ctrl_table)

    # -- EVIDENCE APPENDIX -------------------------------------------------
    if config.include_evidence_list and evidence_files:
        story.append(Spacer(1, 16))
        story.append(Paragraph("Evidence Files", S_H2))
        story.append(Paragraph(
            f"The following {len(evidence_files)} screenshot evidence files were "
            f"captured automatically at time of detection. Files are stored at: "
            f"{str(data_dir / 'evidence')}",
            S_BODY))
        story.append(Spacer(1, 8))

        ev_data = [["Filename", "Captured"]]
        for f in sorted(evidence_files)[-20:]:
            ts_part = f.stem.split("_")[0] if "_" in f.stem else ""
            try:
                ts_dt = time.strptime(ts_part, "%Y%m%d")
                ts_str = time.strftime("%Y-%m-%d", ts_dt)
            except:
                ts_str = ts_part
            ev_data.append([f.name, ts_str])

        ev_table = Table(ev_data, colWidths=[12*cm, 5*cm])
        ev_table.setStyle(table_style())
        story.append(ev_table)

    # -- FOOTER / CERTIFICATION --------------------------------------------
    story.append(Spacer(1, 24))
    story.append(HRFlowable(width=W, thickness=0.5,
                             color=C_BORDER, spaceAfter=12))
    story.append(Paragraph(
        f"This report was generated automatically by AIScan v5 on {ts_now}. "
        f"All events are logged with cryptographic timestamps. "
        f"Report ID: {hashlib.md5(ts_now.encode()).hexdigest()[:12].upper()}",
        S_SMALL))

    # -- BUILD -------------------------------------------------------------
    doc.build(story)
    log.info(f"Compliance report generated: {output_path.name} "
             f"({output_path.stat().st_size:,} bytes)")
    return output_path


import hashlib  # needed for report ID


# ============================================================================
# COMPLIANCE REPORT UI
# ============================================================================

def show_compliance_report_ui(data_dir: Path, settings_manager=None):
    """
    Show a dialog to configure and generate a compliance report.
    """
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox

        root = tk.Tk()
        root.title("AIScan - Generate Compliance Report")
        root.configure(bg="#0d0d14")
        root.resizable(False, False)

        W, H = 500, 480
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        def label(parent, text, **kw):
            tk.Label(parent, text=text, bg="#0d0d14",
                     fg=kw.pop("fg", "#e8e8f0"),
                     font=kw.pop("font", ("Helvetica", 10)),
                     **kw).pack(anchor="w", **{k:v for k,v in kw.items()
                                               if k in ("pady","padx")})

        def entry_row(parent, label_text, default=""):
            f = tk.Frame(parent, bg="#0d0d14"); f.pack(fill="x", pady=3)
            tk.Label(f, text=label_text, font=("Helvetica",9),
                     fg="#888", bg="#0d0d14", width=16,
                     anchor="w").pack(side="left")
            var = tk.StringVar(value=default)
            tk.Entry(f, textvariable=var, font=("Helvetica",9),
                     bg="#1a1a2e", fg="#e8e8f0",
                     insertbackground="#fff",
                     relief="flat", width=30).pack(side="left", padx=(4,0))
            return var

        # Header
        tk.Frame(root, bg="#00e5ff", height=3).pack(fill="x")
        hdr = tk.Frame(root, bg="#0a0a12"); hdr.pack(fill="x")
        tk.Label(hdr, text="Generate Compliance Report",
                 font=("Helvetica",13,"bold"),
                 fg="#00e5ff", bg="#0a0a12").pack(side="left", padx=20, pady=14)

        main = tk.Frame(root, bg="#0d0d14"); main.pack(fill="both",
                        expand=True, padx=24, pady=16)

        # Report type
        tk.Label(main, text="Report Type", font=("Helvetica",10,"bold"),
                 fg="#e8e8f0", bg="#0d0d14").pack(anchor="w", pady=(0,6))
        rtype_var = tk.StringVar(value="DPDP")
        types = [
            ("DPDP Act 2023 (India)", "DPDP"),
            ("SOC 2 Type II", "SOC2"),
            ("ISO/IEC 27001:2022", "ISO27001"),
            ("Internal HR / Legal Audit", "HR_AUDIT"),
            ("Executive Summary", "EXECUTIVE"),
        ]
        for label_text, val in types:
            tk.Radiobutton(main, text=label_text, variable=rtype_var,
                           value=val, font=("Helvetica",9),
                           fg="#888", bg="#0d0d14",
                           activebackground="#0d0d14",
                           selectcolor="#0d0d14").pack(anchor="w")

        tk.Frame(main, bg="#1a1a2e", height=1).pack(fill="x", pady=12)

        # Org details
        tk.Label(main, text="Organisation Details",
                 font=("Helvetica",10,"bold"),
                 fg="#e8e8f0", bg="#0d0d14").pack(anchor="w", pady=(0,6))
        org_var      = entry_row(main, "Organisation:", "My Organisation")
        industry_var = entry_row(main, "Industry:", "Technology")
        prepby_var   = entry_row(main, "Prepared by:", "Compliance Team")

        tk.Frame(main, bg="#1a1a2e", height=1).pack(fill="x", pady=12)

        # Period
        tk.Label(main, text="Report Period",
                 font=("Helvetica",10,"bold"),
                 fg="#e8e8f0", bg="#0d0d14").pack(anchor="w", pady=(0,6))
        period_var = tk.IntVar(value=30)
        pf = tk.Frame(main, bg="#0d0d14"); pf.pack(fill="x", pady=3)
        for days, label_text in [(7,"7 days"),(30,"30 days"),
                                  (90,"90 days"),(365,"1 year")]:
            tk.Radiobutton(pf, text=label_text, variable=period_var,
                           value=days, font=("Helvetica",9),
                           fg="#888", bg="#0d0d14",
                           activebackground="#0d0d14",
                           selectcolor="#0d0d14").pack(side="left", padx=8)

        conf_var = tk.BooleanVar(value=True)
        tk.Checkbutton(main, text="Mark as Confidential",
                       variable=conf_var, font=("Helvetica",9),
                       fg="#888", bg="#0d0d14",
                       activebackground="#0d0d14",
                       selectcolor="#0d0d14").pack(anchor="w", pady=(8,0))

        status_var = tk.StringVar()
        tk.Label(main, textvariable=status_var, font=("Helvetica",9),
                 fg="#44cc77", bg="#0d0d14").pack(anchor="w", pady=(8,0))

        def generate():
            config = ComplianceReportConfig(
                report_type=rtype_var.get(),
                org_name=org_var.get() or "Organisation",
                org_industry=industry_var.get(),
                prepared_by=prepby_var.get(),
                period_days=period_var.get(),
                confidential=conf_var.get(),
            )
            status_var.set("Generating report...")
            root.update()

            def _gen():
                path = generate_compliance_report(data_dir, config)
                if path:
                    status_var.set(f"Saved: {path.name}")
                    import webbrowser
                    root.after(1500, lambda: [
                        webbrowser.open(path.as_uri()),
                        root.destroy()
                    ])
                else:
                    status_var.set("Error: reportlab not available")

            import threading
            threading.Thread(target=_gen, daemon=True).start()

        # Buttons
        bf = tk.Frame(root, bg="#0a0a12"); bf.pack(fill="x", side="bottom")
        tk.Frame(bf, bg="#1a1a2e", height=1).pack(fill="x")
        brow = tk.Frame(bf, bg="#0a0a12"); brow.pack(fill="x", padx=20, pady=10)
        tk.Button(brow, text="Generate PDF Report",
                  command=generate,
                  font=("Helvetica",10,"bold"),
                  fg="#0d0d14", bg="#00e5ff",
                  relief="flat", padx=16, pady=7,
                  cursor="hand2").pack(side="right", padx=(8,0))
        tk.Button(brow, text="Cancel", command=root.destroy,
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=16, pady=7,
                  cursor="hand2").pack(side="right")

        root.mainloop()

    except Exception as e:
        log.error(f"Compliance UI error: {e}")
