"""
AIScan PDF Report Generator
Generates professional, shareable PDF reports for individual scans and bulk scans.
Uses reportlab  -  bundled in the exe, zero extra install.
"""
import time, logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("aiscan")

# -- Colors ----------------------------------------------------------------
BLACK      = (0.05, 0.05, 0.08)
WHITE      = (0.93, 0.93, 0.94)
CYAN       = (0.0,  0.898, 1.0)
BG_DARK    = (0.05, 0.05, 0.08)
BG_CARD    = (0.067, 0.067, 0.1)
BG_MID     = (0.08, 0.08, 0.13)
RED        = (1.0,  0.267, 0.333)
AMBER      = (1.0,  0.667, 0.0)
GREEN      = (0.267, 0.8,  0.467)
GREY       = (0.3,  0.3,  0.4)
GREY_LIGHT = (0.6,  0.6,  0.7)


def _rgb(c): return c  # already 0-1 tuples


def generate_scan_report(
    filename: str,
    ai_score: float,
    risk_level: str,
    classification: str,
    llm_suspected: str,
    confidence: str,
    reasons: list,
    paragraph_results: list,
    output_path: Path,
    scan_time: Optional[str] = None,
) -> Path:
    """
    Generate a single-scan PDF report.
    Professional, dark-themed, shareable  -  suitable for HR, academic, legal.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    W, H = A4
    c = canvas.Canvas(str(output_path), pagesize=A4)

    def rgb(col): c.setFillColorRGB(*col)
    def srgb(col): c.setStrokeColorRGB(*col)

    risk_color = RED if risk_level == "High" else AMBER if risk_level == "Medium" else GREEN
    date_str = scan_time or time.strftime("%B %d, %Y at %I:%M %p")

    # -- Header bar --------------------------------------------------------
    rgb(BG_DARK); c.rect(0, 0, W, H, fill=1, stroke=0)
    rgb(CYAN);    c.rect(0, H - 3*mm, W, 3*mm, fill=1, stroke=0)

    # Logo + title
    rgb(CYAN)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(20*mm, H - 18*mm, "AIScan")
    rgb(GREY_LIGHT)
    c.setFont("Helvetica", 11)
    c.drawString(20*mm, H - 25*mm, "AI Content Detection Report")
    rgb(GREY)
    c.setFont("Helvetica", 8)
    c.drawRightString(W - 20*mm, H - 18*mm, date_str)

    # Divider
    srgb(BG_MID); c.setLineWidth(0.5)
    c.line(20*mm, H - 30*mm, W - 20*mm, H - 30*mm)

    # -- Score card --------------------------------------------------------
    card_y = H - 75*mm
    rgb(BG_CARD)
    c.roundRect(20*mm, card_y, W - 40*mm, 38*mm, 3*mm, fill=1, stroke=0)

    # Big score
    rgb(risk_color)
    c.setFont("Helvetica-Bold", 48)
    c.drawString(28*mm, card_y + 16*mm, f"{ai_score:.0f}%")

    # Risk badge
    rgb(risk_color)
    c.roundRect(28*mm, card_y + 8*mm, 22*mm, 6*mm, 1*mm, fill=1, stroke=0)
    rgb(BLACK)
    c.setFont("Helvetica-Bold", 7)
    c.drawCentredString(39*mm, card_y + 10.5*mm, f"{risk_level.upper()} RISK")

    # Classification + LLM
    rgb(WHITE)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(65*mm, card_y + 24*mm, classification)
    rgb(GREY_LIGHT)
    c.setFont("Helvetica", 10)
    c.drawString(65*mm, card_y + 17*mm, f"Suspected: {llm_suspected}")
    c.drawString(65*mm, card_y + 11*mm, f"Confidence: {confidence}")

    # Score bar
    bar_x, bar_y = 28*mm, card_y + 4*mm
    bar_w = W - 56*mm
    rgb(BG_MID)
    c.roundRect(bar_x, bar_y, bar_w, 3*mm, 1*mm, fill=1, stroke=0)
    rgb(risk_color)
    c.roundRect(bar_x, bar_y, bar_w * (ai_score / 100), 3*mm, 1*mm, fill=1, stroke=0)

    # -- File info ---------------------------------------------------------
    y = card_y - 12*mm
    rgb(GREY)
    c.setFont("Helvetica", 8)
    c.drawString(20*mm, y, "FILE")
    rgb(WHITE)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(20*mm, y - 5*mm, filename[:70])

    # -- Reasons -----------------------------------------------------------
    y -= 18*mm
    rgb(GREY)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(20*mm, y, "DETECTION SIGNALS")
    y -= 6*mm

    for reason in (reasons or ["No specific signals detected"])[:5]:
        rgb(BG_CARD)
        c.roundRect(20*mm, y - 2*mm, W - 40*mm, 7*mm, 1*mm, fill=1, stroke=0)
        rgb(CYAN)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(24*mm, y + 0.5*mm, "?")
        rgb(GREY_LIGHT)
        c.setFont("Helvetica", 8)
        c.drawString(28*mm, y + 0.5*mm, reason[:90])
        y -= 9*mm

    # -- Paragraph breakdown -----------------------------------------------
    if paragraph_results:
        y -= 6*mm
        rgb(GREY)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(20*mm, y, "PARAGRAPH ANALYSIS")
        y -= 6*mm

        for i, para in enumerate(paragraph_results[:6]):
            p_score = para.get("score", 0) if isinstance(para, dict) else para.ai_score
            p_cls   = para.get("classification", "") if isinstance(para, dict) else para.classification
            p_text  = para.get("text", "")[:80] if isinstance(para, dict) else para.text[:80]

            p_color = RED if p_score > 75 else AMBER if p_score > 40 else GREEN

            rgb(BG_CARD)
            c.roundRect(20*mm, y - 3*mm, W - 40*mm, 9*mm, 1*mm, fill=1, stroke=0)

            # Score pill
            rgb(p_color)
            c.roundRect(22*mm, y - 1.5*mm, 14*mm, 5*mm, 1*mm, fill=1, stroke=0)
            rgb(BLACK)
            c.setFont("Helvetica-Bold", 7)
            c.drawCentredString(29*mm, y + 0.5*mm, f"{p_score:.0f}%")

            rgb(GREY_LIGHT)
            c.setFont("Helvetica", 7)
            c.drawString(38*mm, y + 1*mm, f"{p_cls}  .  {p_text}...")

            y -= 11*mm
            if y < 30*mm:
                c.showPage()
                rgb(BG_DARK); c.rect(0, 0, W, H, fill=1, stroke=0)
                y = H - 20*mm

    # -- Footer ------------------------------------------------------------
    rgb(BG_MID); c.rect(0, 0, W, 12*mm, fill=1, stroke=0)
    rgb(GREY)
    c.setFont("Helvetica", 7)
    c.drawString(20*mm, 4*mm, "Generated by AIScan v4  .  Offline AI Detection  .  aiscan.app")
    c.drawRightString(W - 20*mm, 4*mm, f"Report ID: {int(time.time())}")

    c.save()
    log.info(f"PDF report saved: {output_path}")
    return output_path


def generate_bulk_report_pdf(summary, output_path: Path) -> Path:
    """Generate a multi-page PDF report for bulk scans."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    W, H = A4
    c = canvas.Canvas(str(output_path), pagesize=A4)

    def rgb(col): c.setFillColorRGB(*col)
    def srgb(col): c.setStrokeColorRGB(*col)

    def new_page():
        c.showPage()
        rgb(BG_DARK); c.rect(0, 0, W, H, fill=1, stroke=0)

    def header(title=""):
        rgb(BG_DARK); c.rect(0, 0, W, H, fill=1, stroke=0)
        rgb(CYAN); c.rect(0, H - 3*mm, W, 3*mm, fill=1, stroke=0)
        rgb(CYAN); c.setFont("Helvetica-Bold", 16); c.drawString(20*mm, H - 17*mm, "AIScan")
        rgb(GREY_LIGHT); c.setFont("Helvetica", 10)
        c.drawString(20*mm, H - 24*mm, title or "Bulk Scan Report")
        rgb(GREY); c.setFont("Helvetica", 8)
        c.drawRightString(W-20*mm, H-18*mm, time.strftime("%B %d, %Y"))
        srgb(BG_MID); c.setLineWidth(0.5)
        c.line(20*mm, H-28*mm, W-20*mm, H-28*mm)

    from reportlab.lib.units import mm

    # PAGE 1  -  Summary
    header("Bulk Scan Report  -  Executive Summary")
    y = H - 40*mm

    # Stats row
    stats = [
        (str(summary.scanned),    "Files Scanned", CYAN),
        (str(summary.high_risk),  "High Risk",     RED),
        (str(summary.medium_risk),"Medium Risk",   AMBER),
        (str(summary.low_risk),   "Low Risk",      GREEN),
        (f"{summary.avg_score:.0f}%", "Avg Score", GREY_LIGHT),
    ]
    box_w = (W - 40*mm) / len(stats)
    for i, (val, label, color) in enumerate(stats):
        bx = 20*mm + i * box_w
        rgb(BG_CARD); c.roundRect(bx, y - 18*mm, box_w - 3*mm, 20*mm, 2*mm, fill=1, stroke=0)
        rgb(color); c.setFont("Helvetica-Bold", 20)
        c.drawCentredString(bx + box_w/2 - 1.5*mm, y - 6*mm, val)
        rgb(GREY); c.setFont("Helvetica", 7)
        c.drawCentredString(bx + box_w/2 - 1.5*mm, y - 13*mm, label)

    y -= 28*mm

    # Folder info
    rgb(GREY); c.setFont("Helvetica", 8); c.drawString(20*mm, y, "SCANNED FOLDER")
    y -= 5*mm
    rgb(WHITE); c.setFont("Helvetica-Bold", 9)
    c.drawString(20*mm, y, str(summary.folder)[:80])
    y -= 4*mm
    rgb(GREY); c.setFont("Helvetica", 8)
    c.drawString(20*mm, y, f"Duration: {summary.duration_seconds:.1f}s  .  {summary.scanned} files scanned")

    y -= 14*mm

    # Results table
    rgb(GREY); c.setFont("Helvetica-Bold", 8); c.drawString(20*mm, y, "ALL FILES  -  SORTED BY RISK")
    y -= 7*mm

    # Table header
    cols = [80*mm, 20*mm, 22*mm, 45*mm]
    headers = ["File Name", "Score", "Risk", "Detected"]
    rgb(BG_MID); c.rect(20*mm, y - 2*mm, W - 40*mm, 7*mm, fill=1, stroke=0)
    x = 20*mm
    for i, (h_txt, cw) in enumerate(zip(headers, cols)):
        rgb(GREY); c.setFont("Helvetica-Bold", 7)
        c.drawString(x + 2*mm, y + 0.5*mm, h_txt)
        x += cw
    y -= 9*mm

    for result in (summary.results or [])[:40]:
        if y < 25*mm:
            # Footer on current page
            rgb(BG_MID); c.rect(0, 0, W, 10*mm, fill=1, stroke=0)
            rgb(GREY); c.setFont("Helvetica", 7)
            c.drawString(20*mm, 3*mm, "AIScan v4  .  aiscan.app")
            new_page()
            header("Bulk Scan Report  -  Continued")
            y = H - 35*mm

        risk = result.risk if hasattr(result, 'risk') else result.get('risk','')
        score = result.score if hasattr(result, 'score') else result.get('score', 0)
        name = result.name if hasattr(result, 'name') else result.get('name', '')
        llm = result.llm if hasattr(result, 'llm') else result.get('llm', '')
        r_color = RED if risk == "High" else AMBER if risk == "Medium" else GREEN

        # Row bg
        rgb(BG_CARD); c.rect(20*mm, y - 2*mm, W - 40*mm, 7*mm, fill=1, stroke=0)

        # Score pill
        x = 20*mm
        rgb(GREY_LIGHT); c.setFont("Helvetica", 7)
        c.drawString(x + 2*mm, y + 0.5*mm, name[:38])
        x += cols[0]

        rgb(r_color); c.setFont("Helvetica-Bold", 7)
        c.drawString(x + 2*mm, y + 0.5*mm, f"{score:.0f}%")
        x += cols[1]

        rgb(r_color); c.setFont("Helvetica-Bold", 7)
        c.drawString(x + 2*mm, y + 0.5*mm, risk)
        x += cols[2]

        rgb(GREY); c.setFont("Helvetica", 7)
        c.drawString(x + 2*mm, y + 0.5*mm, (llm or " - ")[:22])

        y -= 8*mm

    # Footer
    rgb(BG_MID); c.rect(0, 0, W, 10*mm, fill=1, stroke=0)
    rgb(GREY); c.setFont("Helvetica", 7)
    c.drawString(20*mm, 3*mm, f"AIScan v4  .  aiscan.app  .  Report ID: {int(time.time())}")

    c.save()
    log.info(f"Bulk PDF report saved: {output_path}")
    return output_path
