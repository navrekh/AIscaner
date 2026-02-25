"""
AIScan Bulk Scanner + PDF Report Generator
Scan entire folders at once and generate professional PDF/HTML reports.
"""
import json, time, threading, logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable, Optional

log = logging.getLogger("aiscan")

SUPPORTED = {".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".md",
             ".csv", ".py", ".js", ".ts", ".java", ".cpp", ".c"}

@dataclass
class BulkScanResult:
    file: str
    name: str
    score: float
    risk: str
    classification: str
    llm: str
    reasons: list
    error: str = ""
    scan_time: float = 0.0


@dataclass 
class BulkScanSummary:
    folder: str
    total_files: int = 0
    scanned: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    errors: int = 0
    avg_score: float = 0.0
    results: list = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    duration_seconds: float = 0.0


class BulkScanner:
    """Scans an entire folder of documents at once."""

    def __init__(self, extract_fn, detect_fn):
        self.extract_text = extract_fn
        self.detect = detect_fn
        self._running = False
        self._progress_callback: Optional[Callable] = None

    def scan_folder(self,
                    folder: Path,
                    progress_callback: Optional[Callable] = None,
                    recursive: bool = True) -> BulkScanSummary:
        """
        Scan all supported files in a folder.
        progress_callback(current, total, filename) called for each file.
        """
        self._running = True
        summary = BulkScanSummary(
            folder=str(folder),
            started_at=time.time()
        )

        # Find all files
        if recursive:
            files = [f for ext in SUPPORTED
                    for f in folder.rglob(f"*{ext}")]
        else:
            files = [f for ext in SUPPORTED
                    for f in folder.glob(f"*{ext}")]

        # Filter out temp files
        files = [f for f in files
                if not f.name.startswith(("~$", ".", ".~"))
                and f.stat().st_size > 100]

        summary.total_files = len(files)

        for i, file_path in enumerate(files):
            if not self._running:
                break

            if progress_callback:
                progress_callback(i + 1, len(files), file_path.name)

            start = time.time()
            try:
                text = self.extract_text(file_path)
                if not text or len(text.split()) < 15:
                    continue

                result = self.detect(text)
                scan_time = time.time() - start

                bulk_result = BulkScanResult(
                    file=str(file_path),
                    name=file_path.name,
                    score=result.ai_score,
                    risk=result.risk_level,
                    classification=result.classification,
                    llm=result.llm_suspected,
                    reasons=result.reasons,
                    scan_time=round(scan_time, 2)
                )

                summary.results.append(bulk_result)
                summary.scanned += 1

                if result.risk_level == "High":   summary.high_risk += 1
                elif result.risk_level == "Medium": summary.medium_risk += 1
                else:                               summary.low_risk += 1

            except Exception as e:
                log.error(f"Bulk scan error {file_path.name}: {e}")
                summary.errors += 1
                summary.results.append(BulkScanResult(
                    file=str(file_path), name=file_path.name,
                    score=0, risk="Unknown", classification="Error",
                    llm="", reasons=[], error=str(e)
                ))

        summary.completed_at = time.time()
        summary.duration_seconds = summary.completed_at - summary.started_at
        if summary.results:
            summary.avg_score = sum(r.score for r in summary.results) / len(summary.results)

        # Sort by score descending
        summary.results.sort(key=lambda r: r.score, reverse=True)
        self._running = False
        return summary

    def stop(self):
        self._running = False


def generate_html_report(summary: BulkScanSummary, output_path: Path) -> Path:
    """Generate a rich HTML report from a bulk scan."""
    date = time.strftime("%B %d, %Y at %I:%M %p")
    duration = summary.duration_seconds

    rows = ""
    for r in summary.results:
        if r.error:
            rows += f"""<tr><td>{r.name}</td><td colspan="4" style="color:#444">Error: {r.error}</td></tr>"""
            continue
        color = "#ff4455" if r.risk == "High" else "#ffaa00" if r.risk == "Medium" else "#44cc77"
        bar = f'<div style="height:6px;width:{r.score:.0f}%;background:{color};border-radius:3px"></div>'
        reasons = " · ".join(r.reasons[:2]) if r.reasons else "—"
        rows += f"""
        <tr>
            <td style="font-weight:600;color:#e8e8f0">{r.name}</td>
            <td>
                <div style="font-size:1.1em;font-weight:700;color:{color}">{r.score:.0f}%</div>
                {bar}
            </td>
            <td><span style="color:{color};font-weight:600">{r.risk}</span></td>
            <td style="color:#888">{r.llm or '—'}</td>
            <td style="color:#555;font-size:11px">{reasons}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<title>AIScan Bulk Report</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
* {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ background:#0d0d14; color:#e8e8f0; font-family:'DM Sans',sans-serif; font-size:13px }}
.header {{ background:#0a0a10; border-bottom:1px solid #1a1a2e; padding:24px 40px }}
.header h1 {{ font-size:1.4em; font-weight:800 }} .header h1 span {{ color:#00e5ff }}
.header .sub {{ color:#444; font-size:12px; margin-top:4px }}
.stats {{ display:flex; gap:16px; padding:24px 40px }}
.stat {{ background:#111; border:1px solid #1a1a2e; border-radius:10px; padding:20px 24px; flex:1; text-align:center }}
.stat .n {{ font-size:2em; font-weight:800; color:#00e5ff }}
.stat .l {{ font-size:11px; color:#555; margin-top:4px }}
.section {{ padding:0 40px 40px }}
.section h2 {{ font-size:1em; font-weight:700; color:#555; text-transform:uppercase;
               letter-spacing:1px; margin-bottom:12px }}
table {{ width:100%; border-collapse:collapse; background:#111;
         border:1px solid #1a1a2e; border-radius:10px; overflow:hidden }}
th {{ text-align:left; padding:12px 16px; background:#0d0d14; color:#444;
      font-size:11px; text-transform:uppercase; letter-spacing:1px }}
td {{ padding:12px 16px; border-top:1px solid #1a1a2e }}
tr:hover td {{ background:#131320 }}
.badge {{ display:inline-block; padding:2px 10px; border-radius:20px;
          font-size:11px; font-weight:600 }}
.footer {{ padding:24px 40px; color:#333; font-size:11px; border-top:1px solid #1a1a2e }}
</style></head><body>
<div class="header">
    <h1>👁 <span>AI</span>Scan — Bulk Scan Report</h1>
    <div class="sub">Folder: {summary.folder} · Scanned: {date} · Duration: {duration:.1f}s</div>
</div>
<div class="stats">
    <div class="stat"><div class="n">{summary.scanned}</div><div class="l">Files Scanned</div></div>
    <div class="stat"><div class="n" style="color:#ff4455">{summary.high_risk}</div><div class="l">High Risk</div></div>
    <div class="stat"><div class="n" style="color:#ffaa00">{summary.medium_risk}</div><div class="l">Medium Risk</div></div>
    <div class="stat"><div class="n" style="color:#44cc77">{summary.low_risk}</div><div class="l">Low Risk</div></div>
    <div class="stat"><div class="n">{summary.avg_score:.0f}%</div><div class="l">Avg AI Score</div></div>
</div>
<div class="section">
    <h2>All Files — Sorted by AI Score</h2>
    <table>
        <thead><tr>
            <th>File</th><th>AI Score</th><th>Risk</th>
            <th>Suspected LLM</th><th>Reasons</th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>
<div class="footer">
    Generated by AIScan v3 · {summary.scanned} files · {summary.errors} errors
</div>
</body></html>"""

    output_path.write_text(html, encoding="utf-8")
    return output_path


def show_bulk_scan_ui(folder: Path, extract_fn, detect_fn, history_html: Path):
    """Show a bulk scan progress window and generate report."""
    import tkinter as tk
    import tkinter.ttk as ttk
    import webbrowser

    root = tk.Tk()
    root.title("AIScan — Bulk Scan")
    root.configure(bg="#0d0d14")
    root.geometry("520x400")
    root.resizable(False, False)
    root.attributes("-topmost", True)

    # Center
    root.update_idletasks()
    x = (root.winfo_screenwidth()  - 520) // 2
    y = (root.winfo_screenheight() - 400) // 2
    root.geometry(f"520x400+{x}+{y}")

    tk.Frame(root, bg="#00e5ff", height=3).pack(fill="x")
    main = tk.Frame(root, bg="#0d0d14"); main.pack(fill="both", expand=True, padx=24, pady=20)

    tk.Label(main, text="👁 Bulk Scan", font=("Helvetica",14,"bold"),
             fg="#00e5ff", bg="#0d0d14").pack(anchor="w")
    tk.Label(main, text=str(folder), font=("Helvetica",9),
             fg="#444", bg="#0d0d14").pack(anchor="w", pady=(2,16))

    progress_var = tk.DoubleVar()
    bar = ttk.Progressbar(main, variable=progress_var, maximum=100,
                          length=460, style="TProgressbar")
    bar.pack(fill="x")

    status_var = tk.StringVar(value="Starting scan...")
    tk.Label(main, textvariable=status_var, font=("Helvetica",9),
             fg="#666", bg="#0d0d14").pack(anchor="w", pady=(6,16))

    stats_frame = tk.Frame(main, bg="#0d0d14"); stats_frame.pack(fill="x")
    high_var   = tk.StringVar(value="0")
    medium_var = tk.StringVar(value="0")
    total_var  = tk.StringVar(value="0")

    for label, var, color in [("High Risk", high_var, "#ff4455"),
                               ("Medium Risk", medium_var, "#ffaa00"),
                               ("Scanned", total_var, "#00e5ff")]:
        f = tk.Frame(stats_frame, bg="#111", padx=16, pady=12); f.pack(side="left", padx=(0,8))
        tk.Label(f, textvariable=var, font=("Helvetica",18,"bold"),
                 fg=color, bg="#111").pack()
        tk.Label(f, text=label, font=("Helvetica",9),
                 fg="#555", bg="#111").pack()

    result_var = tk.StringVar()
    tk.Label(main, textvariable=result_var, font=("Helvetica",9),
             fg="#44cc77", bg="#0d0d14").pack(pady=(16,0))

    btn_frame = tk.Frame(main, bg="#0d0d14"); btn_frame.pack(pady=(8,0))
    report_btn = tk.Button(btn_frame, text="View Report",
                           font=("Helvetica",10,"bold"), fg="#0d0d14", bg="#00e5ff",
                           relief="flat", padx=16, pady=6, cursor="hand2", state="disabled")
    report_btn.pack(side="left", padx=(0,8))
    tk.Button(btn_frame, text="Close", command=root.destroy,
              font=("Helvetica",10), fg="#888", bg="#1a1a28",
              relief="flat", padx=16, pady=6, cursor="hand2").pack(side="left")

    report_path = [None]

    def run_scan():
        scanner = BulkScanner(extract_fn, detect_fn)

        def on_progress(current, total, filename):
            pct = (current / total * 100) if total > 0 else 0
            progress_var.set(pct)
            status_var.set(f"Scanning {current}/{total}: {filename}")
            total_var.set(str(current))

        summary = scanner.scan_folder(folder, on_progress)

        # Generate report
        report_file = folder / "AIScan_Report.html"
        generate_html_report(summary, report_file)
        report_path[0] = report_file

        high_var.set(str(summary.high_risk))
        medium_var.set(str(summary.medium_risk))
        total_var.set(str(summary.scanned))
        progress_var.set(100)
        status_var.set(f"Complete! {summary.scanned} files in {summary.duration_seconds:.1f}s")
        result_var.set(f"Report saved: {report_file.name}")
        report_btn.config(state="normal",
            command=lambda: webbrowser.open(report_path[0].as_uri()))

    threading.Thread(target=run_scan, daemon=True).start()
    root.mainloop()
