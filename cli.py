"""
AIScan CLI - Command Line Interface
Enables scripting, CI/CD integration, and developer workflows.

Usage:
  aiscan scan <file>                  -- scan a single file
  aiscan scan <file> --json           -- JSON output
  aiscan bulk <folder>                -- bulk scan a folder
  aiscan bulk <folder> --extensions docx,pdf,txt
  aiscan benchmark                   -- run accuracy benchmark
  aiscan pii <file>                  -- PII scan only
  aiscan version                     -- show version info
  aiscan help                        -- show help

Exit codes:
  0  -- clean (no AI detected, no critical PII)
  1  -- AI detected
  2  -- critical PII detected
  3  -- both AI and critical PII
  10 -- file not found / error
"""
import sys, json, time, argparse, logging
from pathlib import Path

log = logging.getLogger("aiscan")


def _setup_sys_path():
    """Ensure aiscan modules are findable."""
    exe_dir = Path(sys.executable).parent
    script_dir = Path(__file__).parent
    for d in [script_dir, exe_dir]:
        if str(d) not in sys.path:
            sys.path.insert(0, str(d))


def cmd_scan(args):
    """Scan a single file."""
    _setup_sys_path()
    file_path = Path(args.file)
    if not file_path.exists():
        _error(f"File not found: {file_path}", exit_code=10)

    try:
        from agent_standalone import _detect, _read_file
        text = _read_file(file_path)
        if not text:
            _error(f"Could not read file: {file_path}", exit_code=10)

        result = _detect(text)

        if args.json:
            out = {
                "file": str(file_path),
                "ai_score": result.ai_score,
                "classification": result.classification,
                "risk_level": result.risk_level,
                "llm_suspected": result.llm_suspected,
                "confidence": result.confidence,
                "reasons": result.reasons,
                "paragraphs": len(result.paragraph_results),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            print(json.dumps(out, indent=2))
        else:
            col = _ansi_color(result.risk_level)
            print(f"\n{col}AIScan Result{_RESET}")
            print(f"  File:           {file_path.name}")
            print(f"  AI Score:       {result.ai_score:.1f}%")
            print(f"  Classification: {col}{result.classification}{_RESET}")
            print(f"  Risk:           {col}{result.risk_level}{_RESET}")
            print(f"  LLM suspected:  {result.llm_suspected}")
            print(f"  Confidence:     {result.confidence}")
            if result.reasons:
                print(f"  Reasons:")
                for r in result.reasons:
                    print(f"    - {r}")

        # Exit code
        is_ai = result.ai_score >= 35
        sys.exit(1 if is_ai else 0)

    except Exception as e:
        _error(f"Scan error: {e}", exit_code=10)


def cmd_bulk(args):
    """Bulk scan a folder."""
    _setup_sys_path()
    folder = Path(args.folder)
    if not folder.exists():
        _error(f"Folder not found: {folder}", exit_code=10)

    extensions = set(args.extensions.split(",")) if args.extensions else {
        "txt","docx","pdf","doc","rtf","md","odt"
    }

    try:
        from agent_standalone import _detect, _read_file

        files = []
        for ext in extensions:
            files.extend(folder.rglob(f"*.{ext}"))
        files = sorted(set(files))

        if not files:
            print(f"No files found in {folder} with extensions: {extensions}")
            sys.exit(0)

        results = []
        ai_count = 0
        total = len(files)

        for i, fp in enumerate(files, 1):
            if not args.json:
                print(f"\r  Scanning {i}/{total}: {fp.name[:40]:<40}", end="", flush=True)
            try:
                text = _read_file(fp)
                if text:
                    r = _detect(text)
                    is_ai = r.ai_score >= 35
                    if is_ai:
                        ai_count += 1
                    results.append({
                        "file": str(fp),
                        "ai_score": r.ai_score,
                        "classification": r.classification,
                        "risk_level": r.risk_level,
                        "is_ai": is_ai,
                    })
            except Exception:
                pass

        if not args.json:
            print()  # newline after progress

        if args.json:
            print(json.dumps({
                "folder": str(folder),
                "files_scanned": total,
                "ai_detected": ai_count,
                "clean": total - ai_count,
                "results": results,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }, indent=2))
        else:
            col_h = "\033[91m" if ai_count > 0 else "\033[92m"
            print(f"\n{col_h}Bulk Scan Complete{_RESET}")
            print(f"  Files scanned:  {total}")
            print(f"  AI detected:    {col_h}{ai_count}{_RESET}")
            print(f"  Clean:          {total - ai_count}")
            if ai_count:
                print(f"\n  Flagged files:")
                for r in results:
                    if r["is_ai"]:
                        c = _ansi_color(r["risk_level"])
                        print(f"    {c}{r['ai_score']:5.1f}%{_RESET}  {Path(r['file']).name}")

        sys.exit(1 if ai_count > 0 else 0)

    except Exception as e:
        _error(f"Bulk scan error: {e}", exit_code=10)


def cmd_benchmark(args):
    """Run accuracy benchmark."""
    _setup_sys_path()
    try:
        import importlib.util as ilu
        spec = ilu.spec_from_file_location("benchmark",
            Path(__file__).parent / "benchmark.py")
        bm = ilu.module_from_spec(spec); spec.loader.exec_module(bm)
        from agent_standalone import _detect

        if not args.json:
            print("Running AIScan accuracy benchmark...")

        m = bm.run_benchmark(_detect)

        if args.json:
            print(json.dumps(m.to_dict(), indent=2))
        else:
            col = "\033[92m" if m.accuracy >= 0.85 else "\033[93m"
            print(f"\n{col}Benchmark Results{_RESET}")
            print(f"  Accuracy:         {col}{m.accuracy*100:.1f}%{_RESET}")
            print(f"  Precision (AI):   {m.precision_ai*100:.1f}%")
            print(f"  Recall (AI):      {m.recall_ai*100:.1f}%")
            print(f"  F1 Score:         {m.f1_ai:.3f}")
            print(f"  False Pos Rate:   {m.false_positive_rate*100:.1f}%")
            print(f"  False Neg Rate:   {m.false_negative_rate*100:.1f}%")
            print(f"  Score separation: {m.score_separation:.1f}pts")
            print(f"  Samples tested:   {m.total}")

        sys.exit(0)
    except Exception as e:
        _error(f"Benchmark error: {e}", exit_code=10)


def cmd_pii(args):
    """PII scan a file."""
    _setup_sys_path()
    file_path = Path(args.file)
    if not file_path.exists():
        _error(f"File not found: {file_path}", exit_code=10)

    try:
        import importlib.util as ilu
        spec = ilu.spec_from_file_location("security_mode",
            Path(__file__).parent / "security_mode.py")
        sec = ilu.module_from_spec(spec); spec.loader.exec_module(sec)

        scanner = sec.SecurityScanner(sec.SecuritySettings())
        text = file_path.read_text(encoding="utf-8", errors="replace")
        result = scanner.scan_file_content(text, str(file_path))

        if args.json:
            print(json.dumps({
                "file": str(file_path),
                "pii_found": result.pii_found if hasattr(result,"pii_found") else False,
                "severity": result.severity if hasattr(result,"severity") else "NONE",
                "findings": result.findings if hasattr(result,"findings") else [],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }, indent=2))
        else:
            found = getattr(result,"pii_found",False)
            sev = getattr(result,"severity","NONE")
            col = _ansi_color(sev) if found else "\033[92m"
            print(f"\n{col}PII Scan Result{_RESET}")
            print(f"  File:     {file_path.name}")
            print(f"  PII:      {col}{'Found' if found else 'None detected'}{_RESET}")
            print(f"  Severity: {col}{sev}{_RESET}")
            if hasattr(result, "findings") and result.findings:
                for f in result.findings[:5]:
                    print(f"    - {f}")

        sev = getattr(result,"severity","NONE")
        sys.exit(2 if sev in ("CRITICAL","HIGH") else 0)

    except Exception as e:
        _error(f"PII scan error: {e}", exit_code=10)


def cmd_version(args):
    print("AIScan v6.0.0")
    print("AI Content Detection + Security + Compliance")
    print("100% offline  |  Made for India  |  DPDP compliant")
    sys.exit(0)


# ANSI colors
_RESET = "\033[0m"
def _ansi_color(risk):
    return {
        "CRITICAL":"\033[91m","HIGH":"\033[91m",
        "MEDIUM":"\033[93m","Low":"\033[92m","Low ":"\033[92m"
    }.get(risk, "\033[93m")

def _error(msg, exit_code=1):
    print(f"\033[91mError: {msg}{_RESET}", file=sys.stderr)
    sys.exit(exit_code)


def main():
    parser = argparse.ArgumentParser(
        prog="aiscan",
        description="AIScan - AI Content Detection & Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aiscan scan report.docx
  aiscan scan report.docx --json
  aiscan bulk C:\\Users\\me\\Documents
  aiscan bulk /home/user/docs --extensions txt,md,docx
  aiscan benchmark
  aiscan pii contract.pdf
  aiscan version
        """)

    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a single file")
    p_scan.add_argument("file", help="File to scan")
    p_scan.add_argument("--json", action="store_true", help="JSON output")
    p_scan.set_defaults(func=cmd_scan)

    # bulk
    p_bulk = sub.add_parser("bulk", help="Bulk scan a folder")
    p_bulk.add_argument("folder", help="Folder to scan")
    p_bulk.add_argument("--extensions", default="", help="Comma-separated extensions")
    p_bulk.add_argument("--json", action="store_true", help="JSON output")
    p_bulk.set_defaults(func=cmd_bulk)

    # benchmark
    p_bm = sub.add_parser("benchmark", help="Run accuracy benchmark")
    p_bm.add_argument("--json", action="store_true", help="JSON output")
    p_bm.set_defaults(func=cmd_benchmark)

    # pii
    p_pii = sub.add_parser("pii", help="PII scan a file")
    p_pii.add_argument("file", help="File to scan")
    p_pii.add_argument("--json", action="store_true", help="JSON output")
    p_pii.set_defaults(func=cmd_pii)

    # version
    p_ver = sub.add_parser("version", help="Show version")
    p_ver.set_defaults(func=cmd_version)

    # help
    p_help = sub.add_parser("help", help="Show help")
    p_help.set_defaults(func=lambda a: parser.print_help())

    args = parser.parse_args()
    if not hasattr(args, "func") or args.command is None:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
