"""
AIScan Quarantine System
Moves suspicious files to a quarantine folder instead of just alerting.
Transforms from detection to prevention.

Features:
  - One-click quarantine from any alert popup
  - Quarantine folder with metadata (why quarantined, original path)
  - Restore with one click
  - Auto-quarantine option for CRITICAL PII
  - Quarantine log for compliance evidence
"""
import os, sys, json, time, shutil, logging, threading
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

log = logging.getLogger("aiscan")


@dataclass
class QuarantineEntry:
    original_path: str
    quarantine_path: str
    reason: str          # AI_DETECTION / PII_CRITICAL / THREAT
    severity: str
    score: float
    quarantined_at: str
    restored: bool = False
    restored_at: str = ""

    def to_dict(self):
        return {
            "original_path":  self.original_path,
            "quarantine_path": self.quarantine_path,
            "reason":         self.reason,
            "severity":       self.severity,
            "score":          self.score,
            "quarantined_at": self.quarantined_at,
            "restored":       self.restored,
            "restored_at":    self.restored_at,
        }


class QuarantineManager:
    """
    Manages the quarantine folder.
    Quarantine folder: DATA_DIR/quarantine/
    Each file is moved there with a .quarantine_meta JSON sidecar.
    """

    def __init__(self, data_dir: Path):
        self._data_dir = data_dir
        self._quarantine_dir = data_dir / "quarantine"
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = data_dir / "quarantine_log.jsonl"
        self._entries: List[QuarantineEntry] = []
        self._lock = threading.Lock()
        self._load_log()
        log.info(f"Quarantine ready: {len(self._entries)} entries, "
                 f"folder: {self._quarantine_dir}")

    def _load_log(self):
        if self._log_file.exists():
            for line in self._log_file.read_text(encoding="utf-8").splitlines():
                try:
                    d = json.loads(line)
                    self._entries.append(QuarantineEntry(**d))
                except Exception:
                    pass

    def _save_entry(self, entry: QuarantineEntry):
        with open(self._log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

    def quarantine_file(self, file_path: Path, reason: str,
                        severity: str, score: float = 0.0) -> Optional[QuarantineEntry]:
        """
        Move file to quarantine. Returns entry or None if failed.
        """
        if not file_path.exists():
            log.warning(f"Quarantine: file not found: {file_path}")
            return None

        try:
            ts = time.strftime("%Y%m%d_%H%M%S")
            safe_name = f"{ts}_{file_path.name}"
            dest = self._quarantine_dir / safe_name

            # Move the file
            shutil.move(str(file_path), str(dest))

            entry = QuarantineEntry(
                original_path=str(file_path),
                quarantine_path=str(dest),
                reason=reason,
                severity=severity,
                score=score,
                quarantined_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            )

            with self._lock:
                self._entries.append(entry)
            self._save_entry(entry)

            log.info(f"QUARANTINE: {file_path.name} -> {safe_name} "
                     f"[{severity}] reason={reason}")
            return entry

        except PermissionError:
            log.warning(f"Quarantine: permission denied for {file_path}")
            return None
        except Exception as e:
            log.error(f"Quarantine error for {file_path}: {e}")
            return None

    def restore_file(self, entry: QuarantineEntry) -> bool:
        """Restore a quarantined file to its original location."""
        qpath = Path(entry.quarantine_path)
        opath = Path(entry.original_path)

        if not qpath.exists():
            log.warning(f"Quarantine restore: file missing: {qpath}")
            return False

        try:
            opath.parent.mkdir(parents=True, exist_ok=True)
            # If original path exists, add suffix to avoid overwrite
            if opath.exists():
                opath = opath.with_stem(opath.stem + "_restored")
            shutil.move(str(qpath), str(opath))
            entry.restored = True
            entry.restored_at = time.strftime("%Y-%m-%d %H:%M:%S")
            log.info(f"QUARANTINE RESTORE: {qpath.name} -> {opath}")
            return True
        except Exception as e:
            log.error(f"Quarantine restore error: {e}")
            return False

    def get_active(self) -> List[QuarantineEntry]:
        with self._lock:
            return [e for e in self._entries if not e.restored]

    def get_all(self) -> List[QuarantineEntry]:
        with self._lock:
            return list(self._entries)

    def stats(self) -> dict:
        entries = self.get_all()
        return {
            "total": len(entries),
            "active": sum(1 for e in entries if not e.restored),
            "restored": sum(1 for e in entries if e.restored),
            "critical": sum(1 for e in entries if e.severity == "CRITICAL" and not e.restored),
        }


def show_quarantine_manager_ui(manager: QuarantineManager):
    """Show a UI to review and restore quarantined files."""
    threading.Thread(target=_quarantine_ui, args=(manager,), daemon=True).start()


def _quarantine_ui(manager: QuarantineManager):
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.title("AIScan - Quarantine Manager")
        root.configure(bg="#0d0d14")
        root.geometry("720x480")

        W, H = 720, 480
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        tk.Frame(root, bg="#ff6600", height=3).pack(fill="x")
        hdr = tk.Frame(root, bg="#0a0a12"); hdr.pack(fill="x")
        tk.Label(hdr, text="Quarantine Manager",
                 font=("Helvetica",13,"bold"),
                 fg="#ff6600", bg="#0a0a12").pack(side="left",padx=20,pady=14)
        stats = manager.stats()
        tk.Label(hdr, text=f"{stats['active']} active  |  {stats['restored']} restored",
                 font=("Helvetica",9), fg="#555",
                 bg="#0a0a12").pack(side="right",padx=20)

        # File list
        list_frame = tk.Frame(root, bg="#0d0d14"); list_frame.pack(fill="both", expand=True, padx=16, pady=12)
        
        cols = ("File", "Reason", "Severity", "Date", "Status")
        tree_frame = tk.Frame(list_frame, bg="#0d0d14")
        tree_frame.pack(fill="both", expand=True)

        from tkinter import ttk
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
            background="#0d0d14", foreground="#e8e8f0",
            fieldbackground="#0d0d14", rowheight=28,
            font=("Helvetica",9))
        style.configure("Treeview.Heading",
            background="#1a1a2e", foreground="#888",
            font=("Helvetica",9,"bold"))

        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=14)
        for col, w in zip(cols, [200,100,80,130,80]):
            tree.heading(col, text=col)
            tree.column(col, width=w, minwidth=w)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def refresh():
            for item in tree.get_children():
                tree.delete(item)
            for entry in manager.get_all():
                status = "Restored" if entry.restored else "Quarantined"
                tree.insert("", "end", values=(
                    Path(entry.original_path).name,
                    entry.reason,
                    entry.severity,
                    entry.quarantined_at[:16],
                    status,
                ), tags=("restored" if entry.restored else "active",))
            tree.tag_configure("active",    foreground="#ff6600")
            tree.tag_configure("restored",  foreground="#555")

        refresh()

        def restore_selected():
            sel = tree.selection()
            if not sel: return
            idx = tree.index(sel[0])
            entries = manager.get_all()
            if idx >= len(entries): return
            entry = entries[idx]
            if entry.restored:
                messagebox.showinfo("Already Restored", "This file has already been restored.")
                return
            ok = manager.restore_file(entry)
            if ok:
                messagebox.showinfo("Restored", f"File restored to:\n{entry.original_path}")
                refresh()
            else:
                messagebox.showerror("Error", "Could not restore file. Check permissions.")

        bf = tk.Frame(root, bg="#0a0a12"); bf.pack(fill="x", side="bottom")
        tk.Frame(bf, bg="#1a1a2e", height=1).pack(fill="x")
        brow = tk.Frame(bf, bg="#0a0a12"); brow.pack(fill="x", padx=16, pady=10)
        tk.Button(brow, text="Restore Selected",
                  command=restore_selected,
                  font=("Helvetica",10,"bold"),
                  fg="#0d0d14", bg="#ff6600",
                  relief="flat", padx=16, pady=7).pack(side="right", padx=(8,0))
        tk.Button(brow, text="Refresh",
                  command=refresh,
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=16, pady=7).pack(side="right")
        tk.Button(brow, text="Close",
                  command=root.destroy,
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=16, pady=7).pack(side="left")

        root.mainloop()
    except Exception as e:
        log.error(f"Quarantine UI error: {e}")
