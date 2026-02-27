"""
AIScan Whitelist / Exceptions Manager
Mark files, folders, or patterns as trusted - suppress further alerts.
Critical for preventing false-positive fatigue.

Types:
  - FILE: exact file path
  - FOLDER: all files under this folder
  - PATTERN: glob pattern (e.g. *.template.docx)
  - HASH: file content hash (survives renames)
"""
import json, hashlib, logging, threading
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
import fnmatch

log = logging.getLogger("aiscan")


@dataclass
class WhitelistEntry:
    entry_type: str  # FILE / FOLDER / PATTERN / HASH
    value: str       # path, pattern, or hash
    label: str       # human note ("Q3 template", "Marketing assets")
    added_at: str
    added_by: str = "user"
    hit_count: int = 0

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


class WhitelistManager:
    """Manages the trusted-file whitelist."""

    def __init__(self, data_dir: Path):
        self._file = data_dir / "whitelist.json"
        self._entries: List[WhitelistEntry] = []
        self._lock = threading.Lock()
        self._load()
        log.info(f"Whitelist loaded: {len(self._entries)} entries")

    def _load(self):
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text(encoding="utf-8"))
                for d in data:
                    self._entries.append(WhitelistEntry(**d))
            except Exception as e:
                log.debug(f"Whitelist load error: {e}")

    def _save(self):
        try:
            self._file.write_text(
                json.dumps([e.to_dict() for e in self._entries], indent=2),
                encoding="utf-8")
        except Exception as e:
            log.debug(f"Whitelist save error: {e}")

    def add_file(self, file_path: Path, label: str = "") -> WhitelistEntry:
        import time
        entry = WhitelistEntry(
            entry_type="FILE",
            value=str(file_path.resolve()),
            label=label or file_path.name,
            added_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        with self._lock:
            self._entries.append(entry)
        self._save()
        log.info(f"Whitelist: added file {file_path.name}")
        return entry

    def add_folder(self, folder: Path, label: str = "") -> WhitelistEntry:
        import time
        entry = WhitelistEntry(
            entry_type="FOLDER",
            value=str(folder.resolve()),
            label=label or folder.name,
            added_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        with self._lock:
            self._entries.append(entry)
        self._save()
        log.info(f"Whitelist: added folder {folder.name}")
        return entry

    def add_pattern(self, pattern: str, label: str = "") -> WhitelistEntry:
        import time
        entry = WhitelistEntry(
            entry_type="PATTERN",
            value=pattern,
            label=label or pattern,
            added_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        with self._lock:
            self._entries.append(entry)
        self._save()
        log.info(f"Whitelist: added pattern {pattern}")
        return entry

    def add_hash(self, file_path: Path, label: str = "") -> Optional[WhitelistEntry]:
        import time
        try:
            h = hashlib.md5(file_path.read_bytes()).hexdigest()
        except Exception:
            return None
        entry = WhitelistEntry(
            entry_type="HASH",
            value=h,
            label=label or file_path.name,
            added_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        with self._lock:
            self._entries.append(entry)
        self._save()
        log.info(f"Whitelist: added hash for {file_path.name} ({h[:8]}...)")
        return entry

    def is_whitelisted(self, file_path: Path) -> bool:
        """
        Returns True if this file should be suppressed.
        Increments hit_count for matched entries.
        """
        path_str = str(file_path.resolve())
        path_name = file_path.name
        file_hash = None  # lazy-compute only if needed

        with self._lock:
            for entry in self._entries:
                matched = False

                if entry.entry_type == "FILE":
                    matched = path_str == entry.value

                elif entry.entry_type == "FOLDER":
                    matched = path_str.startswith(entry.value)

                elif entry.entry_type == "PATTERN":
                    matched = fnmatch.fnmatch(path_name, entry.value)

                elif entry.entry_type == "HASH":
                    if file_hash is None:
                        try:
                            file_hash = hashlib.md5(file_path.read_bytes()).hexdigest()
                        except Exception:
                            file_hash = ""
                    matched = file_hash == entry.value

                if matched:
                    entry.hit_count += 1
                    return True

        return False

    def remove(self, index: int):
        with self._lock:
            if 0 <= index < len(self._entries):
                removed = self._entries.pop(index)
                log.info(f"Whitelist: removed {removed.label}")
        self._save()

    def get_all(self) -> List[WhitelistEntry]:
        with self._lock:
            return list(self._entries)

    def count(self) -> int:
        return len(self._entries)


def show_whitelist_ui(manager: WhitelistManager):
    threading.Thread(target=_whitelist_ui, args=(manager,), daemon=True).start()


def _whitelist_ui(manager: WhitelistManager):
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox

        root = tk.Tk()
        root.title("AIScan - Whitelist / Exceptions")
        root.configure(bg="#0d0d14")
        W, H = 660, 420
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        tk.Frame(root, bg="#44cc77", height=3).pack(fill="x")
        hdr = tk.Frame(root, bg="#0a0a12"); hdr.pack(fill="x")
        tk.Label(hdr, text="Whitelist / Exceptions",
                 font=("Helvetica",13,"bold"),
                 fg="#44cc77", bg="#0a0a12").pack(side="left",padx=20,pady=14)
        tk.Label(hdr, text=f"{manager.count()} entries",
                 font=("Helvetica",9), fg="#555", bg="#0a0a12").pack(side="right",padx=20)

        list_frame = tk.Frame(root, bg="#0d0d14")
        list_frame.pack(fill="both", expand=True, padx=16, pady=12)

        style = ttk.Style(); style.theme_use("default")
        style.configure("Treeview", background="#0d0d14", foreground="#e8e8f0",
                        fieldbackground="#0d0d14", rowheight=26, font=("Helvetica",9))
        style.configure("Treeview.Heading", background="#1a1a2e",
                        foreground="#888", font=("Helvetica",9,"bold"))

        cols = ("Type","Value","Label","Hits","Added")
        tree = ttk.Treeview(list_frame, columns=cols, show="headings", height=10)
        for col, w in zip(cols, [70,240,140,50,110]):
            tree.heading(col, text=col); tree.column(col, width=w, minwidth=w)
        tree.pack(fill="both", expand=True)

        def refresh():
            for i in tree.get_children(): tree.delete(i)
            for e in manager.get_all():
                tree.insert("","end",values=(
                    e.entry_type, e.value[:50], e.label, e.hit_count, e.added_at[:10]))

        refresh()

        def add_file():
            p = filedialog.askopenfilename()
            if p:
                lbl = tk.simpledialog.askstring("Label","Label for this file:",
                                                initialvalue=Path(p).name) if hasattr(tk,'simpledialog') else Path(p).name
                manager.add_file(Path(p), lbl or "")
                refresh()

        def add_folder():
            p = filedialog.askdirectory()
            if p:
                manager.add_folder(Path(p))
                refresh()

        def remove_selected():
            sel = tree.selection()
            if sel:
                idx = tree.index(sel[0])
                manager.remove(idx)
                refresh()

        bf = tk.Frame(root, bg="#0a0a12"); bf.pack(fill="x", side="bottom")
        tk.Frame(bf, bg="#1a1a2e", height=1).pack(fill="x")
        brow = tk.Frame(bf, bg="#0a0a12"); brow.pack(fill="x", padx=16, pady=8)
        tk.Button(brow, text="Add File", command=add_file,
                  font=("Helvetica",10), fg="#0d0d14", bg="#44cc77",
                  relief="flat", padx=12, pady=6).pack(side="right", padx=(6,0))
        tk.Button(brow, text="Add Folder", command=add_folder,
                  font=("Helvetica",10), fg="#0d0d14", bg="#44cc77",
                  relief="flat", padx=12, pady=6).pack(side="right", padx=(6,0))
        tk.Button(brow, text="Remove", command=remove_selected,
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=12, pady=6).pack(side="right", padx=(6,0))
        tk.Button(brow, text="Close", command=root.destroy,
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=12, pady=6).pack(side="left")
        root.mainloop()
    except Exception as e:
        log.error(f"Whitelist UI error: {e}")
