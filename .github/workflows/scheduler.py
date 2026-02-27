"""
AIScan Scheduled Scan Engine
Runs folder scans on a configurable schedule.
Catches historical files, enables compliance audits.

Schedule types:
  - DAILY   (runs at a fixed time each day)
  - WEEKLY  (runs on a specific day of week)
  - STARTUP (runs once when AIScan starts)
  - INTERVAL (every N hours)

Persists schedule to DATA_DIR/schedules.json.
"""
import json, logging, threading, time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Callable

log = logging.getLogger("aiscan")


@dataclass
class ScanSchedule:
    schedule_id: str
    folder: str
    schedule_type: str   # DAILY / WEEKLY / STARTUP / INTERVAL
    hour: int = 22       # for DAILY/WEEKLY
    minute: int = 0
    weekday: int = 0     # 0=Monday for WEEKLY
    interval_hours: int = 24  # for INTERVAL
    enabled: bool = True
    last_run: float = 0.0
    next_run: float = 0.0
    run_count: int = 0
    last_files_found: int = 0
    last_ai_detected: int = 0

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    @property
    def next_run_str(self):
        if self.next_run <= 0:
            return "Not scheduled"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(self.next_run))

    @property
    def last_run_str(self):
        if self.last_run <= 0:
            return "Never"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(self.last_run))


class ScanScheduler:
    """
    Manages scheduled folder scans.
    Runs scan_fn(folder_path) -> (files_scanned, ai_detected) on schedule.
    """

    def __init__(self, data_dir: Path, scan_fn: Callable):
        self._data_dir = data_dir
        self._scan_fn = scan_fn
        self._file = data_dir / "schedules.json"
        self._schedules: List[ScanSchedule] = []
        self._running = False
        self._lock = threading.Lock()
        self._load()
        log.info(f"Scheduler loaded: {len(self._schedules)} schedules")

    def _load(self):
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text(encoding="utf-8"))
                for d in data:
                    self._schedules.append(ScanSchedule(**d))
            except Exception as e:
                log.debug(f"Schedule load error: {e}")

    def _save(self):
        try:
            self._file.write_text(
                json.dumps([s.to_dict() for s in self._schedules], indent=2),
                encoding="utf-8")
        except Exception as e:
            log.debug(f"Schedule save error: {e}")

    def add_schedule(self, folder: str, schedule_type: str,
                     hour: int = 22, minute: int = 0,
                     weekday: int = 0, interval_hours: int = 24) -> ScanSchedule:
        sid = f"sched_{int(time.time())}_{len(self._schedules)}"
        s = ScanSchedule(
            schedule_id=sid,
            folder=folder,
            schedule_type=schedule_type,
            hour=hour, minute=minute,
            weekday=weekday,
            interval_hours=interval_hours,
            next_run=self._compute_next_run(schedule_type, hour, minute,
                                            weekday, interval_hours),
        )
        with self._lock:
            self._schedules.append(s)
        self._save()
        log.info(f"Schedule added: {folder} ({schedule_type}) next={s.next_run_str}")
        return s

    def remove_schedule(self, schedule_id: str):
        with self._lock:
            self._schedules = [s for s in self._schedules
                               if s.schedule_id != schedule_id]
        self._save()

    def _compute_next_run(self, stype, hour, minute, weekday, interval_hours) -> float:
        now = time.time()
        t = time.localtime(now)
        if stype == "STARTUP":
            return now + 5   # 5 seconds after start
        if stype == "INTERVAL":
            return now + interval_hours * 3600
        if stype == "DAILY":
            # Next occurrence of hour:minute
            candidate = time.mktime((t.tm_year, t.tm_mon, t.tm_mday,
                                     hour, minute, 0, 0, 0, -1))
            if candidate <= now:
                candidate += 86400
            return candidate
        if stype == "WEEKLY":
            # Next occurrence of weekday at hour:minute
            days_ahead = (weekday - t.tm_wday) % 7
            if days_ahead == 0:
                candidate = time.mktime((t.tm_year, t.tm_mon, t.tm_mday,
                                         hour, minute, 0, 0, 0, -1))
                if candidate <= now:
                    days_ahead = 7
            if days_ahead > 0:
                import datetime
                d = datetime.date.today() + datetime.timedelta(days=days_ahead)
                candidate = time.mktime((d.year, d.month, d.day,
                                         hour, minute, 0, 0, 0, -1))
            return candidate
        return now + 86400

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True,
                         name="ScanScheduler").start()
        log.info("Scan scheduler started")

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            now = time.time()
            with self._lock:
                due = [s for s in self._schedules
                       if s.enabled and s.next_run > 0 and s.next_run <= now]
            for sched in due:
                self._run_schedule(sched)
            time.sleep(30)  # check every 30 seconds

    def _run_schedule(self, sched: ScanSchedule):
        folder = Path(sched.folder)
        if not folder.exists():
            log.warning(f"Scheduled scan: folder not found: {folder}")
            return

        log.info(f"SCHEDULED SCAN starting: {folder} ({sched.schedule_type})")
        try:
            result = self._scan_fn(folder)
            files = result[0] if isinstance(result, tuple) else 0
            ai_det = result[1] if isinstance(result, tuple) and len(result) > 1 else 0
        except Exception as e:
            log.error(f"Scheduled scan error: {e}")
            files, ai_det = 0, 0

        with self._lock:
            sched.last_run = time.time()
            sched.run_count += 1
            sched.last_files_found = files
            sched.last_ai_detected = ai_det
            sched.next_run = self._compute_next_run(
                sched.schedule_type, sched.hour, sched.minute,
                sched.weekday, sched.interval_hours)
        self._save()

        log.info(f"SCHEDULED SCAN complete: {files} files, {ai_det} AI detections, "
                 f"next={sched.next_run_str}")

    def get_all(self) -> List[ScanSchedule]:
        with self._lock:
            return list(self._schedules)

    def run_now(self, schedule_id: str):
        """Trigger a schedule immediately."""
        with self._lock:
            matches = [s for s in self._schedules if s.schedule_id == schedule_id]
        if matches:
            threading.Thread(target=self._run_schedule,
                             args=(matches[0],), daemon=True).start()


def show_scheduler_ui(scheduler: ScanScheduler):
    threading.Thread(target=_scheduler_ui, args=(scheduler,), daemon=True).start()


def _scheduler_ui(scheduler: ScanScheduler):
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox

        root = tk.Tk()
        root.title("AIScan - Scheduled Scans")
        root.configure(bg="#0d0d14")
        W, H = 680, 420
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        tk.Frame(root, bg="#00e5ff", height=3).pack(fill="x")
        hdr = tk.Frame(root, bg="#0a0a12"); hdr.pack(fill="x")
        tk.Label(hdr, text="Scheduled Scans",
                 font=("Helvetica",13,"bold"),
                 fg="#00e5ff", bg="#0a0a12").pack(side="left", padx=20, pady=14)

        # List existing schedules
        list_frame = tk.Frame(root, bg="#0d0d14")
        list_frame.pack(fill="both", expand=True, padx=16, pady=(12,0))

        style = ttk.Style(); style.theme_use("default")
        style.configure("Treeview", background="#0d0d14",
                        foreground="#e8e8f0", fieldbackground="#0d0d14",
                        rowheight=26, font=("Helvetica",9))
        style.configure("Treeview.Heading", background="#1a1a2e",
                        foreground="#888", font=("Helvetica",9,"bold"))

        cols = ("Folder","Type","Next Run","Last Run","Files","AI Found")
        tree = ttk.Treeview(list_frame, columns=cols, show="headings", height=8)
        for col, w in zip(cols, [200,80,120,120,60,70]):
            tree.heading(col, text=col); tree.column(col, width=w, minwidth=w)
        tree.pack(fill="both", expand=True)

        def refresh():
            for i in tree.get_children(): tree.delete(i)
            for s in scheduler.get_all():
                tree.insert("", "end", iid=s.schedule_id, values=(
                    Path(s.folder).name, s.schedule_type, s.next_run_str,
                    s.last_run_str, s.last_files_found, s.last_ai_detected))

        refresh()

        # Add new schedule form
        form = tk.LabelFrame(root, text="Add Schedule",
                             bg="#0d0d14", fg="#888",
                             font=("Helvetica",9))
        form.pack(fill="x", padx=16, pady=8)

        row1 = tk.Frame(form, bg="#0d0d14"); row1.pack(fill="x", padx=10, pady=6)
        folder_var = tk.StringVar()
        tk.Label(row1, text="Folder:", width=8, anchor="w",
                 font=("Helvetica",9), fg="#888",
                 bg="#0d0d14").pack(side="left")
        tk.Entry(row1, textvariable=folder_var,
                 font=("Helvetica",9), bg="#1a1a2e", fg="#e8e8f0",
                 insertbackground="#fff", relief="flat",
                 width=30).pack(side="left", padx=(4,4))
        tk.Button(row1, text="...",
                  command=lambda: folder_var.set(filedialog.askdirectory() or folder_var.get()),
                  font=("Helvetica",8), fg="#888", bg="#1a1a28",
                  relief="flat", padx=6).pack(side="left")

        type_var = tk.StringVar(value="DAILY")
        hour_var = tk.IntVar(value=22)
        for label_text, var, choices in [
            ("Type:", type_var, ["DAILY","WEEKLY","STARTUP","INTERVAL"]),
        ]:
            rf = tk.Frame(form, bg="#0d0d14"); rf.pack(fill="x", padx=10, pady=3)
            tk.Label(rf, text=label_text, width=8, anchor="w",
                     font=("Helvetica",9), fg="#888", bg="#0d0d14").pack(side="left")
            for choice in choices:
                tk.Radiobutton(rf, text=choice, variable=var, value=choice,
                               font=("Helvetica",9), fg="#888",
                               bg="#0d0d14", activebackground="#0d0d14",
                               selectcolor="#0d0d14").pack(side="left", padx=6)
            tk.Label(rf, text="  Hour:", font=("Helvetica",9),
                     fg="#888", bg="#0d0d14").pack(side="left")
            tk.Spinbox(rf, from_=0, to=23, textvariable=hour_var,
                       width=4, font=("Helvetica",9),
                       bg="#1a1a2e", fg="#e8e8f0").pack(side="left", padx=4)

        def add_schedule():
            folder = folder_var.get().strip()
            if not folder:
                messagebox.showwarning("Missing", "Please select a folder.")
                return
            scheduler.add_schedule(folder, type_var.get(), hour=hour_var.get())
            refresh()
            messagebox.showinfo("Added", f"Schedule added for {Path(folder).name}")

        def remove_selected():
            sel = tree.selection()
            if sel:
                scheduler.remove_schedule(sel[0])
                refresh()

        def run_now():
            sel = tree.selection()
            if sel:
                scheduler.run_now(sel[0])
                messagebox.showinfo("Running", "Scan started in background.")

        bf = tk.Frame(root, bg="#0a0a12"); bf.pack(fill="x", side="bottom")
        tk.Frame(bf, bg="#1a1a2e", height=1).pack(fill="x")
        brow = tk.Frame(bf, bg="#0a0a12"); brow.pack(fill="x", padx=16, pady=8)
        tk.Button(brow, text="Add Schedule", command=add_schedule,
                  font=("Helvetica",10,"bold"), fg="#0d0d14", bg="#00e5ff",
                  relief="flat", padx=14, pady=6).pack(side="right", padx=(6,0))
        tk.Button(brow, text="Run Now", command=run_now,
                  font=("Helvetica",10), fg="#0d0d14", bg="#44cc77",
                  relief="flat", padx=14, pady=6).pack(side="right", padx=(6,0))
        tk.Button(brow, text="Remove", command=remove_selected,
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=14, pady=6).pack(side="right", padx=(6,0))
        tk.Button(brow, text="Close", command=root.destroy,
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=14, pady=6).pack(side="left")
        root.mainloop()
    except Exception as e:
        log.error(f"Scheduler UI error: {e}")
