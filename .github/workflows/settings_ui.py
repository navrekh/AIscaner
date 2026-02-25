"""
AIScan Settings UI
Full configuration panel for sensitivity, watched folders,
notification preferences, and app behavior.
"""
import json, logging
from pathlib import Path
from dataclasses import dataclass, asdict, field

log = logging.getLogger("aiscan")


@dataclass
class AIScanSettings:
    # Detection
    sensitivity: str = "Medium"        # Low / Medium / High
    min_word_count: int = 30
    show_low_risk: bool = False
    show_medium_risk: bool = True
    show_high_risk: bool = True

    # Screen monitor
    screen_monitor_enabled: bool = True
    screen_interval_seconds: int = 4

    # Clipboard
    clipboard_enabled: bool = True
    clipboard_min_words: int = 30

    # Watched folders
    watch_documents: bool = True
    watch_desktop: bool = True
    watch_downloads: bool = True
    watch_onedrive: bool = True
    watch_google_drive: bool = True
    watch_dropbox: bool = True
    custom_folders: list = field(default_factory=list)

    # Notifications
    popup_duration_seconds: int = 12
    show_reasons: bool = True
    play_sound: bool = False

    # Thresholds
    low_threshold: int = 35      # below = human
    medium_threshold: int = 60   # below = AI-assisted, above = AI-generated

    # Reports
    auto_save_reports: bool = False
    reports_folder: str = ""


SENSITIVITY_PRESETS = {
    "Low":    {"min_word_count": 60, "low_threshold": 50, "medium_threshold": 75},
    "Medium": {"min_word_count": 30, "low_threshold": 35, "medium_threshold": 60},
    "High":   {"min_word_count": 15, "low_threshold": 25, "medium_threshold": 45},
}


class SettingsManager:
    def __init__(self, data_dir: Path):
        self.settings_file = data_dir / "settings.json"
        self.settings = self._load()

    def _load(self) -> AIScanSettings:
        if self.settings_file.exists():
            try:
                d = json.loads(self.settings_file.read_text())
                return AIScanSettings(**{k: v for k, v in d.items()
                                        if k in AIScanSettings.__dataclass_fields__})
            except: pass
        return AIScanSettings()

    def save(self):
        self.settings_file.write_text(json.dumps(asdict(self.settings), indent=2))
        log.info("Settings saved")

    def apply_sensitivity(self, level: str):
        preset = SENSITIVITY_PRESETS.get(level, SENSITIVITY_PRESETS["Medium"])
        self.settings.sensitivity = level
        self.settings.min_word_count  = preset["min_word_count"]
        self.settings.low_threshold   = preset["low_threshold"]
        self.settings.medium_threshold = preset["medium_threshold"]
        self.save()


def show_settings_window(settings_manager, restart_callback=None):
    """Show the full settings window."""
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    s = settings_manager.settings
    root = tk.Tk()
    root.title("AIScan Settings")
    root.configure(bg="#0d0d14")
    root.geometry("560x680")
    root.resizable(False, True)
    root.attributes("-topmost", True)

    # Center
    root.update_idletasks()
    x = (root.winfo_screenwidth()  - 560) // 2
    y = (root.winfo_screenheight() - 680) // 2
    root.geometry(f"560x680+{x}+{y}")

    # Style
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TNotebook",        background="#0d0d14", borderwidth=0)
    style.configure("TNotebook.Tab",    background="#111", foreground="#555",
                    padding=[14, 6], font=("Helvetica", 9))
    style.map("TNotebook.Tab",
              background=[("selected","#1a1a2e")],
              foreground=[("selected","#00e5ff")])
    style.configure("TCheckbutton",     background="#0d0d14", foreground="#e8e8f0",
                    font=("Helvetica", 10))
    style.map("TCheckbutton",           background=[("active","#0d0d14")])
    style.configure("Vertical.TScrollbar", background="#1a1a2e", troughcolor="#0d0d14")

    # Header
    tk.Frame(root, bg="#00e5ff", height=3).pack(fill="x")
    hdr = tk.Frame(root, bg="#0a0a10"); hdr.pack(fill="x", padx=0, pady=0)
    tk.Label(hdr, text="⚙  AIScan Settings", font=("Helvetica",13,"bold"),
             fg="#00e5ff", bg="#0a0a10").pack(side="left", padx=20, pady=12)
    tk.Label(hdr, text="v4", font=("Helvetica",9),
             fg="#333", bg="#0a0a10").pack(side="left")

    # Tabs
    nb = ttk.Notebook(root); nb.pack(fill="both", expand=True, padx=0, pady=0)

    def make_tab(label):
        frame = tk.Frame(nb, bg="#0d0d14")
        nb.add(frame, text=label)
        canvas = tk.Canvas(frame, bg="#0d0d14", highlightthickness=0)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=scroll.set)
        inner = tk.Frame(canvas, bg="#0d0d14")
        win = canvas.create_window((0,0), window=inner, anchor="nw")
        def on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(win, width=canvas.winfo_width())
        inner.bind("<Configure>", on_configure)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))
        return inner

    def section(parent, title):
        tk.Label(parent, text=title, font=("Helvetica",9,"bold"),
                 fg="#555", bg="#0d0d14").pack(anchor="w", padx=20, pady=(16,4))
        tk.Frame(parent, bg="#1a1a2e", height=1).pack(fill="x", padx=20, pady=(0,8))

    def row(parent, label, widget_fn):
        f = tk.Frame(parent, bg="#111", padx=16, pady=10); f.pack(fill="x", padx=20, pady=2)
        tk.Label(f, text=label, font=("Helvetica",10), fg="#e8e8f0",
                 bg="#111", anchor="w").pack(side="left")
        w = widget_fn(f); w.pack(side="right")
        return w

    def check(parent, label, var):
        f = tk.Frame(parent, bg="#111", padx=16, pady=8); f.pack(fill="x", padx=20, pady=2)
        cb = tk.Checkbutton(f, text=label, variable=var, font=("Helvetica",10),
                            fg="#e8e8f0", bg="#111", selectcolor="#1a1a2e",
                            activebackground="#111", activeforeground="#e8e8f0",
                            cursor="hand2")
        cb.pack(anchor="w")
        return cb

    # ── TAB 1: Detection ──────────────────────────────────────────────────
    t1 = make_tab("  Detection  ")

    section(t1, "SENSITIVITY")
    sens_var = tk.StringVar(value=s.sensitivity)
    f_sens = tk.Frame(t1, bg="#111", padx=16, pady=12); f_sens.pack(fill="x", padx=20, pady=2)
    tk.Label(f_sens, text="Sensitivity Level", font=("Helvetica",10),
             fg="#e8e8f0", bg="#111").pack(side="left")
    for level, desc in [("Low","Fewer alerts, fewer false positives"),
                         ("Medium","Balanced (recommended)"),
                         ("High","Maximum detection, more alerts")]:
        rf = tk.Frame(t1, bg="#0d0d14"); rf.pack(fill="x", padx=32, pady=1)
        tk.Radiobutton(rf, text=f"{level} — {desc}", variable=sens_var, value=level,
                       font=("Helvetica",9), fg="#888", bg="#0d0d14",
                       selectcolor="#1a1a2e", activebackground="#0d0d14",
                       cursor="hand2").pack(anchor="w")

    section(t1, "ALERT THRESHOLDS")
    min_words_var = tk.IntVar(value=s.min_word_count)
    row(t1, "Minimum words to scan", lambda p: tk.Spinbox(
        p, from_=10, to=200, textvariable=min_words_var, width=6,
        font=("Helvetica",10), bg="#1a1a2e", fg="#e8e8f0",
        buttonbackground="#1a1a2e", relief="flat"))

    section(t1, "SHOW POPUPS FOR")
    show_low_var    = tk.BooleanVar(value=s.show_low_risk)
    show_medium_var = tk.BooleanVar(value=s.show_medium_risk)
    show_high_var   = tk.BooleanVar(value=s.show_high_risk)
    check(t1, "Low risk files (0–35%)",    show_low_var)
    check(t1, "Medium risk files (35–60%)", show_medium_var)
    check(t1, "High risk files (60%+)",     show_high_var)

    # ── TAB 2: Monitoring ─────────────────────────────────────────────────
    t2 = make_tab("  Monitoring  ")

    section(t2, "SCREEN MONITOR")
    screen_enabled_var = tk.BooleanVar(value=s.screen_monitor_enabled)
    check(t2, "Enable real-time screen monitoring", screen_enabled_var)
    screen_interval_var = tk.IntVar(value=s.screen_interval_seconds)
    row(t2, "Scan interval (seconds)", lambda p: tk.Spinbox(
        p, from_=2, to=30, textvariable=screen_interval_var, width=6,
        font=("Helvetica",10), bg="#1a1a2e", fg="#e8e8f0",
        buttonbackground="#1a1a2e", relief="flat"))

    section(t2, "CLIPBOARD MONITOR")
    clipboard_var = tk.BooleanVar(value=s.clipboard_enabled)
    check(t2, "Monitor clipboard for AI content", clipboard_var)
    clip_words_var = tk.IntVar(value=s.clipboard_min_words)
    row(t2, "Min words to scan clipboard", lambda p: tk.Spinbox(
        p, from_=10, to=200, textvariable=clip_words_var, width=6,
        font=("Helvetica",10), bg="#1a1a2e", fg="#e8e8f0",
        buttonbackground="#1a1a2e", relief="flat"))

    section(t2, "WATCHED FOLDERS")
    folder_vars = {}
    for key, label in [
        ("watch_documents",    "Documents"),
        ("watch_desktop",      "Desktop"),
        ("watch_downloads",    "Downloads"),
        ("watch_onedrive",     "OneDrive"),
        ("watch_google_drive", "Google Drive"),
        ("watch_dropbox",      "Dropbox"),
    ]:
        v = tk.BooleanVar(value=getattr(s, key))
        check(t2, label, v)
        folder_vars[key] = v

    # Custom folders
    section(t2, "CUSTOM FOLDERS")
    custom_frame = tk.Frame(t2, bg="#0d0d14"); custom_frame.pack(fill="x", padx=20)
    custom_list = tk.Listbox(custom_frame, bg="#111", fg="#e8e8f0", height=3,
                              selectbackground="#1a1a2e", font=("Helvetica",9),
                              relief="flat", borderwidth=0)
    custom_list.pack(fill="x", pady=4)
    for folder in s.custom_folders:
        custom_list.insert("end", folder)

    btn_row = tk.Frame(t2, bg="#0d0d14"); btn_row.pack(fill="x", padx=20, pady=4)
    def add_folder():
        folder = filedialog.askdirectory(title="Select folder to watch")
        if folder:
            custom_list.insert("end", folder)
    def remove_folder():
        sel = custom_list.curselection()
        if sel: custom_list.delete(sel[0])
    tk.Button(btn_row, text="+ Add Folder", command=add_folder,
              font=("Helvetica",9), fg="#0d0d14", bg="#00e5ff",
              relief="flat", padx=10, pady=4, cursor="hand2").pack(side="left", padx=(0,6))
    tk.Button(btn_row, text="Remove", command=remove_folder,
              font=("Helvetica",9), fg="#888", bg="#1a1a28",
              relief="flat", padx=10, pady=4, cursor="hand2").pack(side="left")

    # ── TAB 3: Notifications ──────────────────────────────────────────────
    t3 = make_tab("  Notifications  ")

    section(t3, "POPUP SETTINGS")
    popup_dur_var = tk.IntVar(value=s.popup_duration_seconds)
    row(t3, "Popup duration (seconds)", lambda p: tk.Spinbox(
        p, from_=3, to=60, textvariable=popup_dur_var, width=6,
        font=("Helvetica",10), bg="#1a1a2e", fg="#e8e8f0",
        buttonbackground="#1a1a2e", relief="flat"))
    show_reasons_var = tk.BooleanVar(value=s.show_reasons)
    check(t3, "Show detection reasons in popup", show_reasons_var)
    sound_var = tk.BooleanVar(value=s.play_sound)
    check(t3, "Play sound on detection", sound_var)

    # ── TAB 4: Reports ────────────────────────────────────────────────────
    t4 = make_tab("  Reports  ")

    section(t4, "AUTOMATIC REPORTS")
    auto_report_var = tk.BooleanVar(value=s.auto_save_reports)
    check(t4, "Auto-save PDF report for every scan", auto_report_var)

    section(t4, "REPORTS FOLDER")
    reports_var = tk.StringVar(value=s.reports_folder or str(Path.home() / "Documents" / "AIScan Reports"))
    rf = tk.Frame(t4, bg="#111", padx=16, pady=10); rf.pack(fill="x", padx=20, pady=2)
    tk.Label(rf, text="Save reports to:", font=("Helvetica",10),
             fg="#e8e8f0", bg="#111").pack(anchor="w")
    rf2 = tk.Frame(rf, bg="#111"); rf2.pack(fill="x", pady=(6,0))
    tk.Entry(rf2, textvariable=reports_var, font=("Helvetica",9),
             bg="#1a1a2e", fg="#e8e8f0", insertbackground="#fff",
             relief="flat").pack(side="left", fill="x", expand=True)
    def pick_reports_folder():
        folder = filedialog.askdirectory(title="Select reports folder")
        if folder: reports_var.set(folder)
    tk.Button(rf2, text="Browse", command=pick_reports_folder,
              font=("Helvetica",9), fg="#888", bg="#1a1a28",
              relief="flat", padx=8, pady=2, cursor="hand2").pack(side="left", padx=(6,0))

    # ── Save / Cancel bar ─────────────────────────────────────────────────
    bar = tk.Frame(root, bg="#0a0a10"); bar.pack(fill="x", side="bottom")
    tk.Frame(bar, bg="#1a1a2e", height=1).pack(fill="x")
    bf = tk.Frame(bar, bg="#0a0a10"); bf.pack(fill="x", padx=20, pady=10)

    msg_var = tk.StringVar()
    tk.Label(bf, textvariable=msg_var, font=("Helvetica",9),
             fg="#44cc77", bg="#0a0a10").pack(side="left")

    def save_settings():
        # Detection
        settings_manager.settings.sensitivity         = sens_var.get()
        settings_manager.settings.min_word_count      = min_words_var.get()
        settings_manager.settings.show_low_risk       = show_low_var.get()
        settings_manager.settings.show_medium_risk    = show_medium_var.get()
        settings_manager.settings.show_high_risk      = show_high_var.get()
        # Screen + clipboard
        settings_manager.settings.screen_monitor_enabled    = screen_enabled_var.get()
        settings_manager.settings.screen_interval_seconds   = screen_interval_var.get()
        settings_manager.settings.clipboard_enabled         = clipboard_var.get()
        settings_manager.settings.clipboard_min_words       = clip_words_var.get()
        # Folders
        for key, var in folder_vars.items():
            setattr(settings_manager.settings, key, var.get())
        settings_manager.settings.custom_folders = list(custom_list.get(0, "end"))
        # Notifications
        settings_manager.settings.popup_duration_seconds = popup_dur_var.get()
        settings_manager.settings.show_reasons           = show_reasons_var.get()
        settings_manager.settings.play_sound             = sound_var.get()
        # Reports
        settings_manager.settings.auto_save_reports = auto_report_var.get()
        settings_manager.settings.reports_folder    = reports_var.get()
        # Apply sensitivity preset
        settings_manager.apply_sensitivity(sens_var.get())
        msg_var.set("✓ Settings saved — restart to apply some changes")
        if restart_callback:
            root.after(1500, restart_callback)

    tk.Button(bf, text="Save Settings", command=save_settings,
              font=("Helvetica",10,"bold"), fg="#0d0d14", bg="#00e5ff",
              relief="flat", padx=16, pady=6, cursor="hand2").pack(side="right", padx=(8,0))
    tk.Button(bf, text="Cancel", command=root.destroy,
              font=("Helvetica",10), fg="#888", bg="#1a1a28",
              relief="flat", padx=16, pady=6, cursor="hand2").pack(side="right")

    root.mainloop()
