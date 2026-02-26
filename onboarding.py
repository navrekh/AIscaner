"""
AIScan Onboarding Flow
First-run wizard that explains the product, tests detection,
and gets users set up in under 2 minutes.
"""
import json, time, threading, webbrowser, logging
from pathlib import Path

log = logging.getLogger("aiscan")

ONBOARDING_DONE_FILE = None  # set by main()


def should_show_onboarding(data_dir: Path) -> bool:
    done_file = data_dir / "onboarding_done.json"
    return not done_file.exists()


def mark_onboarding_done(data_dir: Path):
    done_file = data_dir / "onboarding_done.json"
    done_file.write_text(json.dumps({"done": True, "ts": time.time()}))


def show_onboarding(data_dir: Path, detect_fn, history_html: Path):
    """Show onboarding wizard. Blocking  -  call before starting main app."""
    import tkinter as tk
    import tkinter.ttk as ttk

    root = tk.Tk()
    root.title("Welcome to AIScan")
    root.configure(bg="#0d0d14")
    root.geometry("580x520")
    root.resizable(False, False)
    root.attributes("-topmost", True)

    # Center
    root.update_idletasks()
    x = (root.winfo_screenwidth()  - 580) // 2
    y = (root.winfo_screenheight() - 520) // 2
    root.geometry(f"580x520+{x}+{y}")

    # State
    current_step = [0]
    steps = ["welcome", "how_it_works", "test_detection", "setup", "done"]

    # -- Main container ----------------------------------------------------
    tk.Frame(root, bg="#00e5ff", height=3).pack(fill="x")
    content = tk.Frame(root, bg="#0d0d14"); content.pack(fill="both", expand=True)
    footer  = tk.Frame(root, bg="#0a0a10"); footer.pack(fill="x", side="bottom")
    tk.Frame(footer, bg="#1a1a2e", height=1).pack(fill="x")
    foot_inner = tk.Frame(footer, bg="#0a0a10"); foot_inner.pack(fill="x", padx=24, pady=12)

    # Progress dots
    dot_frame = tk.Frame(foot_inner, bg="#0a0a10"); dot_frame.pack(side="left")
    dots = []
    for i in range(len(steps)):
        d = tk.Label(dot_frame, text="*", font=("Helvetica", 8),
                     fg="#1a1a2e", bg="#0a0a10")
        d.pack(side="left", padx=2)
        dots.append(d)

    btn_next = tk.Button(foot_inner, text="Next ->",
                         font=("Helvetica",10,"bold"), fg="#0d0d14", bg="#00e5ff",
                         relief="flat", padx=16, pady=6, cursor="hand2")
    btn_next.pack(side="right")
    btn_skip = tk.Button(foot_inner, text="Skip",
                         font=("Helvetica",9), fg="#444", bg="#0a0a10",
                         relief="flat", padx=8, pady=6, cursor="hand2",
                         command=lambda: [mark_onboarding_done(data_dir), root.destroy()])
    btn_skip.pack(side="right", padx=(0, 8))

    def update_dots(step):
        for i, d in enumerate(dots):
            d.config(fg="#00e5ff" if i == step else ("#555" if i < step else "#1a1a2e"))

    def clear():
        for w in content.winfo_children():
            w.destroy()

    def label(parent, text, font=("Helvetica",10), fg="#888", pady=4, **kw):
        tk.Label(parent, text=text, font=font, fg=fg, bg="#0d0d14",
                 wraplength=500, justify="left", **kw).pack(anchor="w",
                 padx=32, pady=pady)

    # -- STEP 0: Welcome ---------------------------------------------------
    def show_welcome():
        clear()
        tk.Label(content, text="[AIScan]", font=("Helvetica", 48),
                 bg="#0d0d14").pack(pady=(40, 8))
        tk.Label(content, text="Welcome to AIScan",
                 font=("Helvetica", 20, "bold"), fg="#00e5ff",
                 bg="#0d0d14").pack(pady=(0, 4))
        tk.Label(content, text="AI document detection that works in real-time.",
                 font=("Helvetica", 11), fg="#888", bg="#0d0d14").pack()
        tk.Label(content, text="No cloud. No uploads. 100% private.",
                 font=("Helvetica", 11), fg="#555", bg="#0d0d14").pack(pady=(2,24))

        for icon, text in [
            ("?", "Detects AI content before you even save"),
            ("?", "Everything stays on your device"),
            ("?", "Learns your writing style over time"),
        ]:
            f = tk.Frame(content, bg="#111", padx=16, pady=10)
            f.pack(fill="x", padx=32, pady=3)
            tk.Label(f, text=icon, font=("Helvetica", 14),
                     bg="#111").pack(side="left", padx=(0, 10))
            tk.Label(f, text=text, font=("Helvetica", 10),
                     fg="#e8e8f0", bg="#111").pack(side="left")

        btn_next.config(text="Get Started ->")

    # -- STEP 1: How it works ----------------------------------------------
    def show_how_it_works():
        clear()
        tk.Label(content, text="How AIScan Works",
                 font=("Helvetica", 16, "bold"), fg="#e8e8f0",
                 bg="#0d0d14").pack(anchor="w", padx=32, pady=(28, 16))

        steps_info = [
            ("1", "#00e5ff", "Screen Monitor",
             "Reads text visible on your screen every 4 seconds  -  before you save anything"),
            ("2", "#44cc77", "Clipboard Monitor",
             "The moment you copy AI text, AIScan catches it  -  before you paste"),
            ("3", "#ffaa00", "File Watcher",
             "Scans every document when you save it  -  .docx, .pdf, .txt and more"),
            ("4", "#ff4455", "Right-click Scan",
             "Right-click any file and select 'Scan with AIScan' for instant results"),
        ]

        for num, color, title, desc in steps_info:
            f = tk.Frame(content, bg="#111", padx=16, pady=12)
            f.pack(fill="x", padx=32, pady=3)
            badge = tk.Frame(f, bg=color, width=24, height=24)
            badge.pack(side="left", padx=(0,12))
            badge.pack_propagate(False)
            tk.Label(badge, text=num, font=("Helvetica",9,"bold"),
                     fg="#000", bg=color).pack(expand=True)
            right = tk.Frame(f, bg="#111"); right.pack(side="left", fill="x", expand=True)
            tk.Label(right, text=title, font=("Helvetica",10,"bold"),
                     fg="#e8e8f0", bg="#111", anchor="w").pack(anchor="w")
            tk.Label(right, text=desc, font=("Helvetica",9),
                     fg="#666", bg="#111", anchor="w", wraplength=380).pack(anchor="w")

        btn_next.config(text="Next ->")

    # -- STEP 2: Test detection --------------------------------------------
    def show_test_detection():
        clear()
        tk.Label(content, text="Try It Now",
                 font=("Helvetica", 16, "bold"), fg="#e8e8f0",
                 bg="#0d0d14").pack(anchor="w", padx=32, pady=(28, 4))
        tk.Label(content,
                 text="Paste any text below to test the AI detector:",
                 font=("Helvetica", 10), fg="#666", bg="#0d0d14").pack(anchor="w", padx=32)

        text_frame = tk.Frame(content, bg="#111", padx=2, pady=2)
        text_frame.pack(fill="x", padx=32, pady=10)
        txt = tk.Text(text_frame, height=5, font=("Helvetica", 10),
                      bg="#1a1a2e", fg="#e8e8f0", insertbackground="#fff",
                      relief="flat", wrap="word", padx=10, pady=8)
        txt.pack(fill="x")
        txt.insert("1.0", "Paste any text here, or click 'Test AI Sample' to try a sample...")

        result_frame = tk.Frame(content, bg="#0d0d14")
        result_frame.pack(fill="x", padx=32)

        score_var = tk.StringVar(value="")
        risk_var  = tk.StringVar(value="")
        reason_var = tk.StringVar(value="")

        result_box = tk.Frame(content, bg="#111", padx=16, pady=12)
        result_box.pack(fill="x", padx=32, pady=4)
        score_lbl = tk.Label(result_box, text=" - ", font=("Helvetica",24,"bold"),
                             fg="#333", bg="#111")
        score_lbl.pack(side="left")
        rr = tk.Frame(result_box, bg="#111"); rr.pack(side="left", padx=(12,0))
        cls_lbl = tk.Label(rr, text="Paste text and click Scan",
                           font=("Helvetica",10,"bold"), fg="#444", bg="#111")
        cls_lbl.pack(anchor="w")
        rsn_lbl = tk.Label(rr, text="", font=("Helvetica",9), fg="#555",
                           bg="#111", wraplength=340)
        rsn_lbl.pack(anchor="w")

        def run_scan():
            text = txt.get("1.0", "end").strip()
            if len(text.split()) < 10:
                cls_lbl.config(text="Too short  -  need at least 10 words", fg="#555")
                return
            result = detect_fn(text)
            color = ("#ff4455" if result.risk_level == "High"
                     else "#ffaa00" if result.risk_level == "Medium" else "#44cc77")
            score_lbl.config(text=f"{result.ai_score:.0f}%", fg=color)
            cls_lbl.config(text=f"{result.classification}  .  {result.llm_suspected}", fg="#e8e8f0")
            rsn_lbl.config(text=" | ".join(result.reasons[:2]) if result.reasons else "No specific signals")

        def load_ai_sample():
            txt.delete("1.0", "end")
            txt.insert("1.0",
                "Furthermore it is important to note that leveraging robust AI frameworks "
                "plays a crucial role in achieving paradigm shifts. Moreover cutting-edge "
                "solutions enable organizations to optimize their workflows and facilitate "
                "seamless integration across multiple touchpoints. This demonstrates the "
                "transformative potential of scalable AI-driven ecosystems.")
            run_scan()

        bf = tk.Frame(content, bg="#0d0d14"); bf.pack(fill="x", padx=32, pady=4)
        tk.Button(bf, text="? Scan This Text", command=run_scan,
                  font=("Helvetica",9,"bold"), fg="#0d0d14", bg="#00e5ff",
                  relief="flat", padx=12, pady=5, cursor="hand2").pack(side="left", padx=(0,6))
        tk.Button(bf, text="Try AI Sample", command=load_ai_sample,
                  font=("Helvetica",9), fg="#888", bg="#1a1a28",
                  relief="flat", padx=12, pady=5, cursor="hand2").pack(side="left")
        btn_next.config(text="Next ->")

    # -- STEP 3: Setup -----------------------------------------------------
    def show_setup():
        clear()
        tk.Label(content, text="Quick Setup",
                 font=("Helvetica", 16, "bold"), fg="#e8e8f0",
                 bg="#0d0d14").pack(anchor="w", padx=32, pady=(28, 4))
        tk.Label(content, text="AIScan is already configured with smart defaults.",
                 font=("Helvetica", 10), fg="#666", bg="#0d0d14").pack(anchor="w", padx=32)

        items = [
            ("[OK]", "#44cc77", "Watching Documents, Desktop, Downloads"),
            ("[OK]", "#44cc77", "Clipboard monitoring active"),
            ("[OK]", "#44cc77", "Screen monitoring active"),
            ("[OK]", "#44cc77", "System tray icon running"),
            ("[OK]", "#44cc77", "14-day free trial started"),
        ]
        for icon, color, text in items:
            f = tk.Frame(content, bg="#111", padx=16, pady=10)
            f.pack(fill="x", padx=32, pady=3)
            tk.Label(f, text=icon, font=("Helvetica",12,"bold"),
                     fg=color, bg="#111").pack(side="left", padx=(0,10))
            tk.Label(f, text=text, font=("Helvetica",10),
                     fg="#e8e8f0", bg="#111").pack(side="left")

        btn_next.config(text="Finish Setup ->")

    # -- STEP 4: Done ------------------------------------------------------
    def show_done():
        clear()
        tk.Label(content, text="?", font=("Helvetica",48), bg="#0d0d14").pack(pady=(32,8))
        tk.Label(content, text="You're all set!",
                 font=("Helvetica",20,"bold"), fg="#00e5ff", bg="#0d0d14").pack()
        tk.Label(content,
                 text="AIScan is now running in your system tray.\n"
                      "You'll get a popup the moment AI content is detected.",
                 font=("Helvetica",10), fg="#666", bg="#0d0d14", justify="center").pack(pady=12)

        f = tk.Frame(content, bg="#0d0d14"); f.pack(pady=8)
        tk.Button(f, text="? Open History Dashboard",
                  command=lambda: webbrowser.open(history_html.as_uri()),
                  font=("Helvetica",10,"bold"), fg="#0d0d14", bg="#00e5ff",
                  relief="flat", padx=16, pady=8, cursor="hand2").pack(pady=4)
        tk.Button(f, text="?  Open Settings",
                  command=lambda: log.info("Settings requested"),
                  font=("Helvetica",10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=16, pady=8, cursor="hand2").pack(pady=4)

        btn_next.config(text="Start Using AIScan")

    # -- Navigation --------------------------------------------------------
    step_fns = [show_welcome, show_how_it_works, show_test_detection,
                show_setup, show_done]

    def next_step():
        step = current_step[0]
        if step >= len(steps) - 1:
            mark_onboarding_done(data_dir)
            root.destroy()
            return
        current_step[0] += 1
        update_dots(current_step[0])
        step_fns[current_step[0]]()

    btn_next.config(command=next_step)

    # Start
    show_welcome()
    update_dots(0)
    root.mainloop()
