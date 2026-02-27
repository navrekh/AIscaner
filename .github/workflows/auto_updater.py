"""
AIScan Auto-Updater
Checks for new versions on startup and shows a non-intrusive notification.
Version manifest is a simple JSON file hosted at a URL.
Zero dependency - uses urllib only.
"""
import json, logging, threading, time, urllib.request, urllib.error
from pathlib import Path

log = logging.getLogger("aiscan")

CURRENT_VERSION = "5.0.0"
VERSION_URL = "https://raw.githubusercontent.com/aiscan-app/aiscan/main/version.json"
CHECK_INTERVAL_HOURS = 24


def _parse_version(v: str):
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0, 0, 0)


def check_for_update(data_dir: Path, notify_fn=None, force: bool = False) -> dict:
    """
    Check for updates. Returns dict with keys:
      available (bool), current, latest, url, release_notes
    notify_fn(info) called on UI thread if update available.
    """
    # Rate-limit: only check once per CHECK_INTERVAL_HOURS
    cache_file = data_dir / "update_cache.json"
    if not force and cache_file.exists():
        try:
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            last_check = cache.get("last_check", 0)
            if time.time() - last_check < CHECK_INTERVAL_HOURS * 3600:
                log.debug("Update check skipped (checked recently)")
                return cache.get("last_result", {"available": False})
        except Exception:
            pass

    try:
        req = urllib.request.Request(
            VERSION_URL,
            headers={"User-Agent": f"AIScan/{CURRENT_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        latest = data.get("version", CURRENT_VERSION)
        url    = data.get("download_url", "")
        notes  = data.get("release_notes", "")
        available = _parse_version(latest) > _parse_version(CURRENT_VERSION)

        result = {
            "available":      available,
            "current":        CURRENT_VERSION,
            "latest":         latest,
            "url":            url,
            "release_notes":  notes,
            "checked_at":     time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Cache result
        try:
            cache_file.write_text(
                json.dumps({"last_check": time.time(), "last_result": result},
                           indent=2), encoding="utf-8")
        except Exception:
            pass

        if available:
            log.info(f"Update available: {CURRENT_VERSION} -> {latest}")
            if notify_fn:
                notify_fn(result)
        else:
            log.info(f"AIScan is up to date ({CURRENT_VERSION})")

        return result

    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.debug(f"Update check failed (network): {e}")
        return {"available": False, "current": CURRENT_VERSION, "error": str(e)}
    except Exception as e:
        log.debug(f"Update check failed: {e}")
        return {"available": False, "current": CURRENT_VERSION, "error": str(e)}


def check_async(data_dir: Path, notify_fn=None):
    """Run update check in background thread."""
    threading.Thread(
        target=check_for_update,
        args=(data_dir, notify_fn),
        daemon=True,
        name="AutoUpdater"
    ).start()


def show_update_notification(info: dict):
    """Show a small non-intrusive update notification."""
    try:
        import tkinter as tk

        root = tk.Tk()
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        root.configure(bg="#0a1a0a")

        W, H = 380, 120
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        # Bottom-right corner
        root.geometry(f"{W}x{H}+{sw-W-20}+{sh-H-60}")

        tk.Frame(root, bg="#44cc77", height=3).pack(fill="x")

        body = tk.Frame(root, bg="#0a1a0a"); body.pack(fill="both", expand=True, padx=16, pady=10)
        tk.Label(body,
                 text=f"AIScan {info['latest']} available",
                 font=("Helvetica",11,"bold"),
                 fg="#44cc77", bg="#0a1a0a").pack(anchor="w")
        tk.Label(body,
                 text=f"You have {info['current']}. Download the latest for improved accuracy.",
                 font=("Helvetica",9), fg="#888",
                 bg="#0a1a0a", wraplength=340).pack(anchor="w", pady=(4,0))

        bf = tk.Frame(body, bg="#0a1a0a"); bf.pack(fill="x", pady=(8,0))
        if info.get("url"):
            import webbrowser
            tk.Button(bf, text="Download",
                      command=lambda: [webbrowser.open(info["url"]), root.destroy()],
                      font=("Helvetica",9,"bold"),
                      fg="#0d0d14", bg="#44cc77",
                      relief="flat", padx=10, pady=4).pack(side="left")
        tk.Button(bf, text="Later",
                  command=root.destroy,
                  font=("Helvetica",9), fg="#555", bg="#0a1a0a",
                  relief="flat", padx=10, pady=4).pack(side="left", padx=(8,0))

        root.after(15000, root.destroy)  # auto-dismiss after 15s
        root.mainloop()
    except Exception as e:
        log.debug(f"Update notification error: {e}")
