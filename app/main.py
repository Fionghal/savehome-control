from __future__ import annotations

import atexit
import signal
import threading
import webbrowser

import uvicorn

from .config import DEFAULT_PORT
from .db import get_setting, init_db, log_event, set_setting
from .services.monitor import GuardianMonitor
from .services.tray_icon import start_tray
from .web import create_app


def main() -> None:
    init_db()
    monitor = GuardianMonitor()
    monitor.start()
    set_setting("guardian_running", "1")
    log_event("SYSTEM", "program", "STARTED", "Guardian LAN spuštěn")

    shutting_down = {"done": False}

    def _shutdown() -> None:
        if shutting_down["done"]:
            return
        shutting_down["done"] = True
        try:
            monitor.stop()
            set_setting("guardian_running", "0")
        finally:
            log_event("SYSTEM", "program", "STOPPED", "Guardian LAN ukončen")

    def _signal_handler(signum, frame):
        log_event("SYSTEM", "signal", "RECEIVED", f"Přijat signál {signum}")
        _shutdown()
        raise SystemExit(0)

    atexit.register(_shutdown)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_handler)
        except Exception:
            pass

    if get_setting("tray_enabled", "1") == "1":
        start_tray(_shutdown)

    app = create_app()

    if get_setting("open_browser_on_start", "1") == "1":
        try:
            threading.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{DEFAULT_PORT}")).start()
        except Exception:
            pass

    uvicorn.run(app, host="0.0.0.0", port=DEFAULT_PORT, log_level="info", access_log=False, log_config=None)
