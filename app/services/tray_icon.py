from __future__ import annotations

import os
import threading
import webbrowser
from typing import Callable

from ..config import DEFAULT_PORT
from ..db import log_event


def start_tray(on_exit: Callable[[], None] | None = None):
    try:
        import pystray
        from PIL import Image, ImageDraw
    except Exception as exc:
        log_event("SYSTEM", "tray", "DISABLED", f"Tray není dostupný: {exc}")
        return None

    def _image():
        image = Image.new("RGB", (64, 64), color=(33, 37, 41))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((6, 6, 58, 58), radius=12, outline=(120, 200, 120), width=3)
        draw.rectangle((18, 30, 46, 40), fill=(120, 200, 120))
        draw.rectangle((28, 18, 36, 46), fill=(120, 200, 120))
        return image

    def _open_local(icon, item):
        webbrowser.open(f"http://127.0.0.1:{DEFAULT_PORT}")

    def _open_lan(icon, item):
        # IP se ukazuje na dashboardu, zde otevřeme lokální správu.
        webbrowser.open(f"http://127.0.0.1:{DEFAULT_PORT}")

    def _quit(icon, item):
        try:
            if on_exit:
                on_exit()
        finally:
            icon.stop()
            os._exit(0)

    menu = pystray.Menu(
        pystray.MenuItem("Otevřít správu", _open_local),
        pystray.MenuItem("Otevřít localhost", _open_lan),
        pystray.MenuItem("Ukončit Guardian LAN", _quit),
    )
    icon = pystray.Icon("guardian_lan", _image(), "Guardian LAN", menu)
    threading.Thread(target=icon.run, daemon=True).start()
    log_event("SYSTEM", "tray", "STARTED", "Systémová ikona spuštěna")
    return icon
