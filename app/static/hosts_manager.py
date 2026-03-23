from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from ..config import HOSTS_MARKER_BEGIN, HOSTS_MARKER_END, HOSTS_PATH_WINDOWS
from ..db import log_event

REDIRECT_IP = "127.0.0.1"


def get_hosts_path() -> Path:
    return HOSTS_PATH_WINDOWS


def build_guardian_block(domains: Iterable[str]) -> str:
    lines = [HOSTS_MARKER_BEGIN]
    for domain in sorted({d.strip().lower() for d in domains if d.strip()}):
        lines.append(f"{REDIRECT_IP} {domain}")
        lines.append(f"{REDIRECT_IP} www.{domain}")
    lines.append(HOSTS_MARKER_END)
    return "\n".join(lines) + "\n"


def update_hosts(domains: list[str]) -> tuple[bool, str]:
    hosts_path = get_hosts_path()
    if os.name != "nt":
        return False, "Tato MVP verze mění hosts jen na Windows."
    try:
        original = hosts_path.read_text(encoding="utf-8", errors="ignore") if hosts_path.exists() else ""
        start = original.find(HOSTS_MARKER_BEGIN)
        end = original.find(HOSTS_MARKER_END)
        if start != -1 and end != -1:
            end += len(HOSTS_MARKER_END)
            cleaned = (original[:start].rstrip() + "\n\n" + original[end:].lstrip()).strip() + "\n"
        else:
            cleaned = original.rstrip() + "\n\n"

        new_content = cleaned + build_guardian_block(domains)
        hosts_path.write_text(new_content, encoding="utf-8")
        return True, f"Hosts aktualizován, blokovaných domén: {len(domains)}"
    except PermissionError:
        message = "Zápis do hosts selhal: spusť aplikaci jako administrátor."
        log_event("SYSTEM", "hosts", "ERROR", message)
        return False, message
    except Exception as exc:  # pragma: no cover
        message = f"Zápis do hosts selhal: {exc}"
        log_event("SYSTEM", "hosts", "ERROR", message)
        return False, message
