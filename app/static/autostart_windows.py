from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TASK_NAME = "GuardianLAN"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _python_exe() -> Path:
    return Path(sys.executable)


def _run_script() -> Path:
    return _project_root() / "run.py"


def get_autostart_status() -> dict:
    if sys.platform != "win32":
        return {"supported": False, "enabled": False, "message": "Automatický start je připraven jen pro Windows."}
    result = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME], capture_output=True, text=True)
    enabled = result.returncode == 0
    return {"supported": True, "enabled": enabled, "message": "Úloha je nainstalovaná." if enabled else "Úloha není nainstalovaná."}


def install_autostart() -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "Automatický start lze nastavit jen na Windows."
    cmd = [
        "schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "HIGHEST", "/TN", TASK_NAME,
        "/TR", f'"{_python_exe()}" "{_run_script()}"',
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True, "Automatický start byl nastaven do Plánovače úloh."
    message = (result.stderr or result.stdout or "Neznámá chyba").strip().replace(" ", "+")
    return False, f"Chyba+nastavení+autostartu:+{message}"


def remove_autostart() -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "Automatický start lze odebrat jen na Windows."
    result = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME], capture_output=True, text=True)
    if result.returncode == 0:
        return True, "Automatický start byl odebrán."
    message = (result.stderr or result.stdout or "Neznámá chyba").strip().replace(" ", "+")
    return False, f"Chyba+odebrání+autostartu:+{message}"
