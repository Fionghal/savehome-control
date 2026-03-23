from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STOP_FILE = ROOT / "data" / "watchdog.stop"


def main() -> None:
    STOP_FILE.parent.mkdir(exist_ok=True)
    if STOP_FILE.exists():
        STOP_FILE.unlink()
    print("Guardian LAN watchdog běží. Pro zastavení vytvoř soubor data/watchdog.stop nebo ukonči watchdog.")
    while True:
        if STOP_FILE.exists():
            print("Nalezen watchdog.stop, watchdog končí.")
            break
        proc = subprocess.Popen([sys.executable, str(ROOT / "run.py")], cwd=str(ROOT))
        code = proc.wait()
        if STOP_FILE.exists():
            break
        print(f"Guardian LAN skončil s kódem {code}, restart za 2 sekundy...")
        time.sleep(2)


if __name__ == "__main__":
    main()
