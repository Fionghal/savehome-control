from __future__ import annotations

from pathlib import Path

APP_NAME = "Guardian LAN"
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "guardian.db"
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
HOSTS_MARKER_BEGIN = "# GUARDIAN_LAN_BLOCKLIST_BEGIN"
HOSTS_MARKER_END = "# GUARDIAN_LAN_BLOCKLIST_END"
DEFAULT_PORT = 8787
SESSION_SECRET = "guardian-lan-change-this-secret"
HOSTS_PATH_WINDOWS = Path(r"C:\Windows\System32\drivers\etc\hosts")
SCAN_INTERVAL_SECONDS = 3
WARNING_CHECK_INTERVAL_SECONDS = 30
TEMP_UNLOCK_KEY = "temporary_unlock_until"
TEMP_UNLOCK_REASON_KEY = "temporary_unlock_reason"

BROWSER_HISTORY_SCAN_INTERVAL_SECONDS = 20
