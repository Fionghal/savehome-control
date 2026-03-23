from __future__ import annotations

import getpass
import os
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from ..db import get_enabled_blocked_domains, log_event, record_web_visit


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return ""


def _extract_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower().strip()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""


def _copy_sqlite_for_read(db_path: Path) -> Path | None:
    if not db_path.exists():
        return None
    tmp_dir = Path(tempfile.mkdtemp(prefix="guardian_hist_"))
    tmp_db = tmp_dir / db_path.name
    try:
        shutil.copy2(db_path, tmp_db)
        wal = db_path.with_name(db_path.name + "-wal")
        shm = db_path.with_name(db_path.name + "-shm")
        if wal.exists():
            shutil.copy2(wal, tmp_dir / wal.name)
        if shm.exists():
            shutil.copy2(shm, tmp_dir / shm.name)
        return tmp_db
    except Exception:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
        return None


def _cleanup_tmp(db_copy: Path | None) -> None:
    if not db_copy:
        return
    try:
        shutil.rmtree(db_copy.parent, ignore_errors=True)
    except Exception:
        pass


def _chrome_profiles(base_dir: Path) -> list[Path]:
    if not base_dir.exists():
        return []
    profiles = []
    for child in base_dir.iterdir():
        if child.is_dir() and (child.name == "Default" or child.name.startswith("Profile ")):
            hist = child / "History"
            if hist.exists():
                profiles.append(hist)
    return profiles


def _iter_chromium_rows(db_path: Path, browser_name: str, since_dt: datetime):
    db_copy = _copy_sqlite_for_read(db_path)
    if not db_copy:
        return
    try:
        conn = sqlite3.connect(str(db_copy))
        conn.row_factory = sqlite3.Row
        # Chromium stores microseconds since 1601-01-01
        epoch_start = datetime(1601, 1, 1)
        threshold = int((since_dt - epoch_start).total_seconds() * 1_000_000)
        rows = conn.execute(
            """
            SELECT u.url, COALESCE(u.title, '') AS title, v.visit_time
            FROM visits v
            JOIN urls u ON u.id = v.url
            WHERE v.visit_time >= ?
            ORDER BY v.visit_time ASC
            """,
            (threshold,),
        ).fetchall()
        for row in rows:
            url = str(row["url"] or "").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            visited_dt = epoch_start + timedelta(microseconds=int(row["visit_time"]))
            yield {
                "browser": browser_name,
                "url": url,
                "title": str(row["title"] or ""),
                "visited_at": visited_dt.strftime("%Y-%m-%d %H:%M:%S"),
            }
    except Exception:
        return
    finally:
        try:
            conn.close()
        except Exception:
            pass
        _cleanup_tmp(db_copy)


def _iter_firefox_rows(profile_db: Path, since_dt: datetime):
    db_copy = _copy_sqlite_for_read(profile_db)
    if not db_copy:
        return
    try:
        conn = sqlite3.connect(str(db_copy))
        conn.row_factory = sqlite3.Row
        # Firefox stores microseconds since Unix epoch
        threshold = int(since_dt.timestamp() * 1_000_000)
        rows = conn.execute(
            """
            SELECT p.url, COALESCE(p.title, '') AS title, h.visit_date
            FROM moz_historyvisits h
            JOIN moz_places p ON p.id = h.place_id
            WHERE h.visit_date IS NOT NULL AND h.visit_date >= ?
            ORDER BY h.visit_date ASC
            """,
            (threshold,),
        ).fetchall()
        for row in rows:
            url = str(row["url"] or "").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            visited_dt = datetime.fromtimestamp(int(row["visit_date"]) / 1_000_000)
            yield {
                "browser": "Firefox",
                "url": url,
                "title": str(row["title"] or ""),
                "visited_at": visited_dt.strftime("%Y-%m-%d %H:%M:%S"),
            }
    except Exception:
        return
    finally:
        try:
            conn.close()
        except Exception:
            pass
        _cleanup_tmp(db_copy)


def _windows_sources() -> list[tuple[str, Path]]:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roaming = Path(os.environ.get("APPDATA", ""))
    sources = []
    for hist in _chrome_profiles(local / "Google/Chrome/User Data"):
        sources.append(("Chrome", hist))
    for hist in _chrome_profiles(local / "Microsoft/Edge/User Data"):
        sources.append(("Edge", hist))
    for hist in _chrome_profiles(local / "BraveSoftware/Brave-Browser/User Data"):
        sources.append(("Brave", hist))
    ff_profiles = roaming / "Mozilla/Firefox/Profiles"
    if ff_profiles.exists():
        for child in ff_profiles.iterdir():
            places = child / "places.sqlite"
            if child.is_dir() and places.exists():
                sources.append(("Firefox", places))
    return sources


def _linux_sources() -> list[tuple[str, Path]]:
    home = Path.home()
    sources = []
    for hist in _chrome_profiles(home / ".config/google-chrome"):
        sources.append(("Chrome", hist))
    for hist in _chrome_profiles(home / ".config/microsoft-edge"):
        sources.append(("Edge", hist))
    for hist in _chrome_profiles(home / ".config/BraveSoftware/Brave-Browser"):
        sources.append(("Brave", hist))
    ff_profiles = home / ".mozilla/firefox"
    if ff_profiles.exists():
        for child in ff_profiles.iterdir():
            places = child / "places.sqlite"
            if child.is_dir() and places.exists():
                sources.append(("Firefox", places))
    return sources


def scan_browser_history(lookback_minutes: int = 120) -> int:
    since_dt = datetime.now() - timedelta(minutes=lookback_minutes)
    blocked_domains = get_enabled_blocked_domains()
    count = 0

    if os.name == "nt":
        sources = _windows_sources()
    else:
        sources = _linux_sources()

    seen_batch: set[tuple[str, str, str]] = set()
    for browser, path in sources:
        if browser == "Firefox":
            iterator = _iter_firefox_rows(path, since_dt)
        else:
            iterator = _iter_chromium_rows(path, browser, since_dt)
        if iterator is None:
            continue
        for item in iterator:
            domain = _extract_domain(item["url"])
            if not domain:
                continue
            key = (item["browser"], item["url"], item["visited_at"])
            if key in seen_batch:
                continue
            seen_batch.add(key)
            if record_web_visit(item["browser"], item["url"], domain, item["visited_at"], item["title"]):
                action = "BLOCKED_ATTEMPT" if domain in blocked_domains else "VISITED"
                reason = f"{item['browser']} | {item['title'][:120]}" if item['title'] else item["browser"]
                log_event("WEB", domain, action, reason, details=item["url"][:500], windows_user=_safe_user())
                count += 1
    return count
