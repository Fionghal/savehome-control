from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable

from .config import DB_PATH, TEMP_UNLOCK_KEY, TEMP_UNLOCK_REASON_KEY

DAYS = [
    "Pondělí",
    "Úterý",
    "Středa",
    "Čtvrtek",
    "Pátek",
    "Sobota",
    "Neděle",
]


def dict_factory(cursor: sqlite3.Cursor, row: tuple[Any, ...]) -> dict[str, Any]:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


@contextmanager
def get_conn() -> Iterable[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = dict_factory
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def utcnow_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO settings(key, value) VALUES(?, ?)
        ON CONFLICT(key) DO NOTHING
        """,
        (key, value),
    )


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blocked_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT NOT NULL UNIQUE,
                note TEXT DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blocked_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                note TEXT DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS time_rules (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                warning_time TEXT NOT NULL DEFAULT '20:30',
                block_start TEXT NOT NULL DEFAULT '21:00',
                block_end TEXT NOT NULL DEFAULT '06:00',
                warning_message TEXT NOT NULL DEFAULT 'Je čas uložit hru a jít spát.',
                block_message TEXT NOT NULL DEFAULT 'Použití PC je nyní omezeno časovým pravidlem.',
                enabled INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS weekly_rules (
                day_of_week INTEGER PRIMARY KEY,
                day_name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                warning_time TEXT NOT NULL DEFAULT '20:30',
                block_start TEXT NOT NULL DEFAULT '21:00',
                block_end TEXT NOT NULL DEFAULT '06:00',
                warning_message TEXT NOT NULL DEFAULT 'Je čas uložit hru a jít spát.',
                block_message TEXT NOT NULL DEFAULT 'Použití PC je nyní omezeno časovým pravidlem.',
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS temp_allowed_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                reason TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_temp_allowed_apps_process_name
            ON temp_allowed_apps(process_name);

            CREATE TABLE IF NOT EXISTS event_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT DEFAULT '',
                windows_user TEXT DEFAULT '',
                details TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS web_visits_logged (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                browser TEXT NOT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                visited_at TEXT NOT NULL,
                title TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_web_visits_logged_unique
            ON web_visits_logged(browser, url, visited_at);
            """
        )

        if not conn.execute("SELECT 1 FROM time_rules WHERE id = 1").fetchone():
            conn.execute(
                """
                INSERT INTO time_rules
                (id, warning_time, block_start, block_end, warning_message, block_message, enabled, updated_at)
                VALUES (1, '20:30', '21:00', '06:00', 'Je čas uložit hru a jít spát.',
                        'Použití PC je nyní omezeno časovým pravidlem.', 0, ?)
                """,
                (utcnow_str(),),
            )

        for idx, day_name in enumerate(DAYS):
            conn.execute(
                """
                INSERT INTO weekly_rules(day_of_week, day_name, updated_at)
                VALUES(?, ?, ?)
                ON CONFLICT(day_of_week) DO NOTHING
                """,
                (idx, day_name, utcnow_str()),
            )

        _ensure_setting(conn, "time_block_active", "0")
        _ensure_setting(conn, "time_block_message", "Použití PC je nyní omezeno časovým pravidlem.")
        _ensure_setting(conn, "app_control_mode", "blacklist")
        _ensure_setting(conn, "open_browser_on_start", "1")
        _ensure_setting(conn, "tray_enabled", "1")
        _ensure_setting(conn, "watchdog_enabled", "1")
        _ensure_setting(conn, TEMP_UNLOCK_KEY, "")
        _ensure_setting(conn, TEMP_UNLOCK_REASON_KEY, "")


def set_setting(key: str, value: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO settings(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )


def get_setting(key: str, default: str = "") -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def get_weekly_rules() -> list[dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM weekly_rules ORDER BY day_of_week").fetchall()


def cleanup_expired_temp_apps() -> int:
    now = utcnow_str()
    with get_conn() as conn:
        rows = conn.execute("SELECT process_name FROM temp_allowed_apps WHERE expires_at <= ?", (now,)).fetchall()
        count = len(rows)
        if count:
            conn.execute("DELETE FROM temp_allowed_apps WHERE expires_at <= ?", (now,))
    return count


def get_active_temp_allowed_apps() -> list[dict[str, Any]]:
    cleanup_expired_temp_apps()
    now = utcnow_str()
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM temp_allowed_apps WHERE expires_at > ? ORDER BY expires_at ASC, process_name COLLATE NOCASE",
            (now,),
        ).fetchall()


def is_app_temporarily_allowed(process_name: str) -> bool:
    cleanup_expired_temp_apps()
    now = utcnow_str()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM temp_allowed_apps WHERE process_name = ? AND expires_at > ? LIMIT 1",
            (process_name.lower(), now),
        ).fetchone()
        return bool(row)


def upsert_temp_allowed_app(process_name: str, expires_at: str, reason: str = "") -> None:
    pname = process_name.strip().lower()
    if not pname:
        return
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO temp_allowed_apps(process_name, expires_at, reason, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(process_name) DO UPDATE SET expires_at = excluded.expires_at, reason = excluded.reason
            """,
            (pname, expires_at, reason.strip(), utcnow_str()),
        )


def delete_temp_allowed_app(process_name: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM temp_allowed_apps WHERE process_name = ?", (process_name.strip().lower(),))


def log_event(event_type: str, subject: str, action: str, reason: str = "", details: str = "", windows_user: str = "") -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO event_logs(ts, event_type, subject, action, reason, windows_user, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (utcnow_str(), event_type, subject, action, reason, windows_user, details),
        )


def is_web_visit_logged(browser: str, url: str, visited_at: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM web_visits_logged WHERE browser = ? AND url = ? AND visited_at = ? LIMIT 1",
            (browser, url, visited_at),
        ).fetchone()
        return bool(row)


def record_web_visit(browser: str, url: str, domain: str, visited_at: str, title: str = "") -> bool:
    with get_conn() as conn:
        before = conn.total_changes
        conn.execute(
            """
            INSERT INTO web_visits_logged(browser, url, domain, visited_at, title, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(browser, url, visited_at) DO NOTHING
            """,
            (browser, url, domain, visited_at, title[:300], utcnow_str()),
        )
        return conn.total_changes > before


def get_enabled_blocked_domains() -> set[str]:
    with get_conn() as conn:
        rows = conn.execute("SELECT domain FROM blocked_domains WHERE enabled = 1").fetchall()
        return {str(r["domain"]).strip().lower() for r in rows if str(r.get("domain", "")).strip()}
