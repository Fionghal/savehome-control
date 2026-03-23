from __future__ import annotations

import getpass
import threading
import time
from datetime import datetime
from tkinter import Tk, messagebox

import psutil

from ..config import BROWSER_HISTORY_SCAN_INTERVAL_SECONDS, SCAN_INTERVAL_SECONDS, TEMP_UNLOCK_KEY, WARNING_CHECK_INTERVAL_SECONDS
from ..db import cleanup_expired_temp_apps, get_conn, get_setting, is_app_temporarily_allowed, log_event, set_setting
from .browser_history import scan_browser_history

SAFE_PROCESSES = {
    "explorer.exe", "systemsettings.exe", "taskmgr.exe", "cmd.exe", "powershell.exe",
    "python.exe", "pythonw.exe", "conhost.exe", "searchhost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe", "dwm.exe", "ctfmon.exe", "smartscreen.exe",
    # Linux / dev environment
    "python3", "bash", "sh", "konsole", "gnome-shell", "plasmashell", "kwin_x11", "kwin_wayland"
}


class GuardianMonitor:
    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._last_warning_minute = ""
        self._last_block_popup_minute = ""
        self._last_killed: dict[str, float] = {}
        self._last_history_scan = 0.0

    def start(self) -> None:
        self._stop_event.clear()
        self._threads = [
            threading.Thread(target=self._process_loop, daemon=True),
            threading.Thread(target=self._time_rules_loop, daemon=True),
            threading.Thread(target=self._history_loop, daemon=True),
        ]
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _safe_windows_user(self) -> str:
        try:
            return getpass.getuser()
        except Exception:
            return ""

    def _show_popup(self, title: str, text: str) -> None:
        try:
            root = Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            messagebox.showinfo(title, text, parent=root)
            root.destroy()
        except Exception:
            pass

    def _temporary_unlock_active(self) -> bool:
        until = get_setting(TEMP_UNLOCK_KEY, "")
        if not until:
            return False
        try:
            unlock_dt = datetime.strptime(until, "%Y-%m-%d %H:%M:%S")
        except Exception:
            set_setting(TEMP_UNLOCK_KEY, "")
            return False
        if datetime.now() <= unlock_dt:
            return True
        set_setting(TEMP_UNLOCK_KEY, "")
        return False

    def _today_rule(self, now: datetime):
        weekday = now.weekday()
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM weekly_rules WHERE day_of_week = ?", (weekday,)).fetchone()
            if row and int(row.get("enabled", 0)) == 1:
                return row
            return conn.execute("SELECT * FROM time_rules WHERE id = 1").fetchone()

    def _is_warning_time(self, now: datetime, warning_time: str) -> bool:
        return now.strftime("%H:%M") == warning_time

    def _is_within_block_window(self, now: datetime, start_hm: str, end_hm: str) -> bool:
        now_hm = now.strftime("%H:%M")
        if start_hm <= end_hm:
            return start_hm <= now_hm < end_hm
        return now_hm >= start_hm or now_hm < end_hm

    def _kill_process(self, proc: psutil.Process, reason: str) -> None:
        now = time.time()
        key = f"{proc.pid}:{proc.name()}"
        if now - self._last_killed.get(key, 0) < 10:
            return
        self._last_killed[key] = now
        try:
            proc.terminate()
            log_event("APP", proc.name(), "BLOCKED", reason, windows_user=self._safe_windows_user(), details=f"pid={proc.pid}")
            self._show_popup("Guardian LAN", f"Aplikace {proc.name()} je blokována.\n\nDůvod: {reason}")
        except Exception as exc:
            log_event("APP", proc.name(), "ERROR", reason, windows_user=self._safe_windows_user(), details=str(exc))

    def _process_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._temporary_unlock_active():
                time.sleep(SCAN_INTERVAL_SECONDS)
                continue
            cleanup_expired_temp_apps()
            time_block_active = get_setting("time_block_active", "0") == "1"
            time_block_message = get_setting("time_block_message", "Použití PC je nyní omezeno časovým pravidlem.")
            app_control_mode = get_setting("app_control_mode", "blacklist")
            with get_conn() as conn:
                rows = conn.execute("SELECT process_name, note, enabled FROM blocked_apps WHERE enabled = 1").fetchall()
            configured = {r["process_name"].lower(): (r.get("note", "") or "Aplikace je blokována") for r in rows}

            for proc in psutil.process_iter(["pid", "name"]):
                if self._stop_event.is_set():
                    break
                try:
                    name = (proc.info.get("name") or "").strip()
                    lname = name.lower()
                    if not name or lname in SAFE_PROCESSES:
                        continue
                    if is_app_temporarily_allowed(lname):
                        continue
                    if time_block_active:
                        self._kill_process(proc, time_block_message)
                        continue
                    if app_control_mode == "blacklist":
                        if lname in configured:
                            self._kill_process(proc, configured[lname])
                    else:
                        if lname not in configured:
                            self._kill_process(proc, "Whitelist režim – aplikace není povolena")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as exc:
                    log_event("APP", "monitor", "ERROR", "Chyba v monitoru procesů", windows_user=self._safe_windows_user(), details=str(exc))
            time.sleep(SCAN_INTERVAL_SECONDS)

    def _time_rules_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._temporary_unlock_active():
                if get_setting("time_block_active", "0") != "0":
                    set_setting("time_block_active", "0")
                time.sleep(WARNING_CHECK_INTERVAL_SECONDS)
                continue

            now = datetime.now()
            rules = self._today_rule(now)
            if rules and int(rules.get("enabled", 0)) == 1:
                warning_time = rules.get("warning_time", "20:30")
                block_start = rules.get("block_start", "21:00")
                block_end = rules.get("block_end", "06:00")
                warning_message = rules.get("warning_message", "Je čas uložit hru a jít spát.")
                block_message = rules.get("block_message", "Použití PC je nyní omezeno časovým pravidlem.")

                if self._is_warning_time(now, warning_time):
                    minute_key = now.strftime("%Y-%m-%d %H:%M")
                    if self._last_warning_minute != minute_key:
                        self._last_warning_minute = minute_key
                        log_event("TIME", "warning", "WARNING", warning_message, windows_user=self._safe_windows_user())
                        self._show_popup("Guardian LAN", warning_message)

                active = self._is_within_block_window(now, block_start, block_end)
                if active:
                    if get_setting("time_block_active", "0") != "1":
                        set_setting("time_block_active", "1")
                        set_setting("time_block_message", block_message)
                        log_event("TIME", "quiet_hours", "STARTED", block_message, windows_user=self._safe_windows_user())
                    minute_key = now.strftime("%Y-%m-%d %H:%M")
                    if self._last_block_popup_minute != minute_key:
                        self._last_block_popup_minute = minute_key
                        self._show_popup("Guardian LAN", block_message)
                else:
                    if get_setting("time_block_active", "0") != "0":
                        set_setting("time_block_active", "0")
                        log_event("TIME", "quiet_hours", "ENDED", "Časové omezení skončilo", windows_user=self._safe_windows_user())
            else:
                if get_setting("time_block_active", "0") != "0":
                    set_setting("time_block_active", "0")
            time.sleep(WARNING_CHECK_INTERVAL_SECONDS)


    def _history_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                scan_browser_history()
            except Exception as exc:
                log_event("WEB", "history_scan", "ERROR", "Chyba při čtení historie prohlížeče", windows_user=self._safe_windows_user(), details=str(exc))
            for _ in range(BROWSER_HISTORY_SCAN_INTERVAL_SECONDS):
                if self._stop_event.is_set():
                    break
                time.sleep(1)
