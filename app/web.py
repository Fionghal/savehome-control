from __future__ import annotations

import csv
import io
import ipaddress
import socket
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .config import APP_NAME, BASE_DIR, DEFAULT_PORT, SESSION_SECRET, TEMP_UNLOCK_KEY, TEMP_UNLOCK_REASON_KEY
from .db import (
    cleanup_expired_temp_apps,
    delete_temp_allowed_app,
    get_active_temp_allowed_apps,
    get_conn,
    get_setting,
    get_weekly_rules,
    log_event,
    set_setting,
    upsert_temp_allowed_app,
    utcnow_str,
)
from .security import hash_password, verify_password
from .services.autostart_windows import get_autostart_status, install_autostart, remove_autostart
from .services.hosts_manager import update_hosts

TEMPLATES_DIR = BASE_DIR / "app" / "templates"
STATIC_DIR = BASE_DIR / "app" / "static"


class LanOnlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_host = request.client.host if request.client else ""
        allowed = {"127.0.0.1", "::1", "localhost"}
        try:
            ip = ipaddress.ip_address(client_host)
            if ip.is_loopback or ip.is_private:
                return await call_next(request)
        except ValueError:
            if client_host in allowed:
                return await call_next(request)
        if client_host in allowed:
            return await call_next(request)
        return PlainTextResponse("Přístup povolen jen z localhost nebo z privátní LAN.", status_code=403)


class ProcessNameMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cleanup_expired_temp_apps()
        return await call_next(request)


def _templates() -> Jinja2Templates:
    return Jinja2Templates(directory=str(TEMPLATES_DIR))


def _ensure_admin_exists() -> None:
    with get_conn() as conn:
        row = conn.execute("SELECT id FROM admins LIMIT 1").fetchone()
        if not row:
            now = utcnow_str()
            conn.execute(
                "INSERT INTO admins(username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)",
                ("admin", hash_password("admin123"), now, now),
            )


def _is_logged_in(request: Request) -> bool:
    return bool(request.session.get("admin_user"))


def _require_login(request: Request):
    if not _is_logged_in(request):
        return RedirectResponse("/login", status_code=303)
    return None


def _redirect(path: str, **params: str) -> RedirectResponse:
    query = urlencode({k: v for k, v in params.items() if v is not None and v != ""})
    target = f"{path}?{query}" if query else path
    return RedirectResponse(target, status_code=303)


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _active_rule_summary() -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM time_rules WHERE id = 1").fetchone()
        weekly_count = conn.execute("SELECT COUNT(*) AS c FROM weekly_rules WHERE enabled = 1").fetchone()["c"]
    if weekly_count:
        return f"Týdenní kalendář aktivní na {weekly_count} dnech"
    if row and row.get("enabled"):
        return f"Globální pravidlo {row['block_start']}–{row['block_end']}"
    return "Časová pravidla vypnuta"


def _temporary_unlock_status() -> dict[str, Any]:
    until = get_setting(TEMP_UNLOCK_KEY, "")
    reason = get_setting(TEMP_UNLOCK_REASON_KEY, "")
    if not until:
        return {"active": False, "until": "", "reason": ""}
    try:
        unlock_dt = datetime.strptime(until, "%Y-%m-%d %H:%M:%S")
    except Exception:
        set_setting(TEMP_UNLOCK_KEY, "")
        set_setting(TEMP_UNLOCK_REASON_KEY, "")
        return {"active": False, "until": "", "reason": ""}
    if datetime.now() <= unlock_dt:
        return {"active": True, "until": until, "reason": reason}
    set_setting(TEMP_UNLOCK_KEY, "")
    set_setting(TEMP_UNLOCK_REASON_KEY, "")
    return {"active": False, "until": "", "reason": ""}


def _dashboard_stats() -> dict[str, Any]:
    today = datetime.now().strftime("%Y-%m-%d")
    with get_conn() as conn:
        blocked_apps = conn.execute("SELECT COUNT(*) AS c FROM blocked_apps WHERE enabled = 1").fetchone()["c"]
        blocked_domains = conn.execute("SELECT COUNT(*) AS c FROM blocked_domains WHERE enabled = 1").fetchone()["c"]
        today_events = conn.execute("SELECT COUNT(*) AS c FROM event_logs WHERE substr(ts, 1, 10) = ?", (today,)).fetchone()["c"]
        blocked_today = conn.execute(
            "SELECT COUNT(*) AS c FROM event_logs WHERE substr(ts, 1, 10) = ? AND action IN ('BLOCKED','WARNING')",
            (today,),
        ).fetchone()["c"]
        rules = conn.execute("SELECT * FROM time_rules WHERE id = 1").fetchone()

        day_rows = conn.execute(
            """
            SELECT substr(ts, 1, 10) AS day,
                   SUM(CASE WHEN action = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked,
                   SUM(CASE WHEN action = 'WARNING' THEN 1 ELSE 0 END) AS warnings,
                   COUNT(*) AS total
            FROM event_logs
            WHERE ts >= datetime('now', '-6 days')
            GROUP BY substr(ts, 1, 10)
            ORDER BY day ASC
            """
        ).fetchall()
        top_subjects = conn.execute(
            """
            SELECT subject, event_type, COUNT(*) AS c
            FROM event_logs
            WHERE action = 'BLOCKED'
            GROUP BY subject, event_type
            ORDER BY c DESC, subject COLLATE NOCASE ASC
            LIMIT 8
            """
        ).fetchall()
    max_total = max([int(r["total"]) for r in day_rows], default=1)
    chart_days = []
    for row in day_rows:
        total = int(row["total"])
        blocked = int(row["blocked"])
        warnings = int(row["warnings"])
        chart_days.append(
            {
                "day": row["day"],
                "blocked": blocked,
                "warnings": warnings,
                "total": total,
                "height": max(12, int((total / max_total) * 120)) if total else 12,
            }
        )
    max_top = max([int(r["c"]) for r in top_subjects], default=1)
    top_items = []
    for row in top_subjects:
        count = int(row["c"])
        top_items.append(
            {
                "subject": row["subject"],
                "event_type": row["event_type"],
                "count": count,
                "width": max(6, int((count / max_top) * 100)),
            }
        )

    return {
        "blocked_apps": blocked_apps,
        "blocked_domains": blocked_domains,
        "today_events": today_events,
        "blocked_today": blocked_today,
        "rules": rules,
        "local_ip": _local_ip(),
        "port": DEFAULT_PORT,
        "autostart": get_autostart_status(),
        "app_control_mode": get_setting("app_control_mode", "blacklist"),
        "rule_summary": _active_rule_summary(),
        "weekly_rules_count": len([r for r in get_weekly_rules() if int(r.get("enabled", 0)) == 1]),
        "temp_unlock": _temporary_unlock_status(),
        "watchdog_enabled": get_setting("watchdog_enabled", "1"),
        "temp_allowed_apps": get_active_temp_allowed_apps(),
        "chart_days": chart_days,
        "top_items": top_items,
    }


def _sync_hosts() -> tuple[bool, str]:
    with get_conn() as conn:
        rows = conn.execute("SELECT domain FROM blocked_domains WHERE enabled = 1").fetchall()
    domains = [row["domain"] for row in rows]
    return update_hosts(domains)




def _action_label(action: str) -> str:
    labels = {
        "STARTED": "Spuštěno",
        "STOPPED": "Ukončeno",
        "RECEIVED": "Přijato",
        "UPDATED": "Uloženo",
        "WARNING": "Varování",
        "BLOCKED": "Blokováno",
        "TEMP_ALLOWED": "Dočasně povoleno",
        "TEMP_REVOKED": "Dočasné povolení zrušeno",
        "ERROR": "Chyba",
        "ENDED": "Ukončeno",
        "VISITED": "Navštíveno",
        "BLOCKED_ATTEMPT": "Pokus o vstup na blokovanou doménu",
    }
    return labels.get((action or '').upper(), action or '')


def _event_type_label(event_type: str) -> str:
    labels = {
        "APP": "Aplikace",
        "WEB": "Web",
        "TIME": "Čas",
        "SYSTEM": "Systém",
    }
    return labels.get((event_type or '').upper(), event_type or '')


def _link_info(value: str) -> dict[str, str]:
    value = (value or '').strip()
    if not value:
        return {"href": "", "text": ""}
    if value.startswith(("http://", "https://")):
        return {"href": value, "text": value}
    return {"href": "", "text": value}

def _query_logs(
    event_type: str = "",
    action: str = "",
    q: str = "",
    date_from: str = "",
    date_to: str = "",
    sort_by: str = "ts",
    sort_dir: str = "desc",
    limit: int | None = 500,
):
    allowed_sort = {"ts", "event_type", "subject", "action", "windows_user"}
    sort_by = sort_by if sort_by in allowed_sort else "ts"
    sort_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

    sql = "SELECT * FROM event_logs WHERE 1 = 1"
    params: list[Any] = []
    if event_type:
        sql += " AND event_type = ?"
        params.append(event_type)
    if action:
        sql += " AND action = ?"
        params.append(action)
    if q:
        sql += " AND (subject LIKE ? OR reason LIKE ? OR details LIKE ? OR windows_user LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like, like])
    if date_from:
        sql += " AND substr(ts, 1, 10) >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND substr(ts, 1, 10) <= ?"
        params.append(date_to)
    sql += f" ORDER BY {sort_by} {sort_dir}, id DESC"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    with get_conn() as conn:
        return conn.execute(sql, params).fetchall()


def create_app() -> FastAPI:
    _ensure_admin_exists()
    app = FastAPI(title=APP_NAME)
    app.add_middleware(LanOnlyMiddleware)
    app.add_middleware(ProcessNameMiddleware)
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = _templates()
    templates.env.filters["action_label"] = _action_label
    templates.env.filters["event_type_label"] = _event_type_label
    templates.env.filters["link_info"] = _link_info

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "request": request,
                "title": APP_NAME,
                "data": _dashboard_stats(),
                "message": request.query_params.get("message", ""),
            },
        )

    @app.post("/protection/pause")
    def protection_pause(request: Request, minutes: int = Form(...), reason: str = Form("Dočasně povoleno rodičem")):
        redirect = _require_login(request)
        if redirect:
            return redirect
        minutes = max(1, min(720, int(minutes)))
        until = (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        set_setting(TEMP_UNLOCK_KEY, until)
        set_setting(TEMP_UNLOCK_REASON_KEY, reason.strip())
        log_event("SYSTEM", "temporary_unlock", "STARTED", reason.strip() or "Dočasně povoleno", details=f"until={until}")
        return _redirect("/", message=f"Dočasné odblokování aktivní do {until}")

    @app.post("/protection/resume")
    def protection_resume(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        set_setting(TEMP_UNLOCK_KEY, "")
        set_setting(TEMP_UNLOCK_REASON_KEY, "")
        log_event("SYSTEM", "temporary_unlock", "ENDED", "Ochrana znovu aktivní")
        return _redirect("/", message="Ochrana znovu aktivní")

    @app.post("/apps/allow-temporary")
    def apps_allow_temporary(request: Request, process_name: str = Form(...), minutes: int = Form(...), reason: str = Form("Dočasně povoleno rodičem")):
        redirect = _require_login(request)
        if redirect:
            return redirect
        process_name = process_name.strip().lower()
        if not process_name:
            return _redirect("/apps", message="Neplatný název procesu")
        minutes = max(1, min(720, int(minutes)))
        until = (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        upsert_temp_allowed_app(process_name, until, reason)
        log_event("APP", process_name, "TEMP_ALLOWED", reason.strip(), details=f"until={until}")
        return _redirect("/apps", message=f"Aplikace {process_name} povolena do {until}")

    @app.post("/apps/revoke-temporary/{process_name}")
    def apps_revoke_temporary(request: Request, process_name: str):
        redirect = _require_login(request)
        if redirect:
            return redirect
        delete_temp_allowed_app(process_name)
        log_event("APP", process_name.lower(), "TEMP_REVOKED", "Dočasné povolení zrušeno rodičem")
        return _redirect("/apps", message=f"Dočasné povolení zrušeno pro {process_name}")

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": ""})

    @app.post("/login", response_class=HTMLResponse)
    def login(request: Request, username: str = Form(...), password: str = Form(...)):
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Neplatné přihlášení."})
        request.session["admin_user"] = username
        return RedirectResponse("/", status_code=303)

    @app.get("/logout")
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.get("/domains", response_class=HTMLResponse)
    def domains_page(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM blocked_domains ORDER BY domain COLLATE NOCASE").fetchall()
        return templates.TemplateResponse(request, "domains.html", {"request": request, "rows": rows, "message": request.query_params.get("message", "")})

    @app.post("/domains/add")
    async def domains_add(request: Request, domain: str = Form(...), note: str = Form(""), enabled: str | None = Form(None)):
        redirect = _require_login(request)
        if redirect:
            return redirect
        domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
        if not domain:
            return _redirect("/domains", message="Neplatná doména")
        with get_conn() as conn:
            now = utcnow_str()
            conn.execute(
                """
                INSERT INTO blocked_domains(domain, note, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET note = excluded.note, enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (domain, note.strip(), 1 if enabled else 0, now, now),
            )
        _ok, msg = _sync_hosts()
        log_event("WEB", domain, "UPDATED", note.strip(), details=msg)
        return _redirect("/domains", message=msg)

    @app.post("/domains/toggle/{row_id}")
    def domains_toggle(request: Request, row_id: int):
        redirect = _require_login(request)
        if redirect:
            return redirect
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM blocked_domains WHERE id = ?", (row_id,)).fetchone()
            if row:
                conn.execute("UPDATE blocked_domains SET enabled = ?, updated_at = ? WHERE id = ?", (0 if row["enabled"] else 1, utcnow_str(), row_id))
        _ok, msg = _sync_hosts()
        return _redirect("/domains", message=msg)

    @app.post("/domains/delete/{row_id}")
    def domains_delete(request: Request, row_id: int):
        redirect = _require_login(request)
        if redirect:
            return redirect
        with get_conn() as conn:
            conn.execute("DELETE FROM blocked_domains WHERE id = ?", (row_id,))
        _ok, msg = _sync_hosts()
        return _redirect("/domains", message=msg)

    @app.post("/domains/import")
    async def domains_import(request: Request, file: UploadFile):
        redirect = _require_login(request)
        if redirect:
            return redirect
        content = await file.read()
        text = content.decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(text))
        count = 0
        with get_conn() as conn:
            now = utcnow_str()
            for row in reader:
                domain = (row.get("domain") or "").strip().lower()
                if not domain:
                    continue
                note = (row.get("note") or "").strip()
                enabled = 1 if str(row.get("enabled", "1")).strip() not in {"0", "false", "False", "no"} else 0
                conn.execute(
                    """
                    INSERT INTO blocked_domains(domain, note, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET note = excluded.note, enabled = excluded.enabled, updated_at = excluded.updated_at
                    """,
                    (domain, note, enabled, now, now),
                )
                count += 1
        _ok, msg = _sync_hosts()
        return _redirect("/domains", message=f"Importováno {count} položek. {msg}")

    @app.get("/apps", response_class=HTMLResponse)
    def apps_page(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM blocked_apps ORDER BY process_name COLLATE NOCASE").fetchall()
        return templates.TemplateResponse(
            request,
            "apps.html",
            {
                "request": request,
                "rows": rows,
                "message": request.query_params.get("message", ""),
                "app_control_mode": get_setting("app_control_mode", "blacklist"),
                "temp_allowed_apps": get_active_temp_allowed_apps(),
            },
        )

    @app.post("/apps/add")
    def apps_add(request: Request, process_name: str = Form(...), note: str = Form(""), enabled: str | None = Form(None)):
        redirect = _require_login(request)
        if redirect:
            return redirect
        process_name = process_name.strip().lower()
        if not process_name:
            return _redirect("/apps", message="Neplatný název procesu")
        with get_conn() as conn:
            now = utcnow_str()
            conn.execute(
                """
                INSERT INTO blocked_apps(process_name, note, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(process_name) DO UPDATE SET note = excluded.note, enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (process_name, note.strip(), 1 if enabled else 0, now, now),
            )
        return _redirect("/apps", message="Uloženo")

    @app.post("/apps/toggle/{row_id}")
    def apps_toggle(request: Request, row_id: int):
        redirect = _require_login(request)
        if redirect:
            return redirect
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM blocked_apps WHERE id = ?", (row_id,)).fetchone()
            if row:
                conn.execute("UPDATE blocked_apps SET enabled = ?, updated_at = ? WHERE id = ?", (0 if row["enabled"] else 1, utcnow_str(), row_id))
        return _redirect("/apps", message="Změněno")

    @app.post("/apps/delete/{row_id}")
    def apps_delete(request: Request, row_id: int):
        redirect = _require_login(request)
        if redirect:
            return redirect
        with get_conn() as conn:
            conn.execute("DELETE FROM blocked_apps WHERE id = ?", (row_id,))
        return _redirect("/apps", message="Smazáno")

    @app.post("/apps/mode")
    def apps_mode(request: Request, app_control_mode: str = Form(...)):
        redirect = _require_login(request)
        if redirect:
            return redirect
        if app_control_mode not in {"blacklist", "whitelist"}:
            app_control_mode = "blacklist"
        set_setting("app_control_mode", app_control_mode)
        log_event("APP", "mode", "UPDATED", app_control_mode)
        return _redirect("/apps", message="Režim uložen")

    @app.get("/time", response_class=HTMLResponse)
    def time_page(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM time_rules WHERE id = 1").fetchone()
        return templates.TemplateResponse(request, "time_rules.html", {"request": request, "row": row, "weekly_rows": get_weekly_rules(), "message": request.query_params.get("message", "")})

    @app.post("/time/save")
    def time_save(request: Request, warning_time: str = Form(...), block_start: str = Form(...), block_end: str = Form(...), warning_message: str = Form(...), block_message: str = Form(...), enabled: str | None = Form(None)):
        redirect = _require_login(request)
        if redirect:
            return redirect
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE time_rules
                SET warning_time=?, block_start=?, block_end=?, warning_message=?, block_message=?, enabled=?, updated_at=?
                WHERE id = 1
                """,
                (warning_time, block_start, block_end, warning_message.strip(), block_message.strip(), 1 if enabled else 0, utcnow_str()),
            )
        return _redirect("/time", message="Globální pravidlo uloženo")

    @app.post("/time/save-weekly")
    async def time_save_weekly(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        form = await request.form()
        with get_conn() as conn:
            for day in range(7):
                conn.execute(
                    """
                    UPDATE weekly_rules
                    SET enabled=?, warning_time=?, block_start=?, block_end=?, warning_message=?, block_message=?, updated_at=?
                    WHERE day_of_week = ?
                    """,
                    (
                        1 if form.get(f"enabled_{day}") else 0,
                        str(form.get(f"warning_time_{day}") or "20:30"),
                        str(form.get(f"block_start_{day}") or "21:00"),
                        str(form.get(f"block_end_{day}") or "06:00"),
                        str(form.get(f"warning_message_{day}") or "Je čas uložit hru a jít spát.").strip(),
                        str(form.get(f"block_message_{day}") or "Použití PC je nyní omezeno časovým pravidlem.").strip(),
                        utcnow_str(),
                        day,
                    ),
                )
        return _redirect("/time", message="Týdenní kalendář uložen")

    @app.get("/logs", response_class=HTMLResponse)
    def logs_page(request: Request, event_type: str = "", action: str = "", q: str = "", date_from: str = "", date_to: str = "", sort_by: str = "ts", sort_dir: str = "desc"):
        redirect = _require_login(request)
        if redirect:
            return redirect
        rows = _query_logs(event_type, action, q, date_from, date_to, sort_by, sort_dir)
        return templates.TemplateResponse(
            request,
            "logs.html",
            {
                "request": request,
                "rows": rows,
                "filters": {"event_type": event_type, "action": action, "q": q, "date_from": date_from, "date_to": date_to, "sort_by": sort_by, "sort_dir": sort_dir},
            },
        )

    @app.get("/logs/export")
    def logs_export(request: Request, event_type: str = "", action: str = "", q: str = "", date_from: str = "", date_to: str = "", sort_by: str = "ts", sort_dir: str = "desc"):
        redirect = _require_login(request)
        if redirect:
            return redirect
        rows = _query_logs(event_type, action, q, date_from, date_to, sort_by, sort_dir, limit=None)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["ts", "event_type", "subject", "action", "reason", "windows_user", "details"])
        for row in rows:
            writer.writerow([row["ts"], row["event_type"], row["subject"], row["action"], row["reason"], row["windows_user"], row["details"]])
        out = io.BytesIO(buffer.getvalue().encode("utf-8"))
        return StreamingResponse(out, media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="guardian_logs.csv"'})

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        return templates.TemplateResponse(
            request,
            "settings.html",
            {
                "request": request,
                "local_ip": _local_ip(),
                "port": DEFAULT_PORT,
                "autostart": get_autostart_status(),
                "tray_enabled": get_setting("tray_enabled", "1"),
                "open_browser_on_start": get_setting("open_browser_on_start", "1"),
                "watchdog_enabled": get_setting("watchdog_enabled", "1"),
                "message": request.query_params.get("message", ""),
            },
        )

    @app.post("/settings/change-password")
    def settings_change_password(request: Request, username: str = Form(...), password: str = Form(...)):
        redirect = _require_login(request)
        if redirect:
            return redirect
        username = username.strip()
        if not username or not password.strip():
            return _redirect("/settings", message="Neplatné údaje")
        with get_conn() as conn:
            now = utcnow_str()
            row = conn.execute("SELECT id FROM admins LIMIT 1").fetchone()
            if row:
                conn.execute("UPDATE admins SET username=?, password_hash=?, updated_at=? WHERE id=?", (username, hash_password(password), now, row["id"]))
            else:
                conn.execute("INSERT INTO admins(username, password_hash, created_at, updated_at) VALUES(?, ?, ?, ?)", (username, hash_password(password), now, now))
        request.session["admin_user"] = username
        return _redirect("/settings", message="Přihlašovací údaje uloženy")

    @app.post("/settings/autostart/install")
    def settings_autostart_install(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        _ok, msg = install_autostart()
        return _redirect("/settings", message=msg)

    @app.post("/settings/autostart/remove")
    def settings_autostart_remove(request: Request):
        redirect = _require_login(request)
        if redirect:
            return redirect
        _ok, msg = remove_autostart()
        return _redirect("/settings", message=msg)

    @app.post("/settings/ui")
    def settings_ui(request: Request, tray_enabled: str | None = Form(None), open_browser_on_start: str | None = Form(None), watchdog_enabled: str | None = Form(None)):
        redirect = _require_login(request)
        if redirect:
            return redirect
        set_setting("tray_enabled", "1" if tray_enabled else "0")
        set_setting("open_browser_on_start", "1" if open_browser_on_start else "0")
        set_setting("watchdog_enabled", "1" if watchdog_enabled else "0")
        return _redirect("/settings", message="UI a watchdog nastavení uloženo")

    return app
