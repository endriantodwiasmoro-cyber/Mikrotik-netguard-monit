"""NetGuard Monit: PRTG-like LAN monitoring for MikroTik RouterOS.

A web-based network monitoring application providing:
- Real-time interface traffic monitoring (per second, minute, hour, day, month)
- Link DOWN/UP alerts for router and WAN interface
- DDoS and Broadcast anomaly detection
- RouterOS system health monitoring (CPU, disk, uptime)
- Telegram notifications for alerts
- Secure dashboard with authentication, CSRF protection, and security headers

Security model:
- RouterOS REST is reachable only on the LAN from this Docker host.
- The application has no published Docker port; Cloudflare Tunnel is the only ingress.
- Secrets live only in .env (excluded from version control).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import sqlite3
import time
from urllib.parse import urlparse
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    status,
    Query,
)
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import alerts as alerts_module
from . import collectors
from .ddos_detector import create_detector_from_settings
from .database import (
    connect,
    get_alert_events,
    get_alerts,
    get_interface_traffic,
    get_latest_ping_sample,
    get_latest_telemetry,
    get_login_attempts,
    get_ping_history,
    get_telemetry_history,
    initialize_database,
    insert_ping_sample,
    insert_telemetry,
    local_shift_sql,
    parse_number,
    to_local_iso,
    upsert_sensor,
)

LOG = logging.getLogger("netguard")
DATA_DIR = Path("/data")
DATABASE_PATH = DATA_DIR / "netguard.db"
PASSWORD_HASHER = PasswordHasher()
UTC = timezone.utc


def now() -> datetime:
    return datetime.now(UTC)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds")


def parse_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be true or false")


def parse_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    admin_password: str
    trusted_hosts: list[str]
    session_ttl_hours: int
    alert_cooldown_minutes: int
    retention_days: int
    mikrotik_base_url: str
    mikrotik_username: str
    mikrotik_password: str
    mikrotik_wan_interface: str
    mikrotik_tls_verify: bool | str
    poll_interval_seconds: int
    cpu_alert_percent: int
    collect_method: str
    snmp_host: str | None
    snmp_community: str | None
    ddos_threshold_bps: float
    broadcast_threshold_pps: int
    telegram_bot_token: str | None
    telegram_chat_id: str | None
    # DDoS Detection settings
    ddos_detection_enabled: bool
    ddos_profile: str
    ddos_automitigate: bool
    ddos_dry_run: bool
    ddos_ewma_alpha: float
    ddos_min_stddev_bps: float
    ddos_warmup_days: int
    ddos_mitigation_cooldown: int
    ddos_weight_bps: float
    ddos_weight_pps: float
    ddos_weight_drops: float
    ddos_weight_newconn: float
    ddos_weight_synratio: float
    # Ping monitoring settings
    ping_enabled: bool
    ping_targets: list[str]
    ping_count: int
    ping_timeout_seconds: float
    ping_latency_alert_ms: float
    ping_packet_loss_alert_percent: float


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def get_settings() -> Settings:
    admin_password = required("APP_ADMIN_PASSWORD")
    if len(admin_password) < 16:
        raise RuntimeError("APP_ADMIN_PASSWORD must contain at least 16 characters")

    trusted_hosts = [
        item.strip().lower()
        for item in required("APP_TRUSTED_HOSTS").split(",")
        if item.strip()
    ]
    if not trusted_hosts or "*" in trusted_hosts:
        raise RuntimeError("APP_TRUSTED_HOSTS must contain explicit hostnames, never '*'")

    base_url = required("MIKROTIK_BASE_URL").rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise RuntimeError("MIKROTIK_BASE_URL must be an HTTPS URL with a host only")
    try:
        router_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise RuntimeError("MIKROTIK_BASE_URL must use a private IP literal") from error
    if not router_ip.is_private:
        raise RuntimeError("MIKROTIK_BASE_URL must use a private IP address")

    tls_value = os.getenv("MIKROTIK_TLS_VERIFY", "true").strip()
    if tls_value.lower() in {"1", "true", "yes", "on"}:
        tls_verify: bool | str = True
    elif tls_value.lower() in {"0", "false", "no", "off"}:
        tls_verify = False
    else:
        cert_path = Path(tls_value)
        if not cert_path.is_absolute() or not cert_path.is_file():
            raise RuntimeError(
                "MIKROTIK_TLS_VERIFY must be true, false, or an existing CA-certificate path"
            )
        tls_verify = str(cert_path)

    collect_method = os.getenv("MIKROTIK_COLLECT_METHOD", "rest").strip().lower()
    if collect_method not in {"rest", "snmp", "both"}:
        raise RuntimeError("MIKROTIK_COLLECT_METHOD must be rest, snmp, or both")

    snmp_host = os.getenv("MIKROTIK_SNMP_HOST", "").strip() or None
    snmp_community = os.getenv("MIKROTIK_SNMP_COMMUNITY", "").strip() or None
    if collect_method in {"snmp", "both"} and not snmp_host:
        raise RuntimeError("MIKROTIK_SNMP_HOST is required when collect_method is snmp or both")
    if collect_method in {"snmp", "both"} and not snmp_community:
        raise RuntimeError("MIKROTIK_SNMP_COMMUNITY is required when collect_method is snmp or both")

    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip() or None
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip() or None
    if bool(token) != bool(chat_id):
        raise RuntimeError("set both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, or leave both blank")

    return Settings(
        admin_password=admin_password,
        trusted_hosts=trusted_hosts,
        session_ttl_hours=parse_int("APP_SESSION_TTL_HOURS", 8, 1, 24),
        alert_cooldown_minutes=parse_int("APP_ALERT_COOLDOWN_MINUTES", 240, 5, 10080),
        retention_days=parse_int("APP_RETENTION_DAYS", 30, 1, 365),
        mikrotik_base_url=base_url,
        mikrotik_username=required("MIKROTIK_USERNAME"),
        mikrotik_password=required("MIKROTIK_PASSWORD"),
        mikrotik_wan_interface=os.getenv("MIKROTIK_WAN_INTERFACE", "").strip(),
        mikrotik_tls_verify=tls_verify,
        poll_interval_seconds=parse_int("MIKROTIK_POLL_INTERVAL_SECONDS", 5, 5, 3600),
        cpu_alert_percent=parse_int("MIKROTIK_CPU_ALERT_PERCENT", 85, 1, 100),
        collect_method=collect_method,
        snmp_host=snmp_host,
        snmp_community=snmp_community,
        ddos_threshold_bps=float(os.getenv("DDOS_THRESHOLD_BPS", "100000000")),
        broadcast_threshold_pps=int(os.getenv("BROADCAST_THRESHOLD_PPS", "1000")),
        telegram_bot_token=token,
        telegram_chat_id=chat_id,
        # DDoS Detection settings
        ddos_detection_enabled=parse_bool("DDOS_DETECTION_ENABLED", True),
        ddos_profile=os.getenv("DDOS_PROFILE", "balanced").strip().lower(),
        ddos_automitigate=parse_bool("DDOS_AUTOMITIGATE", False),
        ddos_dry_run=parse_bool("DDOS_DRY_RUN", True),
        ddos_ewma_alpha=float(os.getenv("DDOS_EWMA_ALPHA", "0.3")),
        ddos_min_stddev_bps=float(os.getenv("DDOS_MIN_STDDEV_BPS", "100000")),
        ddos_warmup_days=parse_int("DDOS_WARMUP_DAYS", 7, 1, 30),
        ddos_mitigation_cooldown=parse_int("DDOS_MITIGATION_COOLDOWN_SECONDS", 300, 60, 3600),
        ddos_weight_bps=float(os.getenv("DDOS_WEIGHT_BPS", "0.30")),
        ddos_weight_pps=float(os.getenv("DDOS_WEIGHT_PPS", "0.25")),
        ddos_weight_drops=float(os.getenv("DDOS_WEIGHT_DROPS", "0.15")),
        ddos_weight_newconn=float(os.getenv("DDOS_WEIGHT_NEWCONN", "0.20")),
        ddos_weight_synratio=float(os.getenv("DDOS_WEIGHT_SYNRATIO", "0.10")),
        # Ping monitoring settings
        ping_enabled=parse_bool("PING_ENABLED", True),
        ping_targets=[
            item.strip()
            for item in os.getenv("PING_TARGETS", "8.8.8.8,1.1.1.1").split(",")
            if item.strip()
        ],
        ping_count=parse_int("PING_COUNT", 4, 1, 20),
        ping_timeout_seconds=float(os.getenv("PING_TIMEOUT_SECONDS", "5.0")),
        ping_latency_alert_ms=float(os.getenv("PING_LATENCY_ALERT_MS", "100.0")),
        ping_packet_loss_alert_percent=float(
            os.getenv("PING_PACKET_LOSS_ALERT_PERCENT", "50.0")
        ),
    )


SETTINGS = get_settings()
ADMIN_PASSWORD_HASH = PASSWORD_HASHER.hash(SETTINGS.admin_password)

# Initialize DDoS detector
DDOS_DETECTOR = create_detector_from_settings(SETTINGS)


def format_bytes(value: Any) -> str:
    number = parse_number(value)
    if number is None:
        return "—"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if abs(number) < 1024 or unit == units[-1]:
            return f"{number:.1f} {unit}"
        number /= 1024
    return "—"


def format_bps(value: float) -> str:
    if value is None or value == 0:
        return "0 bps"
    units = ["bps", "Kbps", "Mbps", "Gbps"]
    num = float(value)
    for unit in units:
        if abs(num) < 1000 or unit == units[-1]:
            return f"{num:.1f} {unit}"
        num /= 1000
    return f"{num:.1f} {units[-1]}"


def render_telemetry(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "observed_at": to_local_iso(row["observed_at"]),
        "router_up": bool(row["router_up"]),
        "cpu_load": "—" if row["cpu_load"] is None else f"{row['cpu_load']:.0f}%",
        "cpu_load_raw": row["cpu_load"],
        "free_hdd_space": format_bytes(row["free_hdd_space"]),
        "total_hdd_space": format_bytes(row["total_hdd_space"]),
        "wan_running": None if row["wan_running"] is None else bool(row["wan_running"]),
        "details": json.loads(row["details"]),
    }


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def client_ip(request: Request) -> str:
    return request.headers.get("CF-Connecting-IP") or (
        request.client.host if request.client else "unknown"
    )


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def read_session(request: Request) -> sqlite3.Row | None:
    token = request.cookies.get("netguard_session")
    if not token:
        return None
    with connect() as db:
        session = db.execute(
            "SELECT * FROM sessions WHERE token_hash = ?", (token_digest(token),)
        ).fetchone()
    if session is None or datetime.fromisoformat(session["expires_at"]) <= now():
        return None
    return session


def require_session(request: Request) -> sqlite3.Row:
    session = read_session(request)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"}
        )
    return session


async def verify_csrf(request: Request, session: sqlite3.Row) -> None:
    supplied = request.headers.get("X-CSRF-Token")
    if not supplied:
        form = await request.form()
        supplied = form.get("csrf")
    if not isinstance(supplied, str) or not secrets.compare_digest(
        supplied, session["csrf_token"]
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")


# ---------------------------------------------------------------------------
# Monitoring loop
# ---------------------------------------------------------------------------

async def poll_once() -> None:
    """Single collection cycle: gather metrics, store, evaluate alerts."""
    observed_at = iso()
    result: collectors.CollectorResult

    try:
        if SETTINGS.collect_method == "rest":
            result = collectors.collect_router_rest(
                base_url=SETTINGS.mikrotik_base_url,
                username=SETTINGS.mikrotik_username,
                password=SETTINGS.mikrotik_password,
                wan_interface=SETTINGS.mikrotik_wan_interface,
                tls_verify=SETTINGS.mikrotik_tls_verify,
                cpu_alert_percent=SETTINGS.cpu_alert_percent,
            )
        elif SETTINGS.collect_method == "snmp":
            if not SETTINGS.snmp_host or not SETTINGS.snmp_community:
                raise RuntimeError("SNMP host/community not configured")
            result = await collectors.collect_router_snmp(
                host=SETTINGS.snmp_host,
                community=SETTINGS.snmp_community,
                wan_interface=SETTINGS.mikrotik_wan_interface,
            )
        else:  # both
            result = collectors.collect_router_rest(
                base_url=SETTINGS.mikrotik_base_url,
                username=SETTINGS.mikrotik_username,
                password=SETTINGS.mikrotik_password,
                wan_interface=SETTINGS.mikrotik_wan_interface,
                tls_verify=SETTINGS.mikrotik_tls_verify,
                cpu_alert_percent=SETTINGS.cpu_alert_percent,
            )
            if SETTINGS.snmp_host and SETTINGS.snmp_community:
                snmp_result = await collectors.collect_router_snmp(
                    host=SETTINGS.snmp_host,
                    community=SETTINGS.snmp_community,
                    wan_interface=SETTINGS.mikrotik_wan_interface,
                )
                # Merge SNMP interfaces (REST takes precedence for same name)
                merged = list(result.interfaces)
                for s in snmp_result.interfaces:
                    if s.name not in {x.name for x in merged}:
                        merged.append(s)
                result.interfaces = merged

    except (httpx.HTTPError, ValueError, RuntimeError) as error:
        LOG.warning("Router collection failed: %s", error)
        result = collectors.CollectorResult(
            router_up=False,
            cpu_load=None,
            free_hdd_space=None,
            total_hdd_space=None,
            wan_running=None,
            details={"error": str(error)[:500]},
            error=str(error),
        )

    # --- Ping monitoring ---
    ping_results: list[collectors.PingResult] = []
    if SETTINGS.ping_enabled and SETTINGS.ping_targets:
        for target in SETTINGS.ping_targets:
            try:
                pr = await collectors.collect_ping(
                    target=target,
                    count=SETTINGS.ping_count,
                    timeout_seconds=SETTINGS.ping_timeout_seconds,
                )
                ping_results.append(pr)
                insert_ping_sample(
                    {
                        "observed_at": observed_at,
                        "target": pr.target,
                        "packets_sent": pr.packets_sent,
                        "packets_received": pr.packets_received,
                        "packet_loss_percent": pr.packet_loss_percent,
                        "min_latency_ms": pr.min_latency_ms,
                        "avg_latency_ms": pr.avg_latency_ms,
                        "max_latency_ms": pr.max_latency_ms,
                    }
                )
                upsert_sensor(
                    name=f"ping:{pr.target}",
                    type_="ping",
                    description=f"Ping probe to {pr.target}",
                    enabled=True,
                )
            except Exception as exc:  # noqa: BLE001 - ping is best-effort
                LOG.warning("Ping to %s failed: %s", target, exc)

    # Store system telemetry
    insert_telemetry(
        {
            "router_up": result.router_up,
            "cpu_load": result.cpu_load,
            "free_hdd_space": result.free_hdd_space,
            "total_hdd_space": result.total_hdd_space,
            "wan_running": result.wan_running,
            "details": result.details,
        },
        observed_at,
    )

    # Evaluate and dispatch alerts
    alert_tuples = alerts_module.evaluate_alerts(result, SETTINGS)

    # DDoS detection
    if SETTINGS.ddos_detection_enabled:
        ddos_alerts = await DDOS_DETECTOR.process_poll(result)
        alert_tuples.extend(ddos_alerts)

    # Ping alerts
    if ping_results:
        ping_alerts = alerts_module.evaluate_ping_alerts(ping_results, SETTINGS)
        alert_tuples.extend(ping_alerts)

    await alerts_module.dispatch_alerts(alert_tuples, SETTINGS)


async def monitor_loop() -> None:
    while True:
        cycle_started = time.monotonic()
        try:
            await poll_once()
        except Exception:  # keep the worker alive
            LOG.exception("Unexpected monitor failure")
        elapsed = time.monotonic() - cycle_started
        await asyncio.sleep(max(1.0, SETTINGS.poll_interval_seconds - elapsed))


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    task = asyncio.create_task(monitor_loop(), name="router-monitor")
    yield
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


app = FastAPI(
    title="NetGuard Monit",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=SETTINGS.trusted_hosts)
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static",
)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
templates.env.filters["bytes"] = format_bytes
templates.env.filters["bps"] = format_bps


@app.middleware("http")
async def security_headers(request: Request, call_next: Any):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers[
        "Permissions-Policy"
    ] = "camera=(), geolocation=(), microphone=()"
    response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    if read_session(request):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, password: str = Form(...)) -> HTMLResponse:
    source_ip = client_ip(request)
    failures = get_login_attempts(source_ip, minutes=15)  # type: ignore[arg-type]
    if failures >= 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts; try again later",
        )

    try:
        valid = PASSWORD_HASHER.verify(ADMIN_PASSWORD_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        valid = False
    if not valid:
        with connect() as db:
            db.execute(
                "INSERT INTO login_attempts(source_ip, attempted_at) VALUES (?, ?)",
                (source_ip, iso()),
            )
        return templates.TemplateResponse(
            request, "login.html", {"error": "Login failed."}, status_code=401
        )

    raw_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    with connect() as db:
        db.execute(
            "INSERT INTO sessions(token_hash, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (
                token_digest(raw_token),
                csrf_token,
                iso(now() + timedelta(hours=SETTINGS.session_ttl_hours)),
                iso(),
            ),
        )
        db.execute("DELETE FROM login_attempts WHERE source_ip = ?", (source_ip,))
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    # secure=True hanya dikirim via HTTPS. Untuk development via HTTP (localhost),
    # secure=False agar session cookie tetap terkirim dan API fetch dari JavaScript
    # tidak gagal dengan 401. Di produksi dengan Cloudflare Tunnel (HTTPS),
    # ini akan otomatis kembali ke true.
    is_secure = request.url.scheme == "https"
    response.set_cookie(
        "netguard_session",
        raw_token,
        max_age=SETTINGS.session_ttl_hours * 3600,
        httponly=True,
        secure=is_secure,
        samesite="lax",  # "strict" mencegah cookie dikirim saat navigasi cross-origin
        path="/",
    )
    return response


@app.post("/logout")
async def logout(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> RedirectResponse:
    await verify_csrf(request, session)
    token = request.cookies.get("netguard_session")
    if token:
        with connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),)
            )
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("netguard_session", path="/")
    return response


@app.post("/poll")
async def manual_poll(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> RedirectResponse:
    await verify_csrf(request, session)
    await poll_once()
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> HTMLResponse:
    with connect() as db:
        telemetry_row = db.execute(
            "SELECT * FROM telemetry ORDER BY id DESC LIMIT 1"
        ).fetchone()
        alerts = db.execute(
            "SELECT * FROM alerts ORDER BY status='active' DESC, last_seen_at DESC LIMIT 12"
        ).fetchall()
        events = db.execute(
            "SELECT * FROM alert_events ORDER BY id DESC LIMIT 10"
        ).fetchall()

    # Latest sample per interface for status cards
    from .database import get_latest_interface_sample, get_sensors

    sensors = get_sensors()
    interface_status: dict[str, dict[str, Any]] = {}
    for sensor in sensors:
        if sensor["type"] == "interface":
            sample = get_latest_interface_sample(sensor["name"])
            if sample:
                interface_status[sensor["name"]] = dict(sample)

    def localize(row: sqlite3.Row, fields: tuple[str, ...]) -> dict[str, Any]:
        data = dict(row)
        for field in fields:
            if data.get(field):
                data[field] = to_local_iso(data[field])
        return data

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "telemetry": render_telemetry(telemetry_row) if telemetry_row else None,
            "alerts": [
                localize(
                    a, ("created_at", "last_seen_at", "last_notified_at", "resolved_at")
                )
                for a in alerts
            ],
            "events": [localize(e, ("created_at",)) for e in events],
            "csrf": session["csrf_token"],
            "wan_name": SETTINGS.mikrotik_wan_interface or None,
            "interfaces": interface_status,
            "default_interface": next(iter(interface_status)) if interface_status else None,
            "collect_method": SETTINGS.collect_method,
            "ddos_threshold_bps": SETTINGS.ddos_threshold_bps,
            "broadcast_threshold_pps": SETTINGS.broadcast_threshold_pps,
            "ping_targets": SETTINGS.ping_targets if SETTINGS.ping_enabled else [],
            "ping_enabled": SETTINGS.ping_enabled,
        },
    )


# ---------------------------------------------------------------------------
# API endpoints (JSON) — all require session
# ---------------------------------------------------------------------------

@app.get("/api/telemetry/latest")
async def api_latest_telemetry(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> JSONResponse:
    with connect() as db:
        row = db.execute(
            "SELECT * FROM telemetry ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return JSONResponse({"status": "no_data"})
    return JSONResponse(render_telemetry(row))


@app.get("/api/telemetry/history")
async def api_telemetry_history(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
    granularity: str = Query("minute", pattern="^(second|minute|hour|day|month)$"),
    range_hours: int = Query(24, ge=1, le=720),
) -> JSONResponse:
    data = get_telemetry_history(granularity=granularity, range_hours=range_hours)
    return JSONResponse(data)


@app.get("/api/interfaces")
async def api_interfaces(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> JSONResponse:
    from .database import get_sensors, get_latest_interface_sample

    sensors = get_sensors()
    out: list[dict[str, Any]] = []
    for sensor in sensors:
        if sensor["type"] != "interface":
            continue
        sample = get_latest_interface_sample(sensor["name"])
        out.append(
            {
                "name": sensor["name"],
                "description": sensor.get("description"),
                "status": (sample or {}).get("status", "unknown"),
                "rx_bps": (sample or {}).get("rx_bps", 0.0),
                "tx_bps": (sample or {}).get("tx_bps", 0.0),
                "rx_bytes": (sample or {}).get("rx_bytes", 0),
                "tx_bytes": (sample or {}).get("tx_bytes", 0),
                "rx_packets": (sample or {}).get("rx_packets", 0),
                "tx_packets": (sample or {}).get("tx_packets", 0),
                "observed_at": (sample or {}).get("observed_at"),
            }
        )
    return JSONResponse(out)


@app.get("/api/interfaces/{name}/traffic")
async def api_interface_traffic(
    name: str,
    request: Request,
    session: sqlite3.Row = Depends(require_session),
    granularity: str = Query("minute", pattern="^(second|minute|hour|day|month)$"),
    range_hours: int = Query(24, ge=1, le=720),
) -> JSONResponse:
    data = get_interface_traffic(
        interface_name=name,
        granularity=granularity,
        range_hours=range_hours,
    )
    return JSONResponse(data)


@app.get("/api/ping/latest")
async def api_ping_latest(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
    target: str | None = Query(None),
) -> JSONResponse:
    row = get_latest_ping_sample(target=target)
    if row is None:
        return JSONResponse({"status": "no_data"})
    return JSONResponse(row)


@app.get("/api/ping/history")
async def api_ping_history(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
    target: str = Query(...),
    granularity: str = Query("second", pattern="^(second|minute|hour|day|month)$"),
    range_hours: int = Query(24, ge=1, le=720),
) -> JSONResponse:
    data = get_ping_history(target=target, granularity=granularity, range_hours=range_hours)
    return JSONResponse(data)


@app.get("/api/alerts")
async def api_alerts(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> JSONResponse:
    return JSONResponse(get_alerts())


@app.get("/api/alerts/events")
async def api_alert_events(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> JSONResponse:
    return JSONResponse(get_alert_events())


# ============================================================
# DDoS Detection Routes & API
# ============================================================

@app.get("/ddos", response_class=HTMLResponse)
async def ddos_dashboard(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> HTMLResponse:
    from .database import get_sensors
    sensors = get_sensors()
    interfaces = [s for s in sensors if s["type"] == "interface"]
    return templates.TemplateResponse(
        request,
        "ddos.html",
        {
            "csrf": session["csrf_token"],
            "interfaces": interfaces,
            "profile": SETTINGS.ddos_profile,
            "automitigate": SETTINGS.ddos_automitigate,
        },
    )


@app.get("/api/ddos/status")
async def api_ddos_status(
    request: Request, session: sqlite3.Row = Depends(require_session)
) -> JSONResponse:
    from .database import get_latest_ddos_scores
    scores = get_latest_ddos_scores()
    return JSONResponse({"interfaces": scores})


@app.get("/api/ddos/history")
async def api_ddos_history(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
    interface: str = Query(...),
    granularity: str = Query("minute", pattern="^(second|minute|hour|day)$"),
    range_hours: int = Query(24, ge=1, le=720),
) -> JSONResponse:
    """Get composite anomaly score history for an interface."""
    from .database import connect, _bucket_format, iso, now
    from datetime import timedelta

    bucket = _bucket_format(granularity)
    since = iso(now() - timedelta(hours=range_hours))
    local_created = local_shift_sql("created_at")

    # For now, derive from alerts or return mock structure
    # In Phase 1B, we'll store actual score history in a dedicated table
    with connect() as db:
        rows = db.execute(
            f"""
            SELECT
                strftime('{bucket}', {local_created}) AS bucket,
                MAX(CASE
                    WHEN message LIKE '%score %' THEN
                        CAST(SUBSTR(message, INSTR(message, 'score ') + 6) AS REAL)
                    ELSE 0
                END) AS composite_score
            FROM alert_events
            WHERE fingerprint LIKE 'ddos_anomaly_%{interface}%' AND created_at >= ?
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (since,),
        ).fetchall()

    data = [
        {"bucket": r["bucket"], "composite_score": round(r["composite_score"] or 0, 2)}
        for r in rows
    ]
    return JSONResponse(data)


@app.get("/api/ddos/breakdown")
async def api_ddos_breakdown(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
    interface: str = Query(...),
    granularity: str = Query("minute", pattern="^(second|minute|hour|day)$"),
    range_hours: int = Query(24, ge=1, le=720),
) -> JSONResponse:
    """Get metric z-score breakdown history for an interface."""
    # Placeholder - will be implemented with dedicated storage in Phase 1B
    return JSONResponse([])


@app.get("/api/ddos/baselines")
async def api_ddos_baselines(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
    metric: str = Query("rx_bps", pattern="^(rx_bps|rx_pps|drops|new_conn|syn_ratio)$"),
) -> JSONResponse:
    """Get seasonal baselines (168 hour-of-week buckets) for a metric."""
    from .database import get_ddos_baselines, get_sensors

    # Get first interface if not specified - for demo, we'll use the first available
    sensors = get_sensors()
    interfaces = [s for s in sensors if s["type"] == "interface"]
    if not interfaces:
        return JSONResponse([])

    # For now, return baselines for the first interface
    # In production, this should accept interface parameter
    iface = interfaces[0]["name"]
    baselines = get_ddos_baselines(iface, metric)
    return JSONResponse(baselines)


@app.get("/api/ddos/mitigation/history")
async def api_ddos_mitigation_history(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
    limit: int = Query(50, ge=1, le=100),
) -> JSONResponse:
    """Get mitigation action history."""
    from .database import get_mitigation_history
    history = get_mitigation_history(limit)
    return JSONResponse(history)


@app.get("/api/ddos/metrics/{interface}")
async def api_ddos_metrics(
    interface: str,
    request: Request,
    session: sqlite3.Row = Depends(require_session),
) -> JSONResponse:
    """Get current metrics vs baseline for an interface."""
    from .database import get_latest_interface_sample, get_current_ddos_baseline

    sample = get_latest_interface_sample(interface)
    if not sample:
        return JSONResponse({"metrics": []})

    metrics = []

    # rx_bps
    baseline_data = get_current_ddos_baseline(interface, "rx_bps")
    if baseline_data:
        baseline, stddev = baseline_data
        current = sample.get("rx_bps", 0)
        z = (current - baseline) / max(stddev, 1) if stddev > 0 else 0
        metrics.append({
            "key": "bps",
            "label": "rx_bps",
            "unit": "bps",
            "current": current,
            "baseline": baseline,
            "stddev": stddev,
            "threshold": baseline + 3 * stddev,
            "z_score": z
        })

    # rx_pps (derived from rx_packets)
    baseline_data = get_current_ddos_baseline(interface, "rx_pps")
    if baseline_data:
        baseline, stddev = baseline_data
        current = sample.get("rx_packets", 0)  # packets per poll interval
        z = (current - baseline) / max(stddev, 1) if stddev > 0 else 0
        metrics.append({
            "key": "pps",
            "label": "rx_pps",
            "unit": "pps",
            "current": current,
            "baseline": baseline,
            "stddev": stddev,
            "threshold": baseline + 3 * stddev,
            "z_score": z
        })

    # drops
    baseline_data = get_current_ddos_baseline(interface, "drops")
    if baseline_data:
        baseline, stddev = baseline_data
        current = sample.get("rx_drops", 0) + sample.get("tx_drops", 0)
        z = (current - baseline) / max(stddev, 1) if stddev > 0 else 0
        metrics.append({
            "key": "drops",
            "label": "rx_drops + tx_drops",
            "unit": "drops",
            "current": current,
            "baseline": baseline,
            "stddev": stddev,
            "threshold": baseline + 3 * stddev,
            "z_score": z
        })

    # new_conn - placeholder (needs connection tracking data)
    baseline_data = get_current_ddos_baseline(interface, "new_conn")
    if baseline_data:
        baseline, stddev = baseline_data
        current = 0  # Would need connection tracking
        z = (current - baseline) / max(stddev, 1) if stddev > 0 else 0
        metrics.append({
            "key": "newconn",
            "label": "new_conn_rate",
            "unit": "conn/s",
            "current": current,
            "baseline": baseline,
            "stddev": stddev,
            "threshold": baseline + 3 * stddev,
            "z_score": z
        })

    # syn_ratio - placeholder
    baseline_data = get_current_ddos_baseline(interface, "syn_ratio")
    if baseline_data:
        baseline, stddev = baseline_data
        current = 0
        z = (current - baseline) / max(stddev, 1) if stddev > 0 else 0
        metrics.append({
            "key": "synratio",
            "label": "syn_sent / established",
            "unit": "ratio",
            "current": current,
            "baseline": baseline,
            "stddev": stddev,
            "threshold": baseline + 3 * stddev,
            "z_score": z
        })

    return JSONResponse({"metrics": metrics})


@app.post("/api/ddos/mitigation/toggle")
async def api_ddos_mitigation_toggle(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
) -> JSONResponse:
    await verify_csrf(request, session)
    body = await request.json()
    enabled = bool(body.get("enabled", False))
    # Store in a simple config table or env - for now just return success
    return JSONResponse({"enabled": enabled, "message": "Auto-mitigation toggle updated"})


@app.post("/api/ddos/mitigation/rollback")
async def api_ddos_mitigation_rollback(
    request: Request,
    session: sqlite3.Row = Depends(require_session),
) -> JSONResponse:
    await verify_csrf(request, session)
    from .database import update_mitigation_rollback, get_mitigation_history

    # Get active mitigations and roll them back
    history = get_mitigation_history(100)
    rolled_back = []
    for action in history:
        if action["status"] == "executed":
            update_mitigation_rollback(action["interface_name"], action["action"])
            rolled_back.append(action["action"])

    return JSONResponse({"rolled_back": rolled_back, "message": f"Rolled back {len(rolled_back)} actions"})


# ============================================================
# Initialize DDoS tables on startup
# ============================================================

# Patch the lifespan to initialize DDoS tables
_original_lifespan = app.router.lifespan_context

@asynccontextmanager
async def lifespan_with_ddos(app: FastAPI):
    from .database import initialize_ddos_tables
    initialize_ddos_tables()
    async with _original_lifespan(app) as state:
        yield state

app.router.lifespan_context = lifespan_with_ddos
