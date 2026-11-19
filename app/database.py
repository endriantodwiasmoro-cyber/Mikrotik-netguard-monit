"""Database layer for NetGuard Monit.

SQLite schema for time-series telemetry, interface traffic samples,
sensors, alerts, sessions, and login attempts.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

LOG = logging.getLogger("netguard")
DATA_DIR = Path("/data")
DATABASE_PATH = DATA_DIR / "netguard.db"
UTC = timezone.utc
DEFAULT_TIMEZONE = "Asia/Jakarta"


def now() -> datetime:
    return datetime.now(UTC)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds")


def local_timezone() -> timezone | ZoneInfo:
    """Return the configured display timezone (APP_TIMEZONE, default Asia/Jakarta).

    Falls back to a fixed UTC+7 offset when the timezone database is unavailable.
    """
    name = os.getenv("APP_TIMEZONE", DEFAULT_TIMEZONE).strip() or DEFAULT_TIMEZONE
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        LOG.warning("Unknown APP_TIMEZONE %r; falling back to UTC+7", name)
        return timezone(timedelta(hours=7))


def local_offset_minutes() -> int:
    """Offset in minutes between the display timezone and UTC."""
    offset = datetime.now(UTC).astimezone(local_timezone()).utcoffset()
    return int((offset or timedelta(0)).total_seconds() // 60)


def local_shift_sql(column: str) -> str:
    """SQLite expression that converts a stored UTC timestamp column to local time."""
    minutes = local_offset_minutes()
    sign = "+" if minutes >= 0 else "-"
    return f"datetime({column}, '{sign}{abs(minutes)} minutes')"


def to_local_iso(value: str | None) -> str | None:
    """Convert a stored UTC ISO timestamp to the display timezone (ISO with offset)."""
    if not value:
        return value
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(local_timezone()).isoformat(timespec="seconds")


def parse_number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def initialize_database() -> None:
    """Create all tables and indexes if they do not exist."""
    with connect() as db:
        db.executescript(
            """
            -- System-level telemetry (one row per poll)
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY,
                observed_at TEXT NOT NULL,
                router_up INTEGER NOT NULL,
                cpu_load REAL,
                free_hdd_space INTEGER,
                total_hdd_space INTEGER,
                wan_running INTEGER,
                details TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS telemetry_observed_at ON telemetry(observed_at DESC);

            -- Raw interface counter samples (one row per interface per poll)
            CREATE TABLE IF NOT EXISTS interface_samples (
                id INTEGER PRIMARY KEY,
                observed_at TEXT NOT NULL,
                interface_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unknown',
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0,
                rx_packets INTEGER NOT NULL DEFAULT 0,
                tx_packets INTEGER NOT NULL DEFAULT 0,
                rx_drops INTEGER NOT NULL DEFAULT 0,
                tx_drops INTEGER NOT NULL DEFAULT 0,
                rx_bps REAL NOT NULL DEFAULT 0,
                tx_bps REAL NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS interface_samples_iface_time
                ON interface_samples(interface_name, observed_at DESC);
            CREATE INDEX IF NOT EXISTS interface_samples_time
                ON interface_samples(observed_at DESC);

            -- Ping / latency samples (one row per poll per target)
            CREATE TABLE IF NOT EXISTS ping_samples (
                id INTEGER PRIMARY KEY,
                observed_at TEXT NOT NULL,
                target TEXT NOT NULL,
                packets_sent INTEGER NOT NULL DEFAULT 0,
                packets_received INTEGER NOT NULL DEFAULT 0,
                packet_loss_percent REAL NOT NULL DEFAULT 0,
                min_latency_ms REAL,
                avg_latency_ms REAL,
                max_latency_ms REAL
            );
            CREATE INDEX IF NOT EXISTS ping_samples_target_time
                ON ping_samples(target, observed_at DESC);
            CREATE INDEX IF NOT EXISTS ping_samples_time
                ON ping_samples(observed_at DESC);

            -- Registered sensors (interfaces and system metrics)
            CREATE TABLE IF NOT EXISTS sensors (
                name TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                description TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            -- Alert rules (threshold-based)
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                threshold REAL,
                severity TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            -- Persisted alert state
            CREATE TABLE IF NOT EXISTS alerts (
                fingerprint TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('active', 'resolved')),
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                last_notified_at TEXT,
                resolved_at TEXT
            );
            CREATE INDEX IF NOT EXISTS alerts_status_seen ON alerts(status, last_seen_at DESC);

            -- Alert event history
            CREATE TABLE IF NOT EXISTS alert_events (
                id INTEGER PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('raised', 'reminder', 'resolved')),
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS alert_events_created_at ON alert_events(created_at DESC);

            -- Sessions and login attempts (auth)
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY,
                source_ip TEXT NOT NULL,
                attempted_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS login_attempts_ip_time
                ON login_attempts(source_ip, attempted_at DESC);
            """
        )

        # Seed default sensors from enabled interfaces discovered at startup is handled
        # by the collector; here we just ensure system sensor exists.
        _upsert_sensor(db, "system", "system", "RouterOS system health", True)

        # Seed default alert rules if none exist
        existing_rules = db.execute("SELECT COUNT(*) AS c FROM alert_rules").fetchone()["c"]
        if existing_rules == 0:
            now_iso = iso()
            db.executemany(
                """INSERT INTO alert_rules(name, type, target, threshold, severity, enabled, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    ("router_down", "link_down", "router", None, "critical", 1, now_iso),
                    ("wan_down", "link_down", "wan", None, "critical", 1, now_iso),
                    ("cpu_high", "threshold", "cpu_load", 85.0, "warning", 1, now_iso),
                    ("broadcast_high", "threshold", "broadcast_pps", 1000.0, "warning", 1, now_iso),
                    ("ddos_traffic_high", "threshold", "traffic_bps", 100_000_000.0, "critical", 1, now_iso),
                ],
            )
        db.commit()


def _upsert_sensor(
    db: sqlite3.Connection,
    name: str,
    type_: str,
    description: str | None,
    enabled: bool,
) -> None:
    db.execute(
        """INSERT INTO sensors(name, type, description, enabled, created_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET type=excluded.type,
           description=excluded.description, enabled=excluded.enabled""",
        (name, type_, description, 1 if enabled else 0, iso()),
    )


def upsert_sensor(name: str, type_: str, description: str | None = None, enabled: bool = True) -> None:
    with connect() as db:
        _upsert_sensor(db, name, type_, description, enabled)


def get_sensors() -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM sensors WHERE enabled = 1 ORDER BY type, name"
        ).fetchall()
    return [dict(r) for r in rows]


def insert_interface_sample(sample: dict[str, Any]) -> None:
    with connect() as db:
        db.execute(
            """INSERT INTO interface_samples
               (observed_at, interface_name, status, rx_bytes, tx_bytes,
                rx_packets, tx_packets, rx_drops, tx_drops, rx_bps, tx_bps)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sample["observed_at"],
                sample["interface_name"],
                sample.get("status", "unknown"),
                int(sample.get("rx_bytes", 0)),
                int(sample.get("tx_bytes", 0)),
                int(sample.get("rx_packets", 0)),
                int(sample.get("tx_packets", 0)),
                int(sample.get("rx_drops", 0)),
                int(sample.get("tx_drops", 0)),
                float(sample.get("rx_bps", 0.0)),
                float(sample.get("tx_bps", 0.0)),
            ),
        )


def insert_telemetry(payload: dict[str, Any], observed_at: str) -> None:
    with connect() as db:
        db.execute(
            """INSERT INTO telemetry
               (observed_at, router_up, cpu_load, free_hdd_space,
                total_hdd_space, wan_running, details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                observed_at,
                int(payload["router_up"]),
                payload.get("cpu_load"),
                payload.get("free_hdd_space"),
                payload.get("total_hdd_space"),
                None if payload.get("wan_running") is None else int(payload["wan_running"]),
                json.dumps(payload.get("details", {})),
            ),
        )
        cutoff = iso(now() - timedelta(days=30))
        db.execute("DELETE FROM telemetry WHERE observed_at < ?", (cutoff,))
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (iso(),))
        db.execute(
            "DELETE FROM login_attempts WHERE attempted_at < ?",
            (iso(now() - timedelta(days=1)),),
        )
        # Retain raw interface samples for 7 days; older data can be re-aggregated
        db.execute(
            "DELETE FROM interface_samples WHERE observed_at < ?",
            (iso(now() - timedelta(days=7)),),
        )


def insert_ping_sample(sample: dict[str, Any]) -> None:
    """Insert a single ping probe result."""
    with connect() as db:
        db.execute(
            """INSERT INTO ping_samples
               (observed_at, target, packets_sent, packets_received,
                packet_loss_percent, min_latency_ms, avg_latency_ms, max_latency_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sample["observed_at"],
                sample["target"],
                int(sample.get("packets_sent", 0)),
                int(sample.get("packets_received", 0)),
                float(sample.get("packet_loss_percent", 0.0)),
                sample.get("min_latency_ms"),
                sample.get("avg_latency_ms"),
                sample.get("max_latency_ms"),
            ),
        )
        cutoff = iso(now() - timedelta(days=7))
        db.execute("DELETE FROM ping_samples WHERE observed_at < ?", (cutoff,))


def get_latest_ping_sample(target: str | None = None) -> dict[str, Any] | list[dict[str, Any]] | None:
    """Return the most recent ping sample(s).

    If *target* is given, returns the latest sample for that target.
    If *target* is None, returns the latest sample for every target.
    """
    with connect() as db:
        if target:
            row = db.execute(
                "SELECT * FROM ping_samples WHERE target = ? ORDER BY observed_at DESC LIMIT 1",
                (target,),
            ).fetchone()
            return dict(row) if row else None
        rows = db.execute(
            """
            SELECT ps.*
            FROM ping_samples ps
            INNER JOIN (
                SELECT target, MAX(observed_at) AS max_ts
                FROM ping_samples
                GROUP BY target
            ) latest ON ps.target = latest.target AND ps.observed_at = latest.max_ts
            ORDER BY ps.target
            """
        ).fetchall()
    return [dict(r) for r in rows] if rows else None


def get_ping_history(
    target: str, granularity: str = "second", range_hours: int = 24
) -> list[dict[str, Any]]:
    """Return ping samples for a target within the last N hours.

    Timestamps are converted to the configured display timezone (WIB by default)
    so they match the traffic chart's local time labels.

    granularity: second | minute | hour | day | month
    """
    bucket = _bucket_format(granularity)
    since = iso(now() - timedelta(hours=range_hours))
    local_observed = local_shift_sql("observed_at")
    with connect() as db:
        rows = db.execute(
            f"""
            SELECT
                strftime('{bucket}', {local_observed}) AS observed_at,
                target,
                SUM(packets_sent) AS packets_sent,
                SUM(packets_received) AS packets_received,
                AVG(packet_loss_percent) AS packet_loss_percent,
                MIN(min_latency_ms) AS min_latency_ms,
                AVG(avg_latency_ms) AS avg_latency_ms,
                MAX(max_latency_ms) AS max_latency_ms,
                MIN(observed_at) AS first_seen,
                MAX(observed_at) AS last_seen
            FROM ping_samples
            WHERE target = ? AND observed_at >= ?
            GROUP BY strftime('{bucket}', {local_observed})
            ORDER BY observed_at ASC
            """,
            (target, since),
        ).fetchall()
    return [
        {
            "observed_at": r["observed_at"],
            "target": r["target"],
            "packets_sent": r["packets_sent"],
            "packets_received": r["packets_received"],
            "packet_loss_percent": round(r["packet_loss_percent"], 1) if r["packet_loss_percent"] is not None else 0.0,
            "min_latency_ms": round(r["min_latency_ms"], 1) if r["min_latency_ms"] is not None else None,
            "avg_latency_ms": round(r["avg_latency_ms"], 1) if r["avg_latency_ms"] is not None else None,
            "max_latency_ms": round(r["max_latency_ms"], 1) if r["max_latency_ms"] is not None else None,
            "first_seen": to_local_iso(r["first_seen"]),
            "last_seen": to_local_iso(r["last_seen"]),
        }
        for r in rows
    ]


def get_latest_telemetry() -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM telemetry ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        return None
    return {
        "observed_at": to_local_iso(row["observed_at"]),
        "router_up": bool(row["router_up"]),
        "cpu_load": "—" if row["cpu_load"] is None else f"{row['cpu_load']:.0f}%",
        "cpu_load_raw": row["cpu_load"],
        "free_hdd_space": row["free_hdd_space"],
        "total_hdd_space": row["total_hdd_space"],
        "wan_running": None if row["wan_running"] is None else bool(row["wan_running"]),
        "details": json.loads(row["details"]),
    }


def get_telemetry_history(
    granularity: str = "minute", range_hours: int = 24
) -> list[dict[str, Any]]:
    """Return CPU load history aggregated by time bucket.

    granularity: second | minute | hour | day | month
    """
    bucket = _bucket_format(granularity)
    since = iso(now() - timedelta(hours=range_hours))
    local_observed = local_shift_sql("observed_at")
    with connect() as db:
        rows = db.execute(
            f"""
            SELECT
                strftime('{bucket}', {local_observed}) AS bucket,
                AVG(cpu_load) AS avg_cpu,
                MAX(cpu_load) AS max_cpu,
                MIN(observed_at) AS first_seen,
                MAX(observed_at) AS last_seen
            FROM telemetry
            WHERE observed_at >= ? AND cpu_load IS NOT NULL
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (since,),
        ).fetchall()
    return [
        {
            "bucket": r["bucket"],
            "avg_cpu": round(r["avg_cpu"], 1) if r["avg_cpu"] is not None else None,
            "max_cpu": round(r["max_cpu"], 1) if r["max_cpu"] is not None else None,
            "first_seen": to_local_iso(r["first_seen"]),
            "last_seen": to_local_iso(r["last_seen"]),
        }
        for r in rows
    ]


def get_interface_traffic(
    interface_name: str,
    granularity: str = "minute",
    range_hours: int = 24,
) -> list[dict[str, Any]]:
    """Return interface traffic samples aggregated by time bucket.

    Each point contains avg_rx_bps, avg_tx_bps, max_rx_bps, max_tx_bps for
    the bucket, plus first/last timestamps.
    """
    bucket = _bucket_format(granularity)
    since = iso(now() - timedelta(hours=range_hours))
    local_observed = local_shift_sql("observed_at")
    with connect() as db:
        rows = db.execute(
            f"""
            SELECT
                strftime('{bucket}', {local_observed}) AS bucket,
                AVG(rx_bps) AS avg_rx_bps,
                AVG(tx_bps) AS avg_tx_bps,
                MAX(rx_bps) AS max_rx_bps,
                MAX(tx_bps) AS max_tx_bps,
                SUM(rx_bytes) AS sum_rx_bytes,
                SUM(tx_bytes) AS sum_tx_bytes,
                COUNT(*) AS sample_count,
                MIN(observed_at) AS first_seen,
                MAX(observed_at) AS last_seen
            FROM interface_samples
            WHERE interface_name = ? AND observed_at >= ?
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (interface_name, since),
        ).fetchall()
    return [
        {
            "bucket": r["bucket"],
            "avg_rx_bps": round(r["avg_rx_bps"], 1) if r["avg_rx_bps"] is not None else 0.0,
            "avg_tx_bps": round(r["avg_tx_bps"], 1) if r["avg_tx_bps"] is not None else 0.0,
            "max_rx_bps": round(r["max_rx_bps"], 1) if r["max_rx_bps"] is not None else 0.0,
            "max_tx_bps": round(r["max_tx_bps"], 1) if r["max_tx_bps"] is not None else 0.0,
            "sample_count": r["sample_count"],
            "first_seen": to_local_iso(r["first_seen"]),
            "last_seen": to_local_iso(r["last_seen"]),
        }
        for r in rows
    ]


def get_latest_interface_sample(interface_name: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute(
            "SELECT * FROM interface_samples WHERE interface_name = ? "
            "ORDER BY observed_at DESC LIMIT 1",
            (interface_name,),
        ).fetchone()
    if row is None:
        return None
    sample = dict(row)
    sample["observed_at"] = to_local_iso(sample.get("observed_at"))
    return sample


def _bucket_format(granularity: str) -> str:
    formats = {
        "second": "%Y-%m-%d %H:%M:%S",
        "minute": "%Y-%m-%d %H:%M",
        "hour": "%Y-%m-%d %H:00",
        "day": "%Y-%m-%d",
        "month": "%Y-%m-01",
    }
    return formats.get(granularity, formats["minute"])


# --- Alert persistence ---

def _localize_timestamps(row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    for field in fields:
        if row.get(field):
            row[field] = to_local_iso(row[field])
    return row


def get_alerts() -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM alerts ORDER BY status='active' DESC, last_seen_at DESC LIMIT 50"
        ).fetchall()
    return [
        _localize_timestamps(
            dict(r), ("created_at", "last_seen_at", "last_notified_at", "resolved_at")
        )
        for r in rows
    ]


def get_alert_events(limit: int = 50) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM alert_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_localize_timestamps(dict(r), ("created_at",)) for r in rows]


def upsert_alert(
    fingerprint: str,
    severity: str,
    message: str,
    active: bool,
    cooldown_minutes: int,
) -> tuple[str | None, bool]:
    """Persist alert state; return (event_kind, should_notify)."""
    with connect() as db:
        existing = db.execute(
            "SELECT * FROM alerts WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        event: str | None = None
        notify = False
        current = now()
        if active:
            if existing is None or existing["status"] == "resolved":
                db.execute(
                    """INSERT INTO alerts(fingerprint, severity, message, status,
                       created_at, last_seen_at, last_notified_at, resolved_at)
                       VALUES (?, ?, ?, 'active', ?, ?, ?, NULL)
                       ON CONFLICT(fingerprint) DO UPDATE SET
                       severity=excluded.severity, message=excluded.message,
                       status='active', last_seen_at=excluded.last_seen_at,
                       last_notified_at=excluded.last_notified_at, resolved_at=NULL""",
                    (fingerprint, severity, message, iso(current), iso(current), iso(current)),
                )
                event, notify = "raised", True
            else:
                last_notice = (
                    datetime.fromisoformat(existing["last_notified_at"])
                    if existing["last_notified_at"]
                    else current
                )
                if current - last_notice >= timedelta(minutes=cooldown_minutes):
                    db.execute(
                        "UPDATE alerts SET severity=?, message=?, last_seen_at=?, last_notified_at=? WHERE fingerprint=?",
                        (severity, message, iso(current), iso(current), fingerprint),
                    )
                    event, notify = "reminder", True
                else:
                    db.execute(
                        "UPDATE alerts SET severity=?, message=?, last_seen_at=? WHERE fingerprint=?",
                        (severity, message, iso(current), fingerprint),
                    )
        elif existing is not None and existing["status"] == "active":
            db.execute(
                "UPDATE alerts SET status='resolved', resolved_at=?, last_seen_at=? WHERE fingerprint=?",
                (iso(current), iso(current), fingerprint),
            )
            event, notify = "resolved", True
            message = f"RECOVERED: {existing['message']}"

        if event:
            db.execute(
                "INSERT INTO alert_events(fingerprint, kind, message, created_at) VALUES (?, ?, ?, ?)",
                (fingerprint, event, message, iso(current)),
            )
    return event, notify


def get_login_attempts(source_ip: str, minutes: int = 15) -> int:
    with connect() as db:
        cutoff = iso(now() - timedelta(minutes=minutes))
        row = db.execute(
            "SELECT COUNT(*) AS count FROM login_attempts WHERE source_ip=? AND attempted_at >= ?",
            (source_ip, cutoff),
        ).fetchone()
    return row["count"]


# ===== DDoS Detection Tables & Queries =====

def _initialize_ddos_tables(db: sqlite3.Connection) -> None:
    """Create DDoS detection tables if they do not exist."""
    db.executescript(
        """
        -- DDoS baselines per interface, per metric, per hour-of-week bucket
        CREATE TABLE IF NOT EXISTS ddos_baselines (
            interface_name TEXT NOT NULL,
            metric TEXT NOT NULL,              -- 'rx_bps', 'rx_pps', 'drops', 'new_conn', 'syn_ratio'
            hour_of_week INTEGER NOT NULL,     -- 0-167 (Mon 00:00 = 0)
            baseline REAL NOT NULL,
            variance REAL NOT NULL,
            sample_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (interface_name, metric, hour_of_week)
        );
        CREATE INDEX IF NOT EXISTS ddos_baselines_iface_metric
            ON ddos_baselines(interface_name, metric);

        -- Mitigation action audit log
        CREATE TABLE IF NOT EXISTS mitigation_actions (
            id INTEGER PRIMARY KEY,
            interface_name TEXT NOT NULL,
            action TEXT NOT NULL,              -- 'queue_limit', 'syncookie', 'firewall_drop', 'blackhole'
            parameters TEXT NOT NULL,          -- JSON
            triggered_by_score REAL NOT NULL,
            status TEXT NOT NULL,              -- 'executed', 'rolled_back', 'failed'
            executed_at TEXT NOT NULL,
            rolled_back_at TEXT
        );
        CREATE INDEX IF NOT EXISTS mitigation_actions_iface_time
            ON mitigation_actions(interface_name, executed_at DESC);

        -- Composite anomaly score history (dedicated table for fast queries)
        CREATE TABLE IF NOT EXISTS ddos_scores (
            id INTEGER PRIMARY KEY,
            interface_name TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            composite_score REAL NOT NULL,
            state TEXT NOT NULL,               -- normal | elevated | warning | critical | recovering
            metric_bps_z REAL,
            metric_pps_z REAL,
            metric_drops_z REAL,
            metric_newconn_z REAL,
            metric_synratio_z REAL,
            details TEXT                       -- JSON: top contributors, thresholds, etc.
        );
        CREATE INDEX IF NOT EXISTS ddos_scores_iface_time
            ON ddos_scores(interface_name, observed_at DESC);
        CREATE INDEX IF NOT EXISTS ddos_scores_time
            ON ddos_scores(observed_at DESC);

        -- Connection tracking samples (for new_conn, syn_ratio)
        CREATE TABLE IF NOT EXISTS connection_tracking (
            id INTEGER PRIMARY KEY,
            interface_name TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            total_connections INTEGER NOT NULL DEFAULT 0,
            tcp_syn_sent INTEGER NOT NULL DEFAULT 0,
            tcp_established INTEGER NOT NULL DEFAULT 0,
            tcp_time_wait INTEGER NOT NULL DEFAULT 0,
            udp_connections INTEGER NOT NULL DEFAULT 0,
            other_connections INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS conn_track_iface_time
            ON connection_tracking(interface_name, observed_at DESC);
        """
    )


# Call this from initialize_database() - add at the end of the existing function
# We'll monkey-patch or just add the call. Let's add a separate init function.

def initialize_ddos_tables() -> None:
    """Initialize DDoS-specific tables."""
    with connect() as db:
        _initialize_ddos_tables(db)


def upsert_ddos_baseline(
    interface_name: str,
    metric: str,
    hour_of_week: int,
    value: float,
    alpha: float = 0.3
) -> None:
    """Update EWMA baseline for a metric at a specific hour-of-week bucket."""
    with connect() as db:
        _initialize_ddos_tables(db)
        row = db.execute(
            "SELECT baseline, variance, sample_count FROM ddos_baselines "
            "WHERE interface_name = ? AND metric = ? AND hour_of_week = ?",
            (interface_name, metric, hour_of_week)
        ).fetchone()
        current_time = iso()
        if row is None:
            # First sample
            db.execute(
                """INSERT INTO ddos_baselines(interface_name, metric, hour_of_week, baseline, variance, sample_count, updated_at)
                   VALUES (?, ?, ?, ?, 0, 1, ?)""",
                (interface_name, metric, hour_of_week, value, current_time)
            )
        else:
            # EWMA update
            old_baseline = row["baseline"]
            old_variance = row["variance"]
            count = row["sample_count"]
            new_baseline = alpha * value + (1 - alpha) * old_baseline
            # Welford's online algorithm for variance
            new_variance = (1 - alpha) * (old_variance + alpha * (value - old_baseline) ** 2)
            db.execute(
                """UPDATE ddos_baselines SET baseline = ?, variance = ?, sample_count = ?, updated_at = ?
                   WHERE interface_name = ? AND metric = ? AND hour_of_week = ?""",
                (new_baseline, new_variance, count + 1, current_time, interface_name, metric, hour_of_week)
            )


def get_ddos_baselines(interface_name: str, metric: str) -> list[dict[str, Any]]:
    """Get all 168 hourly baselines for an interface/metric."""
    with connect() as db:
        _initialize_ddos_tables(db)
        rows = db.execute(
            "SELECT hour_of_week, baseline, variance, sample_count FROM ddos_baselines "
            "WHERE interface_name = ? AND metric = ? ORDER BY hour_of_week",
            (interface_name, metric)
        ).fetchall()
    return [dict(r) for r in rows]


def get_current_ddos_baseline(interface_name: str, metric: str) -> tuple[float, float] | None:
    """Get baseline and stddev for current hour-of-week."""
    now_dt = now()
    hour_of_week = now_dt.weekday() * 24 + now_dt.hour
    with connect() as db:
        _initialize_ddos_tables(db)
        row = db.execute(
            "SELECT baseline, variance FROM ddos_baselines "
            "WHERE interface_name = ? AND metric = ? AND hour_of_week = ?",
            (interface_name, metric, hour_of_week)
        ).fetchone()
    if row is None or row["sample_count"] < 3:
        return None
    return (row["baseline"], row["variance"] ** 0.5)


def insert_mitigation_action(
    interface_name: str,
    action: str,
    parameters: dict[str, Any],
    triggered_by_score: float,
    status: str = "executed"
) -> None:
    """Log a mitigation action."""
    with connect() as db:
        _initialize_ddos_tables(db)
        db.execute(
            """INSERT INTO mitigation_actions(interface_name, action, parameters, triggered_by_score, status, executed_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (interface_name, action, json.dumps(parameters), triggered_by_score, status, iso())
        )


def update_mitigation_rollback(interface_name: str, action: str) -> None:
    """Mark mitigation actions as rolled back."""
    with connect() as db:
        _initialize_ddos_tables(db)
        db.execute(
            """UPDATE mitigation_actions SET status = 'rolled_back', rolled_back_at = ?
               WHERE interface_name = ? AND action = ? AND status = 'executed'""",
            (iso(), interface_name, action)
        )


def get_mitigation_history(limit: int = 50) -> list[dict[str, Any]]:
    """Get recent mitigation actions."""
    with connect() as db:
        _initialize_ddos_tables(db)
        rows = db.execute(
            "SELECT * FROM mitigation_actions ORDER BY executed_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_latest_ddos_scores() -> dict[str, dict[str, Any]]:
    """Get latest composite anomaly scores per interface from alert state."""
    with connect() as db:
        # Check for active ddos_anomaly alerts
        rows = db.execute(
            "SELECT fingerprint, severity, message, status FROM alerts "
            "WHERE fingerprint LIKE 'ddos_anomaly_%' AND status = 'active'"
        ).fetchall()
    result = {}
    for row in rows:
        # fingerprint format: ddos_anomaly_{interface}_{profile}
        parts = row["fingerprint"].split("_")
        if len(parts) >= 3:
            iface = "_".join(parts[2:-1])  # handle interface names with underscores
            profile = parts[-1]
            # Extract score from message if possible
            import re
            score_match = re.search(r'score ([\d.]+)', row["message"])
            score = float(score_match.group(1)) if score_match else 0.0
            result[iface] = {
                "composite_score": score,
                "severity": row["severity"],
                "status": row["status"],
                "message": row["message"],
                "profile": profile
            }
    return result


# ===== DDoS Score History =====

def insert_ddos_score(
    interface_name: str,
    observed_at: str,
    composite_score: float,
    state: str,
    metric_z: dict[str, float],
    details: dict[str, Any] | None = None
) -> None:
    """Store composite anomaly score for history queries."""
    with connect() as db:
        _initialize_ddos_tables(db)
        db.execute(
            """INSERT INTO ddos_scores(interface_name, observed_at, composite_score, state,
               metric_bps_z, metric_pps_z, metric_drops_z, metric_newconn_z, metric_synratio_z, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                interface_name, observed_at, composite_score, state,
                metric_z.get("bps"), metric_z.get("pps"), metric_z.get("drops"),
                metric_z.get("newconn"), metric_z.get("synratio"),
                json.dumps(details) if details else None
            )
        )
        # Retain 30 days
        cutoff = iso(now() - timedelta(days=30))
        db.execute("DELETE FROM ddos_scores WHERE observed_at < ?", (cutoff,))


def get_ddos_score_history(
    interface_name: str,
    granularity: str = "minute",
    range_hours: int = 24
) -> list[dict[str, Any]]:
    """Get composite score history aggregated by time bucket."""
    bucket = _bucket_format(granularity)
    since = iso(now() - timedelta(hours=range_hours))
    local_observed = local_shift_sql("observed_at")
    with connect() as db:
        _initialize_ddos_tables(db)
        rows = db.execute(
            f"""
            SELECT
                strftime('{bucket}', {local_observed}) AS bucket,
                AVG(composite_score) AS avg_score,
                MAX(composite_score) AS max_score,
                MAX(state) AS state  -- lexicographically highest: warning > normal, etc.
            FROM ddos_scores
            WHERE interface_name = ? AND observed_at >= ?
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (interface_name, since),
        ).fetchall()
    return [
        {
            "bucket": r["bucket"],
            "composite_score": round(r["avg_score"] or 0, 2),
            "max_score": round(r["max_score"] or 0, 2),
            "state": r["state"]
        }
        for r in rows
    ]


def get_ddos_breakdown_history(
    interface_name: str,
    granularity: str = "minute",
    range_hours: int = 24
) -> list[dict[str, Any]]:
    """Get metric z-score breakdown history."""
    bucket = _bucket_format(granularity)
    since = iso(now() - timedelta(hours=range_hours))
    local_observed = local_shift_sql("observed_at")
    with connect() as db:
        _initialize_ddos_tables(db)
        rows = db.execute(
            f"""
            SELECT
                strftime('{bucket}', {local_observed}) AS bucket,
                AVG(metric_bps_z) AS bps,
                AVG(metric_pps_z) AS pps,
                AVG(metric_drops_z) AS drops,
                AVG(metric_newconn_z) AS newconn,
                AVG(metric_synratio_z) AS synratio
            FROM ddos_scores
            WHERE interface_name = ? AND observed_at >= ?
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (interface_name, since),
        ).fetchall()
    return [
        {
            "bucket": r["bucket"],
            "bps": round(r["bps"] or 0, 2),
            "pps": round(r["pps"] or 0, 2),
            "drops": round(r["drops"] or 0, 2),
            "newconn": round(r["newconn"] or 0, 2),
            "synratio": round(r["synratio"] or 0, 2)
        }
        for r in rows
    ]


# ===== Connection Tracking =====

def insert_connection_tracking(
    interface_name: str,
    observed_at: str,
    total: int,
    tcp_syn_sent: int,
    tcp_established: int,
    tcp_time_wait: int,
    udp: int,
    other: int
) -> None:
    """Store connection tracking snapshot."""
    with connect() as db:
        _initialize_ddos_tables(db)
        db.execute(
            """INSERT INTO connection_tracking(interface_name, observed_at, total_connections,
               tcp_syn_sent, tcp_established, tcp_time_wait, udp_connections, other_connections)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (interface_name, observed_at, total, tcp_syn_sent, tcp_established,
             tcp_time_wait, udp, other)
        )
        # Retain 7 days
        cutoff = iso(now() - timedelta(days=7))
        db.execute("DELETE FROM connection_tracking WHERE observed_at < ?", (cutoff,))


def get_latest_connection_tracking(interface_name: str) -> dict[str, Any] | None:
    """Get latest connection tracking sample."""
    with connect() as db:
        _initialize_ddos_tables(db)
        row = db.execute(
            "SELECT * FROM connection_tracking WHERE interface_name = ? ORDER BY observed_at DESC LIMIT 1",
            (interface_name,)
        ).fetchone()
    return dict(row) if row else None
