"""Alert state machine and notifications for NetGuard Monit.

Handles persistence of alert state (active/resolved), cooldown-based reminders,
recovery messages, and Telegram notifications.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from . import collectors
from .database import (
    connect,
    get_login_attempts,
    iso,
    now,
    upsert_alert,
)

LOG = logging.getLogger("netguard")
UTC = timezone.utc


async def send_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    """Send a Telegram message. Failures are logged but never raise."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            response = await client.post(
                url,
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "disable_web_page_preview": True,
                },
            )
            response.raise_for_status()
        return True
    except httpx.HTTPError:
        LOG.exception("Telegram notification failed")
        return False


async def process_alert(
    fingerprint: str,
    severity: str,
    message: str,
    active: bool,
    cooldown_minutes: int,
    bot_token: str | None,
    chat_id: str | None,
) -> None:
    """Persist alert state and send Telegram notification when appropriate."""
    event, notify = upsert_alert(
        fingerprint=fingerprint,
        severity=severity,
        message=message,
        active=active,
        cooldown_minutes=cooldown_minutes,
    )
    if notify and bot_token and chat_id:
        prefix = {"raised": "ALERT", "reminder": "REMINDER", "resolved": "RECOVERY"}[
            event  # type: ignore[index]
        ]
        await send_telegram(
            bot_token,
            chat_id,
            f"NetGuard Monit — {prefix}\n{message}",
        )


def evaluate_alerts(
    result: Any,
    settings: Any,
) -> list[tuple[str, str, str, bool]]:
    """Evaluate collector result against alert rules.

    Returns a list of (fingerprint, severity, message, active) tuples.
    """
    alerts: list[tuple[str, str, str, bool]] = []

    # --- Link DOWN/UP: router reachability ---
    router_active = bool(result.router_up)
    alerts.append(
        (
            "router_down",
            "critical",
            f"Router {settings.mikrotik_base_url} is unreachable"
            if not router_active
            else f"Router {settings.mikrotik_base_url} is reachable again",
            not router_active,
        )
    )

    # --- Link DOWN/UP: WAN interface ---
    if settings.mikrotik_wan_interface:
        wan_name = settings.mikrotik_wan_interface
        wan_match = next(
            (s for s in result.interfaces if s.name == wan_name), None
        )
        wan_up = wan_match.status == "up" if wan_match else None
        if wan_up is not None:
            alerts.append(
                (
                    f"wan_down_{wan_name}",
                    "critical",
                    f"WAN interface {wan_name} is DOWN"
                    if not wan_up
                    else f"WAN interface {wan_name} is UP again",
                    not wan_up,
                )
            )

    # --- CPU threshold ---
    if result.cpu_load is not None:
        cpu_active = result.cpu_load >= settings.cpu_alert_percent
        alerts.append(
            (
                "cpu_high",
                "warning",
                f"Router CPU load is {result.cpu_load:.0f}% "
                f"(threshold {settings.cpu_alert_percent}%)",
                cpu_active,
            )
        )

    # --- Interface-level: DDoS (high tx/rx bps) and broadcast (drops/pps) ---
    for iface in result.interfaces:
        # DDoS: high outbound traffic on WAN
        if iface.name == settings.mikrotik_wan_interface and settings.mikrotik_wan_interface:
            # Use configured threshold from settings (default 100 Mbps via DDOS_THRESHOLD_BPS env)
            ddos_threshold_bps = settings.ddos_threshold_bps
            ddos_active = iface.tx_bps > ddos_threshold_bps or iface.rx_bps > ddos_threshold_bps
            alerts.append(
                (
                    f"ddos_traffic_{iface.name}",
                    "critical",
                    f"High traffic on {iface.name}: "
                    f"rx {iface.rx_bps/1_000_000:.1f} Mbps, "
                    f"tx {iface.tx_bps/1_000_000:.1f} Mbps "
                    f"(threshold {ddos_threshold_bps/1_000_000:.0f} Mbps)",
                    ddos_active,
                )
            )

        # Broadcast / storm: high drop rate can indicate broadcast storm
        # We use rx_drops as a proxy; threshold is packets per poll interval
        broadcast_threshold_pps = settings.broadcast_threshold_pps
        broadcast_active = (iface.rx_drops + iface.tx_drops) > broadcast_threshold_pps
        alerts.append(
            (
                f"broadcast_high_{iface.name}",
                "warning",
                f"High packet drops on {iface.name}: "
                f"rx {iface.rx_drops}, tx {iface.tx_drops} "
                f"(threshold {broadcast_threshold_pps} drops/poll)",
                broadcast_active,
            )
        )

    return alerts


def evaluate_ping_alerts(
    ping_results: list[collectors.PingResult],
    settings: Any,
) -> list[tuple[str, str, str, bool]]:
    """Evaluate ping probe results against latency / packet-loss thresholds.

    Returns a list of (fingerprint, severity, message, active) tuples.
    """
    alerts: list[tuple[str, str, str, bool]] = []

    for pr in ping_results:
        # --- Latency alert ---
        if pr.avg_latency_ms is not None:
            latency_active = pr.avg_latency_ms >= settings.ping_latency_alert_ms
            alerts.append(
                (
                    f"ping_latency_{pr.target}",
                    "warning",
                    f"Ping latency to {pr.target} is {pr.avg_latency_ms:.0f} ms "
                    f"(threshold {settings.ping_latency_alert_ms:.0f} ms)",
                    latency_active,
                )
            )

        # --- Packet loss alert ---
        loss_active = pr.packet_loss_percent >= settings.ping_packet_loss_alert_percent
        alerts.append(
            (
                f"ping_loss_{pr.target}",
                "warning",
                f"Ping packet loss to {pr.target} is {pr.packet_loss_percent:.0f}% "
                f"(threshold {settings.ping_packet_loss_alert_percent:.0f}%)",
                loss_active,
            )
        )

    return alerts


async def dispatch_alerts(
    alerts: list[tuple[str, str, str, bool]],
    settings: Any,
) -> None:
    """Send each alert through the state machine."""
    for fingerprint, severity, message, active in alerts:
        await process_alert(
            fingerprint=fingerprint,
            severity=severity,
            message=message,
            active=active,
            cooldown_minutes=settings.alert_cooldown_minutes,
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_chat_id,
        )
