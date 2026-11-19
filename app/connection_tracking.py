"""Connection Tracking Collector for NetGuard Monit.

Fetches connection tracking data from RouterOS via REST API.
Provides: total connections, TCP SYN sent, established, UDP, etc.
Used for DDoS detection: new_conn_rate, syn_ratio.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

LOG = logging.getLogger("netguard")


@dataclass
class ConnectionTrackingResult:
    """Result of connection tracking collection."""
    total_connections: int
    tcp_syn_sent: int
    tcp_established: int
    tcp_time_wait: int
    udp_connections: int
    other_connections: int
    error: str | None = None


async def collect_connection_tracking(
    base_url: str,
    username: str,
    password: str,
    tls_verify: bool | str,
) -> ConnectionTrackingResult:
    """Collect connection tracking data from RouterOS REST API.

    Endpoint: /rest/ip/firewall/connection
    Returns list of connections with protocol, state, src/dst address/port.
    """
    timeout = httpx.Timeout(15.0, connect=8.0)
    auth = httpx.BasicAuth(username, password)

    try:
        async with httpx.AsyncClient(
            base_url=f"{base_url.rstrip('/')}/rest/",
            auth=auth,
            verify=tls_verify,
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            resp = await client.get("ip/firewall/connection")
            resp.raise_for_status()
            connections = resp.json()

            if not isinstance(connections, list):
                connections = []

            total = 0
            tcp_syn_sent = 0
            tcp_established = 0
            tcp_time_wait = 0
            udp = 0
            other = 0

            for conn in connections:
                if not isinstance(conn, dict):
                    continue
                total += 1
                protocol = str(conn.get("protocol", "")).lower()
                state = str(conn.get("state", "")).lower()

                if protocol == "tcp":
                    if state == "syn-sent":
                        tcp_syn_sent += 1
                    elif state == "established":
                        tcp_established += 1
                    elif state == "time-wait":
                        tcp_time_wait += 1
                    else:
                        other += 1
                elif protocol == "udp":
                    udp += 1
                else:
                    other += 1

            return ConnectionTrackingResult(
                total_connections=total,
                tcp_syn_sent=tcp_syn_sent,
                tcp_established=tcp_established,
                tcp_time_wait=tcp_time_wait,
                udp_connections=udp,
                other_connections=other,
            )

    except (httpx.HTTPError, ValueError) as e:
        LOG.warning("Connection tracking collection failed: %s", e)
        return ConnectionTrackingResult(
            total_connections=0,
            tcp_syn_sent=0,
            tcp_established=0,
            tcp_time_wait=0,
            udp_connections=0,
            other_connections=0,
            error=str(e),
        )


def compute_new_conn_rate(
    current_total: int,
    previous_total: int | None,
    current_ts: str,
    previous_ts: str | None,
    poll_interval: int
) -> float:
    """Compute new connections per second from counter delta."""
    if previous_total is None or previous_ts is None:
        return 0.0
    try:
        from datetime import datetime
        t_cur = datetime.fromisoformat(current_ts)
        t_prev = datetime.fromisoformat(previous_ts)
    except ValueError:
        return 0.0
    delta_seconds = (t_cur - t_prev).total_seconds()
    if delta_seconds <= 0:
        return 0.0
    delta = max(0, current_total - previous_total)
    return delta / delta_seconds


def compute_syn_ratio(tcp_syn_sent: int, tcp_established: int) -> float:
    """Compute SYN sent / established ratio. High ratio = potential SYN flood."""
    if tcp_established == 0:
        return 1.0 if tcp_syn_sent > 0 else 0.0
    return tcp_syn_sent / tcp_established