"""Collectors for NetGuard Monit.

Gathers RouterOS system health and interface statistics via:
- RouterOS REST API (primary, private HTTPS on LAN)
- SNMPv2c (optional fallback, via pysnmp)

Each collector returns a :class:`CollectorResult` with system telemetry and
per-interface samples. Rate values (bits per second) are computed from counter
deltas between consecutive polls.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from .database import (
    connect,
    get_latest_interface_sample,
    insert_interface_sample,
    upsert_sensor,
)

LOG = logging.getLogger("netguard")
UTC = timezone.utc


@dataclass
class InterfaceSample:
    name: str
    status: str  # "up" / "down" / "unknown"
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_drops: int
    tx_drops: int
    rx_bps: float = 0.0
    tx_bps: float = 0.0


@dataclass
class CollectorResult:
    router_up: bool
    cpu_load: float | None
    free_hdd_space: int | None
    total_hdd_space: int | None
    wan_running: bool | None
    details: dict[str, Any]
    interfaces: list[InterfaceSample] = field(default_factory=list)
    error: str | None = None


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def parse_number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _compute_rate(
    current: int,
    previous: int | None,
    current_ts: str,
    previous_ts: str | None,
) -> float:
    """Compute bits per second from counter deltas."""
    if previous is None or previous_ts is None:
        return 0.0
    try:
        t_cur = datetime.fromisoformat(current_ts)
        t_prev = datetime.fromisoformat(previous_ts)
    except ValueError:
        return 0.0
    delta_seconds = (t_cur - t_prev).total_seconds()
    if delta_seconds <= 0:
        return 0.0
    # RouterOS/SNMP counters can wrap or reset; treat negative delta as zero.
    delta_bytes = max(0, current - previous)
    # bytes * 8 / seconds = bits per second
    return (delta_bytes * 8.0) / delta_seconds


def collect_router_rest(
    base_url: str,
    username: str,
    password: str,
    wan_interface: str,
    tls_verify: bool | str,
    cpu_alert_percent: int,
) -> CollectorResult:
    """Read health + interface stats from private RouterOS REST endpoints.

    Endpoints used (all read-only):
      GET /rest/system/resource   -> cpu-load, free-hdd-space, total-hdd-space, version, board-name
      GET /rest/interface         -> per-interface counters (rx-byte, tx-byte, ...)
    """
    timestamp = now_iso()
    timeout = httpx.Timeout(15.0, connect=8.0)
    auth = httpx.BasicAuth(username, password)

    interfaces: list[InterfaceSample] = []
    cpu_load: float | None = None
    free_hdd: int | None = None
    total_hdd: int | None = None
    wan_running: bool | None = None
    details: dict[str, Any] = {}

    try:
        with httpx.Client(
            base_url=f"{base_url.rstrip('/')}/rest/",
            auth=auth,
            verify=tls_verify,
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            # --- system/resource ---
            try:
                res = client.get("system/resource")
                res.raise_for_status()
                resource = res.json()
                if isinstance(resource, list):
                    resource = resource[0] if resource else {}
                cpu_load = parse_number(resource.get("cpu-load"))
                free_hdd = int(parse_number(resource.get("free-hdd-space")) or 0)
                total_hdd = int(parse_number(resource.get("total-hdd-space")) or 0)
                details = {
                    "board_name": resource.get("board-name"),
                    "version": resource.get("version"),
                    "uptime": resource.get("uptime"),
                }
            except (httpx.HTTPError, ValueError, IndexError) as exc:
                LOG.warning("system/resource collection failed: %s", exc)

            # --- interface ---
            try:
                iface_res = client.get("interface")
                iface_res.raise_for_status()
                ifaces = iface_res.json()
                if not isinstance(ifaces, list):
                    ifaces = []
            except (httpx.HTTPError, ValueError) as exc:
                LOG.warning("interface collection failed: %s", exc)
                ifaces = []

            # Load previous samples for rate computation (one connection)
            prev_samples: dict[str, dict[str, Any]] = {}
            with connect() as db:
                for iface in ifaces:
                    if not isinstance(iface, dict):
                        continue
                    name = iface.get("name")
                    if not name:
                        continue
                    prev = get_latest_interface_sample(name)
                    if prev:
                        prev_samples[name] = dict(prev)

            for iface in ifaces:
                if not isinstance(iface, dict):
                    continue
                name = iface.get("name")
                if not name:
                    continue
                running = str(iface.get("running", "false")).lower() == "true"
                status = "up" if running else "down"

                rx_bytes = int(parse_number(iface.get("rx-byte")) or 0)
                tx_bytes = int(parse_number(iface.get("tx-byte")) or 0)
                rx_packets = int(parse_number(iface.get("rx-packet")) or 0)
                tx_packets = int(parse_number(iface.get("tx-packet")) or 0)
                rx_drops = int(parse_number(iface.get("rx-drop")) or 0)
                tx_drops = int(parse_number(iface.get("tx-drop")) or 0)

                prev = prev_samples.get(name)
                prev_rx = int(prev["rx_bytes"]) if prev else None
                prev_tx = int(prev["tx_bytes"]) if prev else None
                prev_ts = prev["observed_at"] if prev else None

                rx_bps = _compute_rate(rx_bytes, prev_rx, timestamp, prev_ts)
                tx_bps = _compute_rate(tx_bytes, prev_tx, timestamp, prev_ts)

                sample = InterfaceSample(
                    name=name,
                    status=status,
                    rx_bytes=rx_bytes,
                    tx_bytes=tx_bytes,
                    rx_packets=rx_packets,
                    tx_packets=tx_packets,
                    rx_drops=rx_drops,
                    tx_drops=tx_drops,
                    rx_bps=rx_bps,
                    tx_bps=tx_bps,
                )
                interfaces.append(sample)
                insert_interface_sample(
                    {
                        "observed_at": timestamp,
                        "interface_name": name,
                        "status": status,
                        "rx_bytes": rx_bytes,
                        "tx_bytes": tx_bytes,
                        "rx_packets": rx_packets,
                        "tx_packets": tx_packets,
                        "rx_drops": rx_drops,
                        "tx_drops": tx_drops,
                        "rx_bps": rx_bps,
                        "tx_bps": tx_bps,
                    }
                )
                upsert_sensor(
                    name=name,
                    type_="interface",
                    description=f"RouterOS interface {name}",
                    enabled=True,
                )

            if wan_interface:
                wan_match = next((s for s in interfaces if s.name == wan_interface), None)
                wan_running = wan_match.status == "up" if wan_match else None

    except (httpx.HTTPError, ValueError) as exc:
        LOG.warning("RouterOS REST collection failed: %s", exc)
        return CollectorResult(
            router_up=False,
            cpu_load=None,
            free_hdd_space=None,
            total_hdd_space=None,
            wan_running=None,
            details={"error": str(exc)[:500]},
            error=str(exc),
        )

    return CollectorResult(
        router_up=True,
        cpu_load=cpu_load,
        free_hdd_space=free_hdd,
        total_hdd_space=total_hdd,
        wan_running=wan_running,
        details=details,
        interfaces=interfaces,
    )


async def collect_router_snmp(
    host: str,
    community: str,
    wan_interface: str,
) -> CollectorResult:
    """Optional SNMPv2c collector using pysnmp.

    Polls ifInOctets/ifOutOctets/ifOperStatus for each interface.
    Fallback when RouterOS REST is not available. Requires ``pysnmp``.
    """
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore[import-not-found]
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            getCmd,
            nextCmd,
        )
    except ImportError:
        LOG.exception("pysnmp is not installed; SNMP collector unavailable")
        return CollectorResult(
            router_up=False,
            cpu_load=None,
            free_hdd_space=None,
            total_hdd_space=None,
            wan_running=None,
            details={"error": "pysnmp not installed"},
            error="pysnmp not installed",
        )

    timestamp = now_iso()
    interfaces: list[InterfaceSample] = []
    error: str | None = None

    try:
        snmp_engine = SnmpEngine()
        community_data = CommunityData(community, mpModel=1)
        transport = UdpTransportTarget((host, 161), timeout=5, retries=1)
        context = ContextData()

        interface_names: dict[int, str] = {}
        interface_status: dict[int, str] = {}

        # Walk ifDescr (1.3.6.1.2.1.2.2.1.2)
        async for error_indication, error_status, error_index, var_binds in nextCmd(
            snmp_engine,
            community_data,
            transport,
            context,
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.2")),
            lexicographic_mode=False,
        ):
            if error_indication:
                error = str(error_indication)
                break
            if error_status:
                error = f"{error_status.prettyPrint()} at {error_index}"
                break
            for var_bind in var_binds:
                oid = str(var_bind[0])
                if_index = oid.split(".")[-1]
                iface_name = str(var_bind[1])
                interface_names[int(if_index)] = iface_name
                upsert_sensor(
                    name=iface_name,
                    type_="interface",
                    description=f"SNMP interface {iface_name}",
                    enabled=True,
                )

        # Walk ifOperStatus (1.3.6.1.2.1.2.2.1.8)
        async for error_indication, error_status, error_index, var_binds in nextCmd(
            snmp_engine,
            community_data,
            transport,
            context,
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.8")),
            lexicographic_mode=False,
        ):
            if error_indication:
                error = str(error_indication)
                break
            if error_status:
                error = f"{error_status.prettyPrint()} at {error_index}"
                break
            for var_bind in var_binds:
                oid = str(var_bind[0])
                if_index = oid.split(".")[-1]
                status_val = str(var_bind[1])
                interface_status[int(if_index)] = "up" if status_val == "1" else "down"

        # Get counters per interface
        for if_index, iface_name in interface_names.items():
            oids = {
                "rx_bytes": f"1.3.6.1.2.1.2.2.1.10.{if_index}",
                "tx_bytes": f"1.3.6.1.2.1.2.2.1.16.{if_index}",
                "rx_packets": f"1.3.6.1.2.1.2.2.1.11.{if_index}",
                "tx_packets": f"1.3.6.1.2.1.2.2.1.17.{if_index}",
            }
            values = {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0}
            for key, oid in oids.items():
                err_ind, err_status, err_idx, var_binds = await getCmd(
                    snmp_engine,
                    community_data,
                    transport,
                    context,
                    ObjectType(ObjectIdentity(oid)),
                )
                if err_ind or err_status:
                    continue
                for var_bind in var_binds:
                    val = parse_number(var_bind[1])
                    if val is not None:
                        values[key] = int(val)

            status = interface_status.get(if_index, "unknown")
            prev = get_latest_interface_sample(iface_name)
            prev_rx = int(prev["rx_bytes"]) if prev else None
            prev_tx = int(prev["tx_bytes"]) if prev else None
            prev_ts = prev["observed_at"] if prev else None

            rx_bps = _compute_rate(values["rx_bytes"], prev_rx, timestamp, prev_ts)
            tx_bps = _compute_rate(values["tx_bytes"], prev_tx, timestamp, prev_ts)

            sample = InterfaceSample(
                name=iface_name,
                status=status,
                rx_bytes=values["rx_bytes"],
                tx_bytes=values["tx_bytes"],
                rx_packets=values["rx_packets"],
                tx_packets=values["tx_packets"],
                rx_drops=0,
                tx_drops=0,
                rx_bps=rx_bps,
                tx_bps=tx_bps,
            )
            interfaces.append(sample)
            insert_interface_sample(
                {
                    "observed_at": timestamp,
                    "interface_name": iface_name,
                    "status": status,
                    "rx_bytes": values["rx_bytes"],
                    "tx_bytes": values["tx_bytes"],
                    "rx_packets": values["rx_packets"],
                    "tx_packets": values["tx_packets"],
                    "rx_drops": 0,
                    "tx_drops": 0,
                    "rx_bps": rx_bps,
                    "tx_bps": tx_bps,
                }
            )

        wan_running = None
        if wan_interface:
            wan_match = next((s for s in interfaces if s.name == wan_interface), None)
            wan_running = wan_match.status == "up" if wan_match else None

    except Exception:  # noqa: BLE001 - SNMP is best-effort fallback
        LOG.exception("SNMP collection failed")
        error = "SNMP collection failed"

    return CollectorResult(
        router_up=error is None,
        cpu_load=None,
        free_hdd_space=None,
        total_hdd_space=None,
        wan_running=wan_running,
        details={"method": "snmp"},
        interfaces=interfaces,
        error=error,
    )


@dataclass
class PingResult:
    target: str
    packets_sent: int
    packets_received: int
    packet_loss_percent: float
    min_latency_ms: float | None
    avg_latency_ms: float | None
    max_latency_ms: float | None
    success: bool
    error: str | None = None


async def collect_ping(
    target: str,
    count: int = 4,
    timeout_seconds: float = 5.0,
) -> PingResult:
    """Send ICMP echo probes to *target* and parse latency / packet loss.

    Works on Linux (Docker container default: ``ping -c -W``) and Windows
    (``ping -n -w``). Returns a :class:`PingResult` even on failure so the
    caller can always record a sample.
    """
    is_windows = platform.system().lower() == "windows"
    timeout_ms = int(timeout_seconds * 1000)

    if is_windows:
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout_seconds)), target]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds * 2 + 5
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return PingResult(
                target=target,
                packets_sent=count,
                packets_received=0,
                packet_loss_percent=100.0,
                min_latency_ms=None,
                avg_latency_ms=None,
                max_latency_ms=None,
                success=False,
                error="ping timed out",
            )

        output = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        if proc.returncode != 0 and not output:
            return PingResult(
                target=target,
                packets_sent=count,
                packets_received=0,
                packet_loss_percent=100.0,
                min_latency_ms=None,
                avg_latency_ms=None,
                max_latency_ms=None,
                success=False,
                error=stderr_text or output or f"exit code {proc.returncode}",
            )

        packets_sent = count
        packets_received = 0
        packet_loss_percent = 100.0
        min_latency_ms: float | None = None
        avg_latency_ms: float | None = None
        max_latency_ms: float | None = None

        if is_windows:
            # Windows ping example:
            #   Paket: Terkirim = 4, Diterima = 4, Hilang = 0 (0% kehilangan),
            #   Minimum = 0ms, Maksimum = 0ms, Rata-rata = 0ms
            sent_match = re.search(r"Terkirim\s*=\s*(\d+)", output)
            recv_match = re.search(r"Diterima\s*=\s*(\d+)", output)
            loss_match = re.search(r"\((\d+(?:\.\d+)?)%\s*kehilangan\)", output)
            min_match = re.search(r"Minimum\s*=\s*([\d.]+)ms", output)
            avg_match = re.search(r"Rata-rata\s*=\s*([\d.]+)ms", output)
            max_match = re.search(r"Maksimum\s*=\s*([\d.]+)ms", output)

            if sent_match:
                packets_sent = int(sent_match.group(1))
            if recv_match:
                packets_received = int(recv_match.group(1))
            if loss_match:
                packet_loss_percent = float(loss_match.group(1))
            elif packets_sent > 0:
                packet_loss_percent = (
                    (packets_sent - packets_received) / packets_sent
                ) * 100.0
            if min_match:
                min_latency_ms = float(min_match.group(1))
            if avg_match:
                avg_latency_ms = float(avg_match.group(1))
            if max_match:
                max_latency_ms = float(max_match.group(1))
        else:
            # Linux ping example:
            #   4 packets transmitted, 4 received, 0% packet loss, time 3003ms
            #   rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms
            stats_match = re.search(
                r"(\d+)\s+packets\s+transmitted,\s+(\d+)\s+received,\s+([\d.]+)%\s+packet\s+loss",
                output,
            )
            rtt_match = re.search(
                r"rtt\s+min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/",
                output,
            )

            if stats_match:
                packets_sent = int(stats_match.group(1))
                packets_received = int(stats_match.group(2))
                packet_loss_percent = float(stats_match.group(3))
            if rtt_match:
                min_latency_ms = float(rtt_match.group(1))
                avg_latency_ms = float(rtt_match.group(2))
                max_latency_ms = float(rtt_match.group(3))

        success = packets_received > 0
        return PingResult(
            target=target,
            packets_sent=packets_sent,
            packets_received=packets_received,
            packet_loss_percent=packet_loss_percent,
            min_latency_ms=min_latency_ms,
            avg_latency_ms=avg_latency_ms,
            max_latency_ms=max_latency_ms,
            success=success,
        )

    except Exception as exc:  # noqa: BLE001 - ping is best-effort
        LOG.exception("Ping collection failed for %s", target)
        return PingResult(
            target=target,
            packets_sent=count,
            packets_received=0,
            packet_loss_percent=100.0,
            min_latency_ms=None,
            avg_latency_ms=None,
            max_latency_ms=None,
            success=False,
            error=str(exc),
        )
