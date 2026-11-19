"""Auto-Mitigation Executor for NetGuard Monit.

Executes RouterOS REST API calls for DDoS mitigation:
- L1: Queue tree limit on WAN
- L2: Enable TCP SYN cookie
- L3: Firewall filter drop top source IPs
- L4: Blackhole route

Safety features:
- Dry-run mode (default)
- Cooldown between actions
- Auto-rollback on recovery
- Audit logging
- Manual override via dashboard
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from .database import (
    connect,
    insert_mitigation_action,
    update_mitigation_rollback,
    get_mitigation_history,
    _initialize_ddos_tables,
)

LOG = logging.getLogger("netguard")
UTC = timezone.utc


@dataclass
class MitigationConfig:
    """Configuration for auto-mitigation."""
    enabled: bool = False
    dry_run: bool = True              # True = log only, no actual API calls
    cooldown_seconds: int = 300       # Min time between actions
    rollback_polls: int = 3           # Consecutive polls below threshold before rollback
    queue_limit_pct: float = 0.8      # L1: limit at % of baseline


class MitigationExecutor:
    """Executes mitigation actions via RouterOS REST API."""

    def __init__(self, config: MitigationConfig, router_settings: Any):
        self.config = config
        self.router_settings = router_settings
        self._last_action_time: dict[str, float] = {}  # (interface, action) -> timestamp
        self._active_mitigations: dict[str, set[str]] = {}  # interface -> set(actions)

    async def execute(
        self,
        interface: str,
        level: int,
        score: float,
        dry_run: bool | None = None
    ) -> bool:
        """Execute mitigation at given level (1-4). Returns True if executed."""
        dry_run = self.config.dry_run if dry_run is None else dry_run

        # Check cooldown
        key = f"{interface}:L{level}"
        now_ts = time.time()
        if now_ts - self._last_action_time.get(key, 0) < self.config.cooldown_seconds:
            LOG.info("Mitigation %s on %s skipped: cooldown active", key, interface)
            return False

        action_map = {
            1: ("queue_limit", self._mitigate_queue_limit),
            2: ("syncookie", self._mitigate_syncookie),
            3: ("firewall_drop", self._mitigate_firewall_drop),
            4: ("blackhole", self._mitigate_blackhole),
        }

        if level not in action_map:
            LOG.warning("Unknown mitigation level: %d", level)
            return False

        action_name, action_fn = action_map[level]

        # Check if already active
        if action_name in self._active_mitigations.get(interface, set()):
            LOG.info("Mitigation %s on %s already active", action_name, interface)
            return False

        try:
            params = await action_fn(interface, score, dry_run)
            status = "executed" if not dry_run else "dry_run"

            # Log action
            insert_mitigation_action(
                interface_name=interface,
                action=action_name,
                parameters={**params, "dry_run": dry_run, "level": level},
                triggered_by_score=score,
                status=status
            )

            if not dry_run:
                self._last_action_time[key] = now_ts
                if interface not in self._active_mitigations:
                    self._active_mitigations[interface] = set()
                self._active_mitigations[interface].add(action_name)
                LOG.warning("MITIGATION L%d EXECUTED on %s: %s", level, interface, params)
            else:
                LOG.info("MITIGATION L%d DRY-RUN on %s: %s", level, interface, params)

            return True

        except Exception as e:
            LOG.exception("Mitigation %s failed on %s: %s", action_name, interface, e)
            insert_mitigation_action(
                interface_name=interface,
                action=action_name,
                parameters={"error": str(e), "level": level, "dry_run": dry_run},
                triggered_by_score=score,
                status="failed"
            )
            return False

    async def rollback(self, interface: str, dry_run: bool | None = None) -> list[str]:
        """Rollback all active mitigations for an interface."""
        dry_run = self.config.dry_run if dry_run is None else dry_run
        rolled_back = []

        active = self._active_mitigations.get(interface, set()).copy()
        for action in active:
            try:
                await self._rollback_action(interface, action, dry_run)
                update_mitigation_rollback(interface, action)
                rolled_back.append(action)

                if not dry_run:
                    self._active_mitigations[interface].discard(action)
                    LOG.warning("MITIGATION ROLLBACK on %s: %s", interface, action)
                else:
                    LOG.info("MITIGATION ROLLBACK DRY-RUN on %s: %s", interface, action)

            except Exception as e:
                LOG.exception("Rollback %s failed on %s: %s", action, interface, e)

        return rolled_back

    async def rollback_all(self, dry_run: bool | None = None) -> dict[str, list[str]]:
        """Rollback all mitigations on all interfaces."""
        results = {}
        for interface in list(self._active_mitigations.keys()):
            results[interface] = await self.rollback(interface, dry_run)
        return results

    # ===== L1: Queue Tree Limit =====
    async def _mitigate_queue_limit(self, interface: str, score: float, dry_run: bool) -> dict[str, Any]:
        """Add queue tree limit on WAN interface."""
        # Get current peak bps from recent samples
        limit_bps = int(self.router_settings.ddos_threshold_bps * self.config.queue_limit_pct)

        params = {
            "interface": interface,
            "queue_type": "queue_tree",
            "max_limit_bps": limit_bps,
            "description": f"DDoS L1 mitigation (score: {score:.1f})"
        }

        if dry_run:
            return params

        # RouterOS REST: /queue/tree/add
        # Note: Requires parent queue to exist. Simplified here.
        async with httpx.AsyncClient(
            base_url=f"{self.router_settings.mikrotik_base_url.rstrip('/')}/rest/",
            auth=httpx.BasicAuth(self.router_settings.mikrotik_username, self.router_settings.mikrotik_password),
            verify=self.router_settings.mikrotik_tls_verify,
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            # Check if queue tree already exists for this interface
            resp = await client.get("queue/tree")
            resp.raise_for_status()
            queues = resp.json() if isinstance(resp.json(), list) else []

            # Find or create parent queue
            parent_name = "DDoS-Parent"
            parent = next((q for q in queues if q.get("name") == parent_name), None)
            if not parent:
                parent_resp = await client.post("queue/tree/add", json={
                    "name": parent_name,
                    "parent": "global",
                    "max-limit": f"{limit_bps}",
                    "bucket-size": "0.1",
                })
                parent_resp.raise_for_status()

            # Add child queue for the interface
            child_name = f"DDoS-{interface}"
            child_resp = await client.post("queue/tree/add", json={
                "name": child_name,
                "parent": parent_name,
                "max-limit": f"{limit_bps}",
                "packet-marks": f"DDoS-{interface}",
                "bucket-size": "0.1",
            })
            child_resp.raise_for_status()

            # Add mangle rule to mark packets
            mangle_resp = await client.post("ip/firewall/mangle/add", json={
                "chain": "forward",
                "action": "mark-packet",
                "new-packet-mark": f"DDoS-{interface}",
                "passthrough": "no",
                "out-interface": interface,
                "comment": f"DDoS L1 mitigation (score: {score:.1f})",
            })
            mangle_resp.raise_for_status()

        return params

    # ===== L2: TCP SYN Cookie =====
    async def _mitigate_syncookie(self, interface: str, score: float, dry_run: bool) -> dict[str, Any]:
        """Enable TCP SYN cookie on WAN interface."""
        params = {
            "interface": interface,
            "setting": "tcp-syncookie=yes",
            "description": f"DDoS L2 mitigation (score: {score:.1f})"
        }

        if dry_run:
            return params

        async with httpx.AsyncClient(
            base_url=f"{self.router_settings.mikrotik_base_url.rstrip('/')}/rest/",
            auth=httpx.BasicAuth(self.router_settings.mikrotik_username, self.router_settings.mikrotik_password),
            verify=self.router_settings.mikrotik_tls_verify,
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            # Enable SYN cookie on the interface
            # RouterOS: /interface/ethernet/set [find name=WAN] tcp-syncookie=yes
            # Or system-wide: /ip/settings/set tcp-syncookie=yes
            resp = await client.put(f"ip/settings", json={"tcp-syncookie": "yes"})
            resp.raise_for_status()

        return params

    async def _rollback_syncookie(self, interface: str, dry_run: bool) -> None:
        """Rollback SYN cookie (disable)."""
        if dry_run:
            return

        async with httpx.AsyncClient(
            base_url=f"{self.router_settings.mikrotik_base_url.rstrip('/')}/rest/",
            auth=httpx.BasicAuth(self.router_settings.mikrotik_username, self.router_settings.mikrotik_password),
            verify=self.router_settings.mikrotik_tls_verify,
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            await client.put("ip/settings", json={"tcp-syncookie": "no"})

    # ===== L3: Firewall Drop Top Sources =====
    async def _mitigate_firewall_drop(self, interface: str, score: float, dry_run: bool) -> dict[str, Any]:
        """Add firewall filter to drop new connections from top source IPs."""
        # Get top source IPs from connection tracking
        top_sources = await self._get_top_source_ips(interface, limit=10)

        params = {
            "interface": interface,
            "top_sources": top_sources,
            "action": "drop",
            "chain": "forward",
            "description": f"DDoS L3 mitigation (score: {score:.1f})"
        }

        if dry_run:
            return params

        async with httpx.AsyncClient(
            base_url=f"{self.router_settings.mikrotik_base_url.rstrip('/')}/rest/",
            auth=httpx.BasicAuth(self.router_settings.mikrotik_username, self.router_settings.mikrotik_password),
            verify=self.router_settings.mikrotik_tls_verify,
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            for src_ip in top_sources:
                # Add to address list
                addr_resp = await client.post("ip/firewall/address-list/add", json={
                    "list": "DDoS-Blocklist",
                    "address": src_ip,
                    "timeout": "1h",
                    "comment": f"DDoS L3 auto-block (score: {score:.1f})",
                })
                addr_resp.raise_for_status()

            # Add filter rule referencing address list (if not exists)
            filter_resp = await client.get("ip/firewall/filter")
            filter_resp.raise_for_status()
            filters = filter_resp.json() if isinstance(filter_resp.json(), list) else []

            exists = any(
                f.get("comment", "").startswith("DDoS L3 auto-block") for f in filters
            )
            if not exists:
                rule_resp = await client.post("ip/firewall/filter/add", json={
                    "chain": "forward",
                    "action": "drop",
                    "src-address-list": "DDoS-Blocklist",
                    "in-interface": interface,
                    "comment": f"DDoS L3 auto-block (score: {score:.1f})",
                    "place-before": 0,  # High priority
                })
                rule_resp.raise_for_status()

        return params

    async def _rollback_firewall_drop(self, interface: str, dry_run: bool) -> None:
        """Rollback firewall drop rules."""
        if dry_run:
            return

        async with httpx.AsyncClient(
            base_url=f"{self.router_settings.mikrotik_base_url.rstrip('/')}/rest/",
            auth=httpx.BasicAuth(self.router_settings.mikrotik_username, self.router_settings.mikrotik_password),
            verify=self.router_settings.mikrotik_tls_verify,
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            # Remove filter rules with DDoS L3 comment
            filter_resp = await client.get("ip/firewall/filter")
            filter_resp.raise_for_status()
            filters = filter_resp.json() if isinstance(filter_resp.json(), list) else []

            for f in filters:
                if f.get("comment", "").startswith("DDoS L3 auto-block"):
                    await client.delete(f"ip/firewall/filter/remove", params={"numbers": f.get(".id")})

            # Remove address list entries
            addr_resp = await client.get("ip/firewall/address-list")
            addr_resp.raise_for_status()
            addrs = addr_resp.json() if isinstance(addr_resp.json(), list) else []

            for a in addrs:
                if a.get("list") == "DDoS-Blocklist" and a.get("comment", "").startswith("DDoS L3 auto-block"):
                    await client.delete("ip/firewall/address-list/remove", params={"numbers": a.get(".id")})

    async def _get_top_source_ips(self, interface: str, limit: int = 10) -> list[str]:
        """Get top source IPs by connection count from connection tracking."""
        try:
            async with httpx.AsyncClient(
                base_url=f"{self.router_settings.mikrotik_base_url.rstrip('/')}/rest/",
                auth=httpx.BasicAuth(self.router_settings.mikrotik_username, self.router_settings.mikrotik_password),
                verify=self.router_settings.mikrotik_tls_verify,
                timeout=httpx.Timeout(10.0, connect=5.0),
            ) as client:
                resp = await client.get("ip/firewall/connection")
                resp.raise_for_status()
                connections = resp.json() if isinstance(resp.json(), list) else []

                # Count by src-address
                from collections import Counter
                src_counter = Counter()
                for conn in connections:
                    if isinstance(conn, dict):
                        src = conn.get("src-address")
                        if src and ":" in src:  # has port
                            src_ip = src.split(":")[0]
                            src_counter[src_ip] += 1

                return [ip for ip, _ in src_counter.most_common(limit)]

        except Exception as e:
            LOG.warning("Failed to get top source IPs: %s", e)
            return []

    # ===== L4: Blackhole Route =====
    async def _mitigate_blackhole(self, interface: str, score: float, dry_run: bool) -> dict[str, Any]:
        """Add blackhole route for attacked subnet (placeholder)."""
        # This is aggressive - would need to identify attacked subnet
        # For now, just log
        params = {
            "interface": interface,
            "action": "blackhole",
            "description": f"DDoS L4 mitigation (score: {score:.1f}) - NOT IMPLEMENTED"
        }

        if dry_run:
            return params

        LOG.critical("BLACKHOLE MITIGATION TRIGGERED on %s - MANUAL INTERVENTION REQUIRED", interface)
        # Actual implementation would:
        # 1. Identify attacked subnet from traffic analysis
        # 2. Add blackhole route: /ip/route/add dst-address=X/Y type=blackhole
        # 3. Or use BGP RTBH if upstream supports it

        return params

    async def _rollback_blackhole(self, interface: str, dry_run: bool) -> None:
        """Rollback blackhole route."""
        if dry_run:
            return
        # Remove blackhole routes added by DDoS mitigation
        LOG.info("Blackhole rollback on %s", interface)

    # ===== Generic Rollback Dispatcher =====
    async def _rollback_action(self, interface: str, action: str, dry_run: bool) -> None:
        """Dispatch rollback based on action type."""
        rollback_map = {
            "queue_limit": self._rollback_queue_limit,
            "syncookie": self._rollback_syncookie,
            "firewall_drop": self._rollback_firewall_drop,
            "blackhole": self._rollback_blackhole,
        }
        if action in rollback_map:
            await rollback_map[action](interface, dry_run)

    async def _rollback_queue_limit(self, interface: str, dry_run: bool) -> None:
        """Remove queue tree and mangle rules for DDoS mitigation."""
        if dry_run:
            return

        async with httpx.AsyncClient(
            base_url=f"{self.router_settings.mikrotik_base_url.rstrip('/')}/rest/",
            auth=httpx.BasicAuth(self.router_settings.mikrotik_username, self.router_settings.mikrotik_password),
            verify=self.router_settings.mikrotik_tls_verify,
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            # Remove mangle rules
            mangle_resp = await client.get("ip/firewall/mangle")
            mangle_resp.raise_for_status()
            mangles = mangle_resp.json() if isinstance(mangle_resp.json(), list) else []

            for m in mangles:
                if m.get("comment", "").startswith("DDoS L1 mitigation"):
                    await client.delete("ip/firewall/mangle/remove", params={"numbers": m.get(".id")})

            # Remove queue tree children
            queue_resp = await client.get("queue/tree")
            queue_resp.raise_for_status()
            queues = queue_resp.json() if isinstance(queue_resp.json(), list) else []

            for q in queues:
                if q.get("name", "").startswith("DDoS-"):
                    await client.delete("queue/tree/remove", params={"numbers": q.get(".id")})


def create_executor_from_settings(settings: Any, dry_run_override: bool | None = None) -> MitigationExecutor:
    """Factory to create MitigationExecutor from application settings."""
    config = MitigationConfig(
        enabled=settings.ddos_automitigate,
        dry_run=dry_run_override if dry_run_override is not None else getattr(settings, 'ddos_dry_run', True),
        cooldown_seconds=settings.ddos_mitigation_cooldown,
        rollback_polls=3,
        queue_limit_pct=0.8,
    )
    return MitigationExecutor(config, settings)