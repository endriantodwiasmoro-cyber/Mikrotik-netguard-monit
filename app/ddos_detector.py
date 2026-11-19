"""DDoS Detection Engine for NetGuard Monit.

Multi-dimensional anomaly scoring with EWMA baselines, seasonal adaptation,
state machine, alert integration, and optional auto-mitigation.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .database import (
    get_current_ddos_baseline,
    upsert_ddos_baseline,
    insert_ddos_score,
    get_latest_connection_tracking,
    insert_connection_tracking,
)
from .connection_tracking import (
    collect_connection_tracking,
    compute_new_conn_rate,
    compute_syn_ratio,
)
from .mitigation import create_executor_from_settings, MitigationExecutor
from . import alerts as alerts_module

LOG = logging.getLogger("netguard")
UTC = timezone.utc


@dataclass
class DDoSConfig:
    """Configuration for DDoS detector."""
    enabled: bool = True
    profile: str = "balanced"          # sensitive | balanced | conservative
    automitigate: bool = False
    dry_run: bool = True               # Safety: default dry-run
    ewma_alpha: float = 0.3
    min_stddev_bps: float = 100_000
    warmup_days: int = 7
    mitigation_cooldown: int = 300
    rollback_polls: int = 3
    weights: dict[str, float] = field(default_factory=lambda: {
        "bps": 0.30,
        "pps": 0.25,
        "drops": 0.15,
        "newconn": 0.20,
        "synratio": 0.10,
    })

    # Threshold multipliers (sigma) per profile
    thresholds: dict[str, float] = field(default_factory=lambda: {
        "sensitive": 2.0,
        "balanced": 3.0,
        "conservative": 4.0,
    })


@dataclass
class MetricScore:
    """Individual metric z-score and contribution."""
    key: str
    label: str
    unit: str
    current: float
    baseline: float
    stddev: float
    z_score: float
    weight: float
    contribution: float


@dataclass
class InterfaceState:
    """Per-interface detection state."""
    name: str
    composite_score: float = 0.0
    state: str = "normal"              # normal | elevated | warning | critical | recovering
    consecutive_above_warn: int = 0
    consecutive_above_crit: int = 0
    consecutive_below_recover: int = 0
    last_mitigation_level: int = 0
    last_mitigation_time: float = 0
    below_threshold_polls: int = 0
    metric_scores: list[MetricScore] = field(default_factory=list)


def now() -> datetime:
    return datetime.now(UTC)


def get_threshold(profile: str) -> float:
    """Get sigma threshold for profile."""
    thresholds = {"sensitive": 2.0, "balanced": 3.0, "conservative": 4.0}
    return thresholds.get(profile, 3.0)


def _hour_of_week() -> int:
    """Get current hour of week (0-167, Mon 00:00 = 0)."""
    dt = now()
    return dt.weekday() * 24 + dt.hour


class DDoSDetector:
    """Main DDoS detection engine."""

    def __init__(self, config: DDoSConfig, settings: Any):
        self.config = config
        self.settings = settings
        self.interfaces: dict[str, InterfaceState] = {}
        self.mitigation_executor: MitigationExecutor | None = None

        if config.automitigate:
            self.mitigation_executor = create_executor_from_settings(
                settings, dry_run_override=config.dry_run
            )
            LOG.info("DDoS auto-mitigation initialized (dry_run=%s)", config.dry_run)

    async def process_poll(self, collector_result: Any) -> list[tuple[str, str, str, bool]]:
        """Process one poll cycle, return alert tuples for alerts module."""
        if not self.config.enabled:
            return []

        alerts = []
        current_time = now().timestamp()
        observed_at = now().isoformat(timespec="seconds")

        # Collect connection tracking data (async, non-blocking)
        conn_tracking = None
        if self.settings.collect_method in ("rest", "both"):
            try:
                conn_tracking = await collect_connection_tracking(
                    base_url=self.settings.mikrotik_base_url,
                    username=self.settings.mikrotik_username,
                    password=self.settings.mikrotik_password,
                    tls_verify=self.settings.mikrotik_tls_verify,
                )
            except Exception as e:
                LOG.warning("Connection tracking collection failed: %s", e)

        for iface in collector_result.interfaces:
            # Initialize interface state if new
            if iface.name not in self.interfaces:
                self.interfaces[iface.name] = InterfaceState(name=iface.name)

            state = self.interfaces[iface.name]

            # Compute metric scores
            metric_scores = await self._compute_metric_scores(iface, conn_tracking, observed_at)
            state.metric_scores = metric_scores

            # Compute composite score
            composite = sum(m.contribution for m in metric_scores)
            state.composite_score = composite

            # Store score history
            metric_z = {m.key: m.z_score for m in metric_scores}
            details = {
                "top_contributors": [
                    {"metric": m.label, "z_score": m.z_score, "contribution": m.contribution}
                    for m in sorted(metric_scores, key=lambda x: x.contribution, reverse=True)[:3]
                ],
                "thresholds": {
                    "warning": get_threshold(self.config.profile),
                    "critical": get_threshold(self.config.profile) + 1.0
                }
            }
            insert_ddos_score(
                interface_name=iface.name,
                observed_at=observed_at,
                composite_score=composite,
                state=state.state,
                metric_z=metric_z,
                details=details
            )

            # Update state machine
            prev_state = state.state
            self._update_state_machine(state, composite)

            # Generate alert if state changed significantly
            alert = self._generate_alert(state, iface, prev_state)
            if alert:
                alerts.append(alert)

            # Handle auto-mitigation
            if self.config.automitigate and self.mitigation_executor:
                await self._handle_mitigation(state, iface, current_time)

        return alerts

    async def _compute_metric_scores(
        self, iface: Any, conn_tracking: Any | None, observed_at: str
    ) -> list[MetricScore]:
        """Compute z-scores for all 5 metrics."""
        scores = []
        weights = self.config.weights

        # Get previous connection tracking for rate calculation
        prev_conn = get_latest_connection_tracking(iface.name)

        # 1. Volume (bps) - use max of rx/tx
        rx_bps = getattr(iface, "rx_bps", 0) or 0
        tx_bps = getattr(iface, "tx_bps", 0) or 0
        bps = max(rx_bps, tx_bps)
        baseline_data = get_current_ddos_baseline(iface.name, "rx_bps")
        if baseline_data:
            baseline, stddev = baseline_data
            stddev = max(stddev, self.config.min_stddev_bps)
            z = (bps - baseline) / stddev if stddev > 0 else 0
            scores.append(MetricScore(
                key="bps", label="rx_bps", unit="bps",
                current=bps, baseline=baseline, stddev=stddev,
                z_score=max(0, z), weight=weights["bps"],
                contribution=weights["bps"] * max(0, z)
            ))
            upsert_ddos_baseline(iface.name, "rx_bps", _hour_of_week(), bps, self.config.ewma_alpha)

        # 2. Packet Rate (pps) - derive from packets per poll
        rx_pps = getattr(iface, "rx_packets", 0) or 0
        tx_pps = getattr(iface, "tx_packets", 0) or 0
        pps = max(rx_pps, tx_pps)
        baseline_data = get_current_ddos_baseline(iface.name, "rx_pps")
        if baseline_data:
            baseline, stddev = baseline_data
            stddev = max(stddev, 1)
            z = (pps - baseline) / stddev if stddev > 0 else 0
            scores.append(MetricScore(
                key="pps", label="rx_pps", unit="pps",
                current=pps, baseline=baseline, stddev=stddev,
                z_score=max(0, z), weight=weights["pps"],
                contribution=weights["pps"] * max(0, z)
            ))
            upsert_ddos_baseline(iface.name, "rx_pps", _hour_of_week(), pps, self.config.ewma_alpha)

        # 3. Drop Rate
        drops = (getattr(iface, "rx_drops", 0) or 0) + (getattr(iface, "tx_drops", 0) or 0)
        baseline_data = get_current_ddos_baseline(iface.name, "drops")
        if baseline_data:
            baseline, stddev = baseline_data
            stddev = max(stddev, 1)
            z = (drops - baseline) / stddev if stddev > 0 else 0
            scores.append(MetricScore(
                key="drops", label="drops", unit="drops",
                current=drops, baseline=baseline, stddev=stddev,
                z_score=max(0, z), weight=weights["drops"],
                contribution=weights["drops"] * max(0, z)
            ))
            upsert_ddos_baseline(iface.name, "drops", _hour_of_week(), drops, self.config.ewma_alpha)

        # 4. New Connection Rate (from connection tracking)
        new_conn = 0.0
        if conn_tracking and not conn_tracking.error:
            new_conn = compute_new_conn_rate(
                current_total=conn_tracking.total_connections,
                previous_total=prev_conn["total_connections"] if prev_conn else None,
                current_ts=observed_at,
                previous_ts=prev_conn["observed_at"] if prev_conn else None,
                poll_interval=self.settings.poll_interval_seconds
            )
            # Store connection tracking snapshot
            insert_connection_tracking(
                interface_name=iface.name,
                observed_at=observed_at,
                total=conn_tracking.total_connections,
                tcp_syn_sent=conn_tracking.tcp_syn_sent,
                tcp_established=conn_tracking.tcp_established,
                tcp_time_wait=conn_tracking.tcp_time_wait,
                udp=conn_tracking.udp_connections,
                other=conn_tracking.other_connections
            )

        baseline_data = get_current_ddos_baseline(iface.name, "new_conn")
        if baseline_data:
            baseline, stddev = baseline_data
            stddev = max(stddev, 1)
            z = (new_conn - baseline) / stddev if stddev > 0 else 0
            scores.append(MetricScore(
                key="newconn", label="new_conn_rate", unit="conn/s",
                current=new_conn, baseline=baseline, stddev=stddev,
                z_score=max(0, z), weight=weights["newconn"],
                contribution=weights["newconn"] * max(0, z)
            ))
            upsert_ddos_baseline(iface.name, "new_conn", _hour_of_week(), new_conn, self.config.ewma_alpha)

        # 5. SYN Ratio (from connection tracking)
        syn_ratio = 0.0
        if conn_tracking and not conn_tracking.error:
            syn_ratio = compute_syn_ratio(conn_tracking.tcp_syn_sent, conn_tracking.tcp_established)

        baseline_data = get_current_ddos_baseline(iface.name, "syn_ratio")
        if baseline_data:
            baseline, stddev = baseline_data
            stddev = max(stddev, 0.01)
            z = (syn_ratio - baseline) / stddev if stddev > 0 else 0
            scores.append(MetricScore(
                key="synratio", label="syn_ratio", unit="ratio",
                current=syn_ratio, baseline=baseline, stddev=stddev,
                z_score=max(0, z), weight=weights["synratio"],
                contribution=weights["synratio"] * max(0, z)
            ))
            upsert_ddos_baseline(iface.name, "syn_ratio", _hour_of_week(), syn_ratio, self.config.ewma_alpha)

        return scores

    def _update_state_machine(self, state: InterfaceState, score: float) -> None:
        """Update interface state machine based on composite score."""
        warn_threshold = get_threshold(self.config.profile)
        crit_threshold = warn_threshold + 1.0  # critical is warn + 1 sigma

        prev_state = state.state

        if score >= crit_threshold:
            state.state = "critical"
            state.consecutive_above_crit += 1
            state.consecutive_above_warn = 0
            state.below_threshold_polls = 0
        elif score >= warn_threshold:
            state.state = "warning"
            state.consecutive_above_warn += 1
            state.consecutive_above_crit = 0
            state.below_threshold_polls = 0
        elif score >= 2.0:
            state.state = "elevated"
            state.consecutive_above_warn = 0
            state.consecutive_above_crit = 0
            state.below_threshold_polls = 0
        elif score >= 1.0:
            state.state = "recovering"
            state.below_threshold_polls += 1
            if state.below_threshold_polls >= self.config.rollback_polls:
                state.state = "normal"
            state.consecutive_above_warn = 0
            state.consecutive_above_crit = 0
        else:
            state.state = "normal"
            state.consecutive_above_warn = 0
            state.consecutive_above_crit = 0
            state.below_threshold_polls = 0

        LOG.debug("Interface %s: score=%.2f, state=%s (prev=%s)", state.name, score, state.state, prev_state)

    def _generate_alert(
        self, state: InterfaceState, iface: Any, prev_state: str
    ) -> tuple[str, str, str, bool] | None:
        """Generate alert tuple if state warrants it."""
        warn_threshold = get_threshold(self.config.profile)
        crit_threshold = warn_threshold + 1.0

        should_alert = False
        severity = "info"
        message = ""

        # Alert on state transitions to warning/critical
        if state.state == "critical" and prev_state != "critical":
            should_alert = True
            severity = "critical"
            message = self._format_message(state, iface, "CRITICAL")
        elif state.state == "warning" and prev_state not in ("warning", "critical"):
            should_alert = True
            severity = "warning"
            message = self._format_message(state, iface, "WARNING")
        # Recovery alert
        elif state.state == "normal" and prev_state in ("recovering", "warning", "critical"):
            should_alert = True
            severity = "info"
            message = f"DDoS anomaly on {state.name} RECOVERED (score: {state.composite_score:.1f})"

        if not should_alert:
            return None

        fingerprint = f"ddos_anomaly_{state.name}_{self.config.profile}"
        return (fingerprint, severity, message, state.state in ("warning", "critical"))

    def _format_message(self, state: InterfaceState, iface: Any, level: str) -> str:
        """Format alert message with top contributing metrics."""
        top_metrics = sorted(state.metric_scores, key=lambda m: m.contribution, reverse=True)[:3]
        contributors = ", ".join(f"{m.label}: +{m.z_score:.1f}σ" for m in top_metrics if m.z_score > 0)
        return (
            f"DDoS anomaly on {state.name}: {level} "
            f"(score {state.composite_score:.1f}, {contributors})"
        )

    async def _handle_mitigation(self, state: InterfaceState, iface: Any, current_time: float) -> None:
        """Handle auto-mitigation escalation and rollback."""
        if not self.mitigation_executor:
            return

        executor = self.mitigation_executor

        # Rollback if recovered
        if state.state == "normal" and state.below_threshold_polls >= self.config.rollback_polls:
            if state.last_mitigation_level > 0:
                LOG.info("DDoS recovered on %s, rolling back mitigations", state.name)
                await executor.rollback(state.name)
                state.last_mitigation_level = 0
                state.last_mitigation_time = 0
            return

        # Escalate if critical
        if state.state != "critical":
            return

        # Check cooldown
        if current_time - state.last_mitigation_time < self.config.mitigation_cooldown:
            return

        level = state.last_mitigation_level + 1

        if level == 1 and state.consecutive_above_crit >= 2:
            await self._execute_mitigation(state, iface, 1, current_time)
        elif level == 2 and state.consecutive_above_crit >= 5:
            await self._execute_mitigation(state, iface, 2, current_time)
        elif level == 3 and state.consecutive_above_crit >= 10:
            await self._execute_mitigation(state, iface, 3, current_time)
        elif level == 4 and state.consecutive_above_crit >= 20:
            await self._execute_mitigation(state, iface, 4, current_time)

    async def _execute_mitigation(
        self, state: InterfaceState, iface: Any, level: int, current_time: float
    ) -> None:
        """Execute mitigation at given level."""
        if not self.mitigation_executor:
            return

        executed = await self.mitigation_executor.execute(
            interface=iface.name,
            level=level,
            score=state.composite_score,
        )

        if executed:
            state.last_mitigation_level = level
            state.last_mitigation_time = current_time
            LOG.warning("DDoS mitigation L%d executed on %s (score=%.1f)", level, iface.name, state.composite_score)


def create_detector_from_settings(settings: Any) -> DDoSDetector:
    """Factory to create DDoSDetector from application settings."""
    config = DDoSConfig(
        enabled=settings.ddos_detection_enabled,
        profile=settings.ddos_profile,
        automitigate=settings.ddos_automitigate,
        dry_run=getattr(settings, 'ddos_dry_run', True),
        ewma_alpha=settings.ddos_ewma_alpha,
        min_stddev_bps=settings.ddos_min_stddev_bps,
        warmup_days=settings.ddos_warmup_days,
        mitigation_cooldown=settings.ddos_mitigation_cooldown,
        rollback_polls=3,
        weights={
            "bps": settings.ddos_weight_bps,
            "pps": settings.ddos_weight_pps,
            "drops": settings.ddos_weight_drops,
            "newconn": settings.ddos_weight_newconn,
            "synratio": settings.ddos_weight_synratio,
        }
    )
    return DDoSDetector(config, settings)