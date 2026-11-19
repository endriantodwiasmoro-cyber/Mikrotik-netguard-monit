# Real-Time DDoS Detection Design for NetGuard Monit

**Version:** 1.0  
**Status:** Draft for Review  
**Date:** 2026-11-09

---

## 1. Executive Summary

Design a **practical, production-ready DDoS detection** system using only data available via RouterOS REST API and SNMP — no packet capture, no NetFlow, no external sensors. Focus on **actionable alerts with low false positives** and optional **auto-mitigation via RouterOS REST**.

---

## 2. Constraints & Assumptions

| Constraint | Detail |
|------------|--------|
| **Data sources** | RouterOS REST (`/rest/interface`, `/rest/system/resource`, `/rest/ip/firewall/connection`), SNMPv2c (IF-MIB, EtherLike-MIB) |
| **Polling interval** | 5 seconds (configurable, min 5s) |
| **Storage** | SQLite (7 days raw, 30 days aggregated) |
| **No** | Port mirror, NetFlow/sFlow, packet capture, L7 inspection, threat intel feeds |
| **RouterOS version** | 6.48+ / 7.x (REST API available) |
| **Deployment** | Single collector, LAN-only access to router |

---

## 3. Detection Strategy: Multi-Dimensional Scoring

Instead of single threshold, compute **composite anomaly score** per interface per poll:

```
anomaly_score = w1*z_bps + w2*z_pps + w3*z_drops + w4*z_newconn + w5*z_synratio
```

| Dimension | Metric | Source | Weight | Rationale |
|-----------|--------|--------|--------|-----------|
| **Volume (bps)** | `rx_bps`, `tx_bps` | REST/SNMP `ifInOctets`/`ifOutOctets` | 0.30 | Classic volumetric |
| **Packet rate (pps)** | `rx_pps`, `tx_pps` | Derived from `ifInUcastPkts` + `ifInNUcastPkts` | 0.25 | Small-packet floods |
| **Drop rate** | `rx_drops`, `tx_drops` | REST `rx-drop`/`tx-drop`, SNMP `ifInDiscards` | 0.15 | Congestion indicator |
| **New connections** | `new_conn_rate` | REST `/ip/firewall/connection` count delta | 0.20 | SYN flood, connection exhaustion |
| **SYN ratio** | `syn_sent / synack_rcvd` | REST connection tracking states | 0.10 | TCP SYN flood signature |

**Weights tunable via `.env`** — default above, operator can adjust per threat model.

---

## 4. Baseline & Adaptive Thresholds

### 4.1 Baseline Calculation (EWMA per interface)

```python
# Per interface, per metric (bps, pps, drops, new_conn, syn_ratio)
# Updated every poll cycle
alpha = 0.3  # smoothing factor, configurable
baseline[metric] = alpha * current_value + (1 - alpha) * baseline[metric]
variance[metric] = alpha * (current_value - baseline[metric])**2 + (1 - alpha) * variance[metric]
stddev[metric] = sqrt(variance[metric])
```

### 4.2 Dynamic Threshold

```
threshold[metric] = baseline[metric] + k * stddev[metric]
```

| Profile | `k` (sigma) | Use Case |
|---------|-------------|----------|
| **Sensitive** | 2.0 | Lab, learning mode |
| **Balanced** | 3.0 | **Default production** |
| **Conservative** | 4.0 | High-noise environments |

### 4.3 Time-of-Day / Day-of-Week Seasonality

- Maintain **separate baselines per hour-of-week** (168 buckets)
- On poll, use bucket matching current time
- Warm-up: first 7 days use global baseline, then switch to seasonal

---

## 5. Detection Logic Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    POLL CYCLE (every 5s)                        │
├─────────────────────────────────────────────────────────────────┤
│ 1. Collect metrics (REST + SNMP)                                │
│    ├── Interface counters (bps, pps, drops)                     │
│    ├── Connection tracking (total, tcp-syn-sent, established)   │
│    └── System health (CPU, memory)                              │
├─────────────────────────────────────────────────────────────────┤
│ 2. Update baselines (EWMA + seasonal bucket)                    │
├─────────────────────────────────────────────────────────────────┤
│ 3. Compute z-scores per metric                                  │
│    z = (current - baseline) / max(stddev, min_stddev)           │
├─────────────────────────────────────────────────────────────────┤
│ 4. Composite anomaly score = Σ(weight_i * z_i)                  │
├─────────────────────────────────────────────────────────────────┤
│ 5. State machine per interface:                                 │
│    NORMAL → (score > 3.0 for 2 consecutive polls) → WARNING     │
│    WARNING → (score > 4.0 for 1 poll) → CRITICAL                │
│    WARNING/CRITICAL → (score < 2.0 for 3 polls) → RECOVERING   │
│    RECOVERING → (score < 1.5 for 2 polls) → NORMAL              │
├─────────────────────────────────────────────────────────────────┤
│ 6. Emit alert with fingerprint:                                 │
│    ddos_anomaly_{interface}_{profile}                           │
│    Includes: score, top contributing metrics, baseline values   │
├─────────────────────────────────────────────────────────────────┤
│ 7. Optional auto-mitigation (if enabled & CRITICAL)             │
│    └── See Section 7                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Alert Schema

### 6.1 Fingerprint Format
```
ddos_anomaly_{interface}_{profile}
# Examples:
ddos_anomaly_ether1_wan_balanced
ddos_anomaly_bridge_lan_conservative
```

### 6.2 Alert Payload (JSON)
```json
{
  "fingerprint": "ddos_anomaly_ether1_wan_balanced",
  "severity": "critical",
  "status": "active",
  "message": "DDoS anomaly on ether1 (WAN): score 4.2 (bps: +3.8σ, pps: +4.1σ, new_conn: +2.9σ)",
  "details": {
    "interface": "ether1",
    "profile": "balanced",
    "composite_score": 4.2,
    "metrics": {
      "rx_bps": {"current": 950000000, "baseline": 45000000, "stddev": 12000000, "z_score": 3.8},
      "rx_pps": {"current": 85000, "baseline": 12000, "stddev": 3000, "z_score": 4.1},
      "new_conn_rate": {"current": 2200, "baseline": 180, "stddev": 50, "z_score": 2.9},
      "syn_ratio": {"current": 0.85, "baseline": 0.12, "stddev": 0.03, "z_score": 3.1}
    },
    "top_contributors": ["rx_pps", "rx_bps", "syn_ratio"],
    "poll_interval_sec": 5,
    "consecutive_polls_above_threshold": 2
  },
  "created_at": "2026-11-09T11:15:22Z"
}
```

### 6.3 Severity Mapping
| Composite Score | State | Severity | Action |
|-----------------|-------|----------|--------|
| 0.0 – 2.0 | NORMAL | info | Baseline update only |
| 2.0 – 3.0 | ELEVATED | info | Log only, no alert |
| 3.0 – 4.0 | WARNING | warning | Alert raised, Telegram notify |
| > 4.0 | CRITICAL | critical | Alert + auto-mitigate (if enabled) |

---

## 7. Auto-Mitigation (Optional, Opt-In)

**Disabled by default.** Enable via `DDOS_AUTOMITIGATE=true` in `.env`.

### 7.1 Mitigation Actions (Escalating)

| Level | Trigger | Action via RouterOS REST |
|-------|---------|--------------------------|
| **L1** | CRITICAL ≥ 2 polls | Add queue tree limit on WAN: `max-limit=80%_of_baseline_bps` |
| **L2** | CRITICAL ≥ 5 polls | Enable `tcp-syncookie=yes` on WAN interface |
| **L3** | CRITICAL ≥ 10 polls | Add firewall filter: drop new connections from top 10 source IPs (from connection tracking) |
| **L4** | CRITICAL ≥ 20 polls | Blackhole route for attacked subnet (if identifiable) |

### 7.2 Safety Guards
- **Max one mitigation action per 5 minutes** (prevent flapping)
- **Auto-rollback** when state → RECOVERING for 3 consecutive polls
- **Manual override** via dashboard: "Disable auto-mitigation" button
- **Audit log** every action in `alert_events` with `kind=mitigation`

### 7.3 Required RouterOS Permissions
API user needs: `read, write, policy, test` + `firewall`, `queue`, `routing` policies.

---

## 8. Implementation Plan

### Phase 1: Core Detection (Week 1)
- [ ] `app/ddos_detector.py` — new module with `DDoSDetector` class
- [ ] EWMA baseline with seasonal buckets (168-hour)
- [ ] Multi-metric z-score computation
- [ ] Composite scoring + state machine
- [ ] Integration with `alerts.py` → `evaluate_alerts()` returns ddos tuples
- [ ] Unit tests with synthetic traffic patterns

### Phase 2: Dashboard & Visualization (Week 1-2)
- [ ] New chart: **Anomaly Score Timeline** (per interface)
- [ ] Metric breakdown: stacked area (bps, pps, drops, conn, syn)
- [ ] Baseline vs actual overlay
- [ ] Alert markers on chart (warning/critical)
- [ ] Configuration panel: profile selection, weights, auto-mitigate toggle

### Phase 3: Auto-Mitigation (Week 2)
- [ ] `app/mitigation.py` — RouterOS REST actions
- [ ] Safety guards (cooldown, rollback, audit)
- [ ] Dashboard mitigation status panel
- [ ] Dry-run mode (log only, no actual API calls)

### Phase 4: Hardening & Tuning (Week 2-3)
- [ ] SNMP `ifInBroadcastPkts` / `ifInMulticastPkts` integration
- [ ] Connection tracking parser optimization
- [ ] False positive analysis on production traffic
- [ ] Document tuning guide per router model (CRS, CCR, RB series)

---

## 9. Configuration (`.env` additions)

```bash
# DDoS Detection
DDOS_DETECTION_ENABLED=true
DDOS_PROFILE=balanced                 # sensitive | balanced | conservative
DDOS_AUTOMITIGATE=false               # true | false
DDOS_BASELINE_WARMUP_DAYS=7
DDOS_EWMA_ALPHA=0.3
DDOS_MIN_STDDEV_BPS=100000            # floor to avoid div-by-zero on quiet links

# Weights (must sum to 1.0)
DDOS_WEIGHT_BPS=0.30
DDOS_WEIGHT_PPS=0.25
DDOS_WEIGHT_DROPS=0.15
DDOS_WEIGHT_NEWCONN=0.20
DDOS_WEIGHT_SYNRATIO=0.10

# Thresholds (sigma multipliers per profile)
DDOS_THRESHOLD_SENSITIVE=2.0
DDOS_THRESHOLD_BALANCED=3.0
DDOS_THRESHOLD_CONSERVATIVE=4.0

# Auto-mitigation
DDOS_MITIGATION_COOLDOWN_SECONDS=300
DDOS_ROLLBACK_POLLS=3
```

---

## 10. Database Schema Extensions

```sql
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
```

---

## 11. API Endpoints (New)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ddos/status` | Current anomaly score, baseline, state per interface |
| GET | `/api/ddos/history` | Score timeline (granularity + range like traffic) |
| GET | `/api/ddos/baselines` | Current baseline values per interface/metric |
| POST | `/api/ddos/mitigation/toggle` | Enable/disable auto-mitigation (CSRF) |
| POST | `/api/ddos/mitigation/rollback` | Manual rollback all active mitigations |
| GET | `/api/ddos/mitigation/history` | Audit log of mitigation actions |

---

## 12. Dashboard UI Additions

### 12.1 New Panel: "DDoS Detection"
- **Top row**: Per-interface anomaly score gauge (0-5, color: green→yellow→red)
- **Chart**: Composite score timeline + threshold lines (warning/critical)
- **Breakdown**: Stacked area of 5 metric z-scores
- **Table**: Current metric values vs baseline vs threshold
- **Controls**: Profile selector, auto-mitigate toggle, manual rollback button

### 12.2 Integration Points
- Reuse existing Chart.js instance (extend `dashboard.js`)
- Same granularity/range selectors as traffic chart
- Alert events already show in "Aktivitas" table

---

## 13. Testing Strategy

### 13.1 Unit Tests (`tests/test_ddos_detector.py`)
- EWMA convergence
- Seasonal bucket selection
- State machine transitions
- Composite score calculation
- Edge cases: zero baseline, missing metrics, counter wrap

### 13.2 Integration Tests
- Synthetic traffic generator (legit + attack patterns)
- Full poll cycle: collect → detect → alert → mitigate → rollback
- False positive rate on 30-day production capture (replay)

### 13.3 Attack Simulations (Lab)
| Attack Type | Tool | Expected Detection |
|-------------|------|-------------------|
| UDP flood (volumetric) | `hping3 --udp --flood` | bps + pps spike |
| TCP SYN flood | `hping3 -S --flood` | new_conn + syn_ratio |
| ICMP flood | `hping3 -1 --flood` | pps + drops |
| Slowloris | `slowhttptest` | new_conn (slow rise) |
| Legit burst | `iperf3` | baseline adapts, no alert |

---

## 14. Operational Runbook

### 14.1 Tuning Guide
1. **Start with `profile=sensitive` for 7 days** (warmup + learning)
2. **Review false positives** in alert history
3. **Switch to `balanced`** — adjust weights if specific metric noisy
4. **Enable auto-mitigate** only after 30 days clean operation

### 14.2 Common Issues
| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Constant WARNING on quiet link | `min_stddev` too low | Increase `DDOS_MIN_STDDEV_BPS` |
| Missed attack (slow ramp) | Baseline adapts too fast | Decrease `DDOS_EWMA_ALPHA` to 0.1 |
| False positive at backup window | No seasonal baseline yet | Wait 7 days, or pre-seed baselines |
| Mitigation flaps | Cooldown too short | Increase `DDOS_MITIGATION_COOLDOWN_SECONDS` |

### 14.3 Emergency Procedures
- **Disable mitigation instantly**: Dashboard button or `DDOS_AUTOMITIGATE=false` + restart
- **Force rollback**: `POST /api/ddos/mitigation/rollback`
- **Debug mode**: Set `LOG_LEVEL=DEBUG` for detector module

---

## 15. Future Enhancements (Out of Scope v1)

- **L7 detection** — integrate with Suricata via Unix socket (separate container)
- **Threat intel** — block known malicious IPs via RouterOS address-list
- **Multi-router correlation** — centralized detector for multiple sites
- **ML-based** — Isolation Forest on metric vectors (needs more training data)
- **Flow analysis** — enable RouterOS `traffic-flow` → NetFlow collector → entropy

---

## 16. Approval Checklist

- [ ] Architecture review (this document)
- [ ] Security review (auto-mitigation permissions, rollback safety)
- [ ] Performance review (SQLite write load, REST call latency)
- [ ] Operations review (runbook, alert fatigue, on-call procedures)
- [ ] Stakeholder sign-off

---

**Next Step:** Review this design. If approved, I'll implement **Phase 1** (core detection module + integration with existing alert system).