# DDoS Detection Implementation Summary

**Status:** Phase 1A-1D Complete (Code Ready, Disabled by Default)  
**Date:** 2026-11-09

---

## Overview

Implemented a comprehensive DDoS detection system for NetGuard Monit with **4 phases** of functionality. All code is in place but **disabled by default** via configuration — requires explicit opt-in to activate.

---

## Phase 1A: Core Detection Engine ✅

### Files Created/Modified

| File | Purpose |
|------|---------|
| `app/ddos_detector.py` | Main detection engine (EWMA, scoring, state machine) |
| `app/templates/base.html` | Shared layout with nav tabs |
| `app/templates/ddos.html` | Full DDoS dashboard (gauges, charts, tables, config) |
| `app/static/ddos.js` | Chart.js logic for all visualizations |
| `app/database.py` | New tables: `ddos_baselines`, `mitigation_actions` |
| `app/main.py` | Routes: `/ddos`, 6 API endpoints, detector integration |

### Detection Algorithm

```
Composite Score = Σ(weight_i × max(0, z_score_i))

Metrics (5 dimensions):
  1. Volume (bps)          weight: 0.30  → rx_bps/tx_bps
  2. Packet Rate (pps)     weight: 0.25  → rx_packets/tx_packets per poll
  3. Drop Rate             weight: 0.15  → rx_drops + tx_drops
  4. New Conn Rate         weight: 0.20  → connection tracking delta
  5. SYN Ratio             weight: 0.10  → tcp-syn-sent / established
```

### Baseline & Thresholds

- **EWMA** (α=0.3 default) per interface, per metric, per hour-of-week (168 buckets)
- **Dynamic threshold**: `baseline + k × stddev` where k = profile sigma
- **Profiles**: Sensitive (2σ), Balanced (3σ), Conservative (4σ)

### State Machine

```
NORMAL → (score≥warn) → ELEVATED → (score≥warn 2 polls) → WARNING
                                        → (score≥crit 1 poll) → CRITICAL
CRITICAL → (score<2σ 3 polls) → RECOVERING → NORMAL
```

### Alert Integration

- Fingerprint: `ddos_anomaly_{interface}_{profile}`
- Severity: `warning` | `critical` | `info` (recovery)
- Auto-dispatched to Telegram via existing `alerts_module`

---

## Phase 1B: Dedicated Score History ✅

### Database Additions (`database.py`)

```sql
-- ddos_scores: composite score history for fast queries
CREATE TABLE ddos_scores (
    id INTEGER PRIMARY KEY,
    interface_name TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    composite_score REAL NOT NULL,
    state TEXT NOT NULL,
    metric_bps_z REAL,
    metric_pps_z REAL,
    metric_drops_z REAL,
    metric_newconn_z REAL,
    metric_synratio_z REAL,
    details TEXT  -- JSON
);

-- connection_tracking: raw connection data for new_conn/syn_ratio
CREATE TABLE connection_tracking (
    id INTEGER PRIMARY KEY,
    interface_name TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    total_connections INTEGER,
    tcp_syn_sent INTEGER,
    tcp_established INTEGER,
    tcp_time_wait INTEGER,
    udp_connections INTEGER,
    other_connections INTEGER
);
```

### New Query Functions

| Function | Purpose |
|----------|---------|
| `insert_ddos_score()` | Store score + metric z-scores each poll |
| `get_ddos_score_history()` | Aggregated timeline for charts |
| `get_ddos_breakdown_history()` | Stacked area chart data |
| `insert_connection_tracking()` | Store connection tracking snapshots |
| `get_latest_connection_tracking()` | Previous sample for rate calculation |

---

## Phase 1C: Connection Tracking Collector ✅

### File: `app/connection_tracking.py`

```python
async def collect_connection_tracking(base_url, username, password, tls_verify):
    """Fetch /rest/ip/firewall/connection from RouterOS"""
    # Returns: total, tcp_syn_sent, tcp_established, tcp_time_wait, udp, other

def compute_new_conn_rate(current, previous, current_ts, previous_ts, poll_interval):
    """New connections per second from counter delta"""

def compute_syn_ratio(tcp_syn_sent, tcp_established):
    """SYN sent / established ratio. High = SYN flood indicator"""
```

### Integration in Detector

- Runs in parallel with interface collection (REST only)
- Updates baselines for `new_conn` and `syn_ratio` metrics
- Stores raw data in `connection_tracking` table
- **Zero impact** if connection tracking fails (graceful degradation)

---

## Phase 1D: Auto-Mitigation Executor ✅

### File: `app/mitigation.py`

### Safety Features (Default)

| Feature | Default | Purpose |
|---------|---------|---------|
| **Dry-run mode** | `True` | Logs actions only, no RouterOS API calls |
| **Cooldown** | 300s | Prevents flapping |
| **Rollback polls** | 3 | Auto-rollback after recovery |
| **Escalation gates** | L1≥2, L2≥5, L3≥10, L4≥20 | Consecutive critical polls required |

### Mitigation Levels

| Level | Trigger | Action | RouterOS REST |
|-------|---------|--------|---------------|
| **L1** | 2× CRITICAL | Queue tree limit (80% baseline) | `/queue/tree/add`, `/ip/firewall/mangle/add` |
| **L2** | 5× CRITICAL | Enable TCP SYN cookie | `/ip/settings` (tcp-syncookie=yes) |
| **L3** | 10× CRITICAL | Firewall drop top 10 source IPs | `/ip/firewall/address-list/add`, `/ip/firewall/filter/add` |
| **L4** | 20× CRITICAL | Blackhole route (manual) | Log only — requires manual intervention |

### Rollback Actions

| Action | Rollback |
|--------|----------|
| Queue limit | Remove mangle rules + queue tree children |
| SYN cookie | Set `tcp-syncookie=no` |
| Firewall drop | Remove filter rules + address list entries |
| Blackhole | Remove blackhole routes |

### Audit Logging

All actions logged to `mitigation_actions` table with:
- Interface, action, parameters (JSON)
- Triggered score, status (executed/rolled_back/failed/dry_run)
- Timestamp, rollback timestamp

---

## Configuration (`.env`)

```bash
# ===== DDoS Detection =====
DDOS_DETECTION_ENABLED=true      # Enable detection engine
DDOS_PROFILE=balanced            # sensitive | balanced | conservative
DDOS_DRY_RUN=true                # SAFETY: dry-run only (no RouterOS changes)
DDOS_AUTOMITIGATE=false          # Enable auto-mitigation (requires DRY_RUN=false)
DDOS_EWMA_ALPHA=0.3              # Baseline smoothing (0.1-0.5)
DDOS_MIN_STDDEV_BPS=100000       # Floor for quiet links
DDOS_WARMUP_DAYS=7               # Days before seasonal baselines active
DDOS_MITIGATION_COOLDOWN_SECONDS=300  # Min time between actions

# Weights (must sum to 1.0)
DDOS_WEIGHT_BPS=0.30
DDOS_WEIGHT_PPS=0.25
DDOS_WEIGHT_DROPS=0.15
DDOS_WEIGHT_NEWCONN=0.20
DDOS_WEIGHT_SYNRATIO=0.10

# Existing (used by L1 threshold)
DDOS_THRESHOLD_BPS=100000000     # 100 Mbps
```

---

## Dashboard Features (`/ddos`)

| Panel | Visualization |
|-------|---------------|
| **Gauges** | Donut gauge per interface (0-5, color-coded) |
| **Timeline** | Composite score line chart + warning/critical zones |
| **Breakdown** | Stacked area: 5 metric z-scores over time |
| **Metrics Table** | Current vs Baseline vs Threshold + Z-score + Contribution |
| **Seasonal Baseline** | 168 bucket hour-of-week bar chart |
| **Config Panel** | Weight sliders (live sum), EWMA, thresholds, cooldown |
| **Mitigation Log** | Audit trail with status badges |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ddos` | Dashboard HTML |
| GET | `/api/ddos/status` | Current scores per interface |
| GET | `/api/ddos/history` | Composite score timeline |
| GET | `/api/ddos/breakdown` | Metric z-score breakdown |
| GET | `/api/ddos/baselines` | Seasonal baselines (168 buckets) |
| GET | `/api/ddos/metrics/{iface}` | Current vs baseline table data |
| POST | `/api/ddos/mitigation/toggle` | Enable/disable auto-mitigation |
| POST | `/api/ddos/mitigation/rollback` | Manual rollback all |

---

## Activation Checklist

Before enabling in production:

- [ ] **Test in lab** with traffic generator (iperf3, hping3)
- [ ] **Verify baselines** stabilize after 7-day warmup
- [ ] **Tune weights** for your traffic profile
- [ ] **Set profile** (start with `conservative` for production)
- [ ] **Keep `DDOS_DRY_RUN=true`** for first 30 days
- [ ] **Review alerts** in dashboard + Telegram for false positives
- [ ] **Test rollback** manually via dashboard button
- [ ] **Only then**: `DDOS_DRY_RUN=false` + `DDOS_AUTOMITIGATE=true`

---

## Files Summary

### New Files
```
app/
├── ddos_detector.py          # Core detection engine
├── connection_tracking.py    # RouterOS connection tracking collector
├── mitigation.py             # Auto-mitigation executor (L1-L4)
├── templates/
│   ├── base.html             # Shared layout with nav tabs
│   └── ddos.html             # DDoS dashboard
└── static/
    └── ddos.js               # Chart.js dashboard logic
```

### Modified Files
```
app/
├── database.py               # + ddos_baselines, ddos_scores, connection_tracking, mitigation_actions
├── main.py                   # + Settings, routes, API, detector integration
└── templates/dashboard.html  # extends base.html
```

---

## Next Steps (Phase 2+)

| Phase | Description |
|-------|-------------|
| **2A** | Per-router-model tuning profiles (CRS, CCR, RB series) |
| **2B** | L7 detection integration (Suricata/Zeek via Unix socket) |
| **2C** | Threat intel feed → address-list blocking |
| **2D** | Multi-router correlation (centralized detector) |
| **2E** | ML-based anomaly (Isolation Forest on metric vectors) |