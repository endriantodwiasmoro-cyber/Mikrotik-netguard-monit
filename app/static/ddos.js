// NetGuard Monit DDoS Detection Dashboard JavaScript
// Loaded from /static/ddos.js - allowed by CSP

const API_BASE = '/api';
const POLL_INTERVAL_MS = 5000;

let scoreChart = null;
let breakdownChart = null;
let baselineChart = null;
let currentInterface = null;
let currentProfile = 'balanced';
let weights = { bps: 0.30, pps: 0.25, drops: 0.15, newconn: 0.20, synratio: 0.10 };
let mitigationEnabled = false;

/**
 * Display a timestamp already expressed in the configured local timezone
 * (APP_TIMEZONE, default Asia/Jakarta). The backend converts UTC -> local,
 * so we only reformat the wall-clock components and never shift again.
 */
function formatLocalTime(value, showDate = false) {
    if (!value) return '—';
    const match = String(value).match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?/);
    if (!match) return value;
    const [, year, month, day, hour, minute, second] = match;
    const time = second ? `${hour}:${minute}:${second}` : `${hour}:${minute}`;
    return showDate ? `${day}/${month}/${year} ${time}` : time;
}

/**
 * Bucket labels come from the API already in local time; show them verbatim.
 */
function formatChartTime(bucket) {
    return bucket || '';
}

// Series colors (fixed order, validated palette)
const seriesColors = {
  bps: '#1971c2',       // Blue - Volume
  pps: '#40c057',       // Green - Packet Rate
  drops: '#f08c00',     // Orange - Drops
  newconn: '#e64980',   // Pink - New Connections
  synratio: '#7048e8'   // Purple - SYN Ratio
};

const statusColors = {
  normal: '#1971c2',
  elevated: '#f08c00',
  warning: '#f08c00',
  critical: '#c92a2a',
  recovering: '#1971c2'
};

function getScoreState(score) {
  if (score >= 4.0) return 'critical';
  if (score >= 3.0) return 'warning';
  if (score >= 2.0) return 'elevated';
  if (score >= 1.0) return 'recovering';
  return 'normal';
}

function getZScoreClass(z) {
  if (z >= 4) return 'z-critical';
  if (z >= 3) return 'z-warning';
  if (z >= 2) return 'z-elevated';
  return 'z-normal';
}

function formatBps(bps) {
  if (!bps && bps !== 0) return '—';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  let num = Number(bps);
  let i = 0;
  while (num >= 1000 && i < units.length - 1) {
    num /= 1000;
    i++;
  }
  return num.toFixed(1) + ' ' + units[i];
}

function formatNumber(num, unit) {
  if (unit === 'bps') return formatBps(num);
  if (unit === 'pps') return num.toLocaleString() + ' pps';
  if (unit === 'ratio') return num.toFixed(2);
  return num.toLocaleString() + ' ' + unit;
}

// ===== Gauge Rendering =====
function renderGauges(interfaces, scores) {
  const container = document.getElementById('gaugeGrid');
  if (!container) return;

  container.innerHTML = interfaces.map(iface => {
    const score = scores[iface.name] ?? 0;
    const state = getScoreState(score);
    const badgeClass = `badge-${state}`;
    const circumference = 2 * Math.PI * 54;
    const offset = circumference * (1 - Math.min(score / 5, 1));

    return `
      <div class="gauge-card">
        <div class="iface-name">${iface.name}</div>
        <div class="gauge-wrapper">
          <svg width="130" height="130" style="transform: rotate(-90deg);">
            <circle cx="65" cy="65" r="54" fill="none" stroke="var(--line)" stroke-width="8"/>
            <circle cx="65" cy="65" r="54" fill="none" stroke="${statusColors[state]}" stroke-width="8"
              stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
              stroke-linecap="round" style="transition: stroke-dashoffset 500ms ease;"/>
          </svg>
          <div class="gauge-value" style="color:${statusColors[state]}">${score.toFixed(1)}</div>
        </div>
        <div class="gauge-label">Skor Komposit</div>
        <span class="badge ${badgeClass}">${state.toUpperCase()}</span>
        <div class="gauge-thresholds">
          <div class="threshold"><span class="threshold-dot" style="background:var(--status-warning);"></span>Warn ≥3.0</div>
          <div class="threshold"><span class="threshold-dot" style="background:var(--status-critical);"></span>Crit ≥4.0</div>
        </div>
      </div>
    `;
  }).join('');
}

// ===== Composite Score Chart =====
async function renderScoreChart(iface, granularity, rangeHours) {
  const ctx = document.getElementById('scoreChart');
  if (!ctx) return;

  try {
    const res = await fetch(`${API_BASE}/ddos/history?interface=${encodeURIComponent(iface)}&granularity=${granularity}&range_hours=${rangeHours}`);
    if (!res.ok) throw new Error('Failed to fetch');
    const data = await res.json();

    const labels = data.map(p => formatChartTime(p.bucket));
    const scores = data.map(p => p.composite_score);
    const lastScore = scores[scores.length - 1] ?? 0;
    const state = getScoreState(lastScore);

    // Gradient for area under curve
    const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 320);
    gradient.addColorStop(0, 'rgba(25,113,194,0.25)');
    gradient.addColorStop(1, 'rgba(25,113,194,0)');

    if (scoreChart) {
      scoreChart.data.labels = labels;
      scoreChart.data.datasets[0].data = scores;
      scoreChart.data.datasets[1].data = labels.map(() => 3.0);
      scoreChart.data.datasets[2].data = labels.map(() => 4.0);
      scoreChart.update('none');
      return;
    }

    scoreChart = new Chart(ctx.getContext('2d'), {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Skor Komposit',
            data: scores,
            borderColor: seriesColors.bps,
            backgroundColor: gradient,
            borderWidth: 2,
            pointRadius: 0,
            pointHoverRadius: 5,
            tension: 0.3,
            fill: true,
            clip: 20
          },
          {
            label: 'Warning Threshold (3.0)',
            data: labels.map(() => 3.0),
            borderColor: 'rgba(240,140,0,0.5)',
            borderWidth: 1,
            borderDash: [6, 4],
            pointRadius: 0,
            fill: false,
            clip: 20
          },
          {
            label: 'Critical Threshold (4.0)',
            data: labels.map(() => 4.0),
            borderColor: 'rgba(201,42,42,0.5)',
            borderWidth: 1,
            borderDash: [6, 4],
            pointRadius: 0,
            fill: false,
            clip: 20
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(8,17,30,0.95)',
            titleColor: '#edf4ff',
            bodyColor: '#edf4ff',
            padding: 12,
            cornerRadius: 6,
            displayColors: true,
            callbacks: {
              title: (ctx) => `Waktu: ${formatLocalTime(ctx[0].label, true)}`,
              label: (ctx) => {
                if (ctx.datasetIndex === 0) {
                  const score = ctx.parsed.y;
                  const state = getScoreState(score);
                  return [`Skor Komposit: ${score.toFixed(2)}`, `State: ${state.toUpperCase()}`];
                }
                return `${ctx.dataset.label}: ${ctx.parsed.y.toFixed(1)}`;
              }
            }
          },
          annotation: {
            annotations: {
              warningZone: {
                type: 'box',
                yMin: 3, yMax: 4,
                backgroundColor: 'rgba(240,140,0,0.08)',
                borderColor: 'rgba(240,140,0,0.2)',
                borderWidth: 1,
                borderDash: [4, 4]
              },
              criticalZone: {
                type: 'box',
                yMin: 4, yMax: 5,
                backgroundColor: 'rgba(201,42,42,0.08)',
                borderColor: 'rgba(201,42,42,0.2)',
                borderWidth: 1,
                borderDash: [4, 4]
              }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false, color: 'var(--chart-grid)' },
            ticks: { maxTicksLimit: 12, color: 'var(--chart-axis)', font: { size: 11 } }
          },
          y: {
            min: 0, max: 5,
            grid: { color: 'var(--chart-grid)', drawBorder: false },
            ticks: { stepSize: 1, color: 'var(--chart-axis)', font: { size: 11 },
              callback: (v) => v === 3 ? '3.0 (Warn)' : v === 4 ? '4.0 (Crit)' : v.toFixed(1)
            },
            title: { display: true, text: 'Skor Anomali', color: 'var(--muted)', font: { size: 11, weight: '500' } }
          }
        },
        animation: { duration: 300 }
      }
    });
  } catch (err) {
    console.error('Error rendering score chart:', err);
  }
}

// ===== Breakdown Stacked Area Chart =====
async function renderBreakdownChart(iface, granularity, rangeHours) {
  const ctx = document.getElementById('breakdownChart');
  if (!ctx) return;

  try {
    const res = await fetch(`${API_BASE}/ddos/breakdown?interface=${encodeURIComponent(iface)}&granularity=${granularity}&range_hours=${rangeHours}`);
    if (!res.ok) throw new Error('Failed to fetch');
    const data = await res.json();

    const labels = data.map(p => formatChartTime(p.bucket));
    const datasets = [
      { key: 'bps', label: 'Volume (bps)', color: seriesColors.bps },
      { key: 'pps', label: 'Packet Rate (pps)', color: seriesColors.pps },
      { key: 'drops', label: 'Drop Rate', color: seriesColors.drops },
      { key: 'newconn', label: 'New Connections', color: seriesColors.newconn },
      { key: 'synratio', label: 'SYN Ratio', color: seriesColors.synratio }
    ].map((d, i) => ({
      label: d.label,
      data: data.map(p => p[d.key] ?? 0),
      backgroundColor: d.color + '80',
      borderColor: d.color,
      borderWidth: 1.5,
      fill: true,
      tension: 0.3,
      pointRadius: 0,
      clip: 20,
      stack: 'metrics'
    }));

    if (breakdownChart) {
      breakdownChart.data.labels = labels;
      datasets.forEach((d, i) => { breakdownChart.data.datasets[i].data = d.data; });
      breakdownChart.update('none');
      return;
    }

    breakdownChart = new Chart(ctx.getContext('2d'), {
      type: 'line',
      data: { labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(8,17,30,0.95)',
            titleColor: '#edf4ff',
            bodyColor: '#edf4ff',
            padding: 12,
            cornerRadius: 6,
            callbacks: {
              title: (ctx) => `Waktu: ${formatLocalTime(ctx[0].label, true)}`,
              label: (ctx) => `${ctx.dataset.label}: ${ctx.parsed.y.toFixed(2)}σ`
            }
          }
        },
        scales: {
          x: { grid: { display: false, color: 'var(--chart-grid)' }, ticks: { maxTicksLimit: 12, color: 'var(--chart-axis)', font: { size: 10 } } },
          y: {
            min: 0, max: 5,
            stacked: true,
            grid: { color: 'var(--chart-grid)', drawBorder: false },
            ticks: { color: 'var(--chart-axis)', font: { size: 10 } },
            title: { display: true, text: 'Z-Score Kontribusi', color: 'var(--muted)', font: { size: 10, weight: '500' } }
          }
        },
        animation: { duration: 300 }
      }
    });
  } catch (err) {
    console.error('Error rendering breakdown chart:', err);
  }
}

// ===== Metrics Table =====
async function renderMetricsTable(iface) {
  const tbody = document.querySelector('#metricsTable tbody');
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE}/ddos/metrics/${encodeURIComponent(iface)}`);
    if (!res.ok) throw new Error('Failed to fetch');
    const data = await res.json();

    if (!data.metrics || data.metrics.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px;">Tidak ada data metrik</td></tr>';
      return;
    }

    tbody.innerHTML = data.metrics.map(m => {
      const z = m.z_score ?? 0;
      const zClamped = Math.max(0, z);
      const contribution = (weights[m.key] * zClamped).toFixed(2);
      const zClass = getZScoreClass(z);
      const threshold = m.threshold ?? (m.baseline + 3 * m.stddev);

      return `
        <tr>
          <td>
            <div class="metric-name">
              <span class="metric-swatch" style="background:${seriesColors[m.key]}"></span>
              <span>${m.label}</span>
            </div>
          </td>
          <td class="current mono">${formatNumber(m.current, m.unit)}</td>
          <td class="baseline mono">${formatNumber(m.baseline, m.unit)}</td>
          <td class="baseline mono">±${formatNumber(m.stddev, m.unit)}</td>
          <td class="baseline mono">${formatNumber(threshold, m.unit)}</td>
          <td class="mono ${zClass}">${z >= 0 ? '+' : ''}${z.toFixed(2)}σ</td>
          <td class="mono contribution" style="color:${seriesColors[m.key]};">${contribution}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Error rendering metrics table:', err);
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--danger);padding:20px;">Error memuat data</td></tr>';
  }
}

// ===== Seasonal Baseline Chart =====
async function renderBaselineChart(metric) {
  const ctx = document.getElementById('baselineChart');
  if (!ctx) return;

  try {
    const res = await fetch(`${API_BASE}/ddos/baselines?metric=${metric}`);
    if (!res.ok) throw new Error('Failed to fetch');
    const data = await res.json();

    const labels = data.map((_, i) => {
      const day = Math.floor(i / 24);
      const hour = i % 24;
      return `D${day} H${hour.toString().padStart(2,'0')}`;
    });
    const baseline = data.map(d => d.baseline ?? 0);

    // Current hour marker
    const now = new Date();
    const currentHour = now.getDay() * 24 + now.getHours();

    const bgColors = baseline.map((_, i) => i === currentHour ? '#1971c2' : 'rgba(25,113,194,0.4)');
    const borderColors = baseline.map((_, i) => i === currentHour ? '#1971c2' : 'rgba(25,113,194,0.6)');
    const borderWidths = baseline.map((_, i) => i === currentHour ? 2 : 1);

    if (baselineChart) {
      baselineChart.data.labels = labels;
      baselineChart.data.datasets[0].data = baseline;
      baselineChart.data.datasets[0].backgroundColor = bgColors;
      baselineChart.data.datasets[0].borderColor = borderColors;
      baselineChart.data.datasets[0].borderWidth = borderWidths;
      baselineChart.update('none');
      return;
    }

    baselineChart = new Chart(ctx.getContext('2d'), {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: `Baseline (${metric})`,
          data: baseline,
          backgroundColor: bgColors,
          borderColor: borderColors,
          borderWidth: borderWidths,
          borderRadius: 2,
          barPercentage: 0.9,
          categoryPercentage: 0.95
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(8,17,30,0.95)',
            titleColor: '#edf4ff',
            bodyColor: '#edf4ff',
            callbacks: {
              title: (ctx) => `Hour of Week: ${ctx[0].label}`,
              label: (ctx) => {
                const val = ctx.parsed.y;
                if (metric === 'rx_bps' || metric === 'rx_pps') return `Baseline: ${formatNumber(val, metric)}`;
                if (metric === 'syn_ratio') return `Baseline: ${val.toFixed(2)}`;
                return `Baseline: ${val.toLocaleString()}`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false, color: 'var(--chart-grid)' },
            ticks: {
              maxTicksLimit: 14,
              color: 'var(--chart-axis)',
              font: { size: 9 },
              callback: (v, i) => i % 24 === 0 ? `Day ${Math.floor(i/24)}` : ''
            }
          },
          y: {
            grid: { color: 'var(--chart-grid)', drawBorder: false },
            ticks: {
              color: 'var(--chart-axis)',
              font: { size: 10 },
              callback: (v) => {
                if (metric === 'rx_bps') return (v/1e6).toFixed(0) + 'M';
                if (metric === 'rx_pps') return (v/1e3).toFixed(0) + 'k';
                return v.toLocaleString();
              }
            },
            title: { display: true, text: `Baseline ${metric}`, color: 'var(--muted)', font: { size: 10, weight: '500' } }
          }
        },
        animation: { duration: 300 }
      }
    });
  } catch (err) {
    console.error('Error rendering baseline chart:', err);
  }
}

// ===== Mitigation Log =====
async function renderMitigationLog() {
  try {
    const res = await fetch(`${API_BASE}/ddos/mitigation/history`);
    const logEl = document.getElementById('mitigationLog');
    if (!logEl) return;

    if (!res.ok) {
      logEl.innerHTML = '<p style="color:var(--muted); padding:12px;">Tidak ada log mitigasi</p>';
      return;
    }

    const history = await res.json();
    if (!history || history.length === 0) {
      logEl.innerHTML = '<p style="color:var(--muted); padding:12px;">Belum ada log mitigasi</p>';
      return;
    }

    logEl.innerHTML = history.map(action => {
      const status = action.status || 'executed';
      const iconBg = status === 'rolled_back' ? 'var(--status-warning-bg)' :
                     status === 'failed' ? 'var(--danger)' : 'var(--status-good-bg)';
      const icon = status === 'rolled_back' ? '↺' : status === 'failed' ? '✗' : '✓';
      const itemClass = `mitigation-item ${status}`;

      const metaParts = [];
      if (action.interface_name) metaParts.push(`Interface: ${action.interface_name}`);
      if (action.triggered_by_score) metaParts.push(`Skor: ${parseFloat(action.triggered_by_score).toFixed(1)}`);
      if (action.parameters) {
        try {
          const params = typeof action.parameters === 'string' ? JSON.parse(action.parameters) : action.parameters;
          if (params.description) metaParts.push(params.description);
          if (params.max_limit_bps) metaParts.push(`Limit: ${formatNumber(params.max_limit_bps, 'bps')}`);
        } catch {}
      }
      if (action.executed_at) metaParts.push(formatLocalTime(action.executed_at, true));

      return `
        <div class="${itemClass}">
          <div class="mitigation-icon" style="background:${iconBg}; color:var(--text);">${icon}</div>
          <div class="mitigation-info">
            <div class="mitigation-action">${action.action?.replace('_', ' ').toUpperCase() || action.action}</div>
            <div class="mitigation-meta">${metaParts.join(' • ')}</div>
          </div>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Error rendering mitigation log:', err);
    const logEl = document.getElementById('mitigationLog');
    if (logEl) {
      logEl.innerHTML = '<p style="color:var(--danger); padding:12px;">Error memuat log mitigasi</p>';
    }
  }
}

// Add API endpoint to get mitigation history
// This will be called from the DDoS API routes

// ===== Global Status Update =====
async function updateGlobalStatus() {
  try {
    const res = await fetch(`${API_BASE}/ddos/status`);
    if (!res.ok) return;
    const data = await res.json();

    const dot = document.getElementById('globalStatusDot');
    const text = document.getElementById('globalStatusText');
    const badge = document.getElementById('overallBadge');
    const badge2 = document.getElementById('overallBadge2');

    // Determine overall state from all interfaces
    let maxScore = 0;
    Object.values(data.interfaces || {}).forEach(iface => {
      if (iface.composite_score > maxScore) maxScore = iface.composite_score;
    });
    const state = getScoreState(maxScore);

    if (dot && text && badge && badge2) {
      dot.className = `status-dot ${state}`;
      text.textContent = state.toUpperCase();
      badge.className = `badge badge-${state}`;
      badge.textContent = state.toUpperCase();
      badge2.className = `badge badge-${state}`;
      badge2.textContent = state.toUpperCase();
    }

    // Render gauges
    const interfaces = Object.entries(data.interfaces || {}).map(([name, iface]) => ({ name, ...iface }));
    renderGauges(interfaces, Object.fromEntries(Object.entries(data.interfaces || {}).map(([k, v]) => [k, v.composite_score])));
  } catch (err) {
    console.error('Error updating global status:', err);
  }
}

// ===== Weight Update =====
function updateWeight(key, value) {
  weights[key] = parseFloat(value);
  const sum = Object.values(weights).reduce((a,b) => a+b, 0);

  const valEl = document.getElementById(`w${key.charAt(0).toUpperCase() + key.slice(1)}Val`);
  if (valEl) valEl.textContent = parseFloat(value).toFixed(2);

  const sumEl = document.getElementById('weightSum');
  if (sumEl) {
    sumEl.textContent = sum.toFixed(2);
    sumEl.className = `weight-sum ${Math.abs(sum - 1.0) < 0.01 ? 'ok' : 'warn'}`;
  }
}

// ===== Mitigation Toggle =====
async function toggleMitigation() {
  mitigationEnabled = !mitigationEnabled;
  const btn = document.getElementById('mitigationToggle');
  const rollbackBtn = document.getElementById('rollbackBtn');
  if (mitigationEnabled) {
    btn.textContent = 'Nonaktifkan Auto-Mitigasi';
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-danger');
    rollbackBtn.disabled = false;
  } else {
    btn.textContent = 'Aktifkan Auto-Mitigasi';
    btn.classList.remove('btn-danger');
    btn.classList.add('btn-primary');
    rollbackBtn.disabled = true;
  }
  try {
    await fetch(`${API_BASE}/ddos/mitigation/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
      body: JSON.stringify({ enabled: mitigationEnabled })
    });
  } catch (err) {
    console.error('Error toggling mitigation:', err);
  }
}

async function rollbackMitigation() {
  try {
    await fetch(`${API_BASE}/ddos/mitigation/rollback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() }
    });
    alert('Manual rollback triggered — all active mitigations will be reverted via RouterOS REST API.');
  } catch (err) {
    console.error('Error rolling back mitigation:', err);
    alert('Gagal rollback: ' + err.message);
  }
}

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : '';
}

// ===== Main Refresh =====
async function refreshAll() {
  const iface = document.getElementById('interfaceSelect')?.value;
  const granularity = document.getElementById('granularitySelect')?.value;
  const rangeHours = document.getElementById('rangeSelect')?.value;
  const profile = document.getElementById('profileSelect')?.value;

  if (iface) {
    currentInterface = iface;
    await Promise.all([
      updateGlobalStatus(),
      renderScoreChart(iface, granularity, rangeHours),
      renderBreakdownChart(iface, granularity, rangeHours),
      renderMetricsTable(iface),
      renderMitigationLog()
    ]);
  } else {
    await Promise.all([
      updateGlobalStatus(),
      renderMitigationLog()
    ]);
  }
}

// ===== Init =====
document.addEventListener('DOMContentLoaded', () => {
  // Initialize from template variables
  currentProfile = '{{ profile }}' || 'balanced';
  mitigationEnabled = {{ 'true' if automitigate else 'false' }};

  const ifaceSelect = document.getElementById('interfaceSelect');
  const granSelect = document.getElementById('granularitySelect');
  const rangeSelect = document.getElementById('rangeSelect');
  const profileSelect = document.getElementById('profileSelect');
  const tableIfaceSelect = document.getElementById('tableInterfaceSelect');
  const baselineMetricSelect = document.getElementById('baselineMetricSelect');

  if (ifaceSelect) {
    currentInterface = ifaceSelect.value;
    ifaceSelect.addEventListener('change', () => {
      currentInterface = ifaceSelect.value;
      refreshAll();
    });
  }
  if (granSelect) granSelect.addEventListener('change', refreshAll);
  if (rangeSelect) rangeSelect.addEventListener('change', refreshAll);
  if (profileSelect) profileSelect.addEventListener('change', () => { currentProfile = profileSelect.value; refreshAll(); });
  if (tableIfaceSelect) tableIfaceSelect.addEventListener('change', (e) => renderMetricsTable(e.target.value));
  if (baselineMetricSelect) baselineMetricSelect.addEventListener('change', (e) => renderBaselineChart(e.target.value));

  // Initial render
  refreshAll();
  renderBaselineChart('rx_bps');

  // Auto-refresh
  setInterval(refreshAll, POLL_INTERVAL_MS);
});