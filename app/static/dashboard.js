// NetGuard Monit Dashboard JavaScript
// Loaded from /static/dashboard.js - allowed by CSP

const API_BASE = '/api';
const POLL_INTERVAL_MS = 5000;

let trafficChart = null;
let currentInterface = null;
let pingChart = null;
let currentPingTarget = null;

/**
 * Display a timestamp already expressed in the configured local timezone
 * (APP_TIMEZONE, default Asia/Jakarta). The backend converts UTC -> local,
 * so we only reformat the wall-clock components and never shift again.
 *
 * Accepts: "2026-11-09T20:36:00+07:00" (ISO with offset) or "2026-11-09 20:36" (bucket).
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

function startLiveClock() {
    const clockEl = document.getElementById('live-clock');
    if (!clockEl) return;
    const tick = () => {
        const now = new Date();
        const pad = (n) => String(n).padStart(2, '0');
        const options = { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' };
        const dateStr = now.toLocaleDateString('id-ID', options);
        clockEl.textContent = `${dateStr} · ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    };
    tick();
    setInterval(tick, 1000);
}

document.addEventListener('DOMContentLoaded', async () => {
    // Convert all server-rendered UTC timestamps to local time
    convertUtcToLocal();
    startLiveClock();

    const ifaceSelect = document.getElementById('interface-select');
    const granSelect = document.getElementById('granularity-select');
    const rangeSelect = document.getElementById('range-select');

    if (ifaceSelect) {
        currentInterface = ifaceSelect.value || null;
        ifaceSelect.addEventListener('change', (e) => {
            currentInterface = e.target.value;
            initChart();
        });
    }
    if (granSelect) {
        granSelect.addEventListener('change', () => initChart());
    }
    if (rangeSelect) {
        rangeSelect.addEventListener('change', () => initChart());
    }

    // Inisialisasi kedua graph secara bersamaan (sinkron)
    await Promise.all([initChart(), initPingChart()]);
    setInterval(updateDashboard, POLL_INTERVAL_MS);
});

/**
 * Find all elements with data-utc attribute and convert to local time
 * Usage in template: <span data-utc="{{ telemetry.observed_at }}">{{ telemetry.observed_at }}</span>
 */
function convertUtcToLocal() {
    document.querySelectorAll('[data-utc]').forEach(el => {
        const utc = el.getAttribute('data-utc');
        if (utc) {
            el.textContent = formatLocalTime(utc, true);
        }
    });
}

async function initChart() {
    if (!currentInterface) return;
    const gran = document.getElementById('granularity-select').value;
    const range = document.getElementById('range-select').value;
    const data = await fetchTraffic(currentInterface, gran, range);
    if (data) {
        renderTrafficChart(data, gran);
    }
    updateStatus();
}

async function fetchTraffic(iface, granularity, rangeHours) {
    try {
        const res = await fetch(`${API_BASE}/interfaces/${encodeURIComponent(iface)}/traffic?granularity=${granularity}&range_hours=${rangeHours}`, { credentials: 'include' });
        if (!res.ok) return null;
        const data = await res.json();
        return data;
    } catch (err) {
        console.error('Error fetching traffic:', err);
        return null;
    }
}

/**
 * Extract just the HH:MM:SS time portion from a bucket string like
 * "2026-11-10 15:14:00" so the X-axis stays readable.
 */
function bucketToTimeLabel(bucket) {
    if (!bucket) return '';
    const s = String(bucket);
    // Ambil HH:MM:SS jika ada, fallback HH:MM
    const match = s.match(/(\d{2}:\d{2}:\d{2})/);
    if (match) return match[1];
    const match2 = s.match(/(\d{2}:\d{2})/);
    return match2 ? match2[0] : s;
}

function renderTrafficChart(points, granularity) {
    const ctx = document.getElementById('trafficChart');
    if (!ctx) return;

    const isSecond = granularity === 'second';
    // Batasi jumlah poin yang ditampilkan agar Chart.js tidak overload
    // dan data terbaru selalu ada di ujung kanan graph.
    const MAX_POINTS = 200;
    const trimmed = points && points.length > MAX_POINTS ? points.slice(-MAX_POINTS) : points || [];

    const labels = trimmed.map(p => bucketToTimeLabel(p.bucket));
    const rx = trimmed.map(p => p.avg_rx_bps);
    const tx = trimmed.map(p => p.avg_tx_bps);

    const pointCount = labels.length;

    if (trafficChart) {
        trafficChart.data.labels = labels;
        trafficChart.data.datasets[0].data = rx;
        trafficChart.data.datasets[1].data = tx;
        const tickLimit = pointCount <= 120 ? pointCount : 120;
        trafficChart.options.scales.x.ticks.autoSkip = true;
        trafficChart.options.scales.x.ticks.maxTicksLimit = tickLimit;
        trafficChart.options.scales.x.ticks.font = { size: 8 };
        trafficChart.update();
        return;
    }

    trafficChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'RX (bps)',
                    data: rx,
                    borderColor: '#50d3a7',
                    backgroundColor: 'rgba(80, 211, 167, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                },
                {
                    label: 'TX (bps)',
                    data: tx,
                    borderColor: '#ffc36a',
                    backgroundColor: 'rgba(255, 195, 106, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    display: true,
                    title: { display: true, text: 'Waktu' },
                    ticks: {
                        autoSkip: true,
                        maxTicksLimit: pointCount <= 120 ? pointCount : 120,
                        maxRotation: 45,
                        minRotation: 45,
                        font: { size: 8 },
                    },
                },
                y: {
                    display: true,
                    title: { display: true, text: 'bits per detik' },
                    beginAtZero: true,
                },
            },
            plugins: {
                legend: { position: 'top' },
                title: { display: false },
            },
        },
    });
}

async function initPingChart() {
    const targetSelect = document.getElementById('ping-target-select');
    const granSelect = document.getElementById('ping-granularity-select');
    const rangeSelect = document.getElementById('ping-range-select');
    if (!targetSelect) return;
    currentPingTarget = targetSelect.value || null;
    targetSelect.addEventListener('change', async (e) => {
        currentPingTarget = e.target.value || null;
        const result = await fetchPingHistory(currentPingTarget);
        if (result) {
            renderPingChart(result.data, result.target, result.granularity);
        }
    });
    if (granSelect) {
        granSelect.addEventListener('change', async () => {
            const result = await fetchPingHistory(currentPingTarget);
            if (result) {
                renderPingChart(result.data, result.target, result.granularity);
            }
        });
    }
    if (rangeSelect) {
        rangeSelect.addEventListener('change', async () => {
            const result = await fetchPingHistory(currentPingTarget);
            if (result) {
                renderPingChart(result.data, result.target, result.granularity);
            }
        });
    }
    const initial = await fetchPingHistory(currentPingTarget);
    if (initial) {
        renderPingChart(initial.data, initial.target, initial.granularity);
    }
}

async function fetchPingHistory(target) {
    if (!target) return null;

    const granSelect = document.getElementById('ping-granularity-select');
    const rangeSelect = document.getElementById('ping-range-select');
    const granularity = granSelect ? granSelect.value : 'second';
    const rangeHours = rangeSelect ? rangeSelect.value : 24;

    try {
        const res = await fetch(`${API_BASE}/ping/history?target=${encodeURIComponent(target)}&granularity=${granularity}&range_hours=${rangeHours}`, { credentials: 'include' });
        if (!res.ok) return null;
        const data = await res.json();
        return { data, target, granularity };
    } catch (err) {
        console.error('Error fetching ping history:', err);
        return null;
    }
}

function renderPingChart(points, target, granularity = 'second') {
    const ctx = document.getElementById('pingChart');
    if (!ctx) return;

    const isSecond = granularity === 'second';
    // Batasi jumlah poin yang ditampilkan agar Chart.js tidak overload
    // dan data terbaru selalu ada di ujung kanan graph.
    const MAX_POINTS = 200;
    const trimmed = points && points.length > MAX_POINTS ? points.slice(-MAX_POINTS) : points || [];

    const labels = trimmed.map(p => bucketToTimeLabel(p.observed_at));
    const avg = trimmed.map(p => p.avg_latency_ms ?? null);
    const min = trimmed.map(p => p.min_latency_ms ?? null);
    const max = trimmed.map(p => p.max_latency_ms ?? null);
    const loss = trimmed.map(p => p.packet_loss_percent ?? 0);

    const pointCount = labels.length;

    if (pingChart) {
        pingChart.data.labels = labels;
        pingChart.data.datasets[0].data = avg;
        pingChart.data.datasets[1].data = min;
        pingChart.data.datasets[2].data = max;
        pingChart.data.datasets[3].data = loss.map(v => v > 0 ? v : null);
        const tickLimit = pointCount <= 120 ? pointCount : 120;
        pingChart.options.scales.x.ticks.autoSkip = true;
        pingChart.options.scales.x.ticks.maxTicksLimit = tickLimit;
        pingChart.options.scales.x.ticks.font = { size: 8 };
        pingChart.update();
        return;
    }

    pingChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Avg Latency (ms)',
                    data: avg,
                    borderColor: '#50d3a7',
                    backgroundColor: 'rgba(80, 211, 167, 0.15)',
                    fill: false,
                    tension: 0.3,
                    pointRadius: 1,
                    pointHoverRadius: 4,
                    borderWidth: 2,
                },
                {
                    label: 'Min Latency (ms)',
                    data: min,
                    borderColor: '#4fa3d3',
                    backgroundColor: 'rgba(79, 163, 211, 0.1)',
                    fill: '-1',
                    tension: 0.3,
                    pointRadius: 0,
                    borderWidth: 1,
                    borderDash: [4, 4],
                },
                {
                    label: 'Max Latency (ms)',
                    data: max,
                    borderColor: '#ffc36a',
                    backgroundColor: 'rgba(255, 195, 106, 0.1)',
                    fill: '+1',
                    tension: 0.3,
                    pointRadius: 0,
                    borderWidth: 1,
                    borderDash: [4, 4],
                },
                {
                    label: 'Packet Loss (%)',
                    data: loss.map(v => v > 0 ? v : null),
                    borderColor: '#ff7d83',
                    backgroundColor: 'rgba(255, 125, 131, 0.15)',
                    fill: false,
                    tension: 0.3,
                    pointRadius: 3,
                    pointBackgroundColor: '#ff7d83',
                    borderWidth: 2,
                    borderDash: [6, 4],
                    yAxisID: 'loss',
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            scales: {
                x: {
                    display: true,
                    title: { display: true, text: 'Waktu' },
                    ticks: {
                        autoSkip: true,
                        maxTicksLimit: pointCount <= 120 ? pointCount : 120,
                        maxRotation: 45,
                        minRotation: 45,
                        font: { size: 8 },
                    },
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: { display: true, text: 'Latency (ms)' },
                    beginAtZero: true,
                    suggestedMin: 0,
                },
                loss: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: { display: true, text: 'Packet Loss (%)' },
                    min: 0,
                    max: 100,
                    grid: { drawOnChartArea: false },
                    ticks: { color: '#ff7d83' },
                    title: { color: '#ff7d83' },
                },
            },
            plugins: {
                legend: { position: 'top' },
                title: { display: false },
            },
        },
    });
}

async function updateStatus() {
    try {
        const res = await fetch(`${API_BASE}/telemetry/latest`, { credentials: 'include' });
        if (!res.ok) return;
        const t = await res.json();
        if (t.status === 'no_data') return;

        const dot = document.querySelector('.status-dot');
        const text = document.querySelector('.status-line strong');
        if (dot && text) {
            dot.className = `status-dot ${t.router_up ? 'up' : 'down'}`;
            text.textContent = t.router_up ? 'Router terhubung' : 'Router tidak terhubung';
        }

        // Update interface metrics
        const ifaceRes = await fetch(`${API_BASE}/interfaces`, { credentials: 'include' });
        if (ifaceRes.ok) {
            const ifaces = await ifaceRes.json();
            const current = ifaces.find(i => i.name === currentInterface);
            if (current) {
                document.getElementById('stat-rx-bps').textContent = formatBps(current.rx_bps);
                document.getElementById('stat-tx-bps').textContent = formatBps(current.tx_bps);
                document.getElementById('stat-status').textContent = current.status;
                document.getElementById('stat-updated').textContent = formatLocalTime(current.observed_at, true);
                document.getElementById('stat-status').className = `stat-value ${current.status === 'up' ? 'status-up' : 'status-down'}`;
            }
        }
    } catch (err) {
        console.error('Error updating status:', err);
    }
}

async function updateDashboard() {
    const granularity = document.getElementById('granularity-select')?.value;
    const rangeHours = document.getElementById('range-select')?.value;
    const refreshTraffic = currentInterface && granularity && rangeHours
        ? fetchTraffic(currentInterface, granularity, rangeHours)
        : Promise.resolve(null);

    const pingGranularity = document.getElementById('ping-granularity-select')?.value;
    const pingRangeHours = document.getElementById('ping-range-select')?.value;
    const refreshPing = currentPingTarget && pingGranularity && pingRangeHours
        ? fetchPingHistory(currentPingTarget)
        : Promise.resolve(null);

    await updateStatus();

    // Tunggu keduanya selesai, baru render kedua chart sekaligus agar sinkron
    const [trafficData, pingResult] = await Promise.all([refreshTraffic, refreshPing]);

    if (trafficData) {
        renderTrafficChart(trafficData, granularity);
    }
    if (pingResult) {
        renderPingChart(pingResult.data, pingResult.target, pingResult.granularity);
    }

    // Tandai sinkronisasi: traffic dan ping di-update dalam satu siklus yang sama
    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const syncTime = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    const syncEl = document.getElementById('sync-status');
    const syncLastEl = document.getElementById('sync-last-updated');
    if (syncEl) syncEl.textContent = 'Aktif (5 detik)';
    if (syncLastEl) syncLastEl.textContent = `Terakhir diperbarui: ${syncTime}`;
}


function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text ?? '';
    return div.innerHTML;
}