'use strict';

/**
 * ndpi-dashboard.js
 * Client-side logic for the LuCI nDPI Deep Packet Inspection dashboard.
 * Uses window.NDPI_API_BASE injected by the Lua template (includes stok token).
 */

// ---------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------
var REFRESH_INTERVAL = 5000;
var MAX_CHART_POINTS = 60;
var ALERT_LIMIT = 50;

// ---------------------------------------------------------------
// State
// ---------------------------------------------------------------
var refreshTimer = null;
var trafficHistory = { labels: [], rx: [], tx: [] };
var currentTab = 'dashboard';

// ---------------------------------------------------------------
// API helper — uses the base URL injected by the Lua template
// which already contains the proper stok CSRF token.
// ---------------------------------------------------------------
function apiCall(endpoint) {
    var base = window.NDPI_API_BASE || '';
    if (!base) {
        return Promise.resolve({});
    }
    var url = base + '/' + endpoint;

    return new Promise(function(resolve) {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.timeout = 15000;
        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    resolve(JSON.parse(xhr.responseText));
                } catch (e) {
                    resolve({});
                }
            } else {
                resolve({});
            }
        };
        xhr.onerror = function() { resolve({}); };
        xhr.ontimeout = function() { resolve({}); };
        xhr.send();
    });
}

// ---------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------
function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    var k = 1024;
    var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    if (i < 0) i = 0;
    if (i >= sizes.length) i = sizes.length - 1;
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    if (!seconds || seconds <= 0) return 'N/A';
    var d = Math.floor(seconds / 86400);
    var h = Math.floor((seconds % 86400) / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    var s = seconds % 60;
    var parts = [];
    if (d > 0) parts.push(d + 'd');
    if (h > 0) parts.push(h + 'h');
    if (m > 0) parts.push(m + 'm');
    parts.push(s + 's');
    return parts.join(' ');
}

function formatTimestamp() {
    return new Date().toLocaleTimeString();
}

function formatNumber(n) {
    if (!n && n !== 0) return '0';
    return Number(n).toLocaleString();
}

// ---------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------
function $(id) { return document.getElementById(id); }

function setText(id, text) {
    var el = $(id);
    if (el) el.textContent = text;
}

function setHTML(id, html) {
    var el = $(id);
    if (el) el.innerHTML = html;
}

// ---------------------------------------------------------------
// Tab navigation
// ---------------------------------------------------------------
function switchTab(tabName) {
    currentTab = tabName;
    document.querySelectorAll('.ndpi-tab-btn').forEach(function(btn) {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    document.querySelectorAll('.ndpi-tab-panel').forEach(function(panel) {
        panel.hidden = panel.id !== 'tab-' + tabName;
    });
    refreshData();
}

// ---------------------------------------------------------------
// Service control — Start / Stop / Restart
// ---------------------------------------------------------------
function serviceAction(action) {
    var btn = $('btn-' + action);
    if (btn) {
        btn.disabled = true;
        btn.classList.add('ndpi-btn-loading');
    }

    apiCall(action).then(function() {
        setTimeout(function() {
            refreshData();
            if (btn) {
                btn.disabled = false;
                btn.classList.remove('ndpi-btn-loading');
            }
        }, 2000);
    });
}

// ---------------------------------------------------------------
// Dashboard: update status KPI cards
// ---------------------------------------------------------------
function updateStatus(data) {
    if (!data) return;

    var running = data.running;
    var badge = $('status-badge');
    if (badge) {
        badge.textContent = running ? 'Running' : 'Stopped';
        badge.className = 'ndpi-badge ' + (running ? 'ndpi-badge-ok' : 'ndpi-badge-err');
    }
    setText('status-pid', running ? (data.pid || 'N/A') : 'N/A');
    setText('status-uptime', running ? formatUptime(data.uptime) : 'N/A');
    setText('status-memory', running ? formatBytes((data.memory_rss || 0) * 1024) : 'N/A');

    // Update button states
    var startBtn = $('btn-start');
    var stopBtn = $('btn-stop');
    if (startBtn) startBtn.style.display = running ? 'none' : '';
    if (stopBtn)  stopBtn.style.display  = running ? '' : 'none';

    // Also update system memory if included in the response
    if (data.system_memory) {
        updateSystemMemory(data.system_memory);
    }
}

function updateSystemMemory(mem) {
    if (!mem) return;

    var total = mem.total || 0;
    var available = mem.available || 0;
    var used = total - available;
    var pct = total > 0 ? Math.round((used / total) * 100) : 0;

    setText('sys-mem-total', formatBytes(total * 1024));
    setText('sys-mem-used', formatBytes(used * 1024));
    setText('sys-mem-pct', pct + '%');

    var bar = $('sys-mem-bar');
    if (bar) {
        bar.style.width = pct + '%';
        bar.className = 'ndpi-progress-fill' +
            (pct > 90 ? ' critical' : pct > 70 ? ' warning' : '');
    }
}

function updateInterfaceStats(stats) {
    if (!stats || stats.error) return;

    setText('iface-name', stats.interface || 'N/A');
    setText('iface-rx', formatBytes(stats.rx_bytes || 0));
    setText('iface-tx', formatBytes(stats.tx_bytes || 0));
    setText('iface-rx-pkt', formatNumber(stats.rx_packets));
    setText('iface-tx-pkt', formatNumber(stats.tx_packets));

    // Update traffic history for the rate chart
    trafficHistory.labels.push(formatTimestamp());
    trafficHistory.rx.push(stats.rx_bytes || 0);
    trafficHistory.tx.push(stats.tx_bytes || 0);

    if (trafficHistory.labels.length > MAX_CHART_POINTS) {
        trafficHistory.labels.shift();
        trafficHistory.rx.shift();
        trafficHistory.tx.shift();
    }

    drawTrafficChart();
}

// ---------------------------------------------------------------
// Protocol distribution bar chart (pure DOM, no canvas needed)
// ---------------------------------------------------------------
function updateProtocolChart(data) {
    var container = $('protocol-chart');
    if (!container) return;

    // Handle both formats: plain array or { protocols: [...], source: "..." }
    var protocols = [];
    var source = '';
    if (data) {
        if (Array.isArray(data)) {
            protocols = data;
        } else if (data.protocols && Array.isArray(data.protocols)) {
            protocols = data.protocols;
            source = data.source || '';
        }
    }

    if (protocols.length === 0) {
        container.innerHTML =
            '<p class="ndpi-muted" style="padding:8px;">No protocol data yet. ' +
            'Make sure nDPI service is running and traffic is flowing.</p>';
        return;
    }

    // Sort by count descending, take top 10
    protocols.sort(function(a, b) { return (b.count || 0) - (a.count || 0); });
    var top = protocols.slice(0, 10);
    var maxCount = top[0].count || 1;

    var colors = [
        '#2563eb', '#059669', '#d97706', '#dc2626', '#7c3aed',
        '#0891b2', '#65a30d', '#c026d3', '#ea580c', '#4f46e5'
    ];

    // Source indicator
    var sourceLabel = '';
    if (source === 'dpi_snapshot') sourceLabel = 'DPI Analysis';
    else if (source === 'xt_ndpi') sourceLabel = 'Kernel Module';
    else if (source === 'conntrack') sourceLabel = 'Conntrack (L4 only)';
    else if (source) sourceLabel = source;

    var html = '';
    if (sourceLabel) {
        html += '<div style="text-align:right;margin-bottom:6px;">' +
            '<span class="ndpi-badge ' + (source === 'conntrack' ? 'ndpi-badge-warn' : 'ndpi-badge-ok') + '" ' +
            'style="font-size:10px;">' + escapeHtml(sourceLabel) + '</span></div>';
    }
    html += '<div class="ndpi-proto-bars">';
    top.forEach(function(p, i) {
        var pct = maxCount > 0 ? Math.round((p.count / maxCount) * 100) : 0;
        var label = escapeHtml(p.protocol || 'Unknown');
        var detail = formatNumber(p.count);
        if (p.bytes && p.bytes > 0) detail += ' (' + formatBytes(p.bytes) + ')';
        html += '<div class="ndpi-proto-row">' +
            '<span class="ndpi-proto-name">' + label + '</span>' +
            '<div class="ndpi-proto-bar-wrap">' +
            '<div class="ndpi-proto-bar" style="width:' + pct + '%;background:' + colors[i % colors.length] + '"></div>' +
            '</div>' +
            '<span class="ndpi-proto-count">' + detail + '</span>' +
            '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
}

// ---------------------------------------------------------------
// Traffic rate chart (canvas-based)
// ---------------------------------------------------------------
function drawTrafficChart() {
    var canvas = $('traffic-canvas');
    if (!canvas) return;

    var parent = canvas.parentElement;
    if (!parent) return;

    if (trafficHistory.rx.length < 2) {
        var ctx0 = canvas.getContext('2d');
        canvas.width = parent.clientWidth || 600;
        canvas.height = 140;
        ctx0.clearRect(0, 0, canvas.width, canvas.height);
        ctx0.fillStyle = '#f9fafb';
        ctx0.fillRect(0, 0, canvas.width, canvas.height);
        ctx0.fillStyle = '#9ca3af';
        ctx0.font = '13px system-ui, sans-serif';
        ctx0.textAlign = 'center';
        ctx0.fillText('Collecting traffic data...', canvas.width / 2, 75);
        return;
    }

    var ctx = canvas.getContext('2d');
    var w = canvas.width = parent.clientWidth || 600;
    var h = canvas.height = 140;
    var pad = { top: 10, right: 10, bottom: 24, left: 60 };
    var plotW = w - pad.left - pad.right;
    var plotH = h - pad.top - pad.bottom;

    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = '#f9fafb';
    ctx.fillRect(0, 0, w, h);

    // Compute deltas (bytes/sec)
    var rxRate = [], txRate = [];
    for (var i = 1; i < trafficHistory.rx.length; i++) {
        var rxDelta = trafficHistory.rx[i] - trafficHistory.rx[i - 1];
        var txDelta = trafficHistory.tx[i] - trafficHistory.tx[i - 1];
        rxRate.push(Math.max(0, rxDelta) / (REFRESH_INTERVAL / 1000));
        txRate.push(Math.max(0, txDelta) / (REFRESH_INTERVAL / 1000));
    }

    if (rxRate.length === 0) return;

    var allVals = rxRate.concat(txRate);
    var maxVal = Math.max(1, Math.max.apply(null, allVals));

    // Grid lines
    ctx.strokeStyle = '#e5e7eb';
    ctx.lineWidth = 1;
    for (var g = 0; g <= 4; g++) {
        var gy = pad.top + plotH - (g / 4) * plotH;
        ctx.beginPath();
        ctx.moveTo(pad.left, gy);
        ctx.lineTo(w - pad.right, gy);
        ctx.stroke();

        ctx.fillStyle = '#6b7280';
        ctx.font = '10px system-ui, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(formatBytes(maxVal * g / 4) + '/s', pad.left - 4, gy + 3);
    }

    function drawLine(data, color) {
        if (data.length < 2) return;
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.lineJoin = 'round';
        data.forEach(function(val, idx) {
            var x = pad.left + (idx / (data.length - 1)) * plotW;
            var y = pad.top + plotH - (val / maxVal) * plotH;
            if (idx === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();
    }

    drawLine(rxRate, '#2563eb');
    drawLine(txRate, '#059669');

    // Legend
    ctx.font = '11px system-ui, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillStyle = '#2563eb';
    ctx.fillText('RX', pad.left, h - 5);
    ctx.fillStyle = '#059669';
    ctx.fillText('TX', pad.left + 55, h - 5);

    var latestRx = rxRate[rxRate.length - 1] || 0;
    var latestTx = txRate[txRate.length - 1] || 0;
    ctx.fillStyle = '#2563eb';
    ctx.fillText(formatBytes(latestRx) + '/s', pad.left + 90, h - 5);
    ctx.fillStyle = '#059669';
    ctx.fillText(formatBytes(latestTx) + '/s', pad.left + 200, h - 5);
}

// ---------------------------------------------------------------
// Flows table
// ---------------------------------------------------------------
function updateFlows(flowData) {
    var container = $('flow-table-body');
    if (!container) return;

    var flows = [];
    var source = '';
    if (flowData) {
        if (Array.isArray(flowData.flows)) flows = flowData.flows;
        else if (Array.isArray(flowData)) flows = flowData;
        source = flowData.source || '';
    }

    if (flows.length === 0) {
        var msg = 'No active flows detected.';
        if (!source || source === 'none') {
            msg += ' DPI snapshot initializing — data appears on next refresh.';
        }
        container.innerHTML = '<tr><td colspan="7" class="ndpi-muted">' + msg + '</td></tr>';
        setText('flow-count', '0');
        return;
    }

    setText('flow-count', flows.length.toString());

    var html = '';
    flows.slice(0, 100).forEach(function(f) {
        html += '<tr>' +
            '<td class="ndpi-mono">' + escapeHtml(f.src_ip || f.src || f['src.ip'] || '') + '</td>' +
            '<td class="ndpi-mono">' + escapeHtml(f.dst_ip || f.dst || f['dst.ip'] || '') + '</td>' +
            '<td>' + escapeHtml(f.protocol || f.detected_protocol || f['detected.protocol.name'] || 'unknown') + '</td>' +
            '<td>' + escapeHtml(f.src_port || f['src.port'] || '') + '</td>' +
            '<td>' + escapeHtml(f.dst_port || f['dst.port'] || '') + '</td>' +
            '<td>' + formatBytes(f.bytes || f['flow.bytes'] || 0) + '</td>' +
            '<td>' + formatNumber(f.packets || f['flow.packets'] || 0) + '</td>' +
            '</tr>';
    });
    container.innerHTML = html;
}

// ---------------------------------------------------------------
// Alerts table
// ---------------------------------------------------------------
function updateAlerts(alertData) {
    var container = $('alert-table-body');
    if (!container) return;

    var alerts = [];
    if (alertData) {
        if (Array.isArray(alertData.alerts)) alerts = alertData.alerts;
        else if (Array.isArray(alertData)) alerts = alertData;
    }

    if (alerts.length === 0) {
        container.innerHTML = '<tr><td colspan="3" class="ndpi-muted">No alerts recorded</td></tr>';
        setText('alert-count', '0');
        return;
    }

    setText('alert-count', alerts.length.toString());

    var html = '';
    alerts.slice(-ALERT_LIMIT).reverse().forEach(function(a, i) {
        var msg = a.message || '';
        var severity = 'info';
        if (/error|critical|fail/i.test(msg)) severity = 'error';
        else if (/warn/i.test(msg)) severity = 'warning';

        html += '<tr>' +
            '<td>' + (i + 1) + '</td>' +
            '<td><span class="ndpi-severity ndpi-severity-' + severity + '">' + severity + '</span></td>' +
            '<td>' + escapeHtml(msg) + '</td>' +
            '</tr>';
    });
    container.innerHTML = html;
}

// ---------------------------------------------------------------
// Live traffic / connections
// ---------------------------------------------------------------
function updateConnections(data) {
    var container = $('conn-table-body');
    if (!container) return;

    var conns = [];
    if (data) {
        if (Array.isArray(data.connections)) conns = data.connections;
        else if (Array.isArray(data)) conns = data;
    }

    if (conns.length === 0) {
        container.innerHTML = '<tr><td colspan="4" class="ndpi-muted">No active connections</td></tr>';
        return;
    }

    var html = '';
    conns.slice(0, 50).forEach(function(c) {
        var proto = c.protocol || '';
        var src = c.src || '';
        var dst = c.dst || '';
        var state = c.state || '';

        // Fallback: parse from raw if structured fields are missing
        if (!proto && c.raw) {
            var raw = c.raw;
            var parts = raw.split(/\s+/);
            if (parts.length > 2) proto = parts[2] || '';
            var srcMatch = raw.match(/src=(\S+)/);
            var dstMatch = raw.match(/dst=(\S+)/);
            if (srcMatch && !src) src = srcMatch[1];
            if (dstMatch && !dst) dst = dstMatch[1];
            var stateMatch = raw.match(/\b(ESTABLISHED|TIME_WAIT|SYN_SENT|SYN_RECV|FIN_WAIT|CLOSE|CLOSE_WAIT|LAST_ACK|LISTEN)\b/);
            if (stateMatch && !state) state = stateMatch[1];
        }

        if (proto || src || dst) {
            html += '<tr>' +
                '<td>' + escapeHtml(proto) + '</td>' +
                '<td class="ndpi-mono">' + escapeHtml(src) + '</td>' +
                '<td class="ndpi-mono">' + escapeHtml(dst) + '</td>' +
                '<td>' + (state ? '<span class="ndpi-badge ndpi-badge-ok">' + escapeHtml(state) + '</span>' : '') + '</td>' +
                '</tr>';
        }
    });
    container.innerHTML = html;
}

// ---------------------------------------------------------------
// Utility
// ---------------------------------------------------------------
function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                       .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------
// Master refresh — fetches all data via controller API
// ---------------------------------------------------------------
function refreshData() {
    setText('last-refresh', formatTimestamp());

    // Status (includes system_memory)
    apiCall('status').then(updateStatus);

    // Interface stats
    apiCall('interface_stats').then(updateInterfaceStats);

    // Tab-specific data
    if (currentTab === 'dashboard') {
        apiCall('protocols').then(updateProtocolChart);
    }
    if (currentTab === 'flows' || currentTab === 'dashboard') {
        apiCall('flows').then(updateFlows);
    }
    if (currentTab === 'alerts') {
        apiCall('alerts_data').then(updateAlerts);
    }
    if (currentTab === 'traffic') {
        apiCall('traffic').then(updateConnections);
    }
}

function startAutoRefresh() {
    refreshData();
    refreshTimer = setInterval(refreshData, REFRESH_INTERVAL);
}

function stopAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}

// ---------------------------------------------------------------
// Init
// ---------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    // Tab click handlers
    document.querySelectorAll('.ndpi-tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            switchTab(this.dataset.tab);
        });
    });

    // Service control buttons
    var startBtn = $('btn-start');
    var stopBtn = $('btn-stop');
    var restartBtn = $('btn-restart');

    if (startBtn) startBtn.addEventListener('click', function() { serviceAction('start'); });
    if (stopBtn)  stopBtn.addEventListener('click',  function() { serviceAction('stop'); });
    if (restartBtn) restartBtn.addEventListener('click', function() { serviceAction('restart'); });

    // Start polling
    startAutoRefresh();
});

// Clean up on page unload
window.addEventListener('beforeunload', stopAutoRefresh);
