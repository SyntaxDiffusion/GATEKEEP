/* ===================================================================
   GATEKEEP — Utility Formatters
   Pure functions for formatting and rendering data values
   =================================================================== */

'use strict';

/**
 * Format an IP address as a styled monospace span.
 * @param {string} ip
 * @returns {string} HTML string
 */
function formatIP(ip) {
  if (!ip) return '<span class="mono" style="color:var(--text-dim)">--</span>';
  return `<span class="mono" style="color:var(--text-secondary)">${escapeHtml(ip)}</span>`;
}

/**
 * Format a MAC address with colons and a copy button.
 * @param {string} mac
 * @returns {string} HTML string
 */
function formatMAC(mac) {
  if (!mac) return '<span class="mono" style="color:var(--text-dim)">--:--:--:--:--:--</span>';

  // Normalize: insert colons if missing
  const cleaned = mac.replace(/[^a-fA-F0-9]/g, '');
  const formatted = cleaned.match(/.{1,2}/g)?.join(':') || mac;
  const display = formatted.toUpperCase();

  return `<span class="mono" style="color:var(--text-dim)">${escapeHtml(display)}</span>` +
    `<button class="copy-btn" onclick="copyToClipboard('${escapeHtml(display)}', this)" ` +
    `title="Copy MAC address" aria-label="Copy MAC address">` +
    `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" ` +
    `stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` +
    `<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>`;
}

/**
 * Format a truncated MAC address (first 8 chars).
 * @param {string} mac
 * @returns {string}
 */
function formatMACShort(mac) {
  if (!mac) return '--';
  const cleaned = mac.replace(/[^a-fA-F0-9]/g, '');
  const formatted = cleaned.match(/.{1,2}/g)?.join(':') || mac;
  return formatted.toUpperCase().substring(0, 8) + '...';
}

/**
 * Format an ISO timestamp into relative time + absolute on hover.
 * @param {string} iso  ISO-8601 timestamp
 * @returns {string} HTML string with tooltip
 */
function formatTimestamp(iso) {
  if (!iso) return '<span style="color:var(--text-dim)">--</span>';

  const date = new Date(iso);
  if (isNaN(date.getTime())) return '<span style="color:var(--text-dim)">Invalid date</span>';

  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  let relative;
  if (diffSec < 5) relative = 'just now';
  else if (diffSec < 60) relative = `${diffSec}s ago`;
  else if (diffMin < 60) relative = `${diffMin} min ago`;
  else if (diffHour < 24) relative = `${diffHour}h ago`;
  else if (diffDay < 7) relative = `${diffDay}d ago`;
  else relative = date.toLocaleDateString();

  const absolute = date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return `<span class="tooltip" data-tooltip="${escapeHtml(absolute)}">${relative}</span>`;
}

/**
 * Format a severity level into a colored badge.
 * @param {string} level  critical | high | medium | low | info
 * @returns {string} HTML badge string
 */
function formatSeverity(level) {
  if (!level) return '';
  const normalized = level.toLowerCase().trim();
  const classMap = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  };
  const cls = classMap[normalized] || 'badge-info';
  return `<span class="badge ${cls}">${escapeHtml(normalized.toUpperCase())}</span>`;
}

/**
 * Format a risk score (0-100) into a colored value.
 * @param {number} score
 * @returns {string} HTML string
 */
function formatRiskScore(score) {
  if (score == null || isNaN(score)) return '<span style="color:var(--text-dim)">--</span>';

  let color;
  if (score >= 80) color = 'var(--accent-red)';
  else if (score >= 60) color = 'var(--accent-amber)';
  else if (score >= 40) color = '#fbbf24';
  else if (score >= 20) color = 'var(--accent-green)';
  else color = 'var(--accent-blue)';

  return `<span class="mono" style="color:${color};font-weight:700">${Math.round(score)}</span>`;
}

/**
 * Format a port state with color coding.
 * @param {string} state  open | closed | filtered
 * @returns {string} HTML string
 */
function formatPortState(state) {
  if (!state) return '';
  const normalized = state.toLowerCase().trim();
  const classMap = {
    open: 'port-state--open',
    closed: 'port-state--closed',
    filtered: 'port-state--filtered',
  };
  const cls = classMap[normalized] || '';
  return `<span class="port-state ${cls}">${escapeHtml(normalized)}</span>`;
}

/**
 * Format byte count into human-readable units.
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
  if (bytes == null || isNaN(bytes) || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Truncate a string with ellipsis.
 * @param {string} str
 * @param {number} len  Maximum length (default 50)
 * @returns {string}
 */
function truncate(str, len = 50) {
  if (!str) return '';
  if (str.length <= len) return str;
  return str.substring(0, len) + '\u2026';
}

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return str.replace(/[&<>"']/g, c => map[c]);
}

/**
 * Format a scan status string.
 * @param {string} status
 * @returns {string} HTML string
 */
function formatScanStatus(status) {
  if (!status) return '';
  const normalized = status.toLowerCase();
  const map = {
    completed: { cls: 'scan-history-item__status--completed', icon: '\u2713', label: 'Completed' },
    failed: { cls: 'scan-history-item__status--failed', icon: '\u2717', label: 'Failed' },
    running: { cls: 'scan-history-item__status--running', icon: '\u25CB', label: 'Running' },
    pending: { cls: 'scan-history-item__status--running', icon: '\u25CB', label: 'Pending' },
    queued: { cls: 'scan-history-item__status--running', icon: '\u25CB', label: 'Queued' },
  };
  const info = map[normalized] || { cls: '', icon: '\u25CB', label: normalized };
  return `<span class="scan-history-item__status ${info.cls}">${info.icon} ${escapeHtml(info.label)}</span>`;
}

/**
 * Format duration in seconds to human-readable.
 * @param {number} seconds
 * @returns {string}
 */
function formatDuration(seconds) {
  if (seconds == null || isNaN(seconds)) return '--';
  if (seconds < 1) return '<1s';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const min = Math.floor(seconds / 60);
  const sec = Math.round(seconds % 60);
  if (min < 60) return sec > 0 ? `${min}m ${sec}s` : `${min}m`;
  const hr = Math.floor(min / 60);
  const remainMin = min % 60;
  return `${hr}h ${remainMin}m`;
}

/**
 * Get a device type icon SVG.
 * @param {string} deviceType  router | computer | phone | iot | unknown
 * @param {boolean} isGateway
 * @returns {string} SVG HTML
 */
function getDeviceIcon(deviceType, isGateway) {
  const size = 20;
  const attrs = `width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"`;

  if (isGateway) {
    // Router/gateway icon
    return `<svg ${attrs}><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`;
  }

  const type = (deviceType || 'unknown').toLowerCase();

  switch (type) {
    case 'router':
    case 'gateway':
    case 'access_point':
    case 'switch':
      return `<svg ${attrs}><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`;
    case 'computer':
    case 'desktop':
    case 'workstation':
    case 'laptop':
      return `<svg ${attrs}><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`;
    case 'phone':
    case 'mobile':
    case 'smartphone':
      return `<svg ${attrs}><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`;
    case 'iot':
    case 'smart_device':
    case 'camera':
    case 'sensor':
      return `<svg ${attrs}><path d="M5 12.55a11 11 0 0114.08 0"/><path d="M1.42 9a16 16 0 0121.16 0"/><path d="M8.53 16.11a6 6 0 016.95 0"/><circle cx="12" cy="20" r="1"/></svg>`;
    case 'printer':
      return `<svg ${attrs}><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>`;
    case 'tv':
    case 'media':
    case 'streaming':
      return `<svg ${attrs}><rect x="2" y="7" width="20" height="15" rx="2"/><polyline points="17 2 12 7 7 2"/></svg>`;
    default:
      return `<svg ${attrs}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
  }
}

/**
 * Copy text to clipboard and animate the button.
 * @param {string} text
 * @param {HTMLElement} btn
 */
async function copyToClipboard(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) {
      btn.classList.add('copy-btn--copied');
      setTimeout(() => btn.classList.remove('copy-btn--copied'), 1500);
    }
  } catch {
    // Fallback for insecure contexts
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    try { document.execCommand('copy'); } catch { /* ignore */ }
    document.body.removeChild(textarea);
    if (btn) {
      btn.classList.add('copy-btn--copied');
      setTimeout(() => btn.classList.remove('copy-btn--copied'), 1500);
    }
  }
}

/**
 * Get risk level classification from score.
 * @param {number} score 0-100
 * @returns {{level: string, label: string, color: string}}
 */
function getRiskLevel(score) {
  if (score >= 80) return { level: 'critical', label: 'CRITICAL', color: 'var(--accent-red)' };
  if (score >= 60) return { level: 'high', label: 'HIGH', color: 'var(--accent-amber)' };
  if (score >= 40) return { level: 'medium', label: 'MEDIUM', color: '#fbbf24' };
  if (score >= 20) return { level: 'low', label: 'LOW', color: 'var(--accent-green)' };
  return { level: 'info', label: 'INFO', color: 'var(--accent-blue)' };
}
