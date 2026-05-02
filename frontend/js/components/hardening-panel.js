/**
 * HardeningPanel — Phase 3 hardening component for GATEKEEP dashboard.
 *
 * Renders into #tab-harden. Two-column layout:
 *   Left (60%): Firewall Recommendations with format toggling
 *   Right (40%): Network Baseline capture + drift detection
 *
 * No frameworks — pure ES2022 class-based component.
 * Consistent with the dashboard's dark navy / glassmorphism aesthetic.
 */

(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Design tokens (must mirror CSS custom properties in index.html)
  // ---------------------------------------------------------------------------
  const TOKEN = {
    navy0: '#0a0f1e',
    navy1: '#111827',
    navy2: '#1a1f36',
    navy3: '#1e2640',
    glass: 'rgba(255,255,255,0.03)',
    glassBorder: 'rgba(255,255,255,0.06)',
    blue: '#3b82f6',
    green: '#10b981',
    amber: '#f59e0b',
    red: '#ef4444',
    textPrimary: '#e2e8f0',
    textSecondary: '#94a3b8',
    textMuted: '#64748b',
    // Code block palette
    codeKeyword: '#79b8ff',
    codeFlag: '#85e89d',
    codeValue: '#ffab70',
    codeComment: '#6a737d',
    codeBg: '#0d1117',
  };

  // Category → display label + color
  const CATEGORY_META = {
    apt28_port:        { label: 'APT28 Defense',   color: TOKEN.red,   id: 'apt28' },
    malicious_ip:      { label: 'APT28 Defense',   color: TOKEN.red,   id: 'apt28' },
    dns_restriction:   { label: 'DNS Protection',  color: TOKEN.amber, id: 'dns' },
    dns_hijack:        { label: 'DNS Protection',  color: TOKEN.amber, id: 'dns' },
    remote_management: { label: 'Port Control',    color: TOKEN.blue,  id: 'port' },
    suspicious_port:   { label: 'Port Control',    color: TOKEN.blue,  id: 'port' },
    default_policy:    { label: 'Network Hygiene', color: TOKEN.green, id: 'hygiene' },
    vulnerable_router: { label: 'Network Hygiene', color: TOKEN.green, id: 'hygiene' },
  };

  function getCategoryMeta(category) {
    return CATEGORY_META[category] || { label: 'General', color: TOKEN.blue, id: 'general' };
  }

  // Drift type → icon char + severity color
  const DRIFT_META = {
    new_device:       { icon: '+', label: 'New Device',        severityFn: () => TOKEN.amber },
    missing_device:   { icon: '−', label: 'Missing Device',    severityFn: () => TOKEN.textSecondary },
    ip_changed:       { icon: '~', label: 'IP Changed',        severityFn: () => TOKEN.blue },
    new_port:         { icon: '+', label: 'New Port',          severityFn: () => TOKEN.amber },
    closed_port:      { icon: '−', label: 'Port Closed',       severityFn: () => TOKEN.textMuted },
    dns_changed:      { icon: '!', label: 'DNS Changed',       severityFn: () => TOKEN.red },
    firmware_changed: { icon: '~', label: 'Firmware Changed',  severityFn: () => TOKEN.amber },
  };

  const SEVERITY_COLOR = {
    critical: TOKEN.red,
    high:     TOKEN.amber,
    medium:   TOKEN.blue,
    low:      TOKEN.green,
  };

  function getDriftMeta(driftType) {
    return DRIFT_META[driftType] || { icon: '?', label: driftType, severityFn: () => TOKEN.blue };
  }

  // ---------------------------------------------------------------------------
  // Utilities
  // ---------------------------------------------------------------------------

  function relativeTime(dateString) {
    if (!dateString) return 'unknown';
    const then = new Date(dateString);
    const now = new Date();
    const diff = Math.floor((now - then) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    const days = Math.floor(diff / 86400);
    return days === 1 ? '1 day ago' : `${days} days ago`;
  }

  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /**
   * Minimal syntax colouring — applies token colours to a single-line command.
   * Works for both iptables and netsh command strings.
   */
  function syntaxHighlight(command, format) {
    if (!command) return '';
    const esc = escapeHtml(command);

    if (format === 'iptables') {
      return esc
        // Command keyword
        .replace(/^(iptables)/, `<span style="color:${TOKEN.codeKeyword}">$1</span>`)
        // Chains / actions
        .replace(/\b(-A|-P|-I|-D|-F|-Z)\b/g, `<span style="color:${TOKEN.codeKeyword}">$1</span>`)
        // Flags
        .replace(/\b(-p|-s|-d|-i|-o|--dport|--sport|--state|-m)\b/g,
          `<span style="color:${TOKEN.codeFlag}">$1</span>`)
        // Target actions
        .replace(/\b(DROP|ACCEPT|REJECT|LOG)\b/g,
          `<span style="color:${TOKEN.codeValue}">$1</span>`)
        // Chain names
        .replace(/\b(INPUT|OUTPUT|FORWARD)\b/g,
          `<span style="color:${TOKEN.codeKeyword}">$1</span>`)
        // Protocols and state values
        .replace(/\b(tcp|udp|icmp)\b/g,
          `<span style="color:${TOKEN.codeFlag}">$1</span>`)
        // CIDR / IP values
        .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d+)?)\b/g,
          `<span style="color:${TOKEN.codeValue}">$1</span>`)
        // Port numbers
        .replace(/(?<=--dport |--sport )(\d+)/g,
          `<span style="color:${TOKEN.codeValue}">$1</span>`);
    }

    if (format === 'windows_firewall') {
      return esc
        .replace(/^(netsh)/,
          `<span style="color:${TOKEN.codeKeyword}">$1</span>`)
        .replace(/\b(advfirewall|firewall)\b/g,
          `<span style="color:${TOKEN.codeKeyword}">$1</span>`)
        .replace(/\b(add|rule|name|dir|action|protocol|localport|remoteport|remoteip)\b/g,
          `<span style="color:${TOKEN.codeFlag}">$1</span>`)
        .replace(/\b(block|allow)\b/g,
          `<span style="color:${TOKEN.codeValue}">$1</span>`)
        .replace(/\b(in|out)\b(?=\s|$)/g,
          `<span style="color:${TOKEN.codeValue}">$1</span>`)
        .replace(/\b(tcp|udp)\b/g,
          `<span style="color:${TOKEN.codeFlag}">$1</span>`)
        .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d+)?)\b/g,
          `<span style="color:${TOKEN.codeValue}">$1</span>`)
        // Quoted rule names
        .replace(/(&quot;[^&]*&quot;)/g,
          `<span style="color:${TOKEN.amber}">$1</span>`);
    }

    // Generic format — highlight IPs and numbers
    return esc
      .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d+)?)\b/g,
        `<span style="color:${TOKEN.codeValue}">$1</span>`)
      .replace(/\b(port\s+\d+)\b/gi,
        `<span style="color:${TOKEN.codeFlag}">$1</span>`)
      .replace(/\b(block|deny|drop|restrict)\b/gi,
        `<span style="color:${TOKEN.red}">$1</span>`)
      .replace(/\b(allow|permit|accept)\b/gi,
        `<span style="color:${TOKEN.green}">$1</span>`);
  }

  // ---------------------------------------------------------------------------
  // CSS injection (appended once, idempotent)
  // ---------------------------------------------------------------------------

  const STYLE_ID = 'gk-hardening-styles';

  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = `
/* =====================================================================
   GATEKEEP — Hardening Panel Styles
   ===================================================================== */

/* ── Layout ─────────────────────────────────────────────────────────── */
.gk-hardening-layout {
  display: grid;
  grid-template-columns: 60fr 40fr;
  gap: 20px;
  align-items: start;
  min-height: 0;
}

@media (max-width: 1024px) {
  .gk-hardening-layout {
    grid-template-columns: 1fr;
  }
}

/* ── Panel cards ─────────────────────────────────────────────────────── */
.gk-panel {
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.06);
  border-radius: 12px;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  overflow: hidden;
}

.gk-panel-header {
  padding: 20px 24px 16px;
  border-bottom: 1px solid rgba(255,255,255,0.05);
}

.gk-panel-title {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #e2e8f0;
  margin: 0 0 4px;
}

.gk-panel-subtitle {
  font-size: 12px;
  color: #64748b;
  margin: 0;
  font-weight: 400;
}

.gk-panel-body {
  padding: 20px 24px;
}

/* ── Format selector ──────────────────────────────────────────────────── */
.gk-format-selector {
  display: flex;
  gap: 4px;
  background: rgba(0,0,0,0.3);
  border: 1px solid rgba(255,255,255,0.06);
  border-radius: 8px;
  padding: 4px;
  width: fit-content;
  margin-bottom: 16px;
}

.gk-format-btn {
  padding: 6px 14px;
  border-radius: 5px;
  border: none;
  background: transparent;
  color: #64748b;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.04em;
  cursor: pointer;
  transition: background 0.15s ease, color 0.15s ease;
  white-space: nowrap;
}

.gk-format-btn:hover:not(.active) {
  background: rgba(255,255,255,0.05);
  color: #94a3b8;
}

.gk-format-btn.active {
  background: #3b82f6;
  color: #fff;
}

/* ── Buttons ─────────────────────────────────────────────────────────── */
.gk-btn {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 8px 16px;
  border-radius: 7px;
  border: 1px solid transparent;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.04em;
  cursor: pointer;
  transition: opacity 0.15s ease, transform 0.1s ease, background 0.15s ease;
  outline: none;
  white-space: nowrap;
}

.gk-btn:active { transform: scale(0.97); }
.gk-btn:disabled { opacity: 0.45; cursor: not-allowed; }

.gk-btn-primary {
  background: #3b82f6;
  color: #fff;
  border-color: rgba(59,130,246,0.4);
}
.gk-btn-primary:hover:not(:disabled) { opacity: 0.88; }

.gk-btn-secondary {
  background: rgba(255,255,255,0.05);
  color: #94a3b8;
  border-color: rgba(255,255,255,0.08);
}
.gk-btn-secondary:hover:not(:disabled) {
  background: rgba(255,255,255,0.09);
  color: #e2e8f0;
}

.gk-btn-danger {
  background: rgba(239,68,68,0.12);
  color: #ef4444;
  border-color: rgba(239,68,68,0.2);
}
.gk-btn-danger:hover:not(:disabled) {
  background: rgba(239,68,68,0.2);
}

.gk-btn-ghost {
  background: transparent;
  color: #64748b;
  border-color: rgba(255,255,255,0.06);
  padding: 5px 10px;
  font-size: 11px;
}
.gk-btn-ghost:hover:not(:disabled) {
  color: #94a3b8;
  border-color: rgba(255,255,255,0.12);
}

.gk-btn-sm {
  padding: 5px 10px;
  font-size: 11px;
}

.gk-btn-xs {
  padding: 4px 8px;
  font-size: 10px;
  border-radius: 5px;
}

.gk-btn-loading .gk-btn-spinner {
  display: inline-block;
  width: 10px;
  height: 10px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: gk-spin 0.7s linear infinite;
}

@keyframes gk-spin {
  to { transform: rotate(360deg); }
}

/* ── Copy button ─────────────────────────────────────────────────────── */
.gk-copy-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 9px;
  border-radius: 5px;
  border: 1px solid rgba(255,255,255,0.08);
  background: rgba(255,255,255,0.04);
  color: #64748b;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  cursor: pointer;
  transition: color 0.2s, background 0.2s, border-color 0.2s;
}
.gk-copy-btn:hover {
  background: rgba(59,130,246,0.12);
  color: #3b82f6;
  border-color: rgba(59,130,246,0.3);
}
.gk-copy-btn.copied {
  color: #10b981;
  background: rgba(16,185,129,0.1);
  border-color: rgba(16,185,129,0.25);
}

.gk-copy-icon {
  width: 11px;
  height: 11px;
  flex-shrink: 0;
}

/* ── Rule cards ──────────────────────────────────────────────────────── */
.gk-rules-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 16px;
  max-height: 68vh;
  overflow-y: auto;
  padding-right: 4px;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,0.08) transparent;
}

.gk-rules-list::-webkit-scrollbar { width: 4px; }
.gk-rules-list::-webkit-scrollbar-track { background: transparent; }
.gk-rules-list::-webkit-scrollbar-thumb {
  background: rgba(255,255,255,0.08);
  border-radius: 2px;
}

.gk-rule-card {
  position: relative;
  background: rgba(0,0,0,0.25);
  border: 1px solid rgba(255,255,255,0.05);
  border-radius: 8px;
  padding: 14px 16px;
  transition: border-color 0.2s ease, background 0.2s ease;
  animation: gk-fadein 0.25s ease both;
}
.gk-rule-card:hover {
  border-color: rgba(255,255,255,0.1);
  background: rgba(0,0,0,0.35);
}

@keyframes gk-fadein {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* Stagger delays for initial load */
.gk-rule-card:nth-child(1)  { animation-delay: 0ms; }
.gk-rule-card:nth-child(2)  { animation-delay: 30ms; }
.gk-rule-card:nth-child(3)  { animation-delay: 60ms; }
.gk-rule-card:nth-child(4)  { animation-delay: 90ms; }
.gk-rule-card:nth-child(5)  { animation-delay: 120ms; }
.gk-rule-card:nth-child(6)  { animation-delay: 150ms; }
.gk-rule-card:nth-child(7)  { animation-delay: 180ms; }
.gk-rule-card:nth-child(8)  { animation-delay: 210ms; }
.gk-rule-card:nth-child(n+9){ animation-delay: 240ms; }

.gk-rule-card-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 10px;
}

.gk-category-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 8px;
  border-radius: 100px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.06em;
  flex-shrink: 0;
  border: 1px solid transparent;
}

.gk-category-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  flex-shrink: 0;
}

/* ── Code block ──────────────────────────────────────────────────────── */
.gk-code-block {
  position: relative;
  background: #0d1117;
  border: 1px solid rgba(255,255,255,0.07);
  border-radius: 6px;
  padding: 11px 40px 11px 14px;
  margin-bottom: 10px;
  overflow: hidden;
}

.gk-code-line {
  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  font-size: 11.5px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
  color: #c9d1d9;
}

.gk-code-copy-btn {
  position: absolute;
  top: 7px;
  right: 7px;
}

/* ── Rule description / rationale ────────────────────────────────────── */
.gk-rule-description {
  font-size: 12.5px;
  color: #94a3b8;
  line-height: 1.5;
  margin-bottom: 5px;
}

.gk-rule-rationale {
  font-size: 11px;
  color: #4b5a6e;
  line-height: 1.45;
  font-style: italic;
  border-left: 2px solid rgba(255,255,255,0.06);
  padding-left: 8px;
  margin-top: 5px;
}

/* ── Copy-all row ────────────────────────────────────────────────────── */
.gk-copy-all-row {
  margin-top: 14px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.gk-rule-count {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: #4b5a6e;
}

/* ── Empty state ─────────────────────────────────────────────────────── */
.gk-empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  text-align: center;
  gap: 14px;
  color: #4b5a6e;
}

.gk-empty-icon {
  width: 40px;
  height: 40px;
  opacity: 0.4;
}

.gk-empty-title {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  font-weight: 600;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin: 0;
}

.gk-empty-body {
  font-size: 12px;
  color: #4b5a6e;
  max-width: 240px;
  line-height: 1.5;
  margin: 0;
}

/* ── Baseline section ────────────────────────────────────────────────── */
.gk-baseline-create {
  background: rgba(0,0,0,0.2);
  border: 1px solid rgba(255,255,255,0.05);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 20px;
}

.gk-baseline-section-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #4b5a6e;
  margin: 0 0 12px;
}

.gk-input, .gk-textarea {
  width: 100%;
  background: rgba(0,0,0,0.35);
  border: 1px solid rgba(255,255,255,0.07);
  border-radius: 6px;
  padding: 9px 12px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: #e2e8f0;
  outline: none;
  transition: border-color 0.15s ease, background 0.15s ease;
  box-sizing: border-box;
  margin-bottom: 8px;
}

.gk-input::placeholder, .gk-textarea::placeholder {
  color: #4b5a6e;
}

.gk-input:focus, .gk-textarea:focus {
  border-color: rgba(59,130,246,0.5);
  background: rgba(0,0,0,0.45);
}

.gk-textarea {
  resize: vertical;
  min-height: 60px;
  max-height: 120px;
  line-height: 1.5;
}

/* ── Baseline card ───────────────────────────────────────────────────── */
.gk-baselines-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  max-height: 56vh;
  overflow-y: auto;
  padding-right: 2px;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,0.08) transparent;
}
.gk-baselines-list::-webkit-scrollbar { width: 4px; }
.gk-baselines-list::-webkit-scrollbar-thumb {
  background: rgba(255,255,255,0.08);
  border-radius: 2px;
}

.gk-baseline-card {
  background: rgba(0,0,0,0.2);
  border: 1px solid rgba(255,255,255,0.06);
  border-radius: 8px;
  overflow: hidden;
  transition: border-color 0.2s ease, transform 0.15s ease, box-shadow 0.15s ease;
  animation: gk-fadein 0.25s ease both;
}
.gk-baseline-card:hover {
  border-color: rgba(255,255,255,0.1);
  transform: translateY(-1px);
  box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}

.gk-baseline-card-body {
  padding: 14px 16px 12px;
}

.gk-baseline-name {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  font-weight: 600;
  color: #e2e8f0;
  margin: 0 0 5px;
}

.gk-baseline-meta {
  display: flex;
  gap: 14px;
  font-size: 11px;
  color: #4b5a6e;
  margin-bottom: 12px;
}

.gk-baseline-meta-item {
  display: flex;
  align-items: center;
  gap: 5px;
}

.gk-baseline-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

/* Delete confirmation inline */
.gk-delete-confirm {
  display: none;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: rgba(239,68,68,0.06);
  border-top: 1px solid rgba(239,68,68,0.15);
  font-size: 11px;
  color: #94a3b8;
}
.gk-delete-confirm.visible {
  display: flex;
}
.gk-delete-confirm-text {
  flex: 1;
  color: #f87171;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
}

/* ── Drift report ────────────────────────────────────────────────────── */
.gk-drift-report {
  overflow: hidden;
  max-height: 0;
  transition: max-height 0.35s cubic-bezier(0.4, 0, 0.2, 1),
              opacity 0.25s ease;
  opacity: 0;
  border-top: 1px solid transparent;
}

.gk-drift-report.expanded {
  max-height: 800px;
  opacity: 1;
  border-top-color: rgba(255,255,255,0.05);
}

.gk-drift-inner {
  padding: 14px 16px;
}

.gk-drift-summary {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: #94a3b8;
  margin-bottom: 10px;
  padding-bottom: 10px;
  border-bottom: 1px solid rgba(255,255,255,0.04);
}

.gk-drift-items {
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.gk-drift-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 9px 12px;
  border-radius: 6px;
  background: rgba(0,0,0,0.2);
  border-left: 3px solid;
  font-size: 12px;
  animation: gk-fadein 0.2s ease both;
}

.gk-drift-item-icon {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  font-weight: 700;
  width: 16px;
  text-align: center;
  flex-shrink: 0;
  line-height: 1.4;
}

.gk-drift-item-content {
  flex: 1;
  min-width: 0;
}

.gk-drift-item-desc {
  color: #94a3b8;
  line-height: 1.4;
  margin-bottom: 3px;
}

.gk-drift-item-values {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: #4b5a6e;
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.gk-drift-item-values .old { color: #6a737d; text-decoration: line-through; }
.gk-drift-item-values .arrow { color: #4b5a6e; }
.gk-drift-item-values .new { color: #85e89d; }

.gk-drift-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 9.5px;
  font-weight: 600;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  opacity: 0.7;
}

/* No-drift success state */
.gk-no-drift {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px;
  background: rgba(16,185,129,0.06);
  border: 1px solid rgba(16,185,129,0.15);
  border-radius: 6px;
  font-size: 12px;
  color: #10b981;
  font-family: 'JetBrains Mono', monospace;
}

/* ── Toast ───────────────────────────────────────────────────────────── */
.gk-toast-container {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 9999;
  display: flex;
  flex-direction: column-reverse;
  gap: 8px;
  pointer-events: none;
}

.gk-toast {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 11px 16px;
  border-radius: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.02em;
  color: #e2e8f0;
  background: #1a1f36;
  border: 1px solid rgba(255,255,255,0.08);
  box-shadow: 0 8px 32px rgba(0,0,0,0.5);
  animation: gk-toast-in 0.25s cubic-bezier(0.34, 1.56, 0.64, 1) both;
  pointer-events: auto;
  max-width: 340px;
}

.gk-toast.exiting {
  animation: gk-toast-out 0.2s ease forwards;
}

.gk-toast-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}

@keyframes gk-toast-in {
  from { opacity: 0; transform: translateY(12px) scale(0.96); }
  to   { opacity: 1; transform: translateY(0) scale(1); }
}

@keyframes gk-toast-out {
  from { opacity: 1; transform: translateY(0) scale(1); }
  to   { opacity: 0; transform: translateY(6px) scale(0.97); }
}

/* ── Loading skeleton ───────────────────────────────────────────────── */
.gk-skeleton {
  background: linear-gradient(90deg,
    rgba(255,255,255,0.03) 0%,
    rgba(255,255,255,0.06) 50%,
    rgba(255,255,255,0.03) 100%);
  background-size: 200% 100%;
  animation: gk-shimmer 1.4s ease infinite;
  border-radius: 4px;
}

@keyframes gk-shimmer {
  0%   { background-position: -200% 0; }
  100% { background-position:  200% 0; }
}

.gk-spinner-inline {
  display: inline-block;
  width: 12px;
  height: 12px;
  border: 2px solid rgba(255,255,255,0.12);
  border-top-color: #3b82f6;
  border-radius: 50%;
  animation: gk-spin 0.7s linear infinite;
  vertical-align: middle;
  margin-right: 6px;
}

/* ── Job status bar ─────────────────────────────────────────────────── */
.gk-job-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 14px;
  background: rgba(59,130,246,0.08);
  border: 1px solid rgba(59,130,246,0.18);
  border-radius: 7px;
  margin-top: 12px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: #60a5fa;
  animation: gk-fadein 0.2s ease both;
}

.gk-job-status.done {
  background: rgba(16,185,129,0.07);
  border-color: rgba(16,185,129,0.2);
  color: #34d399;
}

.gk-job-status.error {
  background: rgba(239,68,68,0.07);
  border-color: rgba(239,68,68,0.2);
  color: #f87171;
}

/* ── Explanation block ──────────────────────────────────────────────── */
.gk-explanation {
  background: rgba(59,130,246,0.04);
  border: 1px solid rgba(59,130,246,0.1);
  border-radius: 7px;
  padding: 12px 14px;
  margin-bottom: 14px;
  font-size: 12px;
  color: #64748b;
  line-height: 1.55;
}

.gk-explanation strong {
  color: #94a3b8;
  font-weight: 600;
}

/* ── Section divider ────────────────────────────────────────────────── */
.gk-divider {
  border: none;
  border-top: 1px solid rgba(255,255,255,0.05);
  margin: 16px 0;
}
    `;
    document.head.appendChild(style);
  }

  // ---------------------------------------------------------------------------
  // Toast notification system
  // ---------------------------------------------------------------------------

  let _toastContainer = null;

  function getToastContainer() {
    if (!_toastContainer) {
      _toastContainer = document.createElement('div');
      _toastContainer.className = 'gk-toast-container';
      document.body.appendChild(_toastContainer);
    }
    return _toastContainer;
  }

  function showToast(message, type = 'info', duration = 3000) {
    const colorMap = {
      success: TOKEN.green,
      error:   TOKEN.red,
      warning: TOKEN.amber,
      info:    TOKEN.blue,
    };
    const color = colorMap[type] || TOKEN.blue;

    const toast = document.createElement('div');
    toast.className = 'gk-toast';
    toast.innerHTML = `
      <span class="gk-toast-dot" style="background:${color}"></span>
      ${escapeHtml(message)}
    `;

    const container = getToastContainer();
    container.appendChild(toast);

    const remove = () => {
      toast.classList.add('exiting');
      toast.addEventListener('animationend', () => toast.remove(), { once: true });
    };

    const timer = setTimeout(remove, duration);
    toast.addEventListener('click', () => { clearTimeout(timer); remove(); });
  }

  // ---------------------------------------------------------------------------
  // API helpers
  // ---------------------------------------------------------------------------

  async function apiFetch(url, options = {}) {
    const response = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
    if (response.status === 204) return null;
    const json = await response.json();
    if (!response.ok) {
      const detail = json?.detail || json?.error?.message || `HTTP ${response.status}`;
      throw new Error(detail);
    }
    return json;
  }

  // ---------------------------------------------------------------------------
  // HardeningPanel class
  // ---------------------------------------------------------------------------

  class HardeningPanel {
    constructor(container) {
      /** @type {HTMLElement} */
      this._container = container;

      // State
      this._format = 'iptables';
      this._rules = [];
      this._baselines = [];
      this._expandedDrift = new Set(); // baseline IDs with open drift panels
      this._pendingDelete = new Set(); // baseline IDs awaiting confirmation
      this._driftData = {};            // { [baselineId]: DriftResponse }
      this._generating = false;
      this._capturingBaseline = false;
      this._loadingDrift = new Set();

      injectStyles();
      this._render();
      this._loadRecommendations();
      this._loadBaselines();
    }

    // ── Top-level render ────────────────────────────────────────────────────

    _render() {
      this._container.innerHTML = `
        <div class="gk-hardening-layout" id="gk-hardening-layout">
          ${this._renderFirewallPanel()}
          ${this._renderBaselinePanel()}
        </div>
      `;
      this._bindEvents();
    }

    // ── Firewall panel ───────────────────────────────────────────────────────

    _renderFirewallPanel() {
      return `
        <div class="gk-panel" id="gk-fw-panel">
          <div class="gk-panel-header">
            <p class="gk-panel-title">Firewall Recommendations</p>
            <p class="gk-panel-subtitle">AI-generated rules based on your network scan</p>
          </div>
          <div class="gk-panel-body">
            <div class="gk-format-selector" id="gk-format-selector">
              <button class="gk-format-btn active" data-format="iptables">iptables</button>
              <button class="gk-format-btn" data-format="windows_firewall">Windows Firewall</button>
              <button class="gk-format-btn" data-format="generic">Generic</button>
            </div>

            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
              <button class="gk-btn gk-btn-primary" id="gk-generate-btn">
                ${this._svgGenerate()}
                Generate Recommendations
              </button>
            </div>

            <div id="gk-job-status-area"></div>
            <div id="gk-explanation-area"></div>
            <div id="gk-rules-area">${this._renderRulesArea()}</div>
          </div>
        </div>
      `;
    }

    _renderRulesArea() {
      if (this._rules.length === 0) {
        return `
          <div class="gk-empty-state" id="gk-rules-empty">
            ${this._svgShield()}
            <p class="gk-empty-title">No Rules Yet</p>
            <p class="gk-empty-body">Run a network scan first, then generate recommendations to populate firewall rules.</p>
          </div>
        `;
      }

      const cards = this._rules.map((rule, i) => this._renderRuleCard(rule, i)).join('');
      return `
        <div class="gk-copy-all-row">
          <button class="gk-btn gk-btn-secondary gk-btn-sm" id="gk-copy-all-btn">
            ${this._svgCopyAll()}
            Copy All Rules
          </button>
          <span class="gk-rule-count">${this._rules.length} rule${this._rules.length !== 1 ? 's' : ''}</span>
        </div>
        <div class="gk-rules-list" id="gk-rules-list">
          ${cards}
        </div>
      `;
    }

    _renderRuleCard(rule, index) {
      const cat = getCategoryMeta(rule.category);
      const cmd = rule.command || rule.rule || '';
      const highlighted = syntaxHighlight(cmd, this._format);
      const cardId = `gk-rule-${index}`;

      return `
        <div class="gk-rule-card" id="${cardId}">
          <div class="gk-rule-card-top">
            <div></div>
            <span class="gk-category-badge"
                  style="color:${cat.color};background:${cat.color}18;border-color:${cat.color}30">
              <span class="gk-category-dot" style="background:${cat.color}"></span>
              ${escapeHtml(cat.label)}
            </span>
          </div>

          <div class="gk-code-block">
            <code class="gk-code-line">${highlighted}</code>
            <button class="gk-copy-btn gk-code-copy-btn" data-copy="${escapeHtml(cmd)}" title="Copy command">
              ${this._svgClipboard()}
            </button>
          </div>

          ${rule.description && rule.description !== cmd ? `
            <p class="gk-rule-description">${escapeHtml(rule.description)}</p>
          ` : ''}

          ${rule.rationale && rule.rationale !== rule.description ? `
            <p class="gk-rule-rationale">${escapeHtml(rule.rationale)}</p>
          ` : ''}
        </div>
      `;
    }

    // ── Baseline panel ───────────────────────────────────────────────────────

    _renderBaselinePanel() {
      return `
        <div class="gk-panel" id="gk-baseline-panel">
          <div class="gk-panel-header">
            <p class="gk-panel-title">Network Baseline</p>
            <p class="gk-panel-subtitle">Track changes to your network over time</p>
          </div>
          <div class="gk-panel-body">
            <div class="gk-baseline-create">
              <p class="gk-baseline-section-label">Capture Baseline</p>
              <input
                class="gk-input"
                id="gk-baseline-name"
                type="text"
                placeholder="Baseline name (e.g. Post-scan 2026-04-30)"
                maxlength="200"
                autocomplete="off"
              />
              <textarea
                class="gk-textarea"
                id="gk-baseline-desc"
                placeholder="Description (optional)"
                maxlength="500"
              ></textarea>
              <button class="gk-btn gk-btn-primary" id="gk-capture-btn">
                ${this._svgCapture()}
                Capture Baseline
              </button>
            </div>

            <p class="gk-baseline-section-label">Saved Baselines</p>
            <div id="gk-baselines-area">
              ${this._renderBaselinesArea()}
            </div>
          </div>
        </div>
      `;
    }

    _renderBaselinesArea() {
      if (this._baselines.length === 0) {
        return `
          <div class="gk-empty-state" style="padding:32px 16px">
            ${this._svgDatabase()}
            <p class="gk-empty-title">No Baselines</p>
            <p class="gk-empty-body">No baselines saved yet. Capture one after running a scan.</p>
          </div>
        `;
      }

      return `
        <div class="gk-baselines-list" id="gk-baselines-list">
          ${this._baselines.map(b => this._renderBaselineCard(b)).join('')}
        </div>
      `;
    }

    _renderBaselineCard(baseline) {
      const id = baseline.id;
      const isExpanded = this._expandedDrift.has(id);
      const isPendingDelete = this._pendingDelete.has(id);
      const isLoadingDrift = this._loadingDrift.has(id);
      const driftData = this._driftData[id] || null;

      return `
        <div class="gk-baseline-card" id="gk-baseline-card-${escapeHtml(id)}">
          <div class="gk-baseline-card-body">
            <p class="gk-baseline-name">${escapeHtml(baseline.name)}</p>
            <div class="gk-baseline-meta">
              <span class="gk-baseline-meta-item">
                ${this._svgClock()}
                ${relativeTime(baseline.created_at)}
              </span>
              <span class="gk-baseline-meta-item">
                ${this._svgDevices()}
                ${baseline.device_count} device${baseline.device_count !== 1 ? 's' : ''}
              </span>
            </div>
            <div class="gk-baseline-actions">
              <button class="gk-btn gk-btn-secondary gk-btn-xs gk-drift-btn"
                      data-id="${escapeHtml(id)}"
                      ${isLoadingDrift ? 'disabled' : ''}>
                ${isLoadingDrift
                  ? `<span class="gk-spinner-inline"></span>Checking...`
                  : `${this._svgRadar()} ${isExpanded ? 'Hide Drift' : 'Check for Drift'}`
                }
              </button>
              <button class="gk-btn gk-btn-danger gk-btn-xs gk-delete-init-btn"
                      data-id="${escapeHtml(id)}">
                ${this._svgTrash()} Delete
              </button>
            </div>
          </div>

          <div class="gk-delete-confirm ${isPendingDelete ? 'visible' : ''}"
               id="gk-delete-confirm-${escapeHtml(id)}">
            <span class="gk-delete-confirm-text">Delete baseline permanently?</span>
            <button class="gk-btn gk-btn-danger gk-btn-xs gk-delete-confirm-btn"
                    data-id="${escapeHtml(id)}">Confirm</button>
            <button class="gk-btn gk-btn-ghost gk-btn-xs gk-delete-cancel-btn"
                    data-id="${escapeHtml(id)}">Cancel</button>
          </div>

          <div class="gk-drift-report ${isExpanded ? 'expanded' : ''}"
               id="gk-drift-${escapeHtml(id)}">
            <div class="gk-drift-inner">
              ${driftData ? this._renderDriftReport(driftData) : ''}
            </div>
          </div>
        </div>
      `;
    }

    _renderDriftReport(driftData) {
      const total = driftData.total_drift_count || 0;

      if (total === 0) {
        return `
          <div class="gk-no-drift">
            ${this._svgCheckShield()}
            No changes detected — network matches baseline exactly
          </div>
        `;
      }

      // Flatten all drift items from the three lists
      const allItems = [
        ...(driftData.new_devices || []).map(d => ({
          drift_type: 'new_device',
          severity: 'high',
          description: `New device detected: ${d.ip_address}${d.mac_address ? ` (MAC: ${d.mac_address})` : ''}`,
          new_value: d.ip_address,
          old_value: null,
        })),
        ...(driftData.missing_devices || []).map(d => ({
          drift_type: 'missing_device',
          severity: 'medium',
          description: `Device no longer visible: ${d.ip_address}${d.mac_address ? ` (MAC: ${d.mac_address})` : ''}`,
          old_value: d.ip_address,
          new_value: null,
        })),
        ...(driftData.changed_devices || []).map(d => ({
          drift_type: d.drift_type || 'ip_changed',
          severity: d.severity || 'medium',
          description: d.description || `Change detected on ${d.device_ip || 'device'}`,
          old_value: d.old_value || null,
          new_value: d.new_value || null,
        })),
      ];

      const items = allItems.map(item => this._renderDriftItem(item)).join('');

      return `
        <p class="gk-drift-summary">
          ${total} change${total !== 1 ? 's' : ''} detected since baseline
        </p>
        <div class="gk-drift-items">
          ${items}
        </div>
      `;
    }

    _renderDriftItem(item) {
      const meta = getDriftMeta(item.drift_type);
      const severityColor = SEVERITY_COLOR[item.severity] || TOKEN.blue;
      const iconColor = meta.severityFn(item.severity);

      const valuesHtml = (item.old_value || item.new_value) ? `
        <div class="gk-drift-item-values">
          ${item.old_value ? `<span class="old">${escapeHtml(item.old_value)}</span>` : ''}
          ${item.old_value && item.new_value ? `<span class="arrow">→</span>` : ''}
          ${item.new_value ? `<span class="new">${escapeHtml(item.new_value)}</span>` : ''}
        </div>
      ` : '';

      return `
        <div class="gk-drift-item" style="border-left-color:${severityColor}">
          <span class="gk-drift-item-icon" style="color:${iconColor}">${meta.icon}</span>
          <div class="gk-drift-item-content">
            <p class="gk-drift-label" style="color:${severityColor}">${escapeHtml(meta.label)}</p>
            <p class="gk-drift-item-desc">${escapeHtml(item.description)}</p>
            ${valuesHtml}
          </div>
        </div>
      `;
    }

    // ── Event binding ────────────────────────────────────────────────────────

    _bindEvents() {
      const root = this._container;

      // Format selector
      root.addEventListener('click', e => {
        const btn = e.target.closest('.gk-format-btn');
        if (btn) {
          const fmt = btn.dataset.format;
          if (fmt && fmt !== this._format) {
            this._setFormat(fmt);
          }
        }
      });

      // Generate button
      const generateBtn = root.querySelector('#gk-generate-btn');
      if (generateBtn) {
        generateBtn.addEventListener('click', () => this._handleGenerate());
      }

      // Copy individual rule
      root.addEventListener('click', e => {
        const btn = e.target.closest('.gk-copy-btn[data-copy]');
        if (btn) this._handleCopy(btn);
      });

      // Copy all
      root.addEventListener('click', e => {
        const btn = e.target.closest('#gk-copy-all-btn');
        if (btn) this._handleCopyAll(btn);
      });

      // Capture baseline
      const captureBtn = root.querySelector('#gk-capture-btn');
      if (captureBtn) {
        captureBtn.addEventListener('click', () => this._handleCaptureBaseline());
      }

      // Baseline actions — use event delegation from the baselines area
      root.addEventListener('click', e => {
        const driftBtn = e.target.closest('.gk-drift-btn');
        if (driftBtn) { this._handleDriftToggle(driftBtn.dataset.id); return; }

        const initBtn = e.target.closest('.gk-delete-init-btn');
        if (initBtn) { this._handleDeleteInit(initBtn.dataset.id); return; }

        const confirmBtn = e.target.closest('.gk-delete-confirm-btn');
        if (confirmBtn) { this._handleDeleteConfirm(confirmBtn.dataset.id); return; }

        const cancelBtn = e.target.closest('.gk-delete-cancel-btn');
        if (cancelBtn) { this._handleDeleteCancel(cancelBtn.dataset.id); return; }
      });
    }

    // ── Format switching ─────────────────────────────────────────────────────

    _setFormat(fmt) {
      this._format = fmt;

      // Update toggle buttons
      this._container.querySelectorAll('.gk-format-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.format === fmt);
      });

      // Re-fetch recommendations in new format
      this._loadRecommendations();
    }

    // ── Firewall recommendations ─────────────────────────────────────────────

    async _loadRecommendations() {
      try {
        const json = await apiFetch(
          `/api/v1/hardening/recommendations?format=${encodeURIComponent(this._format)}`
        );
        const data = json?.data;
        if (data?.rules?.length) {
          this._rules = data.rules;
          this._updateRulesArea();
          if (data.explanation) {
            this._showExplanation(data.explanation);
          }
        }
        // On empty rules, leave existing empty state / silently succeed
      } catch (_) {
        // Fail silently on initial load — no scan yet is expected
      }
    }

    async _handleGenerate() {
      if (this._generating) return;
      this._generating = true;

      const btn = this._container.querySelector('#gk-generate-btn');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="gk-btn-spinner gk-btn-loading" style="display:inline-block;width:11px;height:11px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:gk-spin .7s linear infinite;vertical-align:middle;margin-right:6px;"></span>Generating...`;
      }

      this._showJobStatus('queued', 'Queuing rule generation...');

      try {
        const json = await apiFetch('/api/v1/hardening/recommendations/generate', {
          method: 'POST',
          body: JSON.stringify({ scope: 'network', format: this._format }),
        });

        const jobId = json?.data?.job_id;
        if (jobId) {
          this._showJobStatus('running', `Job queued — rules will refresh automatically`);
          // Poll after a brief pause for the background task to complete
          this._pollForResults(jobId);
        }
      } catch (err) {
        this._showJobStatus('error', `Failed: ${err.message}`);
        showToast(`Generation failed: ${err.message}`, 'error');
      } finally {
        this._generating = false;
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = `${this._svgGenerate()} Generate Recommendations`;
        }
      }
    }

    _pollForResults(jobId, attempts = 0) {
      if (attempts > 12) {
        this._showJobStatus('done', 'Generation complete — refreshing rules');
        this._loadRecommendations();
        return;
      }
      const delay = Math.min(800 + attempts * 400, 3000);
      setTimeout(async () => {
        await this._loadRecommendations();
        if (this._rules.length > 0) {
          this._showJobStatus('done', `Rules generated — ${this._rules.length} rules loaded`);
          showToast(`${this._rules.length} firewall rules generated`, 'success');
        } else {
          this._pollForResults(jobId, attempts + 1);
        }
      }, delay);
    }

    _showJobStatus(state, message) {
      const area = this._container.querySelector('#gk-job-status-area');
      if (!area) return;

      const classMap = { queued: '', running: '', done: 'done', error: 'error' };
      const iconMap = {
        queued:  `<span class="gk-spinner-inline"></span>`,
        running: `<span class="gk-spinner-inline"></span>`,
        done:    `<span style="color:#34d399;font-size:14px;">✓</span>`,
        error:   `<span style="color:#f87171;font-size:14px;">✗</span>`,
      };

      area.innerHTML = `
        <div class="gk-job-status ${classMap[state] || ''}">
          ${iconMap[state] || ''}
          ${escapeHtml(message)}
        </div>
      `;

      // Auto-clear successful/error status after a delay
      if (state === 'done' || state === 'error') {
        setTimeout(() => {
          if (area) area.innerHTML = '';
        }, 5000);
      }
    }

    _showExplanation(text) {
      const area = this._container.querySelector('#gk-explanation-area');
      if (!area || !text) return;
      const paras = text.split('\n').filter(l => l.trim());
      const html = paras
        .map(p => `<p style="margin:0 0 5px">${escapeHtml(p)}</p>`)
        .join('');
      area.innerHTML = `<div class="gk-explanation">${html}</div>`;
    }

    _updateRulesArea() {
      const area = this._container.querySelector('#gk-rules-area');
      if (area) {
        area.innerHTML = this._renderRulesArea();
        // Re-bind copy-all after DOM update (copy individual uses delegation)
      }
    }

    // ── Copy handlers ────────────────────────────────────────────────────────

    async _handleCopy(btn) {
      const text = btn.dataset.copy;
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        btn.classList.add('copied');
        btn.innerHTML = `${this._svgCheck()} Copied!`;
        showToast('Command copied', 'success', 2000);
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.innerHTML = `${this._svgClipboard()}`;
        }, 2000);
      } catch {
        showToast('Copy failed — try manually selecting the text', 'error');
      }
    }

    async _handleCopyAll(btn) {
      const commands = this._rules
        .map(r => r.command || r.rule || '')
        .filter(Boolean)
        .join('\n');

      if (!commands) return;

      try {
        await navigator.clipboard.writeText(commands);
        const orig = btn.innerHTML;
        btn.innerHTML = `${this._svgCheck()} Copied ${this._rules.length} rules!`;
        btn.style.color = TOKEN.green;
        showToast(`${this._rules.length} rules copied to clipboard`, 'success');
        setTimeout(() => {
          btn.innerHTML = orig;
          btn.style.color = '';
        }, 2500);
      } catch {
        showToast('Copy failed', 'error');
      }
    }

    // ── Baseline capture ─────────────────────────────────────────────────────

    async _handleCaptureBaseline() {
      if (this._capturingBaseline) return;

      const nameInput = this._container.querySelector('#gk-baseline-name');
      const descInput = this._container.querySelector('#gk-baseline-desc');
      const captureBtn = this._container.querySelector('#gk-capture-btn');

      const name = nameInput ? nameInput.value.trim() : '';
      if (!name) {
        showToast('Please enter a baseline name', 'warning');
        if (nameInput) {
          nameInput.focus();
          nameInput.style.borderColor = `${TOKEN.amber}60`;
          setTimeout(() => { nameInput.style.borderColor = ''; }, 1500);
        }
        return;
      }

      this._capturingBaseline = true;
      if (captureBtn) {
        captureBtn.disabled = true;
        captureBtn.innerHTML = `<span class="gk-spinner-inline"></span>Capturing...`;
      }

      try {
        const json = await apiFetch('/api/v1/baselines', {
          method: 'POST',
          body: JSON.stringify({
            name,
            description: descInput ? descInput.value.trim() || null : null,
          }),
        });

        if (json?.data) {
          this._baselines.unshift(json.data);
          this._updateBaselinesArea();
          showToast(`Baseline "${name}" captured successfully`, 'success');

          if (nameInput) nameInput.value = '';
          if (descInput) descInput.value = '';
        }
      } catch (err) {
        showToast(`Failed to capture baseline: ${err.message}`, 'error');
      } finally {
        this._capturingBaseline = false;
        if (captureBtn) {
          captureBtn.disabled = false;
          captureBtn.innerHTML = `${this._svgCapture()} Capture Baseline`;
        }
      }
    }

    // ── Baselines list ────────────────────────────────────────────────────────

    async _loadBaselines() {
      try {
        const json = await apiFetch('/api/v1/baselines');
        if (json?.data) {
          this._baselines = Array.isArray(json.data) ? json.data : [];
          this._updateBaselinesArea();
        }
      } catch (_) {
        // Fail silently
      }
    }

    _updateBaselinesArea() {
      const area = this._container.querySelector('#gk-baselines-area');
      if (area) {
        area.innerHTML = this._renderBaselinesArea();
      }
    }

    // ── Drift ────────────────────────────────────────────────────────────────

    async _handleDriftToggle(id) {
      if (!id) return;

      // If already expanded and has data, just collapse
      if (this._expandedDrift.has(id)) {
        this._expandedDrift.delete(id);
        const panel = this._container.querySelector(`#gk-drift-${CSS.escape(id)}`);
        if (panel) panel.classList.remove('expanded');
        this._updateBaselineCard(id);
        return;
      }

      // Expand — load drift if not cached
      if (!this._driftData[id]) {
        this._loadingDrift.add(id);
        this._updateBaselineCard(id);

        try {
          const json = await apiFetch(`/api/v1/baselines/${encodeURIComponent(id)}/drift`);
          if (json?.data) {
            this._driftData[id] = json.data;
          }
        } catch (err) {
          showToast(`Drift check failed: ${err.message}`, 'error');
          this._loadingDrift.delete(id);
          this._updateBaselineCard(id);
          return;
        }

        this._loadingDrift.delete(id);
      }

      this._expandedDrift.add(id);
      this._updateBaselineCard(id);

      // Populate drift content
      const driftInner = this._container.querySelector(`#gk-drift-${CSS.escape(id)} .gk-drift-inner`);
      if (driftInner && this._driftData[id]) {
        driftInner.innerHTML = this._renderDriftReport(this._driftData[id]);
      }

      // Trigger expand animation next tick
      requestAnimationFrame(() => {
        const panel = this._container.querySelector(`#gk-drift-${CSS.escape(id)}`);
        if (panel) panel.classList.add('expanded');
      });
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    _handleDeleteInit(id) {
      if (!id) return;
      this._pendingDelete.add(id);
      const confirmEl = this._container.querySelector(`#gk-delete-confirm-${CSS.escape(id)}`);
      if (confirmEl) confirmEl.classList.add('visible');
    }

    _handleDeleteCancel(id) {
      if (!id) return;
      this._pendingDelete.delete(id);
      const confirmEl = this._container.querySelector(`#gk-delete-confirm-${CSS.escape(id)}`);
      if (confirmEl) confirmEl.classList.remove('visible');
    }

    async _handleDeleteConfirm(id) {
      if (!id) return;

      try {
        await apiFetch(`/api/v1/baselines/${encodeURIComponent(id)}`, { method: 'DELETE' });
        this._baselines = this._baselines.filter(b => b.id !== id);
        this._pendingDelete.delete(id);
        this._expandedDrift.delete(id);
        this._loadingDrift.delete(id);
        delete this._driftData[id];
        this._updateBaselinesArea();
        showToast('Baseline deleted', 'info');
      } catch (err) {
        showToast(`Delete failed: ${err.message}`, 'error');
        this._handleDeleteCancel(id);
      }
    }

    // ── Targeted DOM update for a single baseline card ────────────────────────

    _updateBaselineCard(id) {
      const baseline = this._baselines.find(b => b.id === id);
      if (!baseline) return;

      const existing = this._container.querySelector(`#gk-baseline-card-${CSS.escape(id)}`);
      if (!existing) return;

      const temp = document.createElement('div');
      temp.innerHTML = this._renderBaselineCard(baseline);
      const newCard = temp.firstElementChild;
      if (newCard) {
        existing.replaceWith(newCard);
      }
    }

    // ── SVG icons (inline, sized for the UI) ─────────────────────────────────

    _svgGenerate() {
      return `<svg class="gk-copy-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M2 8a6 6 0 1 1 12 0A6 6 0 0 1 2 8z"/>
        <path d="M8 5v3l2 1.5" stroke-linecap="round"/>
      </svg>`;
    }

    _svgShield() {
      return `<svg class="gk-empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round">
        <path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6z"/>
        <path d="M9 12l2 2 4-4"/>
      </svg>`;
    }

    _svgDatabase() {
      return `<svg class="gk-empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round">
        <ellipse cx="12" cy="5" rx="9" ry="3"/>
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
      </svg>`;
    }

    _svgClipboard() {
      return `<svg class="gk-copy-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
        <rect x="5" y="2" width="9" height="12" rx="1.5"/>
        <path d="M5 4H3.5A1.5 1.5 0 0 0 2 5.5v9A1.5 1.5 0 0 0 3.5 16h7A1.5 1.5 0 0 0 12 14.5V14"/>
      </svg>`;
    }

    _svgCopyAll() {
      return `<svg class="gk-copy-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
        <rect x="1" y="4" width="9" height="11" rx="1.5"/>
        <path d="M4 4V2.5A1.5 1.5 0 0 1 5.5 1H14a1.5 1.5 0 0 1 1.5 1.5V11a1.5 1.5 0 0 1-1.5 1.5H12"/>
      </svg>`;
    }

    _svgCheck() {
      return `<svg class="gk-copy-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M2.5 8.5l3.5 3.5 7.5-7.5"/>
      </svg>`;
    }

    _svgCheckShield() {
      return `<svg style="width:18px;height:18px;flex-shrink:0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
        <path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6z"/>
        <path d="M9 12l2 2 4-4"/>
      </svg>`;
    }

    _svgCapture() {
      return `<svg class="gk-copy-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
        <circle cx="8" cy="8" r="6"/>
        <circle cx="8" cy="8" r="2" fill="currentColor" stroke="none"/>
        <path d="M8 2v2M8 12v2M2 8h2M12 8h2"/>
      </svg>`;
    }

    _svgRadar() {
      return `<svg class="gk-copy-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
        <circle cx="8" cy="8" r="6"/>
        <circle cx="8" cy="8" r="3"/>
        <path d="M8 8L11.5 4.5" stroke-width="1.8"/>
        <circle cx="8" cy="8" r="1" fill="currentColor" stroke="none"/>
      </svg>`;
    }

    _svgTrash() {
      return `<svg class="gk-copy-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
        <path d="M2 4h12M6 4V2h4v2M5 4v9a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1V4"/>
      </svg>`;
    }

    _svgClock() {
      return `<svg style="width:11px;height:11px;flex-shrink:0" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
        <circle cx="8" cy="8" r="6"/>
        <path d="M8 4.5V8l2 1.5"/>
      </svg>`;
    }

    _svgDevices() {
      return `<svg style="width:11px;height:11px;flex-shrink:0" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
        <rect x="1" y="3" width="10" height="8" rx="1.5"/>
        <path d="M11 7h3a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-3"/>
        <path d="M5 11v2M8 11v2"/>
      </svg>`;
    }
  }

  // ---------------------------------------------------------------------------
  // Bootstrap — expose globally and auto-init if target div is present
  // ---------------------------------------------------------------------------

  window.HardeningPanel = HardeningPanel;

  function initHardeningPanel() {
    const target = document.getElementById('tab-harden');
    if (target && !target.dataset.hardeningInit) {
      target.dataset.hardeningInit = '1';
      window._hardeningPanel = new HardeningPanel(target);
    }
  }

  // Init immediately if DOM is ready, otherwise wait
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHardeningPanel);
  } else {
    initHardeningPanel();
  }

  // Re-init support for tab-switching dashboards that show/hide tabs
  document.addEventListener('gk:tab-activated', e => {
    if (e.detail?.tab === 'harden') {
      initHardeningPanel();
    }
  });

})();
