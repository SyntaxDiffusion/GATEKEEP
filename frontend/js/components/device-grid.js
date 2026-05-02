/* ===================================================================
   GATEKEEP — Device Grid Component
   Renders discovered network devices as interactive cards with
   filtering, sorting, and expandable detail views.
   =================================================================== */

'use strict';

class DeviceGrid {
  constructor() {
    this.container = document.getElementById('device-grid');
    this.emptyState = document.getElementById('device-grid-empty');
    this.sortSelect = document.getElementById('device-sort');
    this.filterSuspicious = document.getElementById('filter-suspicious');

    // State
    this.devices = [];
    this.expandedDeviceId = null;
    this.sortBy = 'ip';
    this.suspiciousOnly = false;

    this._bindEvents();
  }

  _bindEvents() {
    if (this.sortSelect) {
      this.sortSelect.addEventListener('change', () => {
        this.sortBy = this.sortSelect.value;
        this._renderGrid();
      });
    }

    if (this.filterSuspicious) {
      this.filterSuspicious.addEventListener('change', () => {
        this.suspiciousOnly = this.filterSuspicious.checked;
        this._renderGrid();
      });
    }
  }

  /**
   * Render a list of devices into the grid.
   * @param {Array} devices  Device snapshot objects from scan detail
   */
  render(devices) {
    this.devices = devices || [];
    this.expandedDeviceId = null;
    this._renderGrid();
  }

  _renderGrid() {
    if (!this.container) return;

    let filtered = [...this.devices];

    // Filter suspicious
    if (this.suspiciousOnly) {
      filtered = filtered.filter(d => this._isSuspicious(d));
    }

    // Sort
    filtered.sort((a, b) => this._compare(a, b));

    if (filtered.length === 0) {
      this.container.innerHTML = `
        <div class="empty-state" style="grid-column: 1 / -1">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
          </svg>
          <p>${this.suspiciousOnly ? 'No suspicious devices found' : 'No devices found \u2014 run a scan'}</p>
        </div>`;
      return;
    }

    this.container.innerHTML = filtered.map(device => this._renderCard(device)).join('');
  }

  _renderCard(device) {
    const ip = device.ip_address || '--';
    const mac = device.mac_address;
    const hostname = device.hostname || ip;
    const vendor = device.vendor || 'Unknown vendor';
    const isGateway = device.is_gateway || false;
    const deviceType = device.device_type || 'unknown';
    const ports = device.open_ports || [];
    const isOnline = device.is_online !== false;
    const suspicious = this._isSuspicious(device);
    const isExpanded = this.expandedDeviceId === (device.id || ip);

    const cardClasses = [
      'device-card',
      isGateway ? 'device-card--gateway' : '',
      suspicious ? 'device-card--suspicious' : '',
    ].filter(Boolean).join(' ');

    const statusDot = isOnline
      ? '<span class="status-dot status-dot--green"></span>'
      : '<span class="status-dot status-dot--neutral"></span>';

    const icon = getDeviceIcon(deviceType, isGateway);

    const deviceId = device.id || ip;
    const macDisplay = mac ? formatMACShort(mac) : '--';

    let detailsHtml = '';
    if (isExpanded) {
      detailsHtml = this._renderExpandedDetails(device);
    }

    return `
      <div class="${cardClasses}" data-device-id="${escapeHtml(deviceId)}" onclick="window.deviceGrid?.toggleDevice('${escapeHtml(deviceId)}')">
        <div class="device-card__header">
          <div class="device-card__icon-group">
            <div class="device-card__icon">${icon}</div>
            <div class="device-card__names">
              <span class="device-card__hostname">${escapeHtml(truncate(hostname, 28))}</span>
              <span class="device-card__vendor">${escapeHtml(truncate(vendor, 30))}</span>
            </div>
          </div>
          <div class="device-card__status">
            ${statusDot}
            ${isGateway ? '<span class="badge badge-info">Gateway</span>' : ''}
            ${suspicious ? '<span class="badge badge-high">!</span>' : ''}
          </div>
        </div>

        <div class="device-card__ip">${escapeHtml(ip)}</div>

        <div class="device-card__mac">
          <span class="mono">${escapeHtml(macDisplay)}</span>
          ${mac ? `<button class="device-card__mac-copy" onclick="event.stopPropagation(); copyToClipboard('${escapeHtml(mac.toUpperCase())}', this)" title="Copy full MAC">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          </button>` : ''}
        </div>

        <div class="device-card__footer">
          <span class="device-card__port-badge">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
            ${ports.length} port${ports.length !== 1 ? 's' : ''}
          </span>
          <span class="device-card__type-badge">${escapeHtml(this._formatType(deviceType))}</span>
        </div>

        ${detailsHtml}
      </div>`;
  }

  _renderExpandedDetails(device) {
    const ports = device.open_ports || [];

    if (ports.length === 0) {
      return `
        <div class="device-card__details">
          <p style="font-size:var(--text-xs);color:var(--text-dim);text-align:center;padding:var(--space-sm)">No open ports detected</p>
        </div>`;
    }

    return `
      <div class="device-card__details">
        <div class="device-card__ports-list">
          ${ports.map(p => {
            const suspicious = p.is_suspicious;
            return `
              <div class="device-card__port-item ${suspicious ? 'device-card__port-item--suspicious' : ''}">
                <span>
                  <span class="port-number">${p.port}</span>/<span class="port-service">${escapeHtml(p.protocol || 'tcp')}</span>
                  ${p.service_name ? ` <span class="port-service">${escapeHtml(p.service_name)}</span>` : ''}
                </span>
                <span>
                  ${formatPortState(p.state)}
                  ${suspicious ? '<span class="port-suspicious-tag">SUSPICIOUS</span>' : ''}
                </span>
              </div>
              ${p.banner ? `<div class="port-banner">${escapeHtml(truncate(p.banner, 100))}</div>` : ''}`;
          }).join('')}
        </div>
        ${device.last_response_time_ms !== undefined && device.last_response_time_ms !== null ? `
          <div style="margin-top:var(--space-sm);font-size:var(--text-xs);color:var(--text-dim)">
            Response: <span class="mono">${device.last_response_time_ms.toFixed(1)}ms</span>
          </div>
        ` : ''}
      </div>`;
  }

  /**
   * Toggle expanded state for a device card.
   * @param {string} deviceId
   */
  toggleDevice(deviceId) {
    this.expandedDeviceId = this.expandedDeviceId === deviceId ? null : deviceId;
    this._renderGrid();
  }

  // -----------------------------------------------------------------
  //  Sorting & Filtering helpers
  // -----------------------------------------------------------------

  _compare(a, b) {
    switch (this.sortBy) {
      case 'ip':
        return this._compareIP(a.ip_address, b.ip_address);
      case 'vendor':
        return (a.vendor || '').localeCompare(b.vendor || '');
      case 'type':
        return (a.device_type || '').localeCompare(b.device_type || '');
      case 'ports':
        return (b.open_ports?.length || 0) - (a.open_ports?.length || 0);
      default:
        return 0;
    }
  }

  _compareIP(a, b) {
    if (!a || !b) return 0;
    const partsA = a.split('.').map(Number);
    const partsB = b.split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      if (partsA[i] !== partsB[i]) return partsA[i] - partsB[i];
    }
    return 0;
  }

  _isSuspicious(device) {
    if (!device) return false;
    // Device is suspicious if any port is flagged
    if (device.open_ports?.some(p => p.is_suspicious)) return true;
    return false;
  }

  _formatType(type) {
    if (!type) return 'Unknown';
    return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }
}

// Global reference
window.deviceGrid = null;
