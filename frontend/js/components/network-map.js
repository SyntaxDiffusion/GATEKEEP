/* ===================================================================
   GATEKEEP — Network Map Component
   SVG-based network topology visualization.  Gateway in center,
   discovered devices arranged radially, color-coded by threat level.
   =================================================================== */

'use strict';

class NetworkMap {
  constructor() {
    this.container = document.getElementById('network-map-container');
    this.devices = [];
    this.gateway = null;
    this.tooltipEl = null;
    this.width = 700;
    this.height = 420;
    this.centerX = this.width / 2;
    this.centerY = this.height / 2;
    this.radius = 160;
  }

  /**
   * Render the network topology map.
   * @param {Array} devices   Device snapshot objects
   * @param {Object} [gateway]  Gateway device (will be centered)
   */
  render(devices, gateway) {
    if (!this.container) return;

    this.devices = devices || [];
    this.gateway = gateway || this.devices.find(d => d.is_gateway) || null;

    // Filter out the gateway from satellite devices
    const satellites = this.devices.filter(d => d !== this.gateway && !d.is_gateway);

    if (this.devices.length === 0) {
      this._renderPlaceholder();
      return;
    }

    // Measure container
    const rect = this.container.getBoundingClientRect();
    if (rect.width > 100) {
      this.width = rect.width;
      this.height = Math.max(400, Math.min(rect.width * 0.6, 500));
      this.centerX = this.width / 2;
      this.centerY = this.height / 2;
      this.radius = Math.min(this.width, this.height) * 0.33;
    }

    // Build SVG
    let svgContent = '';

    // Background grid pattern
    svgContent += `
      <defs>
        <pattern id="mapGrid" width="30" height="30" patternUnits="userSpaceOnUse">
          <path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(255,255,255,0.015)" stroke-width="0.5"/>
        </pattern>
        <radialGradient id="mapBgGrad" cx="50%" cy="50%" r="60%">
          <stop offset="0%" stop-color="rgba(59,130,246,0.03)"/>
          <stop offset="100%" stop-color="transparent"/>
        </radialGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
      <rect width="100%" height="100%" fill="url(#mapGrid)"/>
      <rect width="100%" height="100%" fill="url(#mapBgGrad)"/>`;

    // Orbit ring
    svgContent += `
      <circle cx="${this.centerX}" cy="${this.centerY}" r="${this.radius}"
        fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="1" stroke-dasharray="4 6"/>`;

    // Connection lines from gateway to each satellite
    satellites.forEach((device, i) => {
      const pos = this._getNodePosition(i, satellites.length);
      const suspicious = this._isSuspicious(device);
      const lineClass = suspicious ? 'map-link map-link--suspicious' : 'map-link';
      svgContent += `<line class="${lineClass}" x1="${this.centerX}" y1="${this.centerY}" x2="${pos.x}" y2="${pos.y}"/>`;
    });

    // Gateway node (center)
    if (this.gateway) {
      svgContent += this._renderNode(
        this.centerX,
        this.centerY,
        this.gateway,
        true
      );
    }

    // Satellite nodes
    satellites.forEach((device, i) => {
      const pos = this._getNodePosition(i, satellites.length);
      svgContent += this._renderNode(pos.x, pos.y, device, false);
    });

    this.container.innerHTML = `
      <div class="network-map" id="network-map">
        <svg class="network-map__svg" viewBox="0 0 ${this.width} ${this.height}" xmlns="http://www.w3.org/2000/svg">
          ${svgContent}
        </svg>
        <div class="map-tooltip" id="map-tooltip"></div>
      </div>`;

    this.tooltipEl = document.getElementById('map-tooltip');
    this._bindNodeEvents();
  }

  _renderPlaceholder() {
    this.container.innerHTML = `
      <div class="network-map__placeholder">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="5" r="3"/>
          <circle cx="19" cy="17" r="3"/>
          <circle cx="5" cy="17" r="3"/>
          <line x1="12" y1="8" x2="19" y2="14"/>
          <line x1="12" y1="8" x2="5" y2="14"/>
          <line x1="5" y1="17" x2="19" y2="17"/>
        </svg>
        <p>Run a scan to see your network topology</p>
      </div>`;
  }

  _renderNode(x, y, device, isGateway) {
    const radius = isGateway ? 22 : 16;
    const suspicious = this._isSuspicious(device);
    const ip = device.ip_address || '--';
    const shortIp = ip.split('.').slice(-1)[0]; // Last octet

    let circleClass = 'map-node-circle map-node-circle--clean';
    if (isGateway) circleClass = 'map-node-circle map-node-circle--gateway';
    else if (suspicious) circleClass = 'map-node-circle map-node-circle--warning';

    const filter = suspicious ? ' filter="url(#glow)"' : '';

    // Device icon (simplified for SVG)
    let iconPath = '';
    if (isGateway) {
      iconPath = `<rect x="${x - 6}" y="${y - 5}" width="12" height="4" rx="1" fill="none" stroke="currentColor" stroke-width="1.2"/>
                   <rect x="${x - 6}" y="${y + 1}" width="12" height="4" rx="1" fill="none" stroke="currentColor" stroke-width="1.2"/>`;
    }

    const escapedIp = escapeHtml(ip);
    const escapedVendor = escapeHtml(device.vendor || '');
    const portCount = device.open_ports?.length || 0;

    return `
      <g class="map-node" data-ip="${escapedIp}" data-vendor="${escapedVendor}" data-ports="${portCount}" data-gateway="${isGateway}"${filter}>
        <circle class="${circleClass}" cx="${x}" cy="${y}" r="${radius}"/>
        ${iconPath}
        <text class="map-node-label" x="${x}" y="${y + radius + 14}">
          ${isGateway ? escapedIp : '.' + escapeHtml(shortIp)}
        </text>
      </g>`;
  }

  _getNodePosition(index, total) {
    if (total === 0) return { x: this.centerX, y: this.centerY };

    // Distribute evenly around the orbit, starting from the top
    const angle = (2 * Math.PI * index / total) - Math.PI / 2;

    // Add slight randomness to radius for organic feel
    const jitter = (index % 3 - 1) * 12;
    const r = this.radius + jitter;

    return {
      x: this.centerX + r * Math.cos(angle),
      y: this.centerY + r * Math.sin(angle),
    };
  }

  _isSuspicious(device) {
    if (!device) return false;
    if (device.open_ports?.some(p => p.is_suspicious)) return true;
    return false;
  }

  _bindNodeEvents() {
    const nodes = this.container.querySelectorAll('.map-node');
    nodes.forEach(node => {
      node.addEventListener('mouseenter', (e) => this._showTooltip(e, node));
      node.addEventListener('mouseleave', () => this._hideTooltip());
      node.addEventListener('mousemove', (e) => this._moveTooltip(e));
    });
  }

  _showTooltip(event, node) {
    if (!this.tooltipEl) return;

    const ip = node.dataset.ip;
    const vendor = node.dataset.vendor;
    const ports = node.dataset.ports;
    const isGateway = node.dataset.gateway === 'true';

    this.tooltipEl.innerHTML = `
      <div class="map-tooltip__ip">${escapeHtml(ip)}${isGateway ? ' (Gateway)' : ''}</div>
      ${vendor ? `<div class="map-tooltip__vendor">${escapeHtml(vendor)}</div>` : ''}
      <div class="map-tooltip__ports">${ports} open port${ports !== '1' ? 's' : ''}</div>`;

    this.tooltipEl.classList.add('map-tooltip--visible');
    this._moveTooltip(event);
  }

  _moveTooltip(event) {
    if (!this.tooltipEl) return;
    const mapRect = this.container.querySelector('.network-map')?.getBoundingClientRect();
    if (!mapRect) return;

    const x = event.clientX - mapRect.left + 12;
    const y = event.clientY - mapRect.top - 8;

    this.tooltipEl.style.left = `${x}px`;
    this.tooltipEl.style.top = `${y}px`;
  }

  _hideTooltip() {
    if (this.tooltipEl) {
      this.tooltipEl.classList.remove('map-tooltip--visible');
    }
  }
}

// Global reference
window.networkMap = null;
