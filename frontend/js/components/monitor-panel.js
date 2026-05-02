/**
 * MonitorPanel — monitoring controls and live statistics for GATEKEEP.
 *
 * Injects itself into #monitor-tab alongside AlertFeed.
 * Manages start/stop, WebSocket subscriptions, live stats display,
 * top talkers chart, protocol distribution, and IOC database status.
 *
 * Depends on: GatekeepWebSocket (window.GatekeepWebSocket)
 *             AlertFeed (window.AlertFeed)
 * Styles: injected via _injectStyles() on mount
 */

class MonitorPanel {
  /**
   * @param {Object} [opts]
   * @param {string} [opts.containerId]    - Parent element ID
   * @param {string} [opts.apiBase]        - REST API base URL
   * @param {GatekeepWebSocket} [opts.ws]  - Shared WebSocket instance
   * @param {AlertFeed} [opts.alertFeed]   - Shared AlertFeed instance
   */
  constructor(opts = {}) {
    this._containerId = opts.containerId || 'tab-monitor';
    this._apiBase = opts.apiBase || 'http://localhost:8443/api/v1';
    this._ws = opts.ws || null;
    this._alertFeed = opts.alertFeed || null;

    // Monitoring state
    this._isMonitoring = false;
    this._sessionId = null;
    this._startTime = null;
    this._selectedInterface = null;

    // Live stats (updated from WS monitor_stats events)
    this._stats = {
      packetCount: 0,
      alertCount: 0,
      pps: 0,            // packets per second (computed)
      uptimeSeconds: 0,
    };
    this._lastPacketCount = 0;
    this._lastPpsTs = Date.now();

    // Top talkers: { ip: count }
    this._topTalkers = {};

    // Protocol distribution: { tcp: N, udp: N, dns: N, other: N }
    this._protocols = { tcp: 0, udp: 0, dns: 0, other: 0 };

    // Timers
    this._durationTimer = null;
    this._statusPollTimer = null;

    // DOM refs (populated after mount)
    this._root = null;
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /**
   * Mount the panel. Creates the outer #monitor-tab layout if it doesn't
   * already contain the two-column wrapper.
   */
  mount() {
    const parent = document.getElementById(this._containerId);
    if (!parent) {
      console.error(`[MonitorPanel] Container #${this._containerId} not found.`);
      return;
    }

    this._injectStyles();

    // Build the two-column monitor layout wrapper if not present
    let layoutWrapper = parent.querySelector('.monitor-layout');
    if (!layoutWrapper) {
      layoutWrapper = document.createElement('div');
      layoutWrapper.className = 'monitor-layout';
      parent.innerHTML = ''; // clear any placeholder
      parent.appendChild(layoutWrapper);
    }

    // Panel column (right side, 40%)
    const panelCol = document.createElement('div');
    panelCol.className = 'monitor-col monitor-col--panel';
    layoutWrapper.appendChild(panelCol);

    // Alert feed column (left side, 60%) — AlertFeed mounts here
    const feedCol = document.createElement('div');
    feedCol.className = 'monitor-col monitor-col--feed';
    feedCol.id = 'alert-feed-col';
    layoutWrapper.insertBefore(feedCol, panelCol);

    // Build panel HTML
    panelCol.innerHTML = this._template();
    this._root = panelCol;

    this._bindElements();
    this._bindEvents();
    this._loadInterfaces();
    this._loadIOCStatus();
    this._checkMonitoringStatus();

    // Wire WebSocket if provided
    if (this._ws) {
      this._wireWebSocket();
    }

    // Mount AlertFeed into the feed column
    if (this._alertFeed) {
      // Override containerId to use the col id
      this._alertFeed._containerId = 'alert-feed-col';
      this._alertFeed.mount();
    }
  }

  /**
   * Attach a WebSocket instance (can be called after mount).
   * @param {GatekeepWebSocket} ws
   */
  setWebSocket(ws) {
    this._ws = ws;
    if (this._root) this._wireWebSocket();
  }

  /**
   * Attach an AlertFeed instance (can be called after mount).
   * @param {AlertFeed} feed
   */
  setAlertFeed(feed) {
    this._alertFeed = feed;
  }

  // -------------------------------------------------------------------------
  // Template
  // -------------------------------------------------------------------------

  _template() {
    return `
      <!-- Connection status -->
      <div class="mp-ws-bar" id="mp-ws-bar">
        <span class="mp-ws-dot" id="mp-ws-dot"></span>
        <span class="mp-ws-label" id="mp-ws-label">WebSocket disconnected</span>
      </div>

      <!-- Start / Stop control -->
      <div class="mp-control-card">
        <div class="mp-control-header">
          <div class="mp-section-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
            </svg>
            <span>Real-Time Monitor</span>
          </div>
          <div class="mp-status-indicator" id="mp-status-indicator">
            <span class="mp-status-dot" id="mp-status-dot"></span>
            <span class="mp-status-text" id="mp-status-text">Stopped</span>
          </div>
        </div>

        <div class="mp-iface-row">
          <label class="mp-label" for="mp-iface-select">Interface</label>
          <select class="mp-iface-select" id="mp-iface-select">
            <option value="">Loading interfaces…</option>
          </select>
        </div>

        <button class="mp-toggle-btn mp-toggle-btn--start" id="mp-toggle-btn" disabled>
          <span class="mp-btn-icon" id="mp-btn-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="5 3 19 12 5 21 5 3"/>
            </svg>
          </span>
          <span id="mp-btn-label">Start Monitoring</span>
        </button>

        <div class="mp-error" id="mp-error" hidden></div>
      </div>

      <!-- Live stats (only when monitoring) -->
      <div class="mp-stats-grid" id="mp-stats-grid" hidden>
        <div class="mp-stat-card">
          <div class="mp-stat-label">Packets / sec</div>
          <div class="mp-stat-big" id="mp-pps">0</div>
        </div>
        <div class="mp-stat-card">
          <div class="mp-stat-label">Total Packets</div>
          <div class="mp-stat-big" id="mp-total-pkts">0</div>
        </div>
        <div class="mp-stat-card">
          <div class="mp-stat-label">Duration</div>
          <div class="mp-stat-big mp-stat-mono" id="mp-duration">00:00:00</div>
        </div>
        <div class="mp-stat-card mp-stat-card--alert" id="mp-alert-stat">
          <div class="mp-stat-label">Alerts</div>
          <div class="mp-stat-big mp-stat-big--alert" id="mp-alert-count">0</div>
        </div>
      </div>

      <!-- Top Talkers -->
      <div class="mp-card" id="mp-talkers-card" hidden>
        <div class="mp-card-header">
          <div class="mp-section-label">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/>
              <line x1="6" y1="20" x2="6" y2="14"/>
            </svg>
            <span>Top Talkers</span>
          </div>
          <span class="mp-card-sub">by packet count</span>
        </div>
        <div class="mp-bar-chart" id="mp-talkers-chart">
          <div class="mp-chart-empty">Waiting for traffic…</div>
        </div>
      </div>

      <!-- Protocol Distribution -->
      <div class="mp-card" id="mp-proto-card" hidden>
        <div class="mp-card-header">
          <div class="mp-section-label">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><polyline points="8.56 2.75 4.5 4.5 2.75 8.56"/>
            </svg>
            <span>Protocol Distribution</span>
          </div>
        </div>
        <div class="mp-proto-bars" id="mp-proto-bars">
          <div class="mp-proto-row" data-proto="tcp">
            <span class="mp-proto-label">TCP</span>
            <div class="mp-proto-bar-wrap">
              <div class="mp-proto-bar mp-proto-bar--tcp" style="width:0%"></div>
            </div>
            <span class="mp-proto-pct" data-proto-pct="tcp">0%</span>
          </div>
          <div class="mp-proto-row" data-proto="udp">
            <span class="mp-proto-label">UDP</span>
            <div class="mp-proto-bar-wrap">
              <div class="mp-proto-bar mp-proto-bar--udp" style="width:0%"></div>
            </div>
            <span class="mp-proto-pct" data-proto-pct="udp">0%</span>
          </div>
          <div class="mp-proto-row" data-proto="dns">
            <span class="mp-proto-label">DNS</span>
            <div class="mp-proto-bar-wrap">
              <div class="mp-proto-bar mp-proto-bar--dns" style="width:0%"></div>
            </div>
            <span class="mp-proto-pct" data-proto-pct="dns">0%</span>
          </div>
          <div class="mp-proto-row" data-proto="other">
            <span class="mp-proto-label">Other</span>
            <div class="mp-proto-bar-wrap">
              <div class="mp-proto-bar mp-proto-bar--other" style="width:0%"></div>
            </div>
            <span class="mp-proto-pct" data-proto-pct="other">0%</span>
          </div>
        </div>
      </div>

      <!-- IOC Database Status -->
      <div class="mp-card">
        <div class="mp-card-header">
          <div class="mp-section-label">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
              <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
            </svg>
            <span>IOC Database</span>
          </div>
          <button class="mp-ioc-refresh-btn" id="mp-ioc-refresh-btn" title="Refresh IOC indicators">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="23 4 23 10 17 10"/>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
            </svg>
            Refresh
          </button>
        </div>
        <div class="mp-ioc-stats" id="mp-ioc-stats">
          <div class="mp-ioc-row">
            <span class="mp-ioc-label">Indicators</span>
            <span class="mp-ioc-val" id="mp-ioc-count">—</span>
          </div>
          <div class="mp-ioc-row">
            <span class="mp-ioc-label">Last Updated</span>
            <span class="mp-ioc-val mp-ioc-time" id="mp-ioc-updated">—</span>
          </div>
          <div class="mp-ioc-row">
            <span class="mp-ioc-label">Status</span>
            <span class="mp-ioc-status" id="mp-ioc-status">
              <span class="mp-ioc-status-dot"></span>
              <span id="mp-ioc-status-text">Loading…</span>
            </span>
          </div>
        </div>
        <div class="mp-ioc-message" id="mp-ioc-message" hidden></div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // DOM wiring
  // -------------------------------------------------------------------------

  _bindElements() {
    this._wsDot = this._root.querySelector('#mp-ws-dot');
    this._wsLabel = this._root.querySelector('#mp-ws-label');
    this._ifaceSelect = this._root.querySelector('#mp-iface-select');
    this._toggleBtn = this._root.querySelector('#mp-toggle-btn');
    this._btnIcon = this._root.querySelector('#mp-btn-icon');
    this._btnLabel = this._root.querySelector('#mp-btn-label');
    this._statusDot = this._root.querySelector('#mp-status-dot');
    this._statusText = this._root.querySelector('#mp-status-text');
    this._errorEl = this._root.querySelector('#mp-error');
    this._statsGrid = this._root.querySelector('#mp-stats-grid');
    this._ppsEl = this._root.querySelector('#mp-pps');
    this._totalPktsEl = this._root.querySelector('#mp-total-pkts');
    this._durationEl = this._root.querySelector('#mp-duration');
    this._alertCountEl = this._root.querySelector('#mp-alert-count');
    this._talkersCard = this._root.querySelector('#mp-talkers-card');
    this._talkersChart = this._root.querySelector('#mp-talkers-chart');
    this._protoCard = this._root.querySelector('#mp-proto-card');
    this._iocCountEl = this._root.querySelector('#mp-ioc-count');
    this._iocUpdatedEl = this._root.querySelector('#mp-ioc-updated');
    this._iocStatusText = this._root.querySelector('#mp-ioc-status-text');
    this._iocStatusDot = this._root.querySelector('.mp-ioc-status-dot');
    this._iocMessage = this._root.querySelector('#mp-ioc-message');
    this._iocRefreshBtn = this._root.querySelector('#mp-ioc-refresh-btn');
  }

  _bindEvents() {
    this._toggleBtn.addEventListener('click', () => {
      if (this._isMonitoring) {
        this._stopMonitoring();
      } else {
        this._startMonitoring();
      }
    });

    this._ifaceSelect.addEventListener('change', (e) => {
      this._selectedInterface = e.target.value;
      this._toggleBtn.disabled = !this._selectedInterface;
    });

    this._iocRefreshBtn.addEventListener('click', () => {
      this._refreshIOC();
    });
  }

  // -------------------------------------------------------------------------
  // WebSocket wiring
  // -------------------------------------------------------------------------

  _wireWebSocket() {
    if (!this._ws) return;

    this._ws.onConnectionChange((status) => {
      this._updateWsStatus(status);
    });

    this._ws.onMonitorStats((data) => {
      this._handleMonitorStats(data);
    });

    this._ws.onAlert((data) => {
      if (this._alertFeed) {
        this._alertFeed.handleNewAlert(data);
      }
      // Bump alert counter
      this._stats.alertCount = (this._stats.alertCount || 0) + 1;
      this._updateStatDisplay('mp-alert-count', this._stats.alertCount);
    });

    // Connect if not already connected
    if (!this._ws.isConnected) {
      this._ws.connect();
    }

    // Reflect initial status
    this._updateWsStatus(this._ws.status);
  }

  _updateWsStatus(status) {
    const labels = {
      connected: 'WebSocket connected',
      connecting: 'Connecting…',
      reconnecting: 'Reconnecting…',
      disconnected: 'WebSocket disconnected',
    };

    const dotClasses = {
      connected: 'mp-ws-dot--connected',
      connecting: 'mp-ws-dot--connecting',
      reconnecting: 'mp-ws-dot--reconnecting',
      disconnected: 'mp-ws-dot--disconnected',
    };

    if (this._wsDot) {
      this._wsDot.className = 'mp-ws-dot ' + (dotClasses[status] || dotClasses.disconnected);
    }
    if (this._wsLabel) {
      this._wsLabel.textContent = labels[status] || labels.disconnected;
    }
  }

  // -------------------------------------------------------------------------
  // Monitor start / stop
  // -------------------------------------------------------------------------

  async _startMonitoring() {
    const iface = this._ifaceSelect.value;
    if (!iface) {
      this._showError('Please select a network interface first.');
      return;
    }

    this._setButtonState('loading');
    this._hideError();

    try {
      const resp = await fetch(`${this._apiBase}/monitor/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface }),
      });

      const json = await resp.json();

      if (!resp.ok) {
        const detail = json?.detail;
        const msg = json?.error?.message
          || (typeof detail === 'string' ? detail : detail?.error?.message || detail?.message)
          || `HTTP ${resp.status}`;
        throw new Error(msg);
      }

      this._sessionId = json.data?.session_id || null;
      this._startTime = Date.now();
      this._isMonitoring = true;
      this._selectedInterface = iface;
      this._stats = { packetCount: 0, alertCount: 0, pps: 0, uptimeSeconds: 0 };
      this._topTalkers = {};
      this._protocols = { tcp: 0, udp: 0, dns: 0, other: 0 };

      this._setButtonState('running');
      this._setMonitoringStatus(true);
      this._startDurationTimer();

      // Subscribe WebSocket channels
      if (this._ws) {
        this._ws.subscribe(['alerts', 'monitor_stats']);
      }

    } catch (err) {
      console.error('[MonitorPanel] Start failed:', err);
      this._setButtonState('stopped');
      this._showError(err.message || 'Failed to start monitoring.');
    }
  }

  async _stopMonitoring() {
    this._setButtonState('loading');

    try {
      const resp = await fetch(`${this._apiBase}/monitor/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!resp.ok) {
        const json = await resp.json().catch(() => ({}));
        const msg = json?.error?.message || `HTTP ${resp.status}`;
        throw new Error(msg);
      }

      this._isMonitoring = false;
      this._sessionId = null;
      this._stopDurationTimer();
      this._setButtonState('stopped');
      this._setMonitoringStatus(false);

      // Refresh alert feed after stop
      if (this._alertFeed) {
        this._alertFeed.refresh();
      }

    } catch (err) {
      console.error('[MonitorPanel] Stop failed:', err);
      // Still show stopped state — server may have already stopped
      this._isMonitoring = false;
      this._setButtonState('stopped');
      this._setMonitoringStatus(false);
      this._showError(err.message || 'Failed to stop monitoring.');
    }
  }

  async _checkMonitoringStatus() {
    try {
      const resp = await fetch(`${this._apiBase}/monitor/status`);
      if (!resp.ok) return;
      const json = await resp.json();
      const data = json.data || {};

      if (data.is_active) {
        this._isMonitoring = true;
        this._sessionId = data.session_id;
        // Approximate start time from uptime
        this._startTime = Date.now() - (data.uptime_seconds || 0) * 1000;
        this._stats.packetCount = data.packet_count || 0;
        this._stats.alertCount = data.alert_count || 0;

        // Select the active interface if available
        if (data.interface) {
          this._selectedInterface = data.interface;
        }

        this._setButtonState('running');
        this._setMonitoringStatus(true);
        this._startDurationTimer();

        if (this._ws) {
          this._ws.subscribe(['alerts', 'monitor_stats']);
        }
      }
    } catch {
      // Non-critical — fail silently
    }
  }

  // -------------------------------------------------------------------------
  // Stats handling (from WebSocket)
  // -------------------------------------------------------------------------

  _handleMonitorStats(data) {
    const eventType = data._eventType;

    if (eventType === 'monitor_stats') {
      // Full stats update
      const prevCount = this._stats.packetCount;
      const now = Date.now();
      const dt = (now - this._lastPpsTs) / 1000;

      this._stats.packetCount = data.packet_count || 0;
      this._stats.alertCount = data.alert_count || 0;
      this._stats.uptimeSeconds = data.uptime_seconds || 0;

      // Compute PPS
      if (dt > 0) {
        this._stats.pps = Math.round((this._stats.packetCount - prevCount) / dt);
      }
      this._lastPpsTs = now;
      this._lastPacketCount = this._stats.packetCount;

      // Update top talkers if provided
      if (data.top_talkers) {
        this._topTalkers = data.top_talkers;
        this._renderTopTalkers();
      }

      // Update protocol distribution if provided
      if (data.protocols) {
        this._protocols = { ...this._protocols, ...data.protocols };
        this._renderProtocolBars();
      }

      this._updateLiveStats();

    } else if (eventType === 'monitor_anomaly') {
      // Anomaly event — update alert count
      this._stats.alertCount = (this._stats.alertCount || 0) + 1;
      this._updateStatDisplay('mp-alert-count', this._stats.alertCount);
    }
  }

  _updateLiveStats() {
    this._updateStatDisplay('mp-pps', this._stats.pps);
    this._updateStatDisplay('mp-total-pkts', this._formatNumber(this._stats.packetCount));
    this._updateStatDisplay('mp-alert-count', this._stats.alertCount);
  }

  _updateStatDisplay(id, value) {
    const el = this._root && this._root.querySelector(`#${id}`);
    if (!el) return;
    const strVal = String(value);
    if (el.textContent !== strVal) {
      el.classList.add('mp-stat-bump');
      el.textContent = strVal;
      el.addEventListener('animationend', () => el.classList.remove('mp-stat-bump'), { once: true });
    }
  }

  // -------------------------------------------------------------------------
  // Duration timer
  // -------------------------------------------------------------------------

  _startDurationTimer() {
    this._stopDurationTimer();
    this._durationTimer = setInterval(() => {
      if (!this._startTime || !this._durationEl) return;
      const elapsed = Math.floor((Date.now() - this._startTime) / 1000);
      this._durationEl.textContent = this._formatDuration(elapsed);
    }, 1000);
  }

  _stopDurationTimer() {
    if (this._durationTimer) {
      clearInterval(this._durationTimer);
      this._durationTimer = null;
    }
  }

  _formatDuration(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return [h, m, s].map(v => String(v).padStart(2, '0')).join(':');
  }

  // -------------------------------------------------------------------------
  // Top Talkers chart
  // -------------------------------------------------------------------------

  _renderTopTalkers() {
    if (!this._talkersChart) return;

    // Sort and take top 5
    const sorted = Object.entries(this._topTalkers)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);

    if (sorted.length === 0) {
      this._talkersChart.innerHTML = '<div class="mp-chart-empty">Waiting for traffic…</div>';
      return;
    }

    const maxVal = sorted[0][1] || 1;
    const html = sorted.map(([ip, count], i) => {
      const pct = Math.round((count / maxVal) * 100);
      const delay = i * 0.05;
      return `
        <div class="mp-bar-row" style="animation-delay:${delay}s">
          <span class="mp-bar-ip">${this._escapeHtml(ip)}</span>
          <div class="mp-bar-track">
            <div class="mp-bar-fill" style="width:${pct}%;"></div>
          </div>
          <span class="mp-bar-count">${this._formatNumber(count)}</span>
        </div>
      `;
    }).join('');

    this._talkersChart.innerHTML = html;
  }

  // -------------------------------------------------------------------------
  // Protocol distribution bars
  // -------------------------------------------------------------------------

  _renderProtocolBars() {
    if (!this._protoCard) return;

    const total = Object.values(this._protocols).reduce((a, b) => a + b, 0) || 1;

    for (const [proto, count] of Object.entries(this._protocols)) {
      const pct = Math.round((count / total) * 100);
      const barEl = this._root.querySelector(`.mp-proto-bar--${proto}`);
      const pctEl = this._root.querySelector(`[data-proto-pct="${proto}"]`);
      if (barEl) barEl.style.width = `${pct}%`;
      if (pctEl) pctEl.textContent = `${pct}%`;
    }
  }

  // -------------------------------------------------------------------------
  // UI state helpers
  // -------------------------------------------------------------------------

  _setButtonState(state) {
    if (!this._toggleBtn || !this._btnLabel || !this._btnIcon) return;

    switch (state) {
      case 'loading':
        this._toggleBtn.disabled = true;
        this._toggleBtn.className = 'mp-toggle-btn mp-toggle-btn--loading';
        this._btnLabel.textContent = this._isMonitoring ? 'Stopping…' : 'Starting…';
        this._btnIcon.innerHTML = `<span class="mp-btn-spinner"></span>`;
        break;

      case 'running':
        this._toggleBtn.disabled = false;
        this._toggleBtn.className = 'mp-toggle-btn mp-toggle-btn--stop';
        this._btnLabel.textContent = 'Stop Monitoring';
        this._btnIcon.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="6" y="6" width="12" height="12"/>
          </svg>`;
        break;

      case 'stopped':
      default:
        this._toggleBtn.disabled = !this._ifaceSelect?.value;
        this._toggleBtn.className = 'mp-toggle-btn mp-toggle-btn--start';
        this._btnLabel.textContent = 'Start Monitoring';
        this._btnIcon.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>`;
        break;
    }
  }

  _setMonitoringStatus(active) {
    if (!this._statusDot || !this._statusText) return;

    if (active) {
      this._statusDot.className = 'mp-status-dot mp-status-dot--active';
      this._statusText.textContent = 'Monitoring';
      this._statsGrid.hidden = false;
      this._talkersCard.hidden = false;
      this._protoCard.hidden = false;
    } else {
      this._statusDot.className = 'mp-status-dot mp-status-dot--stopped';
      this._statusText.textContent = 'Stopped';
      this._statsGrid.hidden = true;
      this._talkersCard.hidden = true;
      this._protoCard.hidden = true;
    }
  }

  _showError(msg) {
    if (!this._errorEl) return;
    this._errorEl.textContent = msg;
    this._errorEl.hidden = false;
  }

  _hideError() {
    if (!this._errorEl) return;
    this._errorEl.hidden = true;
    this._errorEl.textContent = '';
  }

  // -------------------------------------------------------------------------
  // Interfaces
  // -------------------------------------------------------------------------

  async _loadInterfaces() {
    try {
      const resp = await fetch(`${this._apiBase}/system/interfaces`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json = await resp.json();
      const interfaces = json.data || [];

      if (!this._ifaceSelect) return;

      if (interfaces.length === 0) {
        this._ifaceSelect.innerHTML = '<option value="">No interfaces found</option>';
        return;
      }

      this._ifaceSelect.innerHTML = '<option value="">Select interface…</option>' +
        interfaces.map(iface => {
          const displayName = iface.display_name || iface.name;
          const ip = iface.ipv4 || iface.address || '';
          const label = displayName + (ip ? ` (${ip})` : '');
          const value = iface.scapy_name || iface.name;
          return `<option value="${this._escapeHtml(value)}">${this._escapeHtml(label)}</option>`;
        }).join('');

      // Re-enable toggle if we have a pre-selected interface
      if (this._selectedInterface) {
        this._ifaceSelect.value = this._selectedInterface;
      }

      this._toggleBtn.disabled = !this._ifaceSelect.value;

    } catch (err) {
      console.error('[MonitorPanel] Failed to load interfaces:', err);
      if (this._ifaceSelect) {
        this._ifaceSelect.innerHTML = '<option value="">Failed to load interfaces</option>';
      }
    }
  }

  // -------------------------------------------------------------------------
  // IOC Database
  // -------------------------------------------------------------------------

  async _loadIOCStatus() {
    try {
      const resp = await fetch(`${this._apiBase}/ioc/status`);
      if (!resp.ok) return;
      const json = await resp.json();
      const data = json.data || {};
      const inMem = data.in_memory || {};

      if (this._iocCountEl) {
        this._iocCountEl.textContent = this._formatNumber(inMem.indicator_count || data.total_count || 0);
      }

      if (this._iocUpdatedEl) {
        const updated = inMem.last_updated || data.last_updated;
        this._iocUpdatedEl.textContent = updated ? this._formatDate(updated) : 'Never';
      }

      if (this._iocStatusDot && this._iocStatusText) {
        const count = inMem.indicator_count || data.total_count || 0;
        if (count > 0) {
          this._iocStatusDot.className = 'mp-ioc-status-dot mp-ioc-status-dot--ok';
          this._iocStatusText.textContent = 'Loaded';
        } else {
          this._iocStatusDot.className = 'mp-ioc-status-dot mp-ioc-status-dot--warn';
          this._iocStatusText.textContent = 'No indicators';
        }
      }

    } catch (err) {
      console.error('[MonitorPanel] IOC status load failed:', err);
      if (this._iocStatusText) this._iocStatusText.textContent = 'Unavailable';
    }
  }

  async _refreshIOC() {
    if (!this._iocRefreshBtn) return;
    this._iocRefreshBtn.disabled = true;
    this._iocRefreshBtn.textContent = 'Refreshing…';
    this._hideIOCMessage();

    try {
      const resp = await fetch(`${this._apiBase}/ioc/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json = await resp.json();
      const data = json.data || {};

      this._showIOCMessage(`Loaded ${data.loaded_count || 0} indicators (${data.inserted || 0} new, ${data.updated || 0} updated)`, 'success');
      await this._loadIOCStatus();

    } catch (err) {
      console.error('[MonitorPanel] IOC refresh failed:', err);
      this._showIOCMessage('Refresh failed: ' + err.message, 'error');
    } finally {
      if (this._iocRefreshBtn) {
        this._iocRefreshBtn.disabled = false;
        this._iocRefreshBtn.innerHTML = `
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="23 4 23 10 17 10"/>
            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
          </svg>
          Refresh`;
      }
    }
  }

  _showIOCMessage(msg, type) {
    if (!this._iocMessage) return;
    this._iocMessage.textContent = msg;
    this._iocMessage.className = `mp-ioc-message mp-ioc-message--${type}`;
    this._iocMessage.hidden = false;
    setTimeout(() => this._hideIOCMessage(), 5000);
  }

  _hideIOCMessage() {
    if (this._iocMessage) {
      this._iocMessage.hidden = true;
      this._iocMessage.textContent = '';
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  _formatNumber(n) {
    if (n === null || n === undefined) return '0';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 10_000) return (n / 1000).toFixed(1) + 'K';
    return String(n);
  }

  _formatDate(isoString) {
    if (!isoString) return '—';
    try {
      const d = new Date(isoString);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
      return isoString;
    }
  }

  _escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // -------------------------------------------------------------------------
  // Styles injection
  // -------------------------------------------------------------------------

  _injectStyles() {
    if (document.getElementById('monitor-panel-styles')) return;

    const style = document.createElement('style');
    style.id = 'monitor-panel-styles';
    style.textContent = `
      /* ── Monitor Layout ──────────────────────────────────────────── */
      .monitor-layout {
        display: grid;
        grid-template-columns: 1fr;
        gap: 14px;
        height: 100%;
        min-height: 0;
        align-items: start;
      }

      /* Two-column on wider viewports */
      @media (min-width: 900px) {
        .monitor-layout {
          grid-template-columns: 1fr 0.6fr;
          align-items: stretch;
        }
      }

      .monitor-col {
        display: flex;
        flex-direction: column;
        gap: 12px;
        min-height: 0;
      }
      .monitor-col--feed {
        min-height: 400px;
        height: 100%;
      }
      .monitor-col--panel {
        overflow-y: auto;
        scrollbar-width: thin;
        scrollbar-color: rgba(255,255,255,0.06) transparent;
        padding-bottom: 16px;
      }
      .monitor-col--panel::-webkit-scrollbar { width: 4px; }
      .monitor-col--panel::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 2px; }

      /* ── WebSocket Status Bar ─────────────────────────────────────── */
      .mp-ws-bar {
        display: flex;
        align-items: center;
        gap: 7px;
        padding: 7px 14px;
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 10px;
        color: rgba(255,255,255,0.4);
        letter-spacing: 0.04em;
      }
      .mp-ws-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        flex-shrink: 0;
        background: rgba(255,255,255,0.15);
        transition: background 0.3s;
      }
      .mp-ws-dot--connected {
        background: #10b981;
        box-shadow: 0 0 6px rgba(16,185,129,0.5);
        animation: mp-ws-pulse 2.5s ease-in-out infinite;
      }
      .mp-ws-dot--connecting,
      .mp-ws-dot--reconnecting {
        background: #f59e0b;
        animation: mp-ws-blink 0.8s ease-in-out infinite;
      }
      .mp-ws-dot--disconnected { background: #ef4444; }

      @keyframes mp-ws-pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(16,185,129,0); }
        50% { box-shadow: 0 0 0 4px rgba(16,185,129,0.15); }
      }
      @keyframes mp-ws-blink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.3; }
      }

      /* ── Cards ───────────────────────────────────────────────────── */
      .mp-control-card,
      .mp-card {
        background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 10px;
        padding: 14px 16px;
        font-family: 'JetBrains Mono', monospace;
      }

      .mp-control-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 12px;
      }
      .mp-section-label {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.55);
      }
      .mp-section-label svg { color: #3b82f6; opacity: 0.8; }

      .mp-card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 12px;
      }
      .mp-card-sub {
        font-size: 10px;
        color: rgba(255,255,255,0.25);
        letter-spacing: 0.03em;
      }

      /* ── Status indicator ─────────────────────────────────────────── */
      .mp-status-indicator {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .mp-status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: rgba(255,255,255,0.15);
        flex-shrink: 0;
        transition: background 0.3s;
      }
      .mp-status-dot--active {
        background: #10b981;
        box-shadow: 0 0 0 0 rgba(16,185,129,0.4);
        animation: mp-active-pulse 1.8s ease-in-out infinite;
      }
      .mp-status-dot--stopped { background: rgba(255,255,255,0.15); }

      @keyframes mp-active-pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(16,185,129,0); }
        50% { box-shadow: 0 0 0 5px rgba(16,185,129,0.2); }
      }

      .mp-status-text {
        font-size: 10px;
        font-weight: 500;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.4);
      }

      /* ── Interface select ─────────────────────────────────────────── */
      .mp-iface-row {
        display: flex;
        flex-direction: column;
        gap: 5px;
        margin-bottom: 12px;
      }
      .mp-label {
        font-size: 10px;
        font-weight: 500;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.35);
      }
      .mp-iface-select {
        width: 100%;
        background: rgba(0,0,0,0.2);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 6px;
        color: rgba(255,255,255,0.7);
        font-family: inherit;
        font-size: 12px;
        padding: 7px 10px;
        outline: none;
        cursor: pointer;
        transition: border-color 0.2s;
        -webkit-appearance: none;
      }
      .mp-iface-select:hover,
      .mp-iface-select:focus { border-color: rgba(59,130,246,0.4); }
      .mp-iface-select option { background: #111827; }

      /* ── Toggle button ────────────────────────────────────────────── */
      .mp-toggle-btn {
        width: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 11px 20px;
        border-radius: 8px;
        border: none;
        font-family: inherit;
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 0.04em;
        cursor: pointer;
        transition: all 0.2s;
        position: relative;
        overflow: hidden;
      }
      .mp-toggle-btn::before {
        content: '';
        position: absolute;
        inset: 0;
        background: rgba(255,255,255,0);
        transition: background 0.15s;
      }
      .mp-toggle-btn:hover::before { background: rgba(255,255,255,0.06); }
      .mp-toggle-btn:active::before { background: rgba(0,0,0,0.1); }

      .mp-toggle-btn--start {
        background: linear-gradient(135deg, #059669 0%, #10b981 100%);
        color: #fff;
        box-shadow: 0 4px 14px rgba(16,185,129,0.2), 0 1px 3px rgba(0,0,0,0.3);
      }
      .mp-toggle-btn--start:hover:not(:disabled) {
        box-shadow: 0 6px 20px rgba(16,185,129,0.35), 0 2px 4px rgba(0,0,0,0.3);
        transform: translateY(-1px);
      }
      .mp-toggle-btn--stop {
        background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%);
        color: #fff;
        box-shadow: 0 4px 14px rgba(239,68,68,0.25), 0 1px 3px rgba(0,0,0,0.3);
      }
      .mp-toggle-btn--stop:hover {
        box-shadow: 0 6px 20px rgba(239,68,68,0.4), 0 2px 4px rgba(0,0,0,0.3);
        transform: translateY(-1px);
      }
      .mp-toggle-btn--loading {
        background: rgba(255,255,255,0.07);
        color: rgba(255,255,255,0.4);
        cursor: wait;
        border: 1px solid rgba(255,255,255,0.1);
      }
      .mp-toggle-btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none !important; }

      .mp-btn-spinner {
        display: inline-block;
        width: 14px;
        height: 14px;
        border: 2px solid rgba(255,255,255,0.2);
        border-top-color: rgba(255,255,255,0.7);
        border-radius: 50%;
        animation: mp-spin 0.7s linear infinite;
      }
      @keyframes mp-spin { to { transform: rotate(360deg); } }

      /* ── Error message ────────────────────────────────────────────── */
      .mp-error {
        margin-top: 8px;
        padding: 8px 10px;
        background: rgba(239,68,68,0.1);
        border: 1px solid rgba(239,68,68,0.25);
        border-radius: 6px;
        font-size: 11px;
        color: #fca5a5;
        line-height: 1.5;
      }

      /* ── Live stats grid ──────────────────────────────────────────── */
      .mp-stats-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
      }
      .mp-stat-card {
        background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 8px;
        padding: 10px 12px;
        font-family: 'JetBrains Mono', monospace;
      }
      .mp-stat-card--alert {
        border-color: rgba(245,158,11,0.15);
        background: rgba(245,158,11,0.04);
      }
      .mp-stat-label {
        font-size: 9px;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.3);
        margin-bottom: 4px;
      }
      .mp-stat-big {
        font-size: 22px;
        font-weight: 700;
        color: rgba(255,255,255,0.85);
        font-variant-numeric: tabular-nums;
        line-height: 1;
        transition: color 0.3s;
      }
      .mp-stat-mono { letter-spacing: -0.02em; font-size: 17px; }
      .mp-stat-big--alert { color: #fbbf24; }

      .mp-stat-bump {
        animation: mp-bump 0.3s ease;
      }
      @keyframes mp-bump {
        0% { transform: scale(1); }
        40% { transform: scale(1.12); }
        100% { transform: scale(1); }
      }

      /* ── Top Talkers bar chart ────────────────────────────────────── */
      .mp-bar-chart {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .mp-chart-empty {
        font-size: 11px;
        color: rgba(255,255,255,0.2);
        text-align: center;
        padding: 12px 0;
        font-family: 'JetBrains Mono', monospace;
      }
      .mp-bar-row {
        display: grid;
        grid-template-columns: 110px 1fr 44px;
        align-items: center;
        gap: 8px;
        animation: mp-bar-in 0.3s ease both;
      }
      @keyframes mp-bar-in {
        from { opacity: 0; transform: translateX(-6px); }
        to { opacity: 1; transform: translateX(0); }
      }
      .mp-bar-ip {
        font-family: 'JetBrains Mono', monospace;
        font-size: 10px;
        color: rgba(255,255,255,0.55);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .mp-bar-track {
        height: 6px;
        background: rgba(255,255,255,0.05);
        border-radius: 3px;
        overflow: hidden;
      }
      .mp-bar-fill {
        height: 100%;
        background: linear-gradient(90deg, #3b82f6 0%, #60a5fa 100%);
        border-radius: 3px;
        transition: width 0.4s ease;
        min-width: 3px;
      }
      /* Highlight top talker */
      .mp-bar-row:first-child .mp-bar-fill {
        background: linear-gradient(90deg, #2563eb 0%, #3b82f6 60%, #7dd3fc 100%);
      }
      .mp-bar-count {
        font-family: 'JetBrains Mono', monospace;
        font-size: 10px;
        color: rgba(255,255,255,0.4);
        text-align: right;
        font-variant-numeric: tabular-nums;
      }

      /* ── Protocol distribution ───────────────────────────────────── */
      .mp-proto-bars {
        display: flex;
        flex-direction: column;
        gap: 7px;
      }
      .mp-proto-row {
        display: grid;
        grid-template-columns: 44px 1fr 34px;
        align-items: center;
        gap: 8px;
      }
      .mp-proto-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 10px;
        font-weight: 600;
        color: rgba(255,255,255,0.45);
        letter-spacing: 0.05em;
      }
      .mp-proto-bar-wrap {
        height: 5px;
        background: rgba(255,255,255,0.05);
        border-radius: 3px;
        overflow: hidden;
      }
      .mp-proto-bar {
        height: 100%;
        border-radius: 3px;
        transition: width 0.5s ease;
        min-width: 0;
      }
      .mp-proto-bar--tcp { background: #3b82f6; }
      .mp-proto-bar--udp { background: #8b5cf6; }
      .mp-proto-bar--dns { background: #10b981; }
      .mp-proto-bar--other { background: rgba(255,255,255,0.2); }
      .mp-proto-pct {
        font-family: 'JetBrains Mono', monospace;
        font-size: 9px;
        color: rgba(255,255,255,0.35);
        text-align: right;
        font-variant-numeric: tabular-nums;
      }

      /* ── IOC Database ─────────────────────────────────────────────── */
      .mp-ioc-stats {
        display: flex;
        flex-direction: column;
        gap: 7px;
        margin-bottom: 10px;
      }
      .mp-ioc-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .mp-ioc-label {
        font-size: 10px;
        font-weight: 500;
        letter-spacing: 0.05em;
        color: rgba(255,255,255,0.3);
      }
      .mp-ioc-val {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        font-weight: 600;
        color: rgba(255,255,255,0.7);
        font-variant-numeric: tabular-nums;
      }
      .mp-ioc-time { font-size: 10px; color: rgba(255,255,255,0.45); }

      .mp-ioc-status {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .mp-ioc-status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: rgba(255,255,255,0.15);
        flex-shrink: 0;
        transition: background 0.3s;
      }
      .mp-ioc-status-dot--ok { background: #10b981; box-shadow: 0 0 5px rgba(16,185,129,0.4); }
      .mp-ioc-status-dot--warn { background: #f59e0b; box-shadow: 0 0 5px rgba(245,158,11,0.3); }
      .mp-ioc-status-dot--error { background: #ef4444; }

      #mp-ioc-status-text {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: rgba(255,255,255,0.55);
      }

      .mp-ioc-refresh-btn {
        display: flex;
        align-items: center;
        gap: 5px;
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 6px;
        color: rgba(255,255,255,0.5);
        font-family: inherit;
        font-size: 10px;
        padding: 4px 8px;
        cursor: pointer;
        transition: all 0.15s;
        letter-spacing: 0.04em;
      }
      .mp-ioc-refresh-btn:hover:not(:disabled) {
        background: rgba(59,130,246,0.1);
        border-color: rgba(59,130,246,0.3);
        color: #93c5fd;
      }
      .mp-ioc-refresh-btn:disabled { opacity: 0.4; cursor: wait; }

      .mp-ioc-message {
        padding: 7px 10px;
        border-radius: 6px;
        font-size: 10px;
        line-height: 1.5;
        font-family: 'JetBrains Mono', monospace;
      }
      .mp-ioc-message--success {
        background: rgba(16,185,129,0.1);
        border: 1px solid rgba(16,185,129,0.2);
        color: #6ee7b7;
      }
      .mp-ioc-message--error {
        background: rgba(239,68,68,0.1);
        border: 1px solid rgba(239,68,68,0.2);
        color: #fca5a5;
      }
    `;

    document.head.appendChild(style);
  }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MonitorPanel;
} else {
  window.MonitorPanel = MonitorPanel;
}
