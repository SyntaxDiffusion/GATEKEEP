/**
 * AlertFeed — real-time scrolling alert list for GATEKEEP.
 *
 * Injects itself into #monitor-tab, manages alert display, filtering,
 * pagination, acknowledgement, and critical-alert audio notifications.
 *
 * Depends on: GatekeepWebSocket (window.GatekeepWebSocket)
 * Styles: injected via _injectStyles() on init
 */

class AlertFeed {
  /**
   * @param {Object} [opts]
   * @param {string} [opts.containerId] - ID of parent element to inject into
   * @param {string} [opts.apiBase]     - REST API base URL
   */
  constructor(opts = {}) {
    this._containerId = opts.containerId || 'tab-monitor';
    this._apiBase = opts.apiBase || 'http://localhost:8443/api/v1';

    // State
    this._alerts = [];               // currently displayed alert objects
    this._filter = 'all';            // 'all' | 'critical' | 'high' | 'medium' | 'low'
    this._totalCount = 0;
    this._criticalCount = 0;
    this._unackedCount = 0;
    this._offset = 0;
    this._pageSize = 25;
    this._loadingMore = false;
    this._hasMore = true;
    this._userScrolledUp = false;
    this._audioEnabled = false;
    this._audioCtx = null;
    this._expandedIds = new Set();

    // DOM refs (populated after mount)
    this._root = null;
    this._listEl = null;
    this._countBadge = null;
    this._totalEl = null;
    this._criticalEl = null;
    this._unackedEl = null;
    this._filterSelect = null;
    this._emptyState = null;
    this._loadMoreBtn = null;
    this._audioToggle = null;
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /**
   * Mount the component into the DOM.
   */
  mount() {
    const parent = document.getElementById(this._containerId);
    if (!parent) {
      console.error(`[AlertFeed] Container #${this._containerId} not found.`);
      return;
    }

    this._injectStyles();

    const wrapper = document.createElement('div');
    wrapper.className = 'af-root';
    wrapper.id = 'alert-feed';
    wrapper.innerHTML = this._template();
    parent.appendChild(wrapper);

    this._root = wrapper;
    this._bindElements();
    this._bindEvents();
    this._loadInitialAlerts();
    this._loadStats();
  }

  /**
   * Receive a new alert from WebSocket (called by MonitorPanel or app).
   * @param {Object} alertData
   */
  handleNewAlert(alertData) {
    // Normalise the WS event shape to the REST alert shape
    const alert = this._normaliseWsAlert(alertData);

    // Update counters
    this._totalCount += 1;
    if (alert.severity === 'critical') this._criticalCount += 1;
    if (!alert.is_acknowledged) this._unackedCount += 1;
    this._updateCounters();

    // Only render if it passes the current filter
    if (this._filter === 'all' || this._filter === alert.severity) {
      this._prependAlert(alert);
    }

    // Critical notifications
    if (alert.severity === 'critical') {
      this._flashCritical(alert.id);
      if (this._audioEnabled) this._playCriticalBeep();
    }
  }

  /**
   * Refresh alert list and stats (e.g. after monitoring stops).
   */
  refresh() {
    this._alerts = [];
    this._offset = 0;
    this._hasMore = true;
    this._listEl.innerHTML = '';
    this._loadInitialAlerts();
    this._loadStats();
  }

  // -------------------------------------------------------------------------
  // Template
  // -------------------------------------------------------------------------

  _template() {
    return `
      <div class="af-header">
        <div class="af-header-left">
          <div class="af-title-row">
            <span class="af-icon-shield">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </span>
            <h2 class="af-title">Alert Feed</h2>
            <span class="af-count-badge" id="af-count-badge">0</span>
          </div>
        </div>
        <div class="af-header-right">
          <button class="af-dismiss-all-btn" id="af-dismiss-all" title="Acknowledge all alerts">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
            <span>Dismiss All</span>
          </button>
          <button class="af-audio-toggle" id="af-audio-toggle" title="Enable audio alerts for critical threats">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/>
              <line x1="23" y1="9" x2="17" y2="15" class="af-mute-line"/>
              <line x1="17" y1="9" x2="23" y2="15" class="af-mute-line"/>
            </svg>
            <span>Audio</span>
          </button>
          <select class="af-filter-select" id="af-filter-select">
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <div class="af-stats-bar">
        <div class="af-stat">
          <span class="af-stat-label">Total</span>
          <span class="af-stat-val" id="af-total">0</span>
        </div>
        <div class="af-stat af-stat--critical">
          <span class="af-stat-label">Critical</span>
          <span class="af-stat-val" id="af-critical">0</span>
        </div>
        <div class="af-stat af-stat--amber">
          <span class="af-stat-label">Unacknowledged</span>
          <span class="af-stat-val" id="af-unacked">0</span>
        </div>
      </div>

      <div class="af-list-container" id="af-list-container">
        <ul class="af-list" id="af-list" role="list" aria-label="Security alerts"></ul>

        <div class="af-empty" id="af-empty" hidden>
          <div class="af-empty-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <polyline points="9 12 11 14 15 10"/>
            </svg>
          </div>
          <p class="af-empty-title">No alerts detected</p>
          <p class="af-empty-sub">Your network looks clean. Alerts will appear here in real-time.</p>
        </div>

        <button class="af-load-more" id="af-load-more" hidden>
          Load more alerts
        </button>

        <div class="af-loading" id="af-loading" hidden>
          <span class="af-spinner"></span>
          <span>Loading alerts…</span>
        </div>
      </div>
    `;
  }

  // -------------------------------------------------------------------------
  // DOM wiring
  // -------------------------------------------------------------------------

  _bindElements() {
    this._listEl = this._root.querySelector('#af-list');
    this._countBadge = this._root.querySelector('#af-count-badge');
    this._totalEl = this._root.querySelector('#af-total');
    this._criticalEl = this._root.querySelector('#af-critical');
    this._unackedEl = this._root.querySelector('#af-unacked');
    this._filterSelect = this._root.querySelector('#af-filter-select');
    this._emptyState = this._root.querySelector('#af-empty');
    this._loadMoreBtn = this._root.querySelector('#af-load-more');
    this._loadingEl = this._root.querySelector('#af-loading');
    this._audioToggle = this._root.querySelector('#af-audio-toggle');
    this._dismissAllBtn = this._root.querySelector('#af-dismiss-all');
    this._listContainer = this._root.querySelector('#af-list-container');
  }

  _bindEvents() {
    // Filter change
    this._filterSelect.addEventListener('change', (e) => {
      this._filter = e.target.value;
      this._resetAndReload();
    });

    // Load more button
    this._loadMoreBtn.addEventListener('click', () => {
      this._loadMoreAlerts();
    });

    // Scroll detection — pause auto-scroll when user scrolls up
    this._listContainer.addEventListener('scroll', () => {
      const { scrollTop, scrollHeight, clientHeight } = this._listContainer;
      // Within 80px of bottom = considered at bottom
      this._userScrolledUp = scrollHeight - scrollTop - clientHeight > 80;
    });

    // Dismiss all button
    if (this._dismissAllBtn) {
      this._dismissAllBtn.addEventListener('click', () => {
        this._dismissAllAlerts();
      });
    }

    // Audio toggle
    this._audioToggle.addEventListener('click', () => {
      this._toggleAudio();
    });

    // Delegate click events on the list
    this._listEl.addEventListener('click', (e) => {
      const ackBtn = e.target.closest('.af-ack-btn');
      if (ackBtn) {
        e.stopPropagation();
        const id = ackBtn.dataset.id;
        if (id) this._acknowledgeAlert(id, ackBtn);
        return;
      }

      const expandBtn = e.target.closest('.af-expand-btn');
      if (expandBtn) {
        e.stopPropagation();
        const id = expandBtn.dataset.id;
        if (id) this._toggleExpand(id);
        return;
      }

      // Click anywhere on the row also expands
      const row = e.target.closest('.af-item');
      if (row) {
        const id = row.dataset.id;
        if (id) this._toggleExpand(id);
      }
    });
  }

  // -------------------------------------------------------------------------
  // Data loading
  // -------------------------------------------------------------------------

  async _loadInitialAlerts() {
    this._setLoading(true);
    try {
      const alerts = await this._fetchAlerts(0, this._pageSize);
      this._alerts = alerts;
      this._offset = alerts.length;
      this._hasMore = alerts.length === this._pageSize;
      this._renderAll();
    } catch (err) {
      console.error('[AlertFeed] Failed to load alerts:', err);
    } finally {
      this._setLoading(false);
    }
  }

  async _loadMoreAlerts() {
    if (this._loadingMore || !this._hasMore) return;
    this._loadingMore = true;
    this._loadMoreBtn.textContent = 'Loading…';
    this._loadMoreBtn.disabled = true;

    try {
      const alerts = await this._fetchAlerts(this._offset, this._pageSize);
      this._offset += alerts.length;
      this._hasMore = alerts.length === this._pageSize;

      for (const alert of alerts) {
        this._alerts.push(alert);
        this._appendAlert(alert);
      }

      this._loadMoreBtn.textContent = 'Load more alerts';
      this._loadMoreBtn.disabled = false;
      this._loadMoreBtn.hidden = !this._hasMore;
    } catch (err) {
      console.error('[AlertFeed] Failed to load more alerts:', err);
      this._loadMoreBtn.textContent = 'Retry';
      this._loadMoreBtn.disabled = false;
    } finally {
      this._loadingMore = false;
    }
  }

  async _loadStats() {
    try {
      const resp = await fetch(`${this._apiBase}/alerts/stats?period=24h`);
      if (!resp.ok) return;
      const json = await resp.json();
      const data = json.data || {};
      this._totalCount = data.total || 0;
      this._criticalCount = (data.by_severity && data.by_severity.critical) || 0;
      this._unackedCount = data.unacknowledged || 0;
      this._updateCounters();
    } catch {
      // Stats are non-critical; fail silently
    }
  }

  async _fetchAlerts(offset, limit) {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (this._filter !== 'all') params.set('severity', this._filter);

    const resp = await fetch(`${this._apiBase}/alerts?${params}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = await resp.json();
    return json.data || [];
  }

  _resetAndReload() {
    this._alerts = [];
    this._offset = 0;
    this._hasMore = true;
    this._listEl.innerHTML = '';
    this._expandedIds.clear();
    this._loadInitialAlerts();
  }

  // -------------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------------

  _renderAll() {
    this._listEl.innerHTML = '';
    if (this._alerts.length === 0) {
      this._emptyState.hidden = false;
      this._loadMoreBtn.hidden = true;
    } else {
      this._emptyState.hidden = true;
      for (const alert of this._alerts) {
        this._appendAlert(alert);
      }
      this._loadMoreBtn.hidden = !this._hasMore;
    }
  }

  /**
   * Prepend a new alert to the top of the list (real-time arrival).
   */
  _prependAlert(alert) {
    this._emptyState.hidden = true;
    const li = this._createAlertEl(alert);
    li.classList.add('af-item--entering');

    this._listEl.insertBefore(li, this._listEl.firstChild);

    // Trigger animation
    requestAnimationFrame(() => {
      li.classList.add('af-item--visible');
    });

    this._alerts.unshift(alert);

    // Auto-scroll to top unless user has scrolled up
    if (!this._userScrolledUp) {
      this._listContainer.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  /**
   * Append an alert at the bottom (pagination).
   */
  _appendAlert(alert) {
    const li = this._createAlertEl(alert);
    li.classList.add('af-item--visible');
    this._listEl.appendChild(li);
  }

  _createAlertEl(alert) {
    const li = document.createElement('li');
    li.className = `af-item af-item--${alert.severity}`;
    li.dataset.id = alert.id;
    li.setAttribute('role', 'listitem');
    li.setAttribute('aria-label', `${alert.severity} alert: ${alert.title}`);

    if (alert.is_acknowledged) li.classList.add('af-item--acked');

    const icon = this._alertIcon(alert.alert_type);
    const relTime = this._relativeTime(alert.created_at);
    const srcIp = alert.source_ip || '—';
    const dstIp = alert.destination_ip || '—';
    const descTruncated = this._truncate(alert.description, 120);

    // Evidence JSON for expanded view
    let evidenceHtml = '';
    if (alert.evidence || alert.ioc_reference) {
      const evidenceData = alert.evidence || alert.ioc_reference || {};
      const evidenceStr = typeof evidenceData === 'string'
        ? evidenceData
        : JSON.stringify(evidenceData, null, 2);
      evidenceHtml = `
        <div class="af-evidence" id="af-evidence-${alert.id}" hidden>
          <div class="af-evidence-label">Evidence</div>
          <pre class="af-evidence-pre">${this._escapeHtml(evidenceStr)}</pre>
        </div>`;
    }

    li.innerHTML = `
      <div class="af-item-stripe"></div>
      <div class="af-item-body">
        <div class="af-item-main">
          <div class="af-item-icon">${icon}</div>
          <div class="af-item-content">
            <div class="af-item-top">
              <span class="af-severity-badge af-severity-badge--${alert.severity}">${alert.severity.toUpperCase()}</span>
              <span class="af-item-title">${this._escapeHtml(alert.title)}</span>
            </div>
            <p class="af-item-desc">${this._escapeHtml(descTruncated)}</p>
            <div class="af-item-meta">
              <span class="af-meta-ip">
                <span class="af-ip-src">${this._escapeHtml(srcIp)}</span>
                <svg class="af-arrow" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
                </svg>
                <span class="af-ip-dst">${this._escapeHtml(dstIp)}</span>
              </span>
              <span class="af-meta-time" title="${this._escapeHtml(alert.created_at || '')}">${relTime}</span>
            </div>
          </div>
        </div>
        <div class="af-item-actions">
          ${!alert.is_acknowledged ? `
            <button class="af-ack-btn" data-id="${alert.id}" title="Acknowledge alert" aria-label="Acknowledge">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            </button>
          ` : `
            <span class="af-acked-mark" title="Acknowledged">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            </span>
          `}
          <button class="af-expand-btn" data-id="${alert.id}" title="Expand details" aria-label="Expand details" aria-expanded="false">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="6 9 12 15 18 9"/>
            </svg>
          </button>
        </div>
      </div>
      ${evidenceHtml}
    `;

    return li;
  }

  // -------------------------------------------------------------------------
  // Interactions
  // -------------------------------------------------------------------------

  async _acknowledgeAlert(id, btn) {
    btn.disabled = true;
    btn.classList.add('af-ack-btn--loading');

    try {
      const resp = await fetch(`${this._apiBase}/alerts/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_acknowledged: true }),
      });

      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

      // Update UI
      const li = this._listEl.querySelector(`[data-id="${id}"]`);
      if (li) {
        li.classList.add('af-item--acked');
        // Replace ack button with acked checkmark
        const actionsEl = li.querySelector('.af-item-actions');
        const ackBtnEl = actionsEl.querySelector('.af-ack-btn');
        if (ackBtnEl) {
          const mark = document.createElement('span');
          mark.className = 'af-acked-mark';
          mark.title = 'Acknowledged';
          mark.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
          actionsEl.replaceChild(mark, ackBtnEl);
        }
      }

      // Update local state
      const alertObj = this._alerts.find(a => a.id === id);
      if (alertObj) alertObj.is_acknowledged = true;

      // Decrement unacked counter
      this._unackedCount = Math.max(0, this._unackedCount - 1);
      this._updateCounters();

    } catch (err) {
      console.error('[AlertFeed] Acknowledge failed:', err);
      btn.disabled = false;
      btn.classList.remove('af-ack-btn--loading');
    }
  }

  async _dismissAllAlerts() {
    if (this._dismissAllBtn) {
      this._dismissAllBtn.disabled = true;
      this._dismissAllBtn.querySelector('span').textContent = 'Dismissing…';
    }

    try {
      const resp = await fetch(`${this._apiBase}/alerts/acknowledge-all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

      // Mark every visible item as acknowledged
      this._listEl.querySelectorAll('.af-item:not(.af-item--acked)').forEach(li => {
        li.classList.add('af-item--acked');
        const actionsEl = li.querySelector('.af-item-actions');
        const ackBtnEl = actionsEl && actionsEl.querySelector('.af-ack-btn');
        if (ackBtnEl) {
          const mark = document.createElement('span');
          mark.className = 'af-acked-mark';
          mark.title = 'Acknowledged';
          mark.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
          actionsEl.replaceChild(mark, ackBtnEl);
        }
      });

      // Update local state
      this._alerts.forEach(a => { a.is_acknowledged = true; });
      this._unackedCount = 0;
      this._updateCounters();

    } catch (err) {
      console.error('[AlertFeed] Dismiss all failed:', err);
    } finally {
      if (this._dismissAllBtn) {
        this._dismissAllBtn.disabled = false;
        this._dismissAllBtn.querySelector('span').textContent = 'Dismiss All';
      }
    }
  }

  _toggleExpand(id) {
    const li = this._listEl.querySelector(`[data-id="${id}"]`);
    if (!li) return;

    const evidenceEl = li.querySelector(`#af-evidence-${id}`);
    const expandBtn = li.querySelector('.af-expand-btn');

    if (this._expandedIds.has(id)) {
      this._expandedIds.delete(id);
      li.classList.remove('af-item--expanded');
      if (evidenceEl) evidenceEl.hidden = true;
      if (expandBtn) expandBtn.setAttribute('aria-expanded', 'false');
    } else {
      this._expandedIds.add(id);
      li.classList.add('af-item--expanded');
      if (evidenceEl) evidenceEl.hidden = false;
      if (expandBtn) expandBtn.setAttribute('aria-expanded', 'true');
    }
  }

  _flashCritical(id) {
    const li = this._listEl.querySelector(`[data-id="${id}"]`);
    if (!li) return;
    li.classList.add('af-item--flash');
    setTimeout(() => li.classList.remove('af-item--flash'), 1500);
  }

  // -------------------------------------------------------------------------
  // Audio
  // -------------------------------------------------------------------------

  _toggleAudio() {
    if (!this._audioEnabled) {
      // Initialise AudioContext on user gesture (required by browsers)
      try {
        this._audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        this._audioEnabled = true;
        this._audioToggle.classList.add('af-audio-toggle--on');
        this._audioToggle.title = 'Disable audio alerts';
        // Remove the mute lines
        this._audioToggle.querySelectorAll('.af-mute-line').forEach(l => l.style.display = 'none');
        // Play a soft confirmation tone
        this._playSoftTone(440, 0.1, 0.15);
      } catch {
        console.warn('[AlertFeed] Web Audio API not available.');
      }
    } else {
      this._audioEnabled = false;
      this._audioToggle.classList.remove('af-audio-toggle--on');
      this._audioToggle.title = 'Enable audio alerts for critical threats';
      this._audioToggle.querySelectorAll('.af-mute-line').forEach(l => l.style.display = '');
    }
  }

  _playCriticalBeep() {
    if (!this._audioCtx) return;
    // Two-tone urgent beep
    this._playSoftTone(880, 0.3, 0.1);
    setTimeout(() => this._playSoftTone(1100, 0.25, 0.1), 120);
    setTimeout(() => this._playSoftTone(880, 0.2, 0.1), 240);
  }

  _playSoftTone(freq, gain, duration) {
    if (!this._audioCtx) return;
    try {
      const osc = this._audioCtx.createOscillator();
      const gainNode = this._audioCtx.createGain();
      osc.connect(gainNode);
      gainNode.connect(this._audioCtx.destination);
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, this._audioCtx.currentTime);
      gainNode.gain.setValueAtTime(gain, this._audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.001, this._audioCtx.currentTime + duration);
      osc.start(this._audioCtx.currentTime);
      osc.stop(this._audioCtx.currentTime + duration);
    } catch {
      // Ignore audio errors
    }
  }

  // -------------------------------------------------------------------------
  // Counter updates
  // -------------------------------------------------------------------------

  _updateCounters() {
    const animate = (el, value) => {
      if (!el) return;
      const current = parseInt(el.textContent, 10) || 0;
      if (current !== value) {
        el.classList.add('af-val-bump');
        el.textContent = value;
        el.addEventListener('animationend', () => el.classList.remove('af-val-bump'), { once: true });
      }
    };

    animate(this._countBadge, this._totalCount);
    animate(this._totalEl, this._totalCount);
    animate(this._criticalEl, this._criticalCount);
    animate(this._unackedEl, this._unackedCount);

    // Visual urgency on badge
    if (this._criticalCount > 0) {
      this._countBadge.classList.add('af-count-badge--critical');
    } else {
      this._countBadge.classList.remove('af-count-badge--critical');
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  _setLoading(on) {
    if (this._loadingEl) this._loadingEl.hidden = !on;
  }

  _alertIcon(type) {
    const icons = {
      ioc_match: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
      dns_hijack: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
      dns_tunneling: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
      port_scan: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>`,
      syn_flood: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
    };
    return icons[type] || `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  }

  _truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  _escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  _relativeTime(isoString) {
    if (!isoString) return 'just now';
    const delta = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (delta < 5) return 'just now';
    if (delta < 60) return `${delta}s ago`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
  }

  _normaliseWsAlert(data) {
    // WS event data may be a partial alert object — fill defaults
    return {
      id: data.alert_id || data.id || `ws-${Date.now()}`,
      alert_type: data.type || data.alert_type || 'unknown',
      severity: data.severity || 'low',
      title: data.title || this._titleFromType(data.type),
      description: data.description || '',
      source_ip: data.source_ip || null,
      destination_ip: data.destination_ip || null,
      is_acknowledged: false,
      created_at: data._envelope?.timestamp || new Date().toISOString(),
      evidence: data.evidence || null,
      ioc_reference: data.ioc_reference || null,
    };
  }

  _titleFromType(type) {
    const map = {
      port_scan: 'Port Scan Detected',
      syn_flood: 'SYN Flood Attack Detected',
      dns_tunneling: 'DNS Tunneling Suspected',
      ioc_match: 'IOC Match Detected',
      dns_hijack: 'DNS Hijack Detected',
    };
    return map[type] || `Alert: ${(type || 'Unknown').replace(/_/g, ' ')}`;
  }

  // -------------------------------------------------------------------------
  // Styles injection
  // -------------------------------------------------------------------------

  _injectStyles() {
    if (document.getElementById('alert-feed-styles')) return;

    const style = document.createElement('style');
    style.id = 'alert-feed-styles';
    style.textContent = `
      /* ── Alert Feed Root ─────────────────────────────────────────── */
      .af-root {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px;
        overflow: hidden;
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
      }

      /* ── Header ──────────────────────────────────────────────────── */
      .af-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 18px;
        background: rgba(255,255,255,0.02);
        border-bottom: 1px solid rgba(255,255,255,0.06);
        flex-shrink: 0;
        gap: 12px;
        flex-wrap: wrap;
      }
      .af-header-left { display: flex; align-items: center; gap: 10px; }
      .af-header-right { display: flex; align-items: center; gap: 8px; }

      .af-title-row { display: flex; align-items: center; gap: 8px; }
      .af-icon-shield {
        display: flex;
        align-items: center;
        color: #3b82f6;
        opacity: 0.9;
      }
      .af-title {
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.85);
        margin: 0;
      }
      .af-count-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 20px;
        height: 20px;
        padding: 0 6px;
        border-radius: 10px;
        background: rgba(59,130,246,0.2);
        border: 1px solid rgba(59,130,246,0.35);
        color: #93c5fd;
        font-size: 11px;
        font-weight: 600;
        transition: background 0.3s, border-color 0.3s, color 0.3s;
      }
      .af-count-badge--critical {
        background: rgba(239,68,68,0.25);
        border-color: rgba(239,68,68,0.5);
        color: #fca5a5;
        animation: af-badge-pulse 2s ease-in-out infinite;
      }

      @keyframes af-badge-pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
        50% { box-shadow: 0 0 0 4px rgba(239,68,68,0.2); }
      }

      /* ── Filter & Audio ──────────────────────────────────────────── */
      .af-filter-select {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 6px;
        color: rgba(255,255,255,0.7);
        font-family: inherit;
        font-size: 11px;
        padding: 5px 8px;
        cursor: pointer;
        outline: none;
        transition: border-color 0.2s;
      }
      .af-filter-select:hover,
      .af-filter-select:focus { border-color: rgba(59,130,246,0.5); }
      .af-filter-select option { background: #1a1f36; }

      .af-dismiss-all-btn {
        display: flex;
        align-items: center;
        gap: 5px;
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 6px;
        color: rgba(255,255,255,0.5);
        font-family: inherit;
        font-size: 11px;
        padding: 5px 8px;
        cursor: pointer;
        transition: all 0.2s;
      }
      .af-dismiss-all-btn:hover:not(:disabled) {
        background: rgba(16,185,129,0.1);
        border-color: rgba(16,185,129,0.35);
        color: #6ee7b7;
      }
      .af-dismiss-all-btn:disabled { opacity: 0.5; cursor: wait; }

      .af-audio-toggle {
        display: flex;
        align-items: center;
        gap: 5px;
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 6px;
        color: rgba(255,255,255,0.45);
        font-family: inherit;
        font-size: 11px;
        padding: 5px 8px;
        cursor: pointer;
        transition: all 0.2s;
      }
      .af-audio-toggle:hover { border-color: rgba(255,255,255,0.2); color: rgba(255,255,255,0.65); }
      .af-audio-toggle--on {
        background: rgba(16,185,129,0.1);
        border-color: rgba(16,185,129,0.35);
        color: #6ee7b7;
      }

      /* ── Stats Bar ───────────────────────────────────────────────── */
      .af-stats-bar {
        display: flex;
        align-items: center;
        gap: 0;
        padding: 8px 18px;
        background: rgba(0,0,0,0.15);
        border-bottom: 1px solid rgba(255,255,255,0.04);
        flex-shrink: 0;
      }
      .af-stat {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 0 16px 0 0;
        margin-right: 16px;
        border-right: 1px solid rgba(255,255,255,0.06);
      }
      .af-stat:last-child { border-right: none; margin-right: 0; padding-right: 0; }
      .af-stat-label {
        font-size: 10px;
        font-weight: 500;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.35);
      }
      .af-stat-val {
        font-size: 15px;
        font-weight: 700;
        color: rgba(255,255,255,0.75);
        transition: transform 0.2s;
        font-variant-numeric: tabular-nums;
      }
      .af-stat--critical .af-stat-val { color: #f87171; }
      .af-stat--amber .af-stat-val { color: #fbbf24; }

      /* ── List container ──────────────────────────────────────────── */
      .af-list-container {
        flex: 1;
        overflow-y: auto;
        overflow-x: hidden;
        min-height: 0;
        scrollbar-width: thin;
        scrollbar-color: rgba(255,255,255,0.08) transparent;
      }
      .af-list-container::-webkit-scrollbar { width: 4px; }
      .af-list-container::-webkit-scrollbar-track { background: transparent; }
      .af-list-container::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }

      .af-list {
        list-style: none;
        margin: 0;
        padding: 8px;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }

      /* ── Alert Item ──────────────────────────────────────────────── */
      .af-item {
        position: relative;
        display: flex;
        flex-direction: column;
        border-radius: 8px;
        background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.05);
        overflow: hidden;
        cursor: pointer;
        transition: background 0.15s, border-color 0.15s, transform 0.15s;

        /* Entry animation */
        opacity: 0;
        transform: translateY(-8px) scale(0.99);
      }
      .af-item--visible {
        opacity: 1;
        transform: translateY(0) scale(1);
        transition: opacity 0.25s ease, transform 0.25s ease, background 0.15s, border-color 0.15s;
      }
      .af-item--entering {
        /* Starting state — class removed then re-added in rAF for animation */
      }
      .af-item:hover {
        background: rgba(255,255,255,0.04);
        border-color: rgba(255,255,255,0.09);
      }
      .af-item--acked {
        opacity: 0.5;
      }
      .af-item--expanded { border-color: rgba(59,130,246,0.2); }

      /* Severity stripe — left edge */
      .af-item-stripe {
        position: absolute;
        left: 0; top: 0; bottom: 0;
        width: 3px;
        border-radius: 3px 0 0 3px;
      }
      .af-item--critical .af-item-stripe { background: #ef4444; }
      .af-item--high .af-item-stripe { background: #f97316; }
      .af-item--medium .af-item-stripe { background: #f59e0b; }
      .af-item--low .af-item-stripe { background: #3b82f6; }

      /* Critical flash animation */
      .af-item--flash {
        animation: af-critical-flash 0.4s ease 0s 3;
      }
      @keyframes af-critical-flash {
        0%, 100% { background: rgba(255,255,255,0.025); }
        50% { background: rgba(239,68,68,0.12); border-color: rgba(239,68,68,0.35); }
      }

      .af-item-body {
        display: flex;
        align-items: flex-start;
        gap: 10px;
        padding: 10px 12px 10px 16px;
      }
      .af-item-main {
        display: flex;
        align-items: flex-start;
        gap: 10px;
        flex: 1;
        min-width: 0;
      }
      .af-item-icon {
        flex-shrink: 0;
        margin-top: 1px;
        opacity: 0.6;
        color: rgba(255,255,255,0.7);
      }
      .af-item--critical .af-item-icon { color: #f87171; opacity: 0.9; }
      .af-item--high .af-item-icon { color: #fb923c; opacity: 0.9; }
      .af-item--medium .af-item-icon { color: #fbbf24; opacity: 0.9; }
      .af-item--low .af-item-icon { color: #60a5fa; opacity: 0.9; }

      .af-item-content { flex: 1; min-width: 0; }

      .af-item-top {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 3px;
        flex-wrap: wrap;
      }
      .af-severity-badge {
        display: inline-flex;
        align-items: center;
        padding: 1px 6px;
        border-radius: 3px;
        font-size: 9px;
        font-weight: 700;
        letter-spacing: 0.1em;
        flex-shrink: 0;
      }
      .af-severity-badge--critical { background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); }
      .af-severity-badge--high { background: rgba(249,115,22,0.18); color: #fdba74; border: 1px solid rgba(249,115,22,0.3); }
      .af-severity-badge--medium { background: rgba(245,158,11,0.15); color: #fcd34d; border: 1px solid rgba(245,158,11,0.3); }
      .af-severity-badge--low { background: rgba(59,130,246,0.15); color: #93c5fd; border: 1px solid rgba(59,130,246,0.3); }

      .af-item-title {
        font-size: 12px;
        font-weight: 600;
        color: rgba(255,255,255,0.88);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .af-item-desc {
        font-size: 11px;
        color: rgba(255,255,255,0.45);
        margin: 0 0 5px;
        line-height: 1.5;
        word-break: break-word;
      }
      .af-item-meta {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
      }
      .af-meta-ip {
        display: flex;
        align-items: center;
        gap: 4px;
        font-size: 10px;
        color: rgba(255,255,255,0.38);
      }
      .af-ip-src, .af-ip-dst {
        font-variant-numeric: tabular-nums;
      }
      .af-arrow { opacity: 0.35; flex-shrink: 0; }
      .af-meta-time {
        font-size: 10px;
        color: rgba(255,255,255,0.28);
        margin-left: auto;
        white-space: nowrap;
      }

      /* ── Actions ─────────────────────────────────────────────────── */
      .af-item-actions {
        display: flex;
        align-items: center;
        gap: 4px;
        flex-shrink: 0;
      }
      .af-ack-btn,
      .af-expand-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 26px;
        height: 26px;
        border-radius: 6px;
        border: 1px solid rgba(255,255,255,0.08);
        background: rgba(255,255,255,0.03);
        color: rgba(255,255,255,0.45);
        cursor: pointer;
        transition: all 0.15s;
      }
      .af-ack-btn:hover { background: rgba(16,185,129,0.15); border-color: rgba(16,185,129,0.35); color: #6ee7b7; }
      .af-ack-btn--loading { opacity: 0.5; cursor: wait; }
      .af-acked-mark {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 26px;
        height: 26px;
        color: #10b981;
        opacity: 0.6;
      }
      .af-expand-btn:hover { background: rgba(59,130,246,0.12); border-color: rgba(59,130,246,0.3); color: #93c5fd; }
      .af-item--expanded .af-expand-btn svg {
        transform: rotate(180deg);
      }
      .af-expand-btn svg { transition: transform 0.2s ease; }

      /* ── Evidence Panel ──────────────────────────────────────────── */
      .af-evidence {
        margin: 0 12px 10px 16px;
        border-top: 1px solid rgba(255,255,255,0.05);
        padding-top: 8px;
      }
      .af-evidence-label {
        font-size: 9px;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: rgba(255,255,255,0.3);
        margin-bottom: 6px;
      }
      .af-evidence-pre {
        background: rgba(0,0,0,0.25);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 6px;
        padding: 8px 10px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 10px;
        color: rgba(255,255,255,0.55);
        overflow-x: auto;
        margin: 0;
        line-height: 1.6;
        white-space: pre-wrap;
        word-break: break-all;
      }

      /* ── Empty State ─────────────────────────────────────────────── */
      .af-empty {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 48px 24px;
        gap: 10px;
        text-align: center;
      }
      .af-empty-icon { color: rgba(16,185,129,0.4); }
      .af-empty-title {
        font-size: 14px;
        font-weight: 600;
        color: rgba(255,255,255,0.55);
        margin: 0;
      }
      .af-empty-sub {
        font-size: 12px;
        color: rgba(255,255,255,0.3);
        margin: 0;
      }

      /* ── Load More ───────────────────────────────────────────────── */
      .af-load-more {
        display: block;
        width: calc(100% - 16px);
        margin: 4px 8px 8px;
        padding: 8px;
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 6px;
        color: rgba(255,255,255,0.4);
        font-family: inherit;
        font-size: 11px;
        cursor: pointer;
        transition: all 0.15s;
        text-align: center;
        letter-spacing: 0.04em;
      }
      .af-load-more:hover:not(:disabled) {
        background: rgba(59,130,246,0.08);
        border-color: rgba(59,130,246,0.25);
        color: rgba(147,197,253,0.8);
      }
      .af-load-more:disabled { cursor: wait; }

      /* ── Loading ─────────────────────────────────────────────────── */
      .af-loading {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 24px;
        color: rgba(255,255,255,0.35);
        font-size: 12px;
      }
      .af-spinner {
        width: 14px;
        height: 14px;
        border: 2px solid rgba(255,255,255,0.1);
        border-top-color: rgba(59,130,246,0.7);
        border-radius: 50%;
        animation: af-spin 0.7s linear infinite;
        flex-shrink: 0;
      }
      @keyframes af-spin { to { transform: rotate(360deg); } }

      /* ── Counter bump animation ──────────────────────────────────── */
      .af-val-bump {
        animation: af-bump 0.3s ease;
      }
      @keyframes af-bump {
        0% { transform: scale(1); }
        50% { transform: scale(1.25); }
        100% { transform: scale(1); }
      }
    `;

    document.head.appendChild(style);
  }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AlertFeed;
} else {
  window.AlertFeed = AlertFeed;
}
