/* ===================================================================
   GATEKEEP — Main Application Controller
   Initializes all components, manages navigation, WebSocket
   connection, settings, and the toast notification system.
   =================================================================== */

'use strict';

class GatekeepApp {
  constructor() {
    // Component references
    this.scanControls = null;
    this.deviceGrid = null;
    this.networkMap = null;

    // WebSocket — uses GatekeepWebSocket if available, falls back to raw WS
    this.ws = null;
    this.wsReconnectTimer = null;
    this.wsReconnectDelay = 2000;
    this.wsMaxReconnectDelay = 30000;
    this.gatekeepWS = null; // shared GatekeepWebSocket instance

    // Toast
    this.toastCounter = 0;

    // State
    this.activeTab = 'scan';
    this.systemHealth = null;
  }

  /**
   * Bootstrap the application.
   */
  async init() {
    // Initialize components
    this.networkMap = new NetworkMap();
    window.networkMap = this.networkMap;

    this.deviceGrid = new DeviceGrid();
    window.deviceGrid = this.deviceGrid;

    this.scanControls = new ScanControls();
    window.scanControls = this.scanControls;

    // Bind navigation
    this._bindNavigation();

    // Bind settings modal
    this._bindSettings();

    // Bind global error handler
    this._bindErrorHandler();

    // Fetch system health
    await this._fetchSystemHealth();

    // Populate interface selector
    await this._populateInterfaces();

    // Connect WebSocket
    this._connectWebSocket();

    // Initialize Phase 2/3 components if available
    this._initPhaseComponents();

    console.log('[GATEKEEP] Application initialized');
  }

  // -----------------------------------------------------------------
  //  Navigation
  // -----------------------------------------------------------------

  _bindNavigation() {
    const tabs = document.querySelectorAll('.tab[data-tab]');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const tabName = tab.dataset.tab;
        this._switchTab(tabName);
      });
    });
  }

  _switchTab(tabName) {
    this.activeTab = tabName;

    // Update tab buttons
    document.querySelectorAll('.tab[data-tab]').forEach(btn => {
      const isActive = btn.dataset.tab === tabName;
      btn.classList.toggle('tab--active', isActive);
      btn.setAttribute('aria-selected', String(isActive));
    });

    // Update tab content panels
    document.querySelectorAll('.tab-content').forEach(panel => {
      const isActive = panel.id === `tab-${tabName}`;
      panel.classList.toggle('tab-content--active', isActive);
    });
  }

  // -----------------------------------------------------------------
  //  System Health
  // -----------------------------------------------------------------

  async _fetchSystemHealth() {
    try {
      const health = await api.getSystemHealth();
      this.systemHealth = health;
      this._renderSystemStatus(health);
    } catch (err) {
      console.warn('[GATEKEEP] Failed to fetch system health:', err.message);
      this._renderSystemStatusOffline();
    }
  }

  _renderSystemStatus(health) {
    // Version
    const versionEl = document.getElementById('app-version');
    if (versionEl) {
      versionEl.textContent = `GATEKEEP v${health.version || '?'}`;
    }

    // Privilege level
    const privValue = document.getElementById('privilege-level');
    const privDot = document.querySelector('#status-privilege .status-dot');
    if (privValue && health.privileges) {
      const level = health.privileges.toLowerCase();
      privValue.textContent = this._capitalizeFirst(level);
      if (privDot) {
        privDot.className = 'status-dot';
        if (level === 'admin' || level === 'root') {
          privDot.classList.add('status-dot--green');
        } else if (level === 'standard' || level === 'user') {
          privDot.classList.add('status-dot--amber');
        } else {
          privDot.classList.add('status-dot--neutral');
        }
      }
    }

    // Npcap
    const npcapValue = document.getElementById('npcap-status');
    const npcapDot = document.querySelector('#status-npcap .status-dot');
    if (npcapValue) {
      npcapValue.textContent = health.npcap_available ? 'Ready' : 'Missing';
      if (npcapDot) {
        npcapDot.className = 'status-dot';
        npcapDot.classList.add(health.npcap_available ? 'status-dot--green' : 'status-dot--red');
      }
    }

    // Database
    const dbValue = document.getElementById('db-status');
    const dbDot = document.querySelector('#status-db .status-dot');
    if (dbValue) {
      dbValue.textContent = health.database_status === 'ok' ? 'OK' : 'Degraded';
      if (dbDot) {
        dbDot.className = 'status-dot';
        dbDot.classList.add(health.database_status === 'ok' ? 'status-dot--green' : 'status-dot--amber');
      }
    }

    // AI
    const aiValue = document.getElementById('ai-status');
    const aiDot = document.querySelector('#status-ai .status-dot');
    if (aiValue) {
      aiValue.textContent = health.ai_available ? 'Ready' : 'Unavailable';
      if (aiDot) {
        aiDot.className = 'status-dot';
        aiDot.classList.add(health.ai_available ? 'status-dot--green' : 'status-dot--amber');
      }
    }
  }

  _renderSystemStatusOffline() {
    ['privilege-level', 'npcap-status', 'db-status', 'ai-status'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '--';
    });

    document.querySelectorAll('.header__status-item .status-dot').forEach(dot => {
      dot.className = 'status-dot status-dot--neutral';
    });
  }

  // -----------------------------------------------------------------
  //  Interface Selector
  // -----------------------------------------------------------------

  async _populateInterfaces() {
    try {
      const interfaces = await api.getInterfaces();
      const select = document.getElementById('scan-interface');
      if (!select || !interfaces) return;

      // Keep the default "Auto-detect" option
      interfaces.forEach(iface => {
        const option = document.createElement('option');
        option.value = iface.scapy_name || iface.name || '';
        const displayName = iface.display_name || iface.name || 'Unknown';
        const ip = iface.ipv4 || iface.ip || '';
        const subnet = iface.subnet || '';
        option.textContent = `${displayName}${ip ? ` (${ip})` : ''}${subnet ? ` - ${subnet}` : ''}`;
        select.appendChild(option);
      });
    } catch (err) {
      console.warn('[GATEKEEP] Failed to load interfaces:', err.message);
    }
  }

  // -----------------------------------------------------------------
  //  Settings Modal
  // -----------------------------------------------------------------

  _bindSettings() {
    const btnOpen = document.getElementById('btn-settings');
    const btnClose = document.getElementById('btn-close-settings');
    const overlay = document.getElementById('settings-modal');
    const btnCheck = document.getElementById('btn-check-status');

    if (btnOpen) {
      btnOpen.addEventListener('click', () => {
        overlay.classList.remove('hidden');
        this._refreshSettingsStatus();
      });
    }

    if (btnClose) {
      btnClose.addEventListener('click', () => {
        overlay.classList.add('hidden');
      });
    }

    // Close on overlay click
    if (overlay) {
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.classList.add('hidden');
      });
    }

    // Close on Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !overlay.classList.contains('hidden')) {
        overlay.classList.add('hidden');
      }
    });

    // Check status button
    if (btnCheck) {
      btnCheck.addEventListener('click', async () => {
        btnCheck.disabled = true;
        btnCheck.textContent = 'Checking...';
        try {
          await this._refreshSettingsStatus();
          this._showFeedback('Status refreshed.', 'success');
        } catch (err) {
          this._showFeedback(`Status check failed: ${err.message}`, 'error');
        } finally {
          btnCheck.disabled = false;
          btnCheck.textContent = 'Refresh Status';
        }
      });
    }
  }

  async _refreshSettingsStatus() {
    const aiStatusEl = document.getElementById('settings-ai-status');
    const dbStatusEl = document.getElementById('settings-db-status');
    const npcapStatusEl = document.getElementById('settings-npcap-status');
    const versionEl = document.getElementById('settings-version');

    try {
      const health = await api.getSystemHealth();

      if (aiStatusEl) {
        aiStatusEl.textContent = health.ai_available
          ? 'Connected via Claude Code'
          : 'Claude Agent SDK not available';
        aiStatusEl.className = 'settings-status__value ' +
          (health.ai_available ? 'settings-status__value--ok' : 'settings-status__value--warn');
      }
      if (dbStatusEl) {
        dbStatusEl.textContent = health.database_status === 'ok' ? 'OK' : 'Degraded';
      }
      if (npcapStatusEl) {
        npcapStatusEl.textContent = health.npcap_available ? 'Installed' : 'Not found';
      }
      if (versionEl) {
        versionEl.textContent = health.version || '?';
      }
    } catch {
      if (aiStatusEl) {
        aiStatusEl.textContent = 'Server unreachable';
        aiStatusEl.className = 'settings-status__value settings-status__value--warn';
      }
    }
  }

  _showFeedback(message, type) {
    const el = document.getElementById('settings-feedback');
    if (!el) return;
    el.textContent = message;
    el.className = `modal__feedback modal__feedback--${type}`;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 5000);
  }

  // -----------------------------------------------------------------
  //  WebSocket Connection
  // -----------------------------------------------------------------

  _connectWebSocket() {
    // Prefer the full-featured GatekeepWebSocket class if loaded
    if (typeof GatekeepWebSocket !== 'undefined') {
      this._connectGatekeepWS();
      return;
    }

    // Fallback: raw WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/events`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('[GATEKEEP] WebSocket connected');
        this.wsReconnectDelay = 2000;
        this._updateWSStatus(true);

        this.ws.send(JSON.stringify({
          type: 'subscribe',
          channels: ['scan_progress', 'alerts', 'system'],
        }));
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this._handleWSEvent(data);
        } catch {
          // Non-JSON message, ignore
        }
      };

      this.ws.onclose = (event) => {
        console.log('[GATEKEEP] WebSocket closed:', event.code);
        this._updateWSStatus(false);
        this._scheduleReconnect();
      };

      this.ws.onerror = () => {
        this._updateWSStatus(false);
      };
    } catch (err) {
      console.warn('[GATEKEEP] WebSocket error:', err.message);
      this._updateWSStatus(false);
      this._scheduleReconnect();
    }
  }

  /**
   * Connect using the shared GatekeepWebSocket class (provides
   * reconnection, queuing, and event routing that Phase 2/3
   * components also depend on).
   */
  _connectGatekeepWS() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/events`;

    this.gatekeepWS = new GatekeepWebSocket(wsUrl);
    window.gatekeepWS = this.gatekeepWS; // expose for Phase 2/3 components

    this.gatekeepWS.onConnectionChange((status) => {
      this._updateWSStatus(status === 'connected');
    });

    // Scan progress events -> ScanControls
    this.gatekeepWS.onScanProgress((event) => {
      const type = event._eventType || event.type;
      this.scanControls?.handleWSEvent({ type, data: event });
    });

    // Alert events -> toast
    this.gatekeepWS.onAlert((event) => {
      const type = event._eventType || 'alert_new';
      if (type === 'alert_new') {
        const severity = event.severity || 'info';
        this.toast(
          `Alert: ${event.title || 'New Alert'}`,
          event.description || '',
          severity === 'critical' || severity === 'high' ? 'error' : 'warning'
        );
      }
    });

    this.gatekeepWS.subscribe(['scan_progress', 'alerts', 'system']);
    this.gatekeepWS.connect();
  }

  _scheduleReconnect() {
    if (this.wsReconnectTimer) return;
    this.wsReconnectTimer = setTimeout(() => {
      this.wsReconnectTimer = null;
      this._connectWebSocket();
    }, this.wsReconnectDelay);
    this.wsReconnectDelay = Math.min(this.wsReconnectDelay * 1.5, this.wsMaxReconnectDelay);
  }

  _updateWSStatus(connected) {
    const dot = document.getElementById('ws-dot');
    const label = document.getElementById('ws-status');
    if (dot) {
      dot.className = 'status-dot';
      dot.classList.add(connected ? 'status-dot--green' : 'status-dot--neutral');
    }
    if (label) {
      label.textContent = connected ? 'Connected' : 'Offline';
    }
  }

  _handleWSEvent(event) {
    if (!event || !event.type) return;

    if (event.type.startsWith('scan_')) {
      this.scanControls?.handleWSEvent(event);
    }

    if (event.type === 'alert_new') {
      const data = event.data || {};
      const severity = data.severity || 'info';
      this.toast(
        `Alert: ${data.title || 'New Alert'}`,
        data.description || '',
        severity === 'critical' || severity === 'high' ? 'error' : 'warning'
      );
    }

    if (event.type === 'system_ping') {
      this.ws?.send(JSON.stringify({ type: 'pong' }));
    }
  }

  // -----------------------------------------------------------------
  //  Phase 2/3 Component Initialization
  // -----------------------------------------------------------------

  _initPhaseComponents() {
    // Initialize Phase 2 components if scripts are loaded
    try {
      if (typeof MonitorPanel !== 'undefined') {
        const monitorPanel = new MonitorPanel({
          containerId: 'tab-monitor',
          ws: this.gatekeepWS,
        });
        monitorPanel.mount();
      }
    } catch (err) {
      console.warn('[GATEKEEP] MonitorPanel init skipped:', err.message);
    }

    try {
      if (typeof AlertFeed !== 'undefined') {
        const alertFeed = new AlertFeed({
          containerId: 'tab-monitor',
        });
        alertFeed.mount();
      }
    } catch (err) {
      console.warn('[GATEKEEP] AlertFeed init skipped:', err.message);
    }

    try {
      if (typeof HardeningPanel !== 'undefined') {
        // HardeningPanel auto-initializes via IIFE
      }
    } catch (err) {
      console.warn('[GATEKEEP] HardeningPanel init skipped:', err.message);
    }
  }

  // -----------------------------------------------------------------
  //  Toast Notification System
  // -----------------------------------------------------------------

  /**
   * Show a toast notification.
   * @param {string} title
   * @param {string} message
   * @param {'info'|'success'|'warning'|'error'} [type='info']
   * @param {number} [duration=5000]  Auto-dismiss time in ms (0 = persistent)
   */
  toast(title, message, type = 'info', duration = 5000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const id = `toast-${++this.toastCounter}`;

    const iconMap = {
      info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
      success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
      warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
      error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    };

    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.id = id;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
      <span class="toast__icon">${iconMap[type] || iconMap.info}</span>
      <div class="toast__content">
        <div class="toast__title">${escapeHtml(title)}</div>
        ${message ? `<div class="toast__message">${escapeHtml(message)}</div>` : ''}
      </div>
      <button class="toast__close" onclick="window.app?.dismissToast('${id}')" aria-label="Dismiss notification">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
      </button>`;

    container.appendChild(toast);

    // Auto-dismiss
    if (duration > 0) {
      setTimeout(() => this.dismissToast(id), duration);
    }

    // Cap at 5 visible toasts
    const toasts = container.querySelectorAll('.toast:not(.toast--removing)');
    if (toasts.length > 5) {
      this.dismissToast(toasts[0].id);
    }
  }

  /**
   * Dismiss a specific toast by ID.
   * @param {string} id
   */
  dismissToast(id) {
    const toast = document.getElementById(id);
    if (!toast) return;
    toast.classList.add('toast--removing');
    setTimeout(() => toast.remove(), 200);
  }

  // -----------------------------------------------------------------
  //  Global Error Handler
  // -----------------------------------------------------------------

  _bindErrorHandler() {
    window.addEventListener('unhandledrejection', (event) => {
      console.error('[GATEKEEP] Unhandled rejection:', event.reason);
      const message = event.reason?.message || String(event.reason);
      // Avoid noisy network errors from WS reconnects
      if (!message.includes('WebSocket') && !message.includes('fetch')) {
        this.toast('Error', message, 'error');
      }
    });
  }

  // -----------------------------------------------------------------
  //  Helpers
  // -----------------------------------------------------------------

  _capitalizeFirst(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
}


/* ===================================================================
   BOOTSTRAP
   =================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  const app = new GatekeepApp();
  window.app = app;
  app.init().catch(err => {
    console.error('[GATEKEEP] Init failed:', err);
  });
});
