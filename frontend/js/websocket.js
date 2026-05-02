/**
 * GatekeepWebSocket — resilient WebSocket client for GATEKEEP real-time events.
 *
 * Handles connection lifecycle, channel subscriptions, auto-reconnection
 * with exponential backoff, heartbeat pong responses, and message routing
 * to registered handler callbacks.
 *
 * Usage:
 *   const ws = new GatekeepWebSocket();
 *   ws.onConnectionChange(status => console.log(status));
 *   ws.onAlert(alert => console.log(alert));
 *   ws.connect();
 *   ws.subscribe(['alerts', 'monitor_stats']);
 */

class GatekeepWebSocket {
  /**
   * @param {string} [url] - WebSocket URL. Defaults to ws://localhost:8443/ws/events
   */
  constructor(url = 'ws://localhost:8443/ws/events') {
    this._url = url;
    this._ws = null;

    // Connection state: 'disconnected' | 'connecting' | 'connected' | 'reconnecting'
    this._status = 'disconnected';

    // Channels to subscribe after (re)connect
    this._channels = [];

    // Registered callbacks
    this._alertHandlers = [];
    this._scanProgressHandlers = [];
    this._monitorStatsHandlers = [];
    this._connectionChangeHandlers = [];

    // Reconnection state
    this._reconnectAttempts = 0;
    this._reconnectTimer = null;
    this._intentionalClose = false;

    // Outbound message queue — replayed on reconnect
    this._messageQueue = [];

    // Session info from server
    this._sessionId = null;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Establish the WebSocket connection.
   */
  connect() {
    if (this._ws && (this._ws.readyState === WebSocket.OPEN || this._ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this._intentionalClose = false;
    this._setStatus(this._reconnectAttempts > 0 ? 'reconnecting' : 'connecting');

    try {
      this._ws = new WebSocket(this._url);
    } catch (err) {
      console.error('[GatekeepWS] Failed to create WebSocket:', err);
      this._scheduleReconnect();
      return;
    }

    this._ws.addEventListener('open', this._onOpen.bind(this));
    this._ws.addEventListener('message', this._onMessage.bind(this));
    this._ws.addEventListener('close', this._onClose.bind(this));
    this._ws.addEventListener('error', this._onError.bind(this));
  }

  /**
   * Close the connection permanently (no reconnect).
   */
  disconnect() {
    this._intentionalClose = true;
    this._clearReconnectTimer();
    if (this._ws) {
      this._ws.close(1000, 'Client disconnecting');
      this._ws = null;
    }
    this._setStatus('disconnected');
  }

  /**
   * Subscribe to one or more event channels.
   * Subscription is re-sent on every reconnect.
   *
   * @param {string[]} channels - e.g. ['alerts', 'scan_progress', 'monitor_stats']
   */
  subscribe(channels) {
    if (!Array.isArray(channels) || channels.length === 0) return;

    // Merge with existing channels (deduplicate)
    const merged = Array.from(new Set([...this._channels, ...channels]));
    this._channels = merged;

    this._sendSubscribe(merged);
  }

  /**
   * Unsubscribe from channels (client-side only — server has no unsubscribe).
   * The handler just won't be called for those channels after this.
   * @param {string[]} channels
   */
  unsubscribe(channels) {
    this._channels = this._channels.filter(c => !channels.includes(c));
  }

  // -------------------------------------------------------------------------
  // Handler registration
  // -------------------------------------------------------------------------

  /**
   * Register a handler for alert_new and alert_updated events.
   * @param {function(Object): void} callback
   */
  onAlert(callback) {
    if (typeof callback === 'function') this._alertHandlers.push(callback);
    return this; // chainable
  }

  /**
   * Register a handler for scan progress events.
   * @param {function(Object): void} callback
   */
  onScanProgress(callback) {
    if (typeof callback === 'function') this._scanProgressHandlers.push(callback);
    return this;
  }

  /**
   * Register a handler for monitor_stats and monitor_anomaly events.
   * @param {function(Object): void} callback
   */
  onMonitorStats(callback) {
    if (typeof callback === 'function') this._monitorStatsHandlers.push(callback);
    return this;
  }

  /**
   * Register a handler for connection status changes.
   * @param {function(string): void} callback - receives 'connected'|'disconnected'|'connecting'|'reconnecting'
   */
  onConnectionChange(callback) {
    if (typeof callback === 'function') this._connectionChangeHandlers.push(callback);
    return this;
  }

  // -------------------------------------------------------------------------
  // Status accessors
  // -------------------------------------------------------------------------

  get status() {
    return this._status;
  }

  get isConnected() {
    return this._status === 'connected';
  }

  get sessionId() {
    return this._sessionId;
  }

  // -------------------------------------------------------------------------
  // Internal WebSocket event handlers
  // -------------------------------------------------------------------------

  _onOpen() {
    this._reconnectAttempts = 0;
    this._clearReconnectTimer();
    this._setStatus('connected');
    console.info('[GatekeepWS] Connected to', this._url);

    // Re-subscribe to all channels after reconnect
    if (this._channels.length > 0) {
      this._sendSubscribe(this._channels);
    }

    // Flush queued messages
    this._flushQueue();
  }

  _onMessage(event) {
    let envelope;
    try {
      envelope = JSON.parse(event.data);
    } catch {
      console.warn('[GatekeepWS] Non-JSON message received:', event.data);
      return;
    }

    const { type, data } = envelope;

    switch (type) {
      // Connection lifecycle
      case 'connected':
        this._sessionId = data?.session_id ?? null;
        console.info('[GatekeepWS] Session ID:', this._sessionId);
        break;

      case 'subscribed':
        console.debug('[GatekeepWS] Subscribed to channels:', data?.channels);
        break;

      // Heartbeat — server sends system_ping, client must pong
      case 'system_ping':
        this._sendRaw({ type: 'pong' });
        break;

      // Alert events
      case 'alert_new':
      case 'alert_updated':
        this._dispatch(this._alertHandlers, { ...data, _eventType: type, _envelope: envelope });
        break;

      // Scan progress events
      case 'scan_started':
      case 'scan_device_found':
      case 'scan_phase':
      case 'scan_completed':
      case 'scan_error':
        this._dispatch(this._scanProgressHandlers, { ...data, _eventType: type, _envelope: envelope });
        break;

      // Monitor stats and anomaly events
      case 'monitor_stats':
      case 'monitor_anomaly':
        this._dispatch(this._monitorStatsHandlers, { ...data, _eventType: type, _envelope: envelope });
        break;

      default:
        console.debug('[GatekeepWS] Unhandled event type:', type, data);
    }
  }

  _onClose(event) {
    this._ws = null;
    this._sessionId = null;

    if (this._intentionalClose) {
      this._setStatus('disconnected');
      console.info('[GatekeepWS] Disconnected intentionally.');
      return;
    }

    console.warn(`[GatekeepWS] Connection closed (code ${event.code}). Scheduling reconnect...`);
    this._scheduleReconnect();
  }

  _onError(error) {
    // Error is always followed by a close event — let _onClose handle reconnect
    console.error('[GatekeepWS] WebSocket error:', error);
  }

  // -------------------------------------------------------------------------
  // Reconnection
  // -------------------------------------------------------------------------

  /**
   * Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 30s.
   */
  _scheduleReconnect() {
    this._clearReconnectTimer();
    this._setStatus('reconnecting');

    const BASE_DELAY_MS = 1000;
    const MAX_DELAY_MS = 30000;
    const delay = Math.min(BASE_DELAY_MS * Math.pow(2, this._reconnectAttempts), MAX_DELAY_MS);

    this._reconnectAttempts += 1;
    console.info(`[GatekeepWS] Reconnect attempt ${this._reconnectAttempts} in ${delay}ms...`);

    this._reconnectTimer = setTimeout(() => {
      if (!this._intentionalClose) {
        this.connect();
      }
    }, delay);
  }

  _clearReconnectTimer() {
    if (this._reconnectTimer !== null) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
  }

  // -------------------------------------------------------------------------
  // Sending
  // -------------------------------------------------------------------------

  /**
   * Send a subscribe message. Queued if not connected.
   * @param {string[]} channels
   */
  _sendSubscribe(channels) {
    this._sendRaw({ type: 'subscribe', channels });
  }

  /**
   * Send raw JSON. Queues the message if the socket is not open yet.
   * @param {Object} payload
   */
  _sendRaw(payload) {
    const json = JSON.stringify(payload);

    if (this._ws && this._ws.readyState === WebSocket.OPEN) {
      try {
        this._ws.send(json);
      } catch (err) {
        console.error('[GatekeepWS] Send failed:', err);
        this._messageQueue.push(json);
      }
    } else {
      // Don't queue pongs — they're time-sensitive and pointless stale
      if (payload.type !== 'pong') {
        this._messageQueue.push(json);
      }
    }
  }

  /**
   * Flush queued messages once reconnected.
   */
  _flushQueue() {
    const queue = this._messageQueue.splice(0);
    for (const json of queue) {
      if (this._ws && this._ws.readyState === WebSocket.OPEN) {
        try {
          this._ws.send(json);
        } catch {
          // Re-queue on failure
          this._messageQueue.push(json);
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  _setStatus(status) {
    if (this._status === status) return;
    this._status = status;
    this._dispatch(this._connectionChangeHandlers, status);
  }

  _dispatch(handlers, payload) {
    for (const fn of handlers) {
      try {
        fn(payload);
      } catch (err) {
        console.error('[GatekeepWS] Handler error:', err);
      }
    }
  }
}

// Export for use as module or global
if (typeof module !== 'undefined' && module.exports) {
  module.exports = GatekeepWebSocket;
} else {
  window.GatekeepWebSocket = GatekeepWebSocket;
}
