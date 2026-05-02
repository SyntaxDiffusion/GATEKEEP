/* ===================================================================
   GATEKEEP — REST API Client
   Typed wrapper for all backend endpoints with automatic envelope
   unwrapping, error handling, and debug logging.
   =================================================================== */

'use strict';

class ApiClient {
  /**
   * @param {Object} [options]
   * @param {string} [options.baseUrl] - Override the auto-detected base URL
   * @param {boolean} [options.debug]  - Enable request/response logging
   */
  constructor(options = {}) {
    const loc = window.location;
    this.baseUrl = options.baseUrl || `${loc.protocol}//${loc.host}/api/v1`;
    this.debug = options.debug || false;
    this._requestId = 0;
  }

  // -------------------------------------------------------------------
  //  Internal HTTP methods
  // -------------------------------------------------------------------

  /**
   * Core fetch wrapper.  Returns unwrapped `data` from the ApiResponse
   * envelope, or throws with structured error info.
   *
   * @param {string} method   HTTP method
   * @param {string} path     Path relative to /api/v1
   * @param {Object} [options]
   * @param {Object} [options.body]   Request body (will be JSON-serialized)
   * @param {Object} [options.params] URL query parameters
   * @returns {Promise<any>} Unwrapped response data
   */
  async _request(method, path, options = {}) {
    const reqId = ++this._requestId;
    const url = new URL(`${this.baseUrl}${path}`);

    // Append query parameters
    if (options.params) {
      Object.entries(options.params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          url.searchParams.set(key, String(value));
        }
      });
    }

    const fetchOptions = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };

    if (options.body !== undefined) {
      fetchOptions.body = JSON.stringify(options.body);
    }

    if (this.debug) {
      console.log(
        `[API #${reqId}] ${method} ${url.pathname}${url.search}`,
        options.body || ''
      );
    }

    let response;
    try {
      response = await fetch(url.toString(), fetchOptions);
    } catch (err) {
      const netErr = new ApiError(
        'Network error — is the GATEKEEP server running?',
        0,
        { originalError: err.message }
      );
      if (this.debug) console.error(`[API #${reqId}] NETWORK ERROR`, err);
      throw netErr;
    }

    // 204 No Content
    if (response.status === 204) {
      if (this.debug) console.log(`[API #${reqId}] 204 No Content`);
      return null;
    }

    let body;
    try {
      body = await response.json();
    } catch {
      const parseErr = new ApiError(
        `Unexpected response format (HTTP ${response.status})`,
        response.status,
        null
      );
      if (this.debug) console.error(`[API #${reqId}] PARSE ERROR`, response.status);
      throw parseErr;
    }

    if (this.debug) {
      console.log(`[API #${reqId}] ${response.status}`, body);
    }

    // Error responses
    if (!response.ok) {
      const message = body?.error?.message
        || body?.detail?.error?.message
        || body?.detail
        || `Request failed (HTTP ${response.status})`;

      throw new ApiError(
        typeof message === 'string' ? message : JSON.stringify(message),
        response.status,
        body
      );
    }

    // Unwrap ApiResponse envelope
    if (body && typeof body === 'object' && 'status' in body && 'data' in body) {
      return body.data;
    }

    return body;
  }

  async _get(path, params) {
    return this._request('GET', path, { params });
  }

  async _post(path, body, params) {
    return this._request('POST', path, { body, params });
  }

  async _patch(path, body) {
    return this._request('PATCH', path, { body });
  }

  async _delete(path) {
    return this._request('DELETE', path);
  }

  // -------------------------------------------------------------------
  //  Scans
  // -------------------------------------------------------------------

  /**
   * Start a new network scan.
   * @param {Object} params
   * @param {string} params.scan_type      - full_scan | quick | arp_discovery | port_scan | dns_check | router_fingerprint
   * @param {string} [params.interface_name] - Network interface name
   * @param {string} [params.subnet]        - CIDR subnet
   * @param {Object} [params.options]       - Additional scan options
   * @returns {Promise<{message: string, scan_type: string, status: string}>}
   */
  async startScan(params) {
    return this._post('/scans', params);
  }

  /**
   * List past scans.
   * @param {number} [limit=50]
   * @param {number} [offset=0]
   * @returns {Promise<Array>}
   */
  async getScans(limit = 50, offset = 0) {
    return this._get('/scans', { limit, offset });
  }

  /**
   * Get full scan detail including devices, DNS checks, router fingerprints, AI analysis.
   * @param {string} scanId
   * @returns {Promise<Object>}
   */
  async getScan(scanId) {
    return this._get(`/scans/${encodeURIComponent(scanId)}`);
  }

  /**
   * Delete a scan and all related data.
   * @param {string} scanId
   * @returns {Promise<null>}
   */
  async deleteScan(scanId) {
    return this._delete(`/scans/${encodeURIComponent(scanId)}`);
  }

  /**
   * Get AI analysis for a specific scan.
   * @param {string} scanId
   * @returns {Promise<Object>}
   */
  async getAIAnalysis(scanId) {
    return this._get(`/scans/${encodeURIComponent(scanId)}/ai-analysis`);
  }

  /**
   * Re-run AI analysis on existing scan data.
   * @param {string} scanId
   * @returns {Promise<{message: string, scan_id: string, status: string}>}
   */
  async reanalyze(scanId) {
    return this._post(`/scans/${encodeURIComponent(scanId)}/reanalyze`);
  }

  // -------------------------------------------------------------------
  //  Devices
  // -------------------------------------------------------------------

  /**
   * List all discovered devices.
   * @param {string} [status] - Optional filter: "online"
   * @returns {Promise<Array>}
   */
  async getDevices(status) {
    return this._get('/devices', { status });
  }

  /**
   * Get device detail with port scan results.
   * @param {string} deviceId
   * @returns {Promise<Object>}
   */
  async getDevice(deviceId) {
    return this._get(`/devices/${encodeURIComponent(deviceId)}`);
  }

  /**
   * Get device history over time.
   * @param {string} deviceId
   * @param {number} [days=30]
   * @returns {Promise<Array>}
   */
  async getDeviceHistory(deviceId, days = 30) {
    return this._get(`/devices/${encodeURIComponent(deviceId)}/history`, { days });
  }

  // -------------------------------------------------------------------
  //  DNS
  // -------------------------------------------------------------------

  /**
   * Run a standalone DNS integrity check.
   * @returns {Promise<Object>}
   */
  async checkDNS() {
    return this._get('/dns/check');
  }

  // -------------------------------------------------------------------
  //  Alerts
  // -------------------------------------------------------------------

  /**
   * List alerts with optional filtering.
   * @param {Object} [params]
   * @param {string} [params.severity]
   * @param {boolean} [params.acknowledged]
   * @param {number} [params.limit]
   * @param {number} [params.offset]
   * @returns {Promise<Array>}
   */
  async getAlerts(params = {}) {
    return this._get('/alerts', params);
  }

  /**
   * Get alert detail.
   * @param {string} alertId
   * @returns {Promise<Object>}
   */
  async getAlert(alertId) {
    return this._get(`/alerts/${encodeURIComponent(alertId)}`);
  }

  /**
   * Get alert statistics.
   * @param {string} [period='24h']
   * @returns {Promise<Object>}
   */
  async getAlertStats(period = '24h') {
    return this._get('/alerts/stats', { period });
  }

  /**
   * Acknowledge an alert or update notes.
   * @param {string} alertId
   * @param {Object} data
   * @param {boolean} [data.is_acknowledged]
   * @param {string} [data.notes]
   * @returns {Promise<Object>}
   */
  async updateAlert(alertId, data) {
    return this._patch(`/alerts/${encodeURIComponent(alertId)}`, data);
  }

  // -------------------------------------------------------------------
  //  System
  // -------------------------------------------------------------------

  /**
   * Get system health, version, capabilities.
   * @returns {Promise<Object>}
   */
  async getSystemHealth() {
    return this._get('/system/health');
  }

  /**
   * Get system configuration (redacted).
   * @returns {Promise<Object>}
   */
  async getSystemConfig() {
    return this._get('/system/config');
  }

  /**
   * List network interfaces.
   * @returns {Promise<Array>}
   */
  async getInterfaces() {
    return this._get('/system/interfaces');
  }

  // -------------------------------------------------------------------
  //  Hardening
  // -------------------------------------------------------------------

  /**
   * Get hardening recommendations.
   * @param {string} [scanId]
   * @returns {Promise<Array>}
   */
  async getHardeningRules(scanId) {
    const params = scanId ? { scan_id: scanId } : {};
    return this._get('/hardening/rules', params);
  }

  // -------------------------------------------------------------------
  //  Baselines
  // -------------------------------------------------------------------

  /**
   * List baselines.
   * @returns {Promise<Array>}
   */
  async getBaselines() {
    return this._get('/baselines');
  }
}


/**
 * Structured API error with HTTP status and response body.
 */
class ApiError extends Error {
  /**
   * @param {string} message
   * @param {number} status  HTTP status code (0 = network error)
   * @param {any} body       Raw response body
   */
  constructor(message, status, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}


// Export singleton
const api = new ApiClient({ debug: false });
