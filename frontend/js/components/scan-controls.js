/* ===================================================================
   GATEKEEP — Scan Controls Component
   Manages the scan button, type/interface selectors, progress tracking,
   and result rendering pipeline.
   =================================================================== */

'use strict';

class ScanControls {
  constructor() {
    // DOM references
    this.btnScan = document.getElementById('btn-scan');
    this.selectType = document.getElementById('scan-type');
    this.selectInterface = document.getElementById('scan-interface');
    this.inputSubnet = document.getElementById('scan-subnet');
    this.progressPanel = document.getElementById('scan-progress');
    this.resultsPanel = document.getElementById('scan-results');
    this.progressBarFill = document.getElementById('progress-bar-fill');
    this.liveDeviceNum = document.getElementById('live-device-num');
    this.btnReanalyze = document.getElementById('btn-reanalyze');
    this.btnDnsCheck = document.getElementById('btn-dns-check');
    this.btnToggleHistory = document.getElementById('btn-toggle-history');
    this.scanHistoryContent = document.getElementById('scan-history-content');

    // State
    this.isScanning = false;
    this.currentScanId = null;
    this.pollInterval = null;
    this.deviceCount = 0;

    // Phase map
    this.phases = ['arp_discovery', 'dns_check', 'port_scan', 'router_fingerprint', 'ai_analysis'];
    this.completedPhases = new Set();
    this.activePhase = null;

    this._bindEvents();
  }

  _bindEvents() {
    // Scan button
    this.btnScan.addEventListener('click', (e) => this._handleScanClick(e));

    // Re-analyze button
    if (this.btnReanalyze) {
      this.btnReanalyze.addEventListener('click', () => this._handleReanalyze());
    }

    // DNS check button
    if (this.btnDnsCheck) {
      this.btnDnsCheck.addEventListener('click', () => this._handleDnsCheck());
    }

    // History toggle
    if (this.btnToggleHistory) {
      this.btnToggleHistory.addEventListener('click', () => this._toggleHistory());
    }
  }

  // -----------------------------------------------------------------
  //  Scan Lifecycle
  // -----------------------------------------------------------------

  async _handleScanClick(event) {
    if (this.isScanning) return;

    // Ripple effect
    this._createRipple(event);

    this.isScanning = true;
    this.deviceCount = 0;
    this.completedPhases.clear();
    this.activePhase = null;

    // UI state
    this.btnScan.classList.add('btn-scan--scanning');
    this.btnScan.querySelector('.btn-scan__label').textContent = 'SCANNING...';
    this.btnScan.disabled = true;
    this.progressPanel.classList.remove('hidden');
    this.progressPanel.classList.add('scan-progress--active');
    this.resultsPanel.classList.add('hidden');
    this._resetPhases();
    this._setProgress(0);
    this.liveDeviceNum.textContent = '0';

    // Build request body
    const scanParams = {
      scan_type: this.selectType.value,
      interface_name: this.selectInterface.value || null,
      subnet: this.inputSubnet.value.trim() || null,
    };

    try {
      await api.startScan(scanParams);
      window.app?.toast('Scan started', `Running ${scanParams.scan_type} scan...`, 'info');

      // Start polling for scan status
      this._startPolling();
    } catch (err) {
      this._scanError(err.message || 'Failed to start scan');
    }
  }

  _startPolling() {
    // Poll every 2 seconds for the latest scan status
    this.pollInterval = setInterval(() => this._pollScanStatus(), 2000);
    // Also do an immediate poll
    this._pollScanStatus();
  }

  async _pollScanStatus() {
    try {
      const scans = await api.getScans(1, 0);
      if (!scans || scans.length === 0) return;

      const latest = scans[0];
      this.currentScanId = latest.id;

      // Update device count
      if (latest.device_count !== undefined) {
        this.deviceCount = latest.device_count;
        this.liveDeviceNum.textContent = String(this.deviceCount);
      }

      // Simulate phase progression based on status
      this._estimatePhases(latest);

      // Check completion
      if (latest.status === 'completed') {
        this._onScanComplete(latest);
      } else if (latest.status === 'failed') {
        this._scanError(latest.error_message || 'Scan failed');
      }
    } catch (err) {
      // Silently continue polling — might be a transient error
      console.warn('Poll error:', err.message);
    }
  }

  _estimatePhases(scan) {
    // Since the backend doesn't expose per-phase progress, estimate from
    // the scan type and status
    const scanType = scan.scan_type;
    const isQuick = scanType === 'quick' || scanType === 'arp_discovery';

    if (scan.status === 'running' || scan.status === 'pending') {
      // Use elapsed time to estimate phase
      const started = scan.started_at ? new Date(scan.started_at) : new Date(scan.created_at);
      const elapsed = (Date.now() - started.getTime()) / 1000;

      if (isQuick) {
        this._setActivePhase('arp_discovery');
        this._setProgress(50);
      } else {
        // Full scan phase timing estimates (rough)
        if (elapsed < 10) {
          this._setActivePhase('arp_discovery');
          this._setProgress(10);
        } else if (elapsed < 25) {
          this._completePhase('arp_discovery');
          this._setActivePhase('dns_check');
          this._setProgress(30);
        } else if (elapsed < 60) {
          this._completePhase('arp_discovery');
          this._completePhase('dns_check');
          this._setActivePhase('port_scan');
          this._setProgress(50);
        } else if (elapsed < 90) {
          this._completePhase('arp_discovery');
          this._completePhase('dns_check');
          this._completePhase('port_scan');
          this._setActivePhase('router_fingerprint');
          this._setProgress(70);
        } else {
          this._completePhase('arp_discovery');
          this._completePhase('dns_check');
          this._completePhase('port_scan');
          this._completePhase('router_fingerprint');
          this._setActivePhase('ai_analysis');
          this._setProgress(85);
        }
      }
    }
  }

  async _onScanComplete(scan) {
    this._stopPolling();

    // Complete all phases
    this.phases.forEach(p => this._completePhase(p));
    this._setProgress(100);

    // Brief pause for visual satisfaction, then render results
    await this._delay(600);

    this.isScanning = false;
    this.btnScan.classList.remove('btn-scan--scanning');
    this.btnScan.querySelector('.btn-scan__label').textContent = 'SCAN NETWORK';
    this.btnScan.disabled = false;
    this.progressPanel.classList.remove('scan-progress--active');
    this.progressPanel.classList.add('hidden');

    // Fetch full scan detail and render
    await this._renderResults(scan.id);

    // Refresh scan history
    this._loadScanHistory();
  }

  _scanError(message) {
    this._stopPolling();
    this.isScanning = false;
    this.btnScan.classList.remove('btn-scan--scanning');
    this.btnScan.querySelector('.btn-scan__label').textContent = 'SCAN NETWORK';
    this.btnScan.disabled = false;
    this.progressPanel.classList.remove('scan-progress--active');
    this.progressPanel.classList.add('hidden');

    window.app?.toast('Scan Failed', message, 'error');
  }

  _stopPolling() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  // -----------------------------------------------------------------
  //  Phase & Progress UI
  // -----------------------------------------------------------------

  _setProgress(percent) {
    if (this.progressBarFill) {
      this.progressBarFill.style.width = `${Math.min(100, percent)}%`;
    }
  }

  _setActivePhase(phaseName) {
    if (this.activePhase === phaseName) return;
    this.activePhase = phaseName;

    document.querySelectorAll('.phase-indicator').forEach(el => {
      const phase = el.dataset.phase;
      if (this.completedPhases.has(phase)) {
        el.classList.add('phase-indicator--complete');
        el.classList.remove('phase-indicator--active');
      } else if (phase === phaseName) {
        el.classList.add('phase-indicator--active');
        el.classList.remove('phase-indicator--complete');
      } else {
        el.classList.remove('phase-indicator--active', 'phase-indicator--complete');
      }
    });
  }

  _completePhase(phaseName) {
    this.completedPhases.add(phaseName);
    const el = document.querySelector(`.phase-indicator[data-phase="${phaseName}"]`);
    if (el) {
      el.classList.add('phase-indicator--complete');
      el.classList.remove('phase-indicator--active');
    }
  }

  _resetPhases() {
    document.querySelectorAll('.phase-indicator').forEach(el => {
      el.classList.remove('phase-indicator--active', 'phase-indicator--complete');
    });
  }

  // -----------------------------------------------------------------
  //  Result Rendering
  // -----------------------------------------------------------------

  async _renderResults(scanId) {
    this.resultsPanel.classList.remove('hidden');

    try {
      const detail = await api.getScan(scanId);
      if (!detail) return;

      // Render risk gauge
      this._renderRiskGauge(detail);

      // Render stats
      this._renderStats(detail);

      // Render AI analysis FIRST — this is the hero summary
      this._renderAIAnalysis(detail.ai_analysis);

      // Render DNS status
      this._renderDNSStatus(detail.dns_checks);

      // Render router info
      this._renderRouterInfo(detail.router_fingerprints);

      // Render network map
      if (window.networkMap && detail.devices) {
        const gateway = detail.devices.find(d => d.is_gateway);
        window.networkMap.render(detail.devices, gateway);
      }

      // Render device grid
      if (window.deviceGrid) {
        window.deviceGrid.render(detail.devices || []);
      }

    } catch (err) {
      window.app?.toast('Error', 'Failed to load scan results: ' + err.message, 'error');
    }
  }

  _renderRiskGauge(detail) {
    const gauge = document.getElementById('risk-gauge');
    const scoreEl = document.getElementById('risk-score');
    const labelEl = document.getElementById('risk-label');
    const summaryEl = document.getElementById('risk-summary');
    const fillEl = gauge.querySelector('.risk-gauge__fill');

    // Remove all risk level classes
    gauge.className = 'risk-gauge';

    if (detail.ai_analysis) {
      const score = detail.ai_analysis.risk_score || 0;
      const level = detail.ai_analysis.risk_level || 'info';
      const riskInfo = getRiskLevel(score);

      scoreEl.textContent = Math.round(score);
      labelEl.textContent = riskInfo.label;
      summaryEl.textContent = detail.ai_analysis.summary || '';
      gauge.classList.add(`risk-gauge--${riskInfo.level}`);

      // Animate the ring fill (circumference = 2 * PI * 52 ≈ 327)
      const circumference = 327;
      const offset = circumference - (circumference * score / 100);
      fillEl.style.strokeDashoffset = String(offset);
    } else {
      scoreEl.textContent = '--';
      labelEl.textContent = 'NO AI DATA';
      summaryEl.textContent = 'AI analysis unavailable. Configure an API key in Settings to enable threat intelligence.';
      gauge.classList.add('risk-gauge--info');
      fillEl.style.strokeDashoffset = '327';
    }
  }

  _renderStats(detail) {
    const devices = detail.devices || [];
    const alerts = detail.alerts || [];

    document.getElementById('stat-devices').textContent = String(devices.length);

    // Count total open ports
    let openPorts = 0;
    devices.forEach(d => {
      if (d.open_ports) openPorts += d.open_ports.length;
    });
    document.getElementById('stat-ports').textContent = String(openPorts);

    document.getElementById('stat-alerts').textContent = String(alerts.length);

    // Duration
    if (detail.started_at && detail.completed_at) {
      const start = new Date(detail.started_at);
      const end = new Date(detail.completed_at);
      const durationSec = (end - start) / 1000;
      document.getElementById('stat-duration').textContent = formatDuration(durationSec);
    } else {
      document.getElementById('stat-duration').textContent = '--';
    }
  }

  _renderAIAnalysis(analysis) {
    const container = document.getElementById('ai-analysis-content');
    if (!analysis) {
      container.innerHTML = `
        <div class="empty-state">
          <p>AI analysis is running or unavailable. Claude will summarize your scan findings here.</p>
        </div>`;
      return;
    }

    let findingsHtml = '';
    if (analysis.findings && analysis.findings.length > 0) {
      findingsHtml = `
        <div class="ai-analysis__section">
          <h4 class="ai-analysis__section-title">Findings</h4>
          ${analysis.findings.map(f => {
            const severity = (f.severity || f.risk_level || 'info').toLowerCase();
            return `
              <div class="finding-card finding-card--${severity}">
                <div class="finding-card__header">
                  <span class="finding-card__title">${escapeHtml(f.title || f.finding || 'Finding')}</span>
                  ${formatSeverity(severity)}
                </div>
                <p class="finding-card__description">${escapeHtml(f.description || f.detail || '')}</p>
                ${f.evidence ? `<div class="finding-card__evidence">${escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2))}</div>` : ''}
              </div>`;
          }).join('')}
        </div>`;
    }

    let recsHtml = '';
    if (analysis.recommendations && analysis.recommendations.length > 0) {
      recsHtml = `
        <div class="ai-analysis__section">
          <h4 class="ai-analysis__section-title">Recommendations</h4>
          ${analysis.recommendations.map(r => {
            const priority = (r.priority || 'medium').toLowerCase();
            return `
              <div class="recommendation-card">
                <div class="recommendation-card__icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                </div>
                <div class="recommendation-card__content">
                  <div class="recommendation-card__title">${escapeHtml(r.action || r.title || r.recommendation || 'Recommendation')}</div>
                  <p class="recommendation-card__description">${escapeHtml(r.reason || r.description || r.detail || '')}</p>
                  <span class="recommendation-card__priority recommendation-card__priority--${priority}">${escapeHtml(r.difficulty || '')} | Priority: ${escapeHtml(priority)}</span>
                </div>
              </div>`;
          }).join('')}
        </div>`;
    }

    container.innerHTML = `
      <div class="ai-analysis">
        <div class="ai-analysis__summary">${escapeHtml(analysis.summary || '')}</div>
        ${findingsHtml}
        ${recsHtml}
        <div class="ai-analysis__meta">
          <span class="ai-analysis__meta-item">Model: <strong>${escapeHtml(analysis.model_used || '--')}</strong></span>
          <span class="ai-analysis__meta-item">Tokens: <strong>${analysis.tokens_used || 0}</strong></span>
          <span class="ai-analysis__meta-item">Latency: <strong>${analysis.latency_ms ? Math.round(analysis.latency_ms) + 'ms' : '--'}</strong></span>
        </div>
      </div>`;
  }

  _renderDNSStatus(dnsChecks) {
    const container = document.getElementById('dns-status-content');
    if (!dnsChecks || dnsChecks.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <p>No DNS check data available.</p>
        </div>`;
      return;
    }

    const hijacked = dnsChecks.filter(c => c.is_hijacked);
    const isClean = hijacked.length === 0;

    const headerClass = isClean ? 'dns-status__header--clean' : 'dns-status__header--hijacked';
    const iconClass = isClean ? 'dns-status__icon--clean' : 'dns-status__icon--hijacked';
    const titleClass = isClean ? 'dns-status__title--clean' : 'dns-status__title--hijacked';
    const icon = isClean
      ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>'
      : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';

    container.innerHTML = `
      <div class="dns-status">
        <div class="dns-status__header ${headerClass}">
          <div class="dns-status__icon ${iconClass}">${icon}</div>
          <div>
            <div class="dns-status__title ${titleClass}">
              ${isClean ? 'DNS Resolvers Clean' : `${hijacked.length} Hijacked Resolutions Detected`}
            </div>
            <div class="dns-status__subtitle">${dnsChecks.length} resolution${dnsChecks.length !== 1 ? 's' : ''} checked</div>
          </div>
        </div>
        ${dnsChecks.slice(0, 10).map(check => `
          <div class="dns-resolution ${check.is_hijacked ? 'dns-resolution--hijacked' : 'dns-resolution--ok'}">
            <span class="dns-resolution__domain">${escapeHtml(check.query_domain || '--')}</span>
            <span class="dns-resolution__status-icon ${check.is_hijacked ? 'dns-resolution__status-icon--hijacked' : 'dns-resolution__status-icon--ok'}">
              ${check.is_hijacked ? '\u2717' : '\u2713'}
            </span>
          </div>
        `).join('')}
      </div>`;
  }

  _renderRouterInfo(fingerprints) {
    const container = document.getElementById('router-info-content');
    if (!container) return;

    // Normalise: accept a single object, an array, or null/undefined
    let fpArray;
    if (!fingerprints) {
      fpArray = [];
    } else if (Array.isArray(fingerprints)) {
      fpArray = fingerprints;
    } else if (typeof fingerprints === 'object') {
      // Single fingerprint object wrapped in an array for uniform handling
      fpArray = [fingerprints];
    } else {
      fpArray = [];
    }

    if (fpArray.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <p>No router identified — run a new scan to detect your gateway router.</p>
        </div>`;
      return;
    }

    const fingerprints_to_render = fpArray;

    container.innerHTML = `
      <div class="router-info">
        ${fingerprints_to_render.map(fp => {
          const isVuln = fp.is_vulnerable;
          const vulns = fp.vulnerability_details || [];
          return `
            <div class="router-info__item ${isVuln ? 'router-info__item--vulnerable' : ''}">
              <div class="router-info__icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>
                  <line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
                </svg>
              </div>
              <div class="router-info__content">
                <div class="router-info__label">Router</div>
                <div class="router-info__value">
                  ${escapeHtml(fp.manufacturer || 'Unknown')} ${escapeHtml(fp.model || '')}
                </div>
                <div class="router-info__details">
                  ${fp.firmware_version ? `<span class="router-info__detail-item">Firmware: <strong class="mono">${escapeHtml(fp.firmware_version)}</strong></span>` : ''}
                  ${fp.fingerprint_method ? `<span class="router-info__detail-item">Method: ${escapeHtml(fp.fingerprint_method)}</span>` : ''}
                  ${fp.admin_panel_url && (fp.admin_panel_url.startsWith('http://') || fp.admin_panel_url.startsWith('https://')) ? `<span class="router-info__detail-item"><a href="${escapeHtml(fp.admin_panel_url)}" target="_blank" rel="noopener">Admin Panel</a></span>` : ''}
                </div>
                ${isVuln ? `
                  <div class="vuln-list">
                    ${vulns.map(v => `
                      <div class="vuln-item">
                        <div class="vuln-item__title">${escapeHtml(v.title || v.cve || 'Vulnerability')}</div>
                        <div class="vuln-item__description">${escapeHtml(v.description || '')}</div>
                      </div>
                    `).join('')}
                  </div>
                ` : `<span style="color:var(--accent-green);font-size:var(--text-xs);margin-top:var(--space-xs);display:inline-block">\u2713 No known vulnerabilities</span>`}
              </div>
              ${isVuln ? formatSeverity('critical') : formatSeverity('low')}
            </div>`;
        }).join('')}
      </div>`;
  }

  // -----------------------------------------------------------------
  //  Actions
  // -----------------------------------------------------------------

  async _handleReanalyze() {
    if (!this.currentScanId) {
      window.app?.toast('Error', 'No scan available to re-analyze', 'warning');
      return;
    }

    try {
      this.btnReanalyze.disabled = true;
      await api.reanalyze(this.currentScanId);
      window.app?.toast('AI Re-analysis', 'Re-analysis queued. Results will update shortly.', 'info');

      // Poll for updated results
      setTimeout(async () => {
        try {
          const analysis = await api.getAIAnalysis(this.currentScanId);
          if (analysis) {
            this._renderAIAnalysis(analysis);
            this._renderRiskGaugeFromAnalysis(analysis);
          }
        } catch { /* will retry */ }
        this.btnReanalyze.disabled = false;
      }, 10000);
    } catch (err) {
      window.app?.toast('Error', err.message, 'error');
      this.btnReanalyze.disabled = false;
    }
  }

  _renderRiskGaugeFromAnalysis(analysis) {
    if (!analysis) return;
    const gauge = document.getElementById('risk-gauge');
    const scoreEl = document.getElementById('risk-score');
    const labelEl = document.getElementById('risk-label');
    const summaryEl = document.getElementById('risk-summary');
    const fillEl = gauge.querySelector('.risk-gauge__fill');

    gauge.className = 'risk-gauge';
    const score = analysis.risk_score || 0;
    const riskInfo = getRiskLevel(score);

    scoreEl.textContent = Math.round(score);
    labelEl.textContent = riskInfo.label;
    summaryEl.textContent = analysis.summary || '';
    gauge.classList.add(`risk-gauge--${riskInfo.level}`);

    const circumference = 327;
    const offset = circumference - (circumference * score / 100);
    fillEl.style.strokeDashoffset = String(offset);
  }

  async _handleDnsCheck() {
    try {
      this.btnDnsCheck.disabled = true;
      window.app?.toast('DNS Check', 'Running DNS integrity check...', 'info');
      const result = await api.checkDNS();

      if (result) {
        const container = document.getElementById('dns-status-content');
        const isClean = !result.is_hijacked && !result.is_malicious_resolver;
        const headerClass = isClean ? 'dns-status__header--clean' : 'dns-status__header--hijacked';
        const iconClass = isClean ? 'dns-status__icon--clean' : 'dns-status__icon--hijacked';
        const titleClass = isClean ? 'dns-status__title--clean' : 'dns-status__title--hijacked';
        const icon = isClean
          ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>'
          : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';

        let resolverHtml = '';
        if (result.resolvers && result.resolvers.length > 0) {
          resolverHtml = result.resolvers.map(r => `
            <div class="dns-resolver">
              <div class="dns-resolver__header">
                <div>
                  <div class="dns-resolver__ip">${escapeHtml(r.resolver_ip)}</div>
                  <div class="dns-resolver__name">${escapeHtml(r.resolver_name || 'Unknown')}</div>
                </div>
                <div class="dns-resolver__badges">
                  ${r.is_trusted ? '<span class="badge badge-low">Trusted</span>' : ''}
                  ${r.is_malicious ? '<span class="badge badge-critical">Malicious</span>' : ''}
                  ${formatSeverity(r.status === 'hijacked' ? 'critical' : r.status === 'clean' ? 'low' : 'info')}
                </div>
              </div>
              ${r.resolution_results && r.resolution_results.length > 0 ? `
                <div class="dns-resolver__details">
                  ${r.resolution_results.map(rr => `
                    <div class="dns-resolution ${rr.is_hijacked ? 'dns-resolution--hijacked' : 'dns-resolution--ok'}">
                      <span class="dns-resolution__domain">${escapeHtml(rr.domain)}</span>
                      <span class="dns-resolution__status-icon ${rr.is_hijacked ? 'dns-resolution__status-icon--hijacked' : 'dns-resolution__status-icon--ok'}">
                        ${rr.is_hijacked ? '\u2717' : '\u2713'}
                      </span>
                    </div>
                  `).join('')}
                </div>
              ` : ''}
            </div>
          `).join('');
        }

        container.innerHTML = `
          <div class="dns-status">
            <div class="dns-status__header ${headerClass}">
              <div class="dns-status__icon ${iconClass}">${icon}</div>
              <div>
                <div class="dns-status__title ${titleClass}">
                  ${isClean ? 'DNS Resolvers Clean' : 'DNS Integrity Compromised'}
                </div>
                <div class="dns-status__subtitle">
                  ${result.resolver_count || 0} resolver${result.resolver_count !== 1 ? 's' : ''} checked,
                  ${result.hijacked_domain_count || 0} hijacked domain${result.hijacked_domain_count !== 1 ? 's' : ''}
                </div>
              </div>
            </div>
            ${resolverHtml}
          </div>`;

        window.app?.toast('DNS Check', isClean ? 'All DNS resolvers clean.' : 'DNS integrity issues detected!', isClean ? 'success' : 'error');
      }
    } catch (err) {
      window.app?.toast('DNS Check Error', err.message, 'error');
    } finally {
      this.btnDnsCheck.disabled = false;
    }
  }

  // -----------------------------------------------------------------
  //  Scan History
  // -----------------------------------------------------------------

  _toggleHistory() {
    const content = this.scanHistoryContent;
    const btn = this.btnToggleHistory;
    const isCollapsed = content.classList.contains('collapsed');

    if (isCollapsed) {
      content.classList.remove('collapsed');
      btn.setAttribute('aria-expanded', 'true');
      btn.querySelector('svg').style.transform = 'rotate(180deg)';
      this._loadScanHistory();
    } else {
      content.classList.add('collapsed');
      btn.setAttribute('aria-expanded', 'false');
      btn.querySelector('svg').style.transform = '';
    }
  }

  async _loadScanHistory() {
    const list = document.getElementById('scan-history-list');
    try {
      const scans = await api.getScans(20, 0);
      if (!scans || scans.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No scan history</p></div>';
        return;
      }

      list.innerHTML = scans.map(scan => `
        <div class="scan-history-item" data-scan-id="${escapeHtml(scan.id)}" onclick="window.scanControls?.loadHistoricScan('${escapeHtml(scan.id)}')">
          <div class="scan-history-item__info">
            <span class="scan-history-item__type">${escapeHtml(scan.scan_type)}</span>
            <span class="scan-history-item__time">${formatTimestamp(scan.created_at)}</span>
          </div>
          <div class="scan-history-item__stats">
            <span class="scan-history-item__stat">${scan.device_count || 0} devices</span>
            <span class="scan-history-item__stat">${scan.alert_count || 0} alerts</span>
            ${formatScanStatus(scan.status)}
          </div>
          <div class="scan-history-item__actions">
            <button class="scan-history-item__delete" onclick="event.stopPropagation(); window.scanControls?.deleteHistoricScan('${escapeHtml(scan.id)}')" title="Delete scan">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
            </button>
          </div>
        </div>
      `).join('');
    } catch (err) {
      list.innerHTML = `<div class="empty-state"><p>Failed to load history: ${escapeHtml(err.message)}</p></div>`;
    }
  }

  async loadHistoricScan(scanId) {
    this.currentScanId = scanId;
    await this._renderResults(scanId);
    window.app?.toast('Scan Loaded', 'Viewing historical scan results', 'info');
  }

  async deleteHistoricScan(scanId) {
    if (!confirm('Delete this scan and all related data?')) return;
    try {
      await api.deleteScan(scanId);
      window.app?.toast('Scan Deleted', 'Scan removed successfully', 'success');
      this._loadScanHistory();
    } catch (err) {
      window.app?.toast('Error', err.message, 'error');
    }
  }

  // -----------------------------------------------------------------
  //  Helpers
  // -----------------------------------------------------------------

  _createRipple(event) {
    const ripple = this.btnScan.querySelector('.btn-scan__ripple');
    const rect = this.btnScan.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    ripple.style.left = `${x}px`;
    ripple.style.top = `${y}px`;
    ripple.classList.remove('animate');
    void ripple.offsetWidth; // trigger reflow
    ripple.classList.add('animate');
  }

  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // -----------------------------------------------------------------
  //  WebSocket event handling (called from app.js)
  // -----------------------------------------------------------------

  handleWSEvent(event) {
    if (!event || !event.type) return;

    switch (event.type) {
      case 'scan_started':
        // Scan was started (possibly from another tab/client)
        if (!this.isScanning) {
          this.isScanning = true;
          this.btnScan.classList.add('btn-scan--scanning');
          this.btnScan.querySelector('.btn-scan__label').textContent = 'SCANNING...';
          this.btnScan.disabled = true;
          this.progressPanel.classList.remove('hidden');
          this.progressPanel.classList.add('scan-progress--active');
          this._resetPhases();
          this._startPolling();
        }
        break;

      case 'scan_device_found':
        this.deviceCount++;
        this.liveDeviceNum.textContent = String(this.deviceCount);
        break;

      case 'scan_phase':
        if (event.data?.phase) {
          // Complete previous phases
          const phaseIdx = this.phases.indexOf(event.data.phase);
          for (let i = 0; i < phaseIdx; i++) {
            this._completePhase(this.phases[i]);
          }
          this._setActivePhase(event.data.phase);
          const progress = ((phaseIdx + 0.5) / this.phases.length) * 100;
          this._setProgress(progress);
        }
        break;

      case 'scan_completed':
        if (this.isScanning) {
          this.phases.forEach(p => this._completePhase(p));
          this._setProgress(100);
          if (event.data?.scan_id) {
            this.currentScanId = event.data.scan_id;
          }
          setTimeout(() => this._onScanComplete({ id: this.currentScanId, status: 'completed' }), 500);
        }
        break;

      case 'scan_error':
        if (this.isScanning) {
          this._scanError(event.data?.message || 'Scan error');
        }
        break;
    }
  }
}

// Global reference
window.scanControls = null;
