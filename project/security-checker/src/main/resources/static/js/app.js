(() => {
    const scanForm = document.getElementById('scanForm');
    const targetInput = document.getElementById('targetInput');
    const portsInput = document.getElementById('portsInput');
    const scanSubmitBtn = document.getElementById('scanSubmitBtn');

    const loadingSection = document.getElementById('loadingSection');
    const loadingTargetText = document.getElementById('loadingTargetText');
    const errorSection = document.getElementById('errorSection');
    const errorTitle = document.getElementById('errorTitle');
    const errorMessage = document.getElementById('errorMessage');
    const reportSection = document.getElementById('reportSection');

    const reportMeta = document.getElementById('reportMeta');
    const metricHostStatus = document.getElementById('metricHostStatus');
    const metricOpenPorts = document.getElementById('metricOpenPorts');
    const metricTotalVulns = document.getElementById('metricTotalVulns');
    const countCritical = document.getElementById('countCritical');
    const countHigh = document.getElementById('countHigh');
    const countMedium = document.getElementById('countMedium');
    const countLow = document.getElementById('countLow');
    const portsContainer = document.getElementById('portsContainer');

    const severityFilter = document.getElementById('severityFilter');
    const exportJsonBtn = document.getElementById('exportJsonBtn');

    // Theme Settings Popover
    const settingsBtn = document.getElementById('settingsBtn');
    const settingsMenu = document.getElementById('settingsMenu');
    const themeOptions = document.querySelectorAll('.theme-option');

    // Modal elements
    const cpeModal = document.getElementById('cpeModal');
    const cpeModalBtn = document.getElementById('cpeModalBtn');
    const closeCpeModalBtn = document.getElementById('closeCpeModalBtn');
    const cpeLookupForm = document.getElementById('cpeLookupForm');
    const cpeInput = document.getElementById('cpeInput');
    const cpeModalResults = document.getElementById('cpeModalResults');

    let latestReport = null;

    // Initialize saved theme (default: navy)
    const savedTheme = localStorage.getItem('sc_theme') || 'navy';
    applyTheme(savedTheme);

    settingsBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isHidden = settingsMenu.classList.toggle('hidden');
        settingsBtn.setAttribute('aria-expanded', String(!isHidden));
    });

    themeOptions.forEach(opt => {
        opt.addEventListener('click', () => {
            const theme = opt.getAttribute('data-theme-value') || 'navy';
            applyTheme(theme);
            localStorage.setItem('sc_theme', theme);
            settingsMenu.classList.add('hidden');
            settingsBtn.setAttribute('aria-expanded', 'false');
        });
    });

    document.addEventListener('click', (e) => {
        if (!settingsMenu.classList.contains('hidden') && !settingsMenu.contains(e.target) && e.target !== settingsBtn) {
            settingsMenu.classList.add('hidden');
            settingsBtn.setAttribute('aria-expanded', 'false');
        }
    });

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        themeOptions.forEach(opt => {
            opt.classList.toggle('active', opt.getAttribute('data-theme-value') === theme);
        });
    }

    // Quick port presets
    document.querySelectorAll('.chip').forEach(btn => {
        btn.addEventListener('click', () => {
            portsInput.value = btn.getAttribute('data-ports') || '';
        });
    });

    // Main scan submission
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = targetInput.value.trim();
        const ports = portsInput.value.trim();

        if (!target) {
            showError('Validation Error', 'Please enter a valid target IP address or hostname.');
            return;
        }

        hideError();
        reportSection.classList.add('hidden');
        loadingSection.classList.remove('hidden');
        loadingTargetText.textContent = `Scanning target "${target}" (${ports ? 'ports: ' + ports : 'default top ports'}) and querying vulnerability database...`;
        scanSubmitBtn.disabled = true;

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, ports })
            });

            const report = await response.json();
            latestReport = report;

            if (!response.ok || report.hostStatus === 'error') {
                showError('Scan Notice', report.message || 'An unexpected error occurred during the scan.');
                return;
            }

            renderReport(report);
        } catch (err) {
            showError('Connection Error', 'Could not reach the Security Checker backend: ' + err.message);
        } finally {
            loadingSection.classList.add('hidden');
            scanSubmitBtn.disabled = false;
        }
    });

    severityFilter.addEventListener('change', () => {
        if (latestReport) {
            renderPortsList(latestReport.portReports || [], severityFilter.value);
        }
    });

    exportJsonBtn.addEventListener('click', () => {
        if (!latestReport) return;
        const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const safeTarget = (latestReport.target || 'scan').replace(/[^a-zA-Z0-9._-]/g, '_');
        a.href = url;
        a.download = `security-report-${safeTarget}.json`;
        a.click();
        URL.revokeObjectURL(url);
    });

    function renderReport(report) {
        reportSection.classList.remove('hidden');
        const ts = report.timestamp ? new Date(report.timestamp).toLocaleString() : 'Just now';
        reportMeta.textContent = `Target: ${report.target} • Ports: ${report.requestedPorts} • Completed: ${ts}`;

        const status = (report.hostStatus || 'unknown').toUpperCase();
        metricHostStatus.textContent = status;

        metricOpenPorts.textContent = String(report.totalOpenPorts ?? 0);
        metricTotalVulns.textContent = String(report.totalVulnerabilities ?? 0);

        countCritical.textContent = String(report.criticalCount ?? 0);
        countHigh.textContent = String(report.highCount ?? 0);
        countMedium.textContent = String(report.mediumCount ?? 0);
        countLow.textContent = String(report.lowCount ?? 0);

        if (status === 'DOWN') {
            showError('Host Unreachable', report.message || 'Target host appears to be down or blocking probes.');
        }

        renderPortsList(report.portReports || [], severityFilter.value);
    }

    function renderPortsList(portReports, minSeverity) {
        portsContainer.innerHTML = '';

        if (!portReports.length) {
            const emptyCard = document.createElement('div');
            emptyCard.className = 'glass-panel scan-card';
            emptyCard.innerHTML = '<p class="muted">No open ports were detected on this target for the selected port range.</p>';
            portsContainer.appendChild(emptyCard);
            return;
        }

        portReports.forEach(pr => {
            const p = pr.portInfo || {};
            const allVulns = pr.vulnerabilities || [];
            const filteredVulns = allVulns.filter(v => passesSeverityFilter(v.severity, minSeverity));

            const card = document.createElement('div');
            card.className = 'glass-panel port-card';

            const header = document.createElement('div');
            header.className = 'port-card-header';

            const titleGroup = document.createElement('div');
            titleGroup.className = 'port-title-group';

            const portBadge = document.createElement('span');
            portBadge.className = 'port-badge';
            portBadge.textContent = `${p.port}/${p.protocol || 'tcp'}`;

            const serviceDesc = [p.serviceName, p.product, p.version, p.extrainfo ? `(${p.extrainfo})` : '']
                .filter(Boolean)
                .join(' ');
            const serviceSpan = document.createElement('span');
            serviceSpan.className = 'service-meta';
            serviceSpan.textContent = serviceDesc || 'Unknown Service';

            titleGroup.appendChild(portBadge);
            titleGroup.appendChild(serviceSpan);

            const rightGroup = document.createElement('div');
            rightGroup.className = 'port-title-group';

            if (p.cpe) {
                const cpeEl = document.createElement('code');
                cpeEl.className = 'cpe-code';
                cpeEl.textContent = p.cpe;
                rightGroup.appendChild(cpeEl);
            } else {
                const noCpe = document.createElement('span');
                noCpe.className = 'badge';
                noCpe.textContent = 'No CPE';
                rightGroup.appendChild(noCpe);
            }

            const vulnCountBadge = document.createElement('span');
            vulnCountBadge.className = 'badge ' + (allVulns.length > 0 ? 'badge-emphasis' : '');
            vulnCountBadge.textContent = `${allVulns.length} CVE${allVulns.length === 1 ? '' : 's'}`;
            rightGroup.appendChild(vulnCountBadge);

            header.appendChild(titleGroup);
            header.appendChild(rightGroup);
            card.appendChild(header);

            const body = document.createElement('div');
            body.className = 'port-card-body';

            if (pr.lookupError) {
                const errBanner = document.createElement('div');
                errBanner.className = 'recommendation-banner';
                errBanner.textContent = pr.lookupError;
                body.appendChild(errBanner);
            }

            if (allVulns.length > 0) {
                const rec = document.createElement('div');
                rec.className = 'recommendation-banner';
                const swName = [p.product, p.version].filter(Boolean).join(' ') || p.serviceName || 'this service';
                rec.innerHTML = `<strong>Remediation Advisory:</strong> ${allVulns.length} known vulnerability record(s) matched <em>${escapeHtml(swName)}</em>. Review the CVE advisories below and update to a patched version.`;
                body.appendChild(rec);
            }

            if (filteredVulns.length === 0) {
                const noneP = document.createElement('p');
                noneP.className = 'muted';
                if (!p.cpe) {
                    noneP.textContent = 'Nmap did not report a version CPE for this port, so automated CVE lookup was skipped.';
                } else if (allVulns.length > 0) {
                    noneP.textContent = `No vulnerabilities match the selected severity filter (${minSeverity}).`;
                } else {
                    noneP.textContent = 'No known vulnerabilities returned from the database for this CPE.';
                }
                body.appendChild(noneP);
            } else {
                const listEl = document.createElement('div');
                listEl.className = 'vuln-list';
                filteredVulns.forEach(v => {
                    listEl.appendChild(createVulnDropdown(v));
                });
                body.appendChild(listEl);
            }

            card.appendChild(body);
            portsContainer.appendChild(card);
        });
    }

    /**
     * Builds the <details> dropdown containing exact fields from Leonhard's notes:
     * Top row: name, cveId, severity, cvssScore
     * Dropdown body: description, datePublished, dateUpdated, references, cweIds
     */
    function createVulnDropdown(v) {
        const details = document.createElement('details');
        details.className = 'vuln-item ' + severityClass(v.severity);

        const summary = document.createElement('summary');

        const left = document.createElement('div');
        left.className = 'vuln-summary-left';

        const cveSpan = document.createElement('span');
        cveSpan.className = 'cve-id';
        cveSpan.textContent = v.cveId || 'UNKNOWN-CVE';

        const nameSpan = document.createElement('span');
        nameSpan.className = 'vuln-name';
        nameSpan.textContent = (v.name && v.name !== v.cveId) ? v.name : (v.description ? truncate(v.description, 95) : v.cveId);

        left.appendChild(cveSpan);
        left.appendChild(nameSpan);

        const right = document.createElement('div');
        right.className = 'vuln-summary-right';

        const sev = (v.severity || 'UNKNOWN').toUpperCase();
        const sevBadge = document.createElement('span');
        sevBadge.className = 'badge ' + severityClass(sev);
        sevBadge.textContent = sev;

        const scoreSpan = document.createElement('span');
        scoreSpan.className = 'cvss-score ' + severityClass(sev);
        scoreSpan.title = 'CVSS Base Score';
        scoreSpan.textContent = v.cvssScore != null ? `CVSS ${Number(v.cvssScore).toFixed(1)}` : 'CVSS N/A';

        const arrow = document.createElement('span');
        arrow.className = 'dropdown-arrow';
        arrow.textContent = '▾';

        right.appendChild(sevBadge);
        right.appendChild(scoreSpan);
        right.appendChild(arrow);

        summary.appendChild(left);
        summary.appendChild(right);
        details.appendChild(summary);

        const body = document.createElement('div');
        body.className = 'vuln-details-body';

        const descP = document.createElement('p');
        descP.className = 'vuln-description';
        descP.textContent = v.description || 'No description provided in CVE record.';
        body.appendChild(descP);

        const metaGrid = document.createElement('div');
        metaGrid.className = 'vuln-meta-grid';

        const pubBlock = document.createElement('div');
        pubBlock.className = 'meta-block';
        pubBlock.innerHTML = `<strong>Date Published</strong><span>${formatDate(v.datePublished)}</span>`;

        const updBlock = document.createElement('div');
        updBlock.className = 'meta-block';
        updBlock.innerHTML = `<strong>Date Updated</strong><span>${formatDate(v.dateUpdated)}</span>`;

        const cweBlock = document.createElement('div');
        cweBlock.className = 'meta-block';
        const cweTitle = document.createElement('strong');
        cweTitle.textContent = 'CWE IDs';
        cweBlock.appendChild(cweTitle);

        const cweList = document.createElement('div');
        cweList.className = 'cwe-list';
        if (v.cweIds && v.cweIds.length > 0) {
            v.cweIds.forEach(cwe => {
                const tag = document.createElement('span');
                tag.className = 'cwe-tag';
                tag.textContent = cwe;
                cweList.appendChild(tag);
            });
        } else {
            const none = document.createElement('span');
            none.className = 'muted';
            none.textContent = 'None listed';
            cweList.appendChild(none);
        }
        cweBlock.appendChild(cweList);

        metaGrid.appendChild(pubBlock);
        metaGrid.appendChild(updBlock);
        metaGrid.appendChild(cweBlock);
        body.appendChild(metaGrid);

        if (v.references && v.references.length > 0) {
            const refBlock = document.createElement('div');
            refBlock.className = 'meta-block';
            const refTitle = document.createElement('strong');
            refTitle.textContent = `References (${v.references.length})`;
            refBlock.appendChild(refTitle);

            const ul = document.createElement('ul');
            ul.className = 'ref-list';
            v.references.forEach(url => {
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.href = url;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.textContent = url;
                li.appendChild(a);
                ul.appendChild(li);
            });
            refBlock.appendChild(ul);
            body.appendChild(refBlock);
        }

        details.appendChild(body);
        return details;
    }

    // Modal handlers for direct CPE testing
    cpeModalBtn.addEventListener('click', () => {
        cpeModal.classList.remove('hidden');
    });

    closeCpeModalBtn.addEventListener('click', () => {
        cpeModal.classList.add('hidden');
    });

    cpeModal.addEventListener('click', (e) => {
        if (e.target === cpeModal) {
            cpeModal.classList.add('hidden');
        }
    });

    cpeLookupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const cpe = cpeInput.value.trim();
        if (!cpe) return;

        cpeModalResults.innerHTML = '<p class="muted">Querying CIRCL Vulnerability Lookup API...</p>';
        try {
            const res = await fetch(`/api/vulnerabilities?cpe=${encodeURIComponent(cpe)}`);
            const data = await res.json();
            if (!res.ok) {
                cpeModalResults.innerHTML = `<p class="muted">${escapeHtml(data.error || 'Failed to lookup CPE')}</p>`;
                return;
            }
            cpeModalResults.innerHTML = '';
            const countP = document.createElement('p');
            countP.className = 'muted';
            countP.style.marginBottom = '0.75rem';
            countP.textContent = `Found ${data.length} vulnerability record(s) for ${cpe}:`;
            cpeModalResults.appendChild(countP);

            const list = document.createElement('div');
            list.className = 'vuln-list';
            data.forEach(v => list.appendChild(createVulnDropdown(v)));
            cpeModalResults.appendChild(list);
        } catch (err) {
            cpeModalResults.innerHTML = `<p class="muted">Request failed: ${escapeHtml(err.message)}</p>`;
        }
    });

    function passesSeverityFilter(severity, filter) {
        if (!filter || filter === 'ALL') return true;
        const rank = severityRank(severity);
        const minRank = severityRank(filter);
        return rank >= minRank;
    }

    function severityRank(sev) {
        switch ((sev || '').toUpperCase()) {
            case 'CRITICAL': return 4;
            case 'HIGH': return 3;
            case 'MEDIUM':
            case 'MODERATE': return 2;
            case 'LOW': return 1;
            default: return 0;
        }
    }

    function severityClass(sev) {
        switch ((sev || '').toUpperCase()) {
            case 'CRITICAL': return 'sev-critical';
            case 'HIGH': return 'sev-high';
            case 'MEDIUM':
            case 'MODERATE': return 'sev-medium';
            case 'LOW': return 'sev-low';
            default: return '';
        }
    }

    function formatDate(iso) {
        if (!iso) return 'N/A';
        const d = new Date(iso);
        return isNaN(d.getTime()) ? iso : d.toISOString().split('T')[0];
    }

    function truncate(str, max) {
        if (!str) return '';
        return str.length > max ? str.slice(0, max - 1) + '…' : str;
    }

    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function showError(title, msg) {
        errorTitle.textContent = title;
        errorMessage.textContent = msg;
        errorSection.classList.remove('hidden');
    }

    function hideError() {
        errorSection.classList.add('hidden');
    }
})();
