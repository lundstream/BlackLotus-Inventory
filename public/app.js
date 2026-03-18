/* Secure Boot Inventory — Frontend */
(async function () {
  'use strict';

  // --- State ---
  let currentSort = 'hostname';
  let currentOrder = 'asc';
  let currentOffset = 0;
  const PAGE_SIZE = 50;
  let totalDevices = 0;
  let phaseChart = null;
  let certChart = null;

  // --- Helpers ---
  async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  function esc(str) {
    if (str == null) return '';
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  function boolIcon(val) {
    if (val === 1 || val === true) return '<span class="bool-yes"><i data-feather="check-circle"></i></span>';
    if (val === 0 || val === false) return '<span class="bool-no"><i data-feather="x-circle"></i></span>';
    return '<span class="bool-null">-</span>';
  }

  function phaseLabel(phase) {
    const labels = {
      'Complete': 'Complete',
      'Phase3_KEKPending': 'Phase 3 — KEK Pending',
      'Phase2_RevocationPending': 'Phase 2 — Revocation Pending',
      'Phase1_InProgress': 'Phase 1 — In Progress',
      'Phase0_NotStarted': 'Not Started',
      'SecureBootDisabled': 'Secure Boot Disabled',
      'Unknown': 'Unknown'
    };
    return labels[phase] || phase || 'Unknown';
  }

  function phaseBadge(phase) {
    const cls = 'phase-' + (phase || 'Unknown');
    return `<span class="phase-badge ${esc(cls)}">${esc(phaseLabel(phase))}</span>`;
  }

  function formatDate(iso) {
    if (!iso) return '-';
    try {
      const d = new Date(iso);
      return d.toLocaleString();
    } catch { return iso; }
  }

  // --- Theme ---
  function isLightTheme() {
    return document.documentElement.classList.contains('light-theme');
  }

  function chartTextColor() {
    return isLightTheme() ? '#1a0a2e' : '#efe8ff';
  }

  function chartGridColor() {
    return isLightTheme() ? 'rgba(100,60,140,0.08)' : 'rgba(255,255,255,0.04)';
  }

  function applyTheme(theme) {
    document.documentElement.classList.toggle('light-theme', theme === 'light');
    const icon = document.querySelector('#theme-toggle i');
    if (icon) icon.setAttribute('data-feather', theme === 'light' ? 'sun' : 'moon');
    feather.replace();
    // Re-render charts with correct colors
    if (lastSummary) {
      renderPhaseChart(lastSummary.byPhase || []);
      if (lastSummary.certStats) renderCertChart(lastSummary.certStats, lastSummary.total);
    }
  }

  let lastSummary = null;

  const savedTheme = localStorage.getItem('sb-theme') || 'dark';
  applyTheme(savedTheme);

  document.getElementById('theme-toggle').addEventListener('click', () => {
    const next = isLightTheme() ? 'dark' : 'light';
    localStorage.setItem('sb-theme', next);
    applyTheme(next);
  });

  // --- Load settings ---
  try {
    const s = await fetchJSON('/api/settings');
    if (s.siteName) {
      document.getElementById('site-title').textContent = s.siteName;
      document.title = s.siteName;
    }
    if (s.footerText) document.getElementById('footer-text').textContent = s.footerText;
  } catch (e) { console.warn('Could not load settings', e); }

  // --- Load filters ---
  async function loadFilters() {
    try {
      const f = await fetchJSON('/api/filters');
      const domSel = document.getElementById('filter-domain');
      const phaseSel = document.getElementById('filter-phase');
      domSel.innerHTML = '<option value="">All Domains</option>';
      phaseSel.innerHTML = '<option value="">All Phases</option>';
      (f.domains || []).forEach(d => {
        const o = document.createElement('option');
        o.value = d; o.textContent = d;
        domSel.appendChild(o);
      });
      (f.phases || []).forEach(p => {
        const o = document.createElement('option');
        o.value = p; o.textContent = phaseLabel(p);
        phaseSel.appendChild(o);
      });
    } catch (e) { console.warn('Could not load filters', e); }
  }

  // --- Load summary ---
  async function loadSummary() {
    try {
      const s = await fetchJSON('/api/summary');
      document.getElementById('sum-total').textContent = s.total;
      document.getElementById('sum-complete').textContent = s.complete;
      document.getElementById('sum-percent').textContent = s.completionPercent + '%';
      document.getElementById('sum-sb-enabled').textContent = s.secureBootEnabled;

      // Pending = not complete and not "not started"
      const notStarted = (s.byPhase || []).filter(p =>
        p.migration_phase === 'Phase0_NotStarted' || p.migration_phase === 'SecureBootDisabled'
      ).reduce((a, b) => a + b.count, 0);
      const pending = s.total - s.complete - notStarted;
      document.getElementById('sum-pending').textContent = pending;
      document.getElementById('sum-not-started').textContent = notStarted;

      // Store for theme re-render
      lastSummary = s;

      // Phase chart
      renderPhaseChart(s.byPhase || []);

      // Cert chart
      if (s.certStats) renderCertChart(s.certStats, s.total);
    } catch (e) { console.warn('Could not load summary', e); }
  }

  // --- Phase chart ---
  const phaseColors = {
    'Complete': '#2ecc71',
    'Phase3_KEKPending': '#3498db',
    'Phase2_RevocationPending': '#f9a825',
    'Phase1_InProgress': '#ff4da6',
    'Phase0_NotStarted': '#e74c3c',
    'SecureBootDisabled': '#95a5a6',
    'Unknown': '#7f8c8d'
  };

  function renderPhaseChart(byPhase) {
    const ctx = document.getElementById('phase-chart').getContext('2d');
    const labels = byPhase.map(p => phaseLabel(p.migration_phase));
    const data = byPhase.map(p => p.count);
    const colors = byPhase.map(p => phaseColors[p.migration_phase] || '#7f8c8d');

    if (phaseChart) phaseChart.destroy();
    phaseChart = new Chart(ctx, {
      type: 'doughnut',
      data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: chartTextColor(), font: { size: 11 }, padding: 10 } }
        }
      }
    });
  }

  // --- Certificate chart ---
  function renderCertChart(certStats, total) {
    const ctx = document.getElementById('cert-chart').getContext('2d');
    const labels = ['DB (UEFI CA 2023)', 'DB Default', 'MS ROM', 'Option ROM', 'KEK 2023', 'DBX Revoked'];
    const data = [certStats.dbInstalled, certStats.dbDefaultInstalled, certStats.msromInstalled,
                  certStats.optromInstalled, certStats.kekInstalled, certStats.dbxRevoked];
    const remaining = data.map(d => total - d);

    if (certChart) certChart.destroy();
    certChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: 'Installed / Revoked', data, backgroundColor: '#2ecc71', borderRadius: 4 },
          { label: 'Missing', data: remaining, backgroundColor: 'rgba(231,76,60,0.4)', borderRadius: 4 }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        indexAxis: 'y',
        scales: {
          x: { stacked: true, ticks: { color: chartTextColor() }, grid: { color: chartGridColor() } },
          y: { stacked: true, ticks: { color: chartTextColor(), font: { size: 11 } }, grid: { display: false } }
        },
        plugins: {
          legend: { labels: { color: chartTextColor(), font: { size: 11 } } }
        }
      }
    });
  }

  // --- Load devices ---
  async function loadDevices() {
    const search = document.getElementById('filter-search').value.trim();
    const domain = document.getElementById('filter-domain').value;
    const phase = document.getElementById('filter-phase').value;

    const params = new URLSearchParams({
      sort: currentSort, order: currentOrder,
      limit: PAGE_SIZE, offset: currentOffset
    });
    if (search) params.set('search', search);
    if (domain) params.set('domain', domain);
    if (phase) params.set('phase', phase);

    try {
      const result = await fetchJSON('/api/devices?' + params);
      totalDevices = result.total;
      renderDeviceTable(result.devices);
      updatePagination();
    } catch (e) {
      console.warn('Could not load devices', e);
      document.getElementById('device-tbody').innerHTML = '<tr><td colspan="13" style="text-align:center;color:var(--muted);padding:30px">Could not load device data</td></tr>';
    }
  }

  // --- Render table ---
  function renderDeviceTable(devices) {
    const tbody = document.getElementById('device-tbody');
    if (!devices || devices.length === 0) {
      tbody.innerHTML = '<tr><td colspan="13" style="text-align:center;color:var(--muted);padding:30px">No devices found</td></tr>';
      feather.replace();
      return;
    }

    tbody.innerHTML = devices.map(d => `
      <tr>
        <td class="hostname" data-hostname="${esc(d.hostname)}" data-domain="${esc(d.domain)}">${esc(d.hostname)}</td>
        <td>${esc(d.domain)}</td>
        <td title="${esc(d.os_version)}">${esc(d.os_name || d.os_version || '-')}</td>
        <td>${esc(d.manufacturer)}</td>
        <td>${esc(d.model)}</td>
        <td>${boolIcon(d.is_virtual_machine)}</td>
        <td>${esc(d.bitlocker_status || '-')}</td>
        <td>${boolIcon(d.secure_boot_enabled)}</td>
        <td>${phaseBadge(d.migration_phase)}</td>
        <td>${boolIcon(d.db_install_status)}</td>
        <td>${boolIcon(d.kek_install_status)}</td>
        <td>${boolIcon(d.dbx_revocation_status)}</td>
        <td>${esc(formatDate(d.collected_at))}</td>
      </tr>
    `).join('');
    feather.replace();
  }

  // --- Pagination ---
  function updatePagination() {
    const page = Math.floor(currentOffset / PAGE_SIZE) + 1;
    const totalPages = Math.max(1, Math.ceil(totalDevices / PAGE_SIZE));
    document.getElementById('page-info').textContent = `Page ${page} of ${totalPages} (${totalDevices} devices)`;
    document.getElementById('btn-prev').disabled = currentOffset === 0;
    document.getElementById('btn-next').disabled = currentOffset + PAGE_SIZE >= totalDevices;
  }

  document.getElementById('btn-prev').addEventListener('click', () => {
    currentOffset = Math.max(0, currentOffset - PAGE_SIZE);
    loadDevices();
  });

  document.getElementById('btn-next').addEventListener('click', () => {
    currentOffset += PAGE_SIZE;
    loadDevices();
  });

  // --- Sorting ---
  document.querySelectorAll('thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (currentSort === col) {
        currentOrder = currentOrder === 'asc' ? 'desc' : 'asc';
      } else {
        currentSort = col;
        currentOrder = 'asc';
      }
      currentOffset = 0;
      // Update sorted indicators
      document.querySelectorAll('thead th').forEach(h => h.classList.remove('sorted'));
      th.classList.add('sorted');
      loadDevices();
    });
  });

  // --- Filters ---
  let searchTimeout;
  document.getElementById('filter-search').addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => { currentOffset = 0; loadDevices(); }, 300);
  });
  document.getElementById('filter-domain').addEventListener('change', () => { currentOffset = 0; loadDevices(); });
  document.getElementById('filter-phase').addEventListener('change', () => { currentOffset = 0; loadDevices(); });

  // --- Export ---
  document.getElementById('btn-export').addEventListener('click', () => {
    window.open('/api/export', '_blank');
  });

  // --- Device detail modal ---
  const modal = document.getElementById('detail-modal');
  const modalBody = document.getElementById('modal-body');

  document.getElementById('modal-close').addEventListener('click', () => modal.classList.remove('visible'));
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('visible'); });

  document.getElementById('device-tbody').addEventListener('click', async (e) => {
    const td = e.target.closest('td.hostname');
    if (!td) return;
    const hostname = td.dataset.hostname;
    const domain = td.dataset.domain;
    await showDeviceDetail(hostname, domain);
  });

  async function showDeviceDetail(hostname, domain) {
    try {
      const params = domain ? `?domain=${encodeURIComponent(domain)}` : '';
      const result = await fetchJSON(`/api/devices/${encodeURIComponent(hostname)}${params}`);
      const d = result.device;
      const history = result.history || [];

      const certItem = (label, val) => {
        const cls = val === 1 ? 'yes' : val === 0 ? 'no' : 'unknown';
        const icon = val === 1 ? 'check-circle' : val === 0 ? 'x-circle' : 'minus-circle';
        return `<div class="cert-item ${cls}"><i data-feather="${icon}"></i> ${esc(label)}</div>`;
      };

      modalBody.innerHTML = `
        <h2><i data-feather="monitor"></i> ${esc(d.hostname)}</h2>

        <h3 style="margin:16px 0 10px;font-size:0.85em;color:var(--muted)">SYSTEM INFORMATION</h3>
        <div class="detail-grid">
          <div class="detail-item"><span class="dlabel">Hostname</span><span class="dvalue">${esc(d.hostname)}</span></div>
          <div class="detail-item"><span class="dlabel">Domain</span><span class="dvalue">${esc(d.domain || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">OS</span><span class="dvalue">${esc(d.os_name || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">OS Build</span><span class="dvalue">${esc(d.os_build || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">Manufacturer</span><span class="dvalue">${esc(d.manufacturer || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">Model</span><span class="dvalue">${esc(d.model || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">BIOS Version</span><span class="dvalue">${esc(d.bios_version || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">BIOS Date</span><span class="dvalue">${esc(d.bios_date || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">Virtual Machine</span><span class="dvalue">${d.is_virtual_machine ? 'Yes' : 'No'}</span></div>
          ${d.vmware_hw_version ? `<div class="detail-item"><span class="dlabel">VMware HW Version</span><span class="dvalue">${esc(d.vmware_hw_version)}</span></div>` : ''}
          <div class="detail-item"><span class="dlabel">BitLocker (System Drive)</span><span class="dvalue">${esc(d.bitlocker_status || '-')}</span></div>
        </div>

        <h3 style="margin:20px 0 10px;font-size:0.85em;color:var(--muted)">SECURE BOOT STATUS</h3>
        <div class="detail-grid">
          <div class="detail-item"><span class="dlabel">Secure Boot</span><span class="dvalue">${d.secure_boot_enabled ? '<span class="bool-yes">Enabled</span>' : '<span class="bool-no">Disabled</span>'}</span></div>
          <div class="detail-item"><span class="dlabel">Migration Phase</span><span class="dvalue">${phaseBadge(d.migration_phase)}</span></div>
          <div class="detail-item"><span class="dlabel">UEFI CA 2023 Status</span><span class="dvalue">${esc(d.uefica2023_status || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">UEFI CA 2023 Error</span><span class="dvalue">${esc(d.uefica2023_error || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">Windows UEFI CA Capable</span><span class="dvalue">${esc(d.windows_uefica2023_capable || '-')}</span></div>
          <div class="detail-item"><span class="dlabel">Available Updates</span><span class="dvalue">${d.available_updates != null ? '0x' + d.available_updates.toString(16) + ' (' + d.available_updates + ')' : '-'}</span></div>
        </div>

        <h3 style="margin:20px 0 10px;font-size:0.85em;color:var(--muted)">CERTIFICATES</h3>
        <div class="cert-grid">
          ${certItem('Windows UEFI CA 2023 (DB)', d.db_install_status)}
          ${certItem('DB Default Store', d.db_default_install_status)}
          ${certItem('Microsoft UEFI CA 2023', d.msrom_install_status)}
          ${certItem('Option ROM UEFI CA 2023', d.optrom_install_status)}
          ${certItem('KEK 2K CA 2023', d.kek_install_status)}
          ${certItem('UEFI CA 2011 (3rd Party)', d.third_party_install_status)}
          ${certItem('PCA 2011 Revoked (DBX)', d.dbx_revocation_status)}
        </div>

        <h3 style="margin:20px 0 10px;font-size:0.85em;color:var(--muted)">REPORT HISTORY</h3>
        <div class="detail-item" style="margin-bottom:8px"><span class="dlabel">Last Report</span><span class="dvalue">${esc(formatDate(d.collected_at))}</span></div>
        ${history.length > 0 ? `
        <table class="history-table">
          <thead><tr><th>Date</th><th>Phase</th></tr></thead>
          <tbody>
            ${history.slice(0, 20).map(h => `<tr><td>${esc(formatDate(h.collected_at))}</td><td>${phaseBadge(h.migration_phase)}</td></tr>`).join('')}
          </tbody>
        </table>
        ` : '<div style="color:var(--muted);font-size:0.85em">No history records</div>'}
      `;

      feather.replace();
      modal.classList.add('visible');
    } catch (e) {
      console.warn('Could not load device detail', e);
    }
  }

  // --- Initial load ---
  await loadFilters();
  await loadSummary();
  await loadDevices();
  feather.replace();

})();
