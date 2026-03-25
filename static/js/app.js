const els = {
  hostsUp: document.getElementById('hostsUp'),
  openPorts: document.getElementById('openPorts'),
  alerts: document.getElementById('alerts'),
  lastScan: document.getElementById('lastScan'),
  runState: document.getElementById('runState'),
  deviceList: document.getElementById('deviceList'),
  findingsList: document.getElementById('findingsList'),
  logConsole: document.getElementById('logConsole'),
  scanBtn: document.getElementById('scanBtn'),
  clearBtn: document.getElementById('clearBtn'),
  exportBtn: document.getElementById('exportBtn'),
  targetInput: document.getElementById('targetInput'),
  targetStatus: document.getElementById('targetStatus'),
  scanProfileText: document.getElementById('scanProfileText'),
  portMode: document.getElementById('portMode'),
  customPorts: document.getElementById('customPorts'),
  scheduledEnabled: document.getElementById('scheduledEnabled'),
  scheduledTargets: document.getElementById('scheduledTargets'),
  scheduledInterval: document.getElementById('scheduledInterval'),
  saveSettingsBtn: document.getElementById('saveSettingsBtn'),
  reloadSettingsBtn: document.getElementById('reloadSettingsBtn'),
  lastScheduledRun: document.getElementById('lastScheduledRun'),
  nextScheduledRun: document.getElementById('nextScheduledRun'),
  tabs: Array.from(document.querySelectorAll('.view-tab')),
  views: {
    dashboard: document.getElementById('dashboardView'),
    settings: document.getElementById('settingsView'),
  },
};

let settingsDirty = false;
let settingsLoaded = false;

function markSettingsDirty() {
  settingsDirty = true;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function severityBadge(level) {
  return `<span class="severity ${level}">${level}</span>`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatIso(value, fallback = 'Never') {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function profileSummary(settings) {
  const mode = settings?.port_mode || 'top200';
  if (mode === 'all') return 'All ports';
  if (mode === 'custom') return `Custom ports: ${settings?.custom_ports || 'Not set'}`;
  return 'Top 200 ports';
}

function renderDevices(devices) {
  if (!devices?.length) {
    els.deviceList.className = 'device-list empty-state';
    els.deviceList.innerHTML = 'No scan results yet.';
    return;
  }

  els.deviceList.className = 'device-list';
  els.deviceList.innerHTML = devices.map((d) => {
    const ports = d.ports?.length
      ? d.ports.map((p) => `<span class="port-pill">${escapeHtml(p.port)}/${escapeHtml(p.proto)} · ${escapeHtml(p.service)}</span>`).join('')
      : '<span class="port-pill">No open ports in configured scan range</span>';

    const metaBits = [
      d.ip,
      `${d.port_count || 0} open ports`,
      d.device_type || '',
      d.vendor || ''
    ].filter(Boolean).map(escapeHtml);

    const detailBits = [
      d.hostname && d.hostname !== d.display_name ? `Hostname: ${d.hostname}` : '',
      d.mac ? `MAC: ${d.mac}` : '',
      d.http_title ? `HTTP: ${d.http_title}` : ''
    ].filter(Boolean).map(escapeHtml);

    return `
      <article class="device-card">
        <div class="device-top">
          <div>
            <div class="device-title">${escapeHtml(d.display_name || d.hostname || d.ip)}</div>
            <div class="device-sub">${metaBits.join(' · ')}</div>
            ${detailBits.length ? `<div class="device-detail">${detailBits.join(' · ')}</div>` : ''}
          </div>
          ${severityBadge(d.severity || 'low')}
        </div>
        <div class="device-ports">${ports}</div>
      </article>
    `;
  }).join('');
}

function renderFindings(findings) {
  if (!findings?.length) {
    els.findingsList.className = 'findings-list empty-state';
    els.findingsList.innerHTML = 'Nothing flagged yet.';
    return;
  }

  els.findingsList.className = 'findings-list';
  els.findingsList.innerHTML = findings.map((f) => `
    <article class="finding-card">
      <div class="device-top">
        <strong>${escapeHtml(f.title)}</strong>
        ${severityBadge(f.severity || 'low')}
      </div>
      <p>${escapeHtml(f.host)}</p>
    </article>
  `).join('');
}

function renderLogs(lines) {
  els.logConsole.textContent = lines?.length ? lines.join('\n') : 'Waiting for a scan…';
  els.logConsole.scrollTop = els.logConsole.scrollHeight;
}

function renderSummary(summary, running, target) {
  els.hostsUp.textContent = summary?.hosts_up ?? 0;
  els.openPorts.textContent = summary?.open_ports ?? 0;
  els.alerts.textContent = summary?.alerts ?? 0;
  els.lastScan.textContent = summary?.last_scan ?? 'Never';
  els.runState.textContent = running ? 'Scanning' : 'Idle';

  const cleanTarget = (target || '').trim();
  if (running && cleanTarget) {
    els.targetStatus.textContent = `Target: ${cleanTarget}`;
  } else if (cleanTarget) {
    els.targetStatus.textContent = `Last target: ${cleanTarget}`;
  } else {
    els.targetStatus.textContent = 'No active target';
  }

  els.exportBtn.classList.toggle('disabled-link', !summary?.hosts_up && !summary?.open_ports && !summary?.alerts);
}

function renderSettings(settings, scheduler) {
  const shouldHydrateForm = !settingsLoaded || !settingsDirty;

  if (shouldHydrateForm) {
    els.portMode.value = settings?.port_mode || 'top200';
    els.customPorts.value = settings?.custom_ports || '';
    els.scheduledEnabled.checked = !!settings?.scheduled_enabled;
    els.scheduledTargets.value = settings?.scheduled_targets || '';
    els.scheduledInterval.value = settings?.scheduled_interval_minutes || 60;
    settingsLoaded = true;
  }

  const liveSummary = {
    port_mode: els.portMode.value || settings?.port_mode || 'top200',
    custom_ports: els.customPorts.value.trim() || settings?.custom_ports || '',
  };

  els.scanProfileText.textContent = profileSummary(liveSummary);
  els.lastScheduledRun.textContent = formatIso(scheduler?.last_run_at, 'Never');
  els.nextScheduledRun.textContent = scheduler?.next_run_at_iso ? formatIso(scheduler.next_run_at_iso, 'Disabled') : 'Disabled';
}

function setActiveView(name) {
  Object.entries(els.views).forEach(([key, node]) => {
    node.classList.toggle('active', key === name);
  });
  els.tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.view === name));
}

async function refreshStatus() {
  try {
    const state = await api('/api/status');
    renderSummary(state.summary, state.running, state.target);
    renderDevices(state.devices);
    renderFindings(state.findings);
    renderLogs(state.logs);
    renderSettings(state.settings || {}, state.scheduler || {});
    els.scanBtn.disabled = !!state.running;
    els.clearBtn.disabled = !!state.running;
    els.scanBtn.textContent = state.running ? 'Scanning…' : 'Start New Scan';
  } catch (err) {
    els.logConsole.textContent = err.message;
  }
}

async function startScan() {
  const target = els.targetInput.value.trim();
  if (!target) return;
  try {
    await api('/api/scan', {
      method: 'POST',
      body: JSON.stringify({ target }),
    });
    await refreshStatus();
  } catch (err) {
    alert(err.message);
  }
}

async function clearResults() {
  try {
    await api('/api/reset', { method: 'POST' });
    await refreshStatus();
  } catch (err) {
    alert(err.message);
  }
}

async function saveSettings() {
  try {
    const saved = await api('/api/settings', {
      method: 'POST',
      body: JSON.stringify({
        port_mode: els.portMode.value,
        custom_ports: els.customPorts.value.trim(),
        scheduled_enabled: els.scheduledEnabled.checked,
        scheduled_targets: els.scheduledTargets.value.trim(),
        scheduled_interval_minutes: Number(els.scheduledInterval.value || 60),
      }),
    });
    settingsDirty = false;
    renderSettings(saved.settings || {}, saved.scheduler || {});
    await refreshStatus();
    alert('Settings saved.');
  } catch (err) {
    alert(err.message);
  }
}

els.scanBtn.addEventListener('click', startScan);
els.clearBtn.addEventListener('click', clearResults);
els.saveSettingsBtn.addEventListener('click', saveSettings);
els.reloadSettingsBtn.addEventListener('click', refreshStatus);

document.querySelectorAll('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    els.targetInput.value = chip.dataset.target || '';
  });
});

els.tabs.forEach((tab) => {
  tab.addEventListener('click', () => setActiveView(tab.dataset.view));
});


els.portMode.addEventListener('change', () => {
  markSettingsDirty();
  els.scanProfileText.textContent = profileSummary({
    port_mode: els.portMode.value,
    custom_ports: els.customPorts.value.trim(),
  });
});

els.customPorts.addEventListener('input', () => {
  markSettingsDirty();
  if (els.portMode.value === 'custom') {
    els.scanProfileText.textContent = profileSummary({
      port_mode: 'custom',
      custom_ports: els.customPorts.value.trim(),
    });
  }
});

els.scheduledEnabled.addEventListener('change', markSettingsDirty);
els.scheduledTargets.addEventListener('input', markSettingsDirty);
els.scheduledInterval.addEventListener('input', markSettingsDirty);

refreshStatus();
setInterval(refreshStatus, 2500);
