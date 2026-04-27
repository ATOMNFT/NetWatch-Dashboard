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
  networkMap: document.getElementById('networkMap'),
  mapFocusCard: document.getElementById('mapFocusCard'),
  tabs: Array.from(document.querySelectorAll('.view-tab')),
  views: {
    dashboard: document.getElementById('dashboardView'),
    map: document.getElementById('mapView'),
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

let lastDevices = [];
let selectedMapDeviceKey = '';

function getDeviceKey(device) {
  return device?.mac || device?.ip || device?.display_name || '';
}

function mapGroup(device) {
  const type = (device?.device_type || '').toLowerCase();
  const title = (device?.display_name || '').toLowerCase();
  if (type.includes('router') || type.includes('gateway') || type.includes('network appliance') || title.includes('router') || title.includes('gateway')) return 'gateway';
  if (type.includes('nas') || type.includes('server') || type.includes('linux') || type.includes('windows host') || type.includes('web server')) return 'server';
  if (type.includes('printer')) return 'printer';
  if (type.includes('camera') || type.includes('iot')) return 'camera';
  return 'endpoint';
}

function mapGroupLabel(group) {
  return ({
    gateway: 'Gateway / Network',
    server: 'Servers / NAS',
    endpoint: 'Endpoints',
    printer: 'Printers',
    camera: 'Cameras / IoT',
  })[group] || 'Other Devices';
}

function deviceMetaLine(device) {
  return [
    device?.ip || '',
    `${device?.port_count || 0} open ports`,
    device?.vendor || '',
    device?.hostname && device.hostname !== device.display_name ? `Host: ${device.hostname}` : ''
  ].filter(Boolean).map(escapeHtml).join(' · ');
}

function renderMapFocus(device) {
  if (!els.mapFocusCard) return;
  if (!device) {
    els.mapFocusCard.className = 'map-focus-card muted';
    els.mapFocusCard.innerHTML = 'Click a node in the map to inspect its device details.';
    return;
  }

  const ports = device.ports?.length
    ? device.ports.map((p) => `<span class="port-pill">${escapeHtml(p.port)}/${escapeHtml(p.proto)} · ${escapeHtml(p.service)}</span>`).join('')
    : '<span class="port-pill">No open ports in configured scan range</span>';

  const detailBits = [
    device?.device_type || '',
    device?.mac ? `MAC: ${device.mac}` : '',
    device?.http_title ? `HTTP: ${device.http_title}` : ''
  ].filter(Boolean).map(escapeHtml).join(' · ');

  els.mapFocusCard.className = 'map-focus-card';
  els.mapFocusCard.innerHTML = `
    <div class="map-focus-top">
      <div>
        <div class="device-title">${escapeHtml(device.display_name || device.hostname || device.ip)}</div>
        <div class="device-sub">${deviceMetaLine(device)}</div>
        ${detailBits ? `<div class="device-detail">${detailBits}</div>` : ''}
      </div>
      ${severityBadge(device.severity || 'low')}
    </div>
    <div class="device-ports">${ports}</div>
  `;
}

function renderNetworkMap(devices) {
  if (!els.networkMap) return;
  lastDevices = Array.isArray(devices) ? devices : [];

  if (!lastDevices.length) {
    els.networkMap.className = 'network-map empty-state';
    els.networkMap.innerHTML = 'Run a scan to generate the network map.';
    renderMapFocus(null);
    return;
  }

  const groups = { gateway: [], server: [], endpoint: [], printer: [], camera: [] };
  lastDevices.forEach((device) => {
    groups[mapGroup(device)].push(device);
  });

  const sections = Object.entries(groups).map(([group, items]) => `
    <section class="map-group ${group}">
      <div class="map-group-header">
        <h3>${mapGroupLabel(group)}</h3>
        <span class="map-group-count">${items.length}</span>
      </div>
      <div class="map-node-grid">
        ${items.length ? items.map((device) => {
          const key = getDeviceKey(device);
          const active = key && key === selectedMapDeviceKey ? ' active' : '';
          return `
            <button class="map-node ${group}${active}" type="button" data-device-key="${escapeHtml(key)}">
              <span class="map-node-title">${escapeHtml(device.display_name || device.hostname || device.ip)}</span>
              <span class="map-node-sub">${escapeHtml(device.ip || '')}</span>
              <span class="map-node-meta">${escapeHtml(device.device_type || 'General Host')}</span>
            </button>
          `;
        }).join('') : '<div class="map-empty-slot">No devices in this group.</div>'}
      </div>
    </section>
  `).join('');

  els.networkMap.className = 'network-map';
  els.networkMap.innerHTML = `
    <div class="network-map-hub">
      <div class="hub-ring"></div>
      <div class="hub-core">
        <span class="hub-label">NetWatch</span>
        <strong>${lastDevices.length} devices</strong>
      </div>
    </div>
    <div class="map-groups">${sections}</div>
  `;

  const fallbackDevice = lastDevices.find((d) => getDeviceKey(d) === selectedMapDeviceKey) || lastDevices[0];
  selectedMapDeviceKey = getDeviceKey(fallbackDevice);
  renderMapFocus(fallbackDevice);

  els.networkMap.querySelectorAll('.map-node').forEach((node) => {
    node.addEventListener('click', () => {
      selectedMapDeviceKey = node.dataset.deviceKey || '';
      renderNetworkMap(lastDevices);
    });
  });
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
    renderNetworkMap(state.devices);
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
