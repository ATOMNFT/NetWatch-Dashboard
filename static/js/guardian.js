/* Network Guardian UI. Data is provided by /api/guardian. */
(function () {
  const byId = id => document.getElementById(id);
  const escapeHtml = value => String(value == null ? '' : value)
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
  const dateText = value => value ? new Date(value).toLocaleString() : 'Never';

  async function request(path, options) {
    const response = await fetch(path, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Guardian request failed');
    return data;
  }

  function render(state) {
    byId('guardianOnline').textContent = state.counts.online;
    byId('guardianTrusted').textContent = state.counts.trusted;
    byId('guardianUnknown').textContent = state.counts.unknown;
    byId('guardianLastScan').textContent = dateText(state.last_scan);
    byId('guardianTarget').textContent = state.target || 'None';
    const devices = byId('guardianDevices');
    if (!devices.contains(document.activeElement)) {
      devices.innerHTML = state.devices.length ? state.devices.map(function (d) {
        const name = escapeHtml(d.guardian_name || d.display_name || d.ip);
        const key = escapeHtml(d.device_key);
        const trusted = !!d.trusted;
        return '<article class="device-card guardian-device">' +
          '<div class="device-top"><div><strong>' + name + '</strong>' +
          '<div class="device-detail">' + escapeHtml(d.ip) + ' · ' +
          escapeHtml(d.vendor || d.device_type || 'Unknown type') + '</div></div>' +
          '<span class="severity ' + (trusted ? 'low' : 'medium') + '">' +
          (trusted ? 'Trusted' : 'Unreviewed') + '</span></div>' +
          '<div class="guardian-profile">' +
          '<input class="target-input guardian-alias" aria-label="Friendly device name" maxlength="80" value="' +
          escapeHtml(d.guardian_name || '') + '" placeholder="Friendly name (optional)">' +
          '<button class="btn secondary guardian-save" type="button" data-key="' + key +
          '" data-trusted="' + (trusted ? '1' : '0') + '">Save name</button>' +
          '<button class="btn ' + (trusted ? 'secondary' : 'primary') +
          ' guardian-trust" type="button" data-key="' + key + '" data-trusted="' +
          (trusted ? '1' : '0') + '">' + (trusted ? 'Remove trust' : 'Mark trusted') + '</button>' +
          '</div></article>';
      }).join('') : '<div class="empty-state">Run a scan to establish your baseline.</div>';
    }
    const events = byId('guardianEvents');
    events.innerHTML = state.events.length ? state.events.map(function (e) {
      return '<div class="finding-card"><div class="device-top"><strong>' +
        escapeHtml(e.event_type.replaceAll('_', ' ')) + '</strong><span class="severity ' +
        (e.severity === 'warning' ? 'medium' : 'low') + '">' + escapeHtml(e.severity) +
        '</span></div><p>' + escapeHtml(e.detail) + '</p><div class="device-detail">' +
        escapeHtml(e.ip) + ' · ' + escapeHtml(dateText(e.created_at)) + '</div></div>';
    }).join('') : '<div class="empty-state">No changes yet. Compare two successful scans of the same target.</div>';
  }

  window.refreshGuardian = async function () {
    try {
      render(await request('/api/guardian'));
    } catch (error) {
      byId('guardianEvents').textContent = error.message;
    }
  };

  byId('guardianDevices').addEventListener('click', async function (event) {
    const button = event.target.closest('.guardian-save, .guardian-trust');
    if (!button) return;
    const profile = button.closest('.guardian-device');
    const display_name = profile.querySelector('.guardian-alias').value.trim();
    const trusted = button.classList.contains('guardian-trust')
      ? button.dataset.trusted !== '1' : button.dataset.trusted === '1';
    button.disabled = true;
    try {
      await request('/api/guardian/profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_key: button.dataset.key, trusted, display_name })
      });
      button.blur();
      await window.refreshGuardian();
    } catch (error) {
      button.disabled = false;
      alert(error.message);
    }
  });
})();
