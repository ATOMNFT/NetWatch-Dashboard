from flask import Flask, Response, jsonify, render_template, request
import csv
import io
import ipaddress
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

app = Flask(__name__)

APP_PORT = int(os.getenv('APP_PORT', '4998'))
DEFAULT_TOP_PORTS = os.getenv('DEFAULT_TOP_PORTS', '200')
MAC_PREFIX_FILE = '/usr/share/nmap/nmap-mac-prefixes'
UNKNOWN_HOST_LABELS = {'', 'unknown host', 'unknown'}
COMMON_ROUTER_VENDORS = {'ubiquiti', 'tp-link', 'netgear', 'linksys', 'mikrotik', 'arris', 'technicolor', 'zyxel', 'fortinet', 'juniper', 'cisco'}
COMMON_PRINTER_VENDORS = {'hp', 'hewlett packard', 'brother', 'canon', 'epson', 'lexmark', 'xerox', 'ricoh', 'kyocera'}
SAFE_TARGET_RE = re.compile(r'^[0-9a-zA-Z\.:/,_\-\s]+$')
TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
MAX_LOG_LINES = 400
MAC_VENDOR_CACHE = None
SETTINGS_DIR = os.getenv('SETTINGS_DIR', '/app/data')
SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'settings.json')

DEFAULT_SETTINGS = {
    'port_mode': 'top200',
    'custom_ports': '22,80,443',
    'scheduled_enabled': False,
    'scheduled_targets': '',
    'scheduled_interval_minutes': 60,
}

SCAN_STATE = {
    'running': False,
    'started_at': None,
    'finished_at': None,
    'target': '',
    'devices': [],
    'findings': [],
    'logs': [],
    'summary': {
        'hosts_up': 0,
        'open_ports': 0,
        'alerts': 0,
        'last_scan': 'Never'
    }
}

SETTINGS_STATE = {
    'settings': dict(DEFAULT_SETTINGS),
    'scheduler': {
        'last_run_at': None,
        'next_run_at': None,
        'last_target': '',
    }
}

LOCK = threading.Lock()


def log(message: str) -> None:
    timestamp = datetime.now().strftime('%H:%M:%S')
    with LOCK:
        SCAN_STATE['logs'].append(f'[{timestamp}] {message}')
        SCAN_STATE['logs'] = SCAN_STATE['logs'][-MAX_LOG_LINES:]


def ensure_settings_dir() -> None:
    os.makedirs(SETTINGS_DIR, exist_ok=True)


def normalize_settings(data: dict | None) -> dict:
    merged = dict(DEFAULT_SETTINGS)
    if isinstance(data, dict):
        merged.update(data)

    port_mode = str(merged.get('port_mode', 'top200')).strip().lower()
    if port_mode not in {'top200', 'all', 'custom'}:
        port_mode = 'top200'

    custom_ports = str(merged.get('custom_ports', '')).strip()
    if len(custom_ports) > 120:
        custom_ports = custom_ports[:120]

    scheduled_targets = str(merged.get('scheduled_targets', '')).strip()
    if len(scheduled_targets) > 200:
        scheduled_targets = scheduled_targets[:200]

    try:
        interval = int(merged.get('scheduled_interval_minutes', 60))
    except (TypeError, ValueError):
        interval = 60
    interval = max(1, min(interval, 10080))

    return {
        'port_mode': port_mode,
        'custom_ports': custom_ports,
        'scheduled_enabled': bool(merged.get('scheduled_enabled', False)),
        'scheduled_targets': scheduled_targets,
        'scheduled_interval_minutes': interval,
    }


def load_settings() -> dict:
    ensure_settings_dir()
    data = None
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception:
            data = None
    normalized = normalize_settings(data)
    with LOCK:
        SETTINGS_STATE['settings'] = normalized
        if not SETTINGS_STATE['scheduler']['next_run_at'] and normalized['scheduled_enabled'] and normalized['scheduled_targets']:
            SETTINGS_STATE['scheduler']['next_run_at'] = time.time() + normalized['scheduled_interval_minutes'] * 60
    return normalized


def save_settings(settings: dict) -> dict:
    normalized = normalize_settings(settings)
    ensure_settings_dir()
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as fh:
        json.dump(normalized, fh, indent=2)
    with LOCK:
        SETTINGS_STATE['settings'] = normalized
        if normalized['scheduled_enabled'] and normalized['scheduled_targets']:
            SETTINGS_STATE['scheduler']['next_run_at'] = time.time() + normalized['scheduled_interval_minutes'] * 60
        else:
            SETTINGS_STATE['scheduler']['next_run_at'] = None
            SETTINGS_STATE['scheduler']['last_target'] = ''
    return normalized


def scheduler_snapshot() -> dict:
    with LOCK:
        scheduler = dict(SETTINGS_STATE['scheduler'])
    next_run_at = scheduler.get('next_run_at')
    scheduler['next_run_at_iso'] = datetime.fromtimestamp(next_run_at).isoformat() if next_run_at else None
    return scheduler


def clear_state() -> None:
    with LOCK:
        SCAN_STATE['running'] = False
        SCAN_STATE['started_at'] = None
        SCAN_STATE['finished_at'] = None
        SCAN_STATE['target'] = ''
        SCAN_STATE['devices'] = []
        SCAN_STATE['findings'] = []
        SCAN_STATE['logs'] = []
        SCAN_STATE['summary'] = {
            'hosts_up': 0,
            'open_ports': 0,
            'alerts': 0,
            'last_scan': 'Never'
        }


def reset_state(target: str) -> None:
    with LOCK:
        SCAN_STATE['running'] = True
        SCAN_STATE['started_at'] = datetime.now().isoformat()
        SCAN_STATE['finished_at'] = None
        SCAN_STATE['target'] = target
        SCAN_STATE['devices'] = []
        SCAN_STATE['findings'] = []
        SCAN_STATE['logs'] = []
        SCAN_STATE['summary'] = {
            'hosts_up': 0,
            'open_ports': 0,
            'alerts': 0,
            'last_scan': 'Running...'
        }


def finish_state() -> None:
    with LOCK:
        SCAN_STATE['running'] = False
        SCAN_STATE['finished_at'] = datetime.now().isoformat()
        SCAN_STATE['summary']['last_scan'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def infer_local_subnet() -> str:
    override = os.getenv('DEFAULT_SCAN_TARGET', '').strip()
    if override:
        return override
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(local_ip)
        if ip.is_loopback:
            return '127.0.0.1'
        if isinstance(ip, ipaddress.IPv4Address):
            return f"{local_ip.rsplit('.', 1)[0]}.0/24"
        return str(ip)
    except Exception:
        return '127.0.0.1'


def validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError('Target is required.')
    if not SAFE_TARGET_RE.match(target):
        raise ValueError('Target contains unsupported characters.')
    if len(target) > 200:
        raise ValueError('Target is too long.')
    return target


def validate_custom_ports(custom_ports: str) -> str:
    custom_ports = custom_ports.strip()
    if not custom_ports:
        raise ValueError('Custom ports cannot be empty when custom mode is selected.')
    if not re.fullmatch(r'[0-9,\-\s]+', custom_ports):
        raise ValueError('Custom ports may only contain digits, commas, spaces, and hyphens.')
    for token in [t.strip() for t in custom_ports.split(',') if t.strip()]:
        if '-' in token:
            parts = token.split('-', 1)
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                raise ValueError(f'Invalid port range: {token}')
            start = int(parts[0])
            end = int(parts[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f'Invalid port range: {token}')
        else:
            if not token.isdigit():
                raise ValueError(f'Invalid port: {token}')
            port = int(token)
            if port < 1 or port > 65535:
                raise ValueError(f'Invalid port: {token}')
    return custom_ports


def current_settings() -> dict:
    with LOCK:
        return dict(SETTINGS_STATE['settings'])


def build_nmap_command(target: str, settings: dict):
    cmd = [
        'nmap',
        '-Pn',
        '-T4',
        '-sV',
    ]

    port_mode = settings.get('port_mode', 'top200')
    if port_mode == 'all':
        cmd.append('-p-')
    elif port_mode == 'custom':
        cmd.extend(['-p', validate_custom_ports(settings.get('custom_ports', ''))])
    else:
        cmd.extend(['--top-ports', DEFAULT_TOP_PORTS])

    cmd.extend(['-oG', '-', target])
    return cmd


def parse_grepable_output(raw: str):
    devices = []
    findings = []
    total_ports = 0

    for line in raw.splitlines():
        if not line.startswith('Host: ') or 'Ports:' not in line:
            continue

        host_match = re.search(r'Host:\s+(\S+)\s+\((.*?)\)', line)
        if not host_match:
            host_match = re.search(r'Host:\s+(\S+)', line)
        ip = host_match.group(1) if host_match else 'unknown'
        hostname = host_match.group(2).strip() if host_match and len(host_match.groups()) > 1 else ''

        ports_section = line.split('Ports:', 1)[1].strip()
        ports_raw = [p.strip() for p in ports_section.split(',') if p.strip()]
        open_ports = []

        for p in ports_raw:
            parts = p.split('/')
            if len(parts) < 5:
                continue
            port = parts[0]
            state = parts[1]
            proto = parts[2]
            service = parts[4] or 'unknown'
            version = parts[6] if len(parts) > 6 else ''
            if state != 'open':
                continue
            total_ports += 1
            open_ports.append({
                'port': port,
                'proto': proto,
                'service': service,
                'version': version
            })

        severity = 'low'
        risk_score = 0
        labels = []

        for port_info in open_ports:
            p = int(port_info['port']) if port_info['port'].isdigit() else -1
            service = port_info['service'].lower()
            version = (port_info.get('version') or '').lower()

            if p in {23, 21}:
                risk_score += 3
                labels.append(f'Legacy admin service exposed: {p}/{service}')
            elif p in {445, 3389}:
                risk_score += 2
                labels.append(f'Common lateral movement target exposed: {p}/{service}')
            elif p in {80, 8080, 8000}:
                risk_score += 1

            if 'smb' in service or service == 'microsoft-ds':
                risk_score += 2
                labels.append('SMB detected: verify version and access controls')
            if 'http' in service and 'apache' in version:
                labels.append('HTTP service detected: verify patch level and headers')

        if risk_score >= 5:
            severity = 'high'
        elif risk_score >= 2:
            severity = 'medium'

        for label in dict.fromkeys(labels):
            findings.append({
                'host': ip,
                'title': label,
                'severity': 'high' if 'legacy' in label.lower() else ('medium' if 'smb' in label.lower() or 'lateral' in label.lower() else 'low')
            })

        devices.append({
            'hostname': hostname or '',
            'display_name': hostname or ip,
            'ip': ip,
            'status': 'up',
            'severity': severity,
            'ports': open_ports,
            'port_count': len(open_ports),
            'mac': '',
            'vendor': '',
            'http_title': '',
            'device_type': '',
        })

    return devices, findings, total_ports


def load_mac_vendor_map():
    global MAC_VENDOR_CACHE
    if MAC_VENDOR_CACHE is not None:
        return MAC_VENDOR_CACHE

    vendor_map = {}
    try:
        with open(MAC_PREFIX_FILE, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = re.split(r'\s+', line, maxsplit=1)
                if len(parts) != 2:
                    continue
                prefix = parts[0].replace(':', '').replace('-', '').upper()
                vendor_map[prefix] = parts[1].strip()
    except FileNotFoundError:
        vendor_map = {}

    MAC_VENDOR_CACHE = vendor_map
    return MAC_VENDOR_CACHE


def normalize_mac(mac: str) -> str:
    return (mac or '').replace(':', '').replace('-', '').upper()


def lookup_vendor_by_mac(mac: str) -> str:
    if not mac:
        return ''
    vendor_map = load_mac_vendor_map()
    normalized = normalize_mac(mac)
    return vendor_map.get(normalized[:6], '')


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''


def get_mac_from_neighbor_table(ip: str) -> str:
    try:
        proc = subprocess.run(['ip', 'neigh', 'show', ip], capture_output=True, text=True, timeout=3)
        if proc.returncode != 0:
            return ''
        match = re.search(r'lladdr\s+([0-9a-f:]{17})', proc.stdout, re.IGNORECASE)
        return match.group(1).lower() if match else ''
    except Exception:
        return ''


def extract_http_title(html_text: str) -> str:
    match = TITLE_RE.search(html_text or '')
    if not match:
        return ''
    title = re.sub(r'\s+', ' ', match.group(1)).strip()
    return title[:120]


def fetch_http_title(ip: str, ports: list[dict]) -> str:
    interesting_ports = []
    for port in ports:
        value = port.get('port', '')
        if value in {'80', '443'}:
            interesting_ports.append(value)

    for port in interesting_ports:
        scheme = 'https' if port == '443' else 'http'
        url = f'{scheme}://{ip}:{port}/'
        try:
            request_obj = urllib.request.Request(url, headers={'User-Agent': 'NetWatch/1.0'})
            context = ssl._create_unverified_context() if scheme == 'https' else None
            with urllib.request.urlopen(request_obj, timeout=2, context=context) as response:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                    continue
                body = response.read(4096).decode('utf-8', errors='ignore')
                title = extract_http_title(body)
                if title:
                    return title
        except (urllib.error.URLError, TimeoutError, ValueError, ssl.SSLError):
            continue
        except Exception:
            continue
    return ''


def hostname_is_unknown(hostname: str) -> bool:
    return hostname.strip().lower() in UNKNOWN_HOST_LABELS


def infer_device_type(device: dict) -> str:
    ports = {int(p['port']) for p in device.get('ports', []) if str(p.get('port', '')).isdigit()}
    services = ' '.join((p.get('service') or '') for p in device.get('ports', [])).lower()
    versions = ' '.join((p.get('version') or '') for p in device.get('ports', [])).lower()
    vendor = (device.get('vendor') or '').lower()
    title = (device.get('http_title') or '').lower()
    hostname = (device.get('hostname') or '').lower()

    if 9100 in ports or any(word in services or word in title or word in vendor for word in ['printer', 'jetdirect', 'ipp', 'laserjet']):
        return 'Printer'
    if 445 in ports or 139 in ports or 'synology' in title or 'qnap' in title or 'truenas' in title:
        return 'NAS / File Server'
    if 554 in ports or 8554 in ports or 'camera' in title or 'hikvision' in title or 'dahua' in title:
        return 'Camera / NVR'
    if 3389 in ports or {'135', '139', '445'} & {str(p) for p in ports}:
        return 'Windows Host'
    if 22 in ports and (80 in ports or 443 in ports) and any(v in vendor for v in COMMON_ROUTER_VENDORS):
        return 'Router / Gateway'
    if 80 in ports or 443 in ports:
        if any(word in title for word in ['router', 'gateway', 'firewall', 'openwrt', 'pfsense', 'opnsense', 'unifi']):
            return 'Router / Gateway'
        if any(v in vendor for v in COMMON_ROUTER_VENDORS):
            return 'Router / Gateway'
        if 'apache' in versions or 'nginx' in versions or 'http' in services:
            return 'Web Server'
    if 22 in ports and ('linux' in hostname or 'ubuntu' in title or 'debian' in title):
        return 'Linux / Unix Host'
    if any(v in vendor for v in COMMON_PRINTER_VENDORS):
        return 'Printer'
    if any(v in vendor for v in COMMON_ROUTER_VENDORS):
        return 'Network Appliance'
    if 1883 in ports or 8883 in ports or 'espressif' in vendor:
        return 'IoT Device'
    return 'General Host'


def build_display_name(device: dict) -> str:
    hostname = (device.get('hostname') or '').strip()
    ip = device.get('ip', '').strip()
    vendor = (device.get('vendor') or '').strip()
    title = (device.get('http_title') or '').strip()
    device_type = (device.get('device_type') or '').strip()

    if hostname and not hostname_is_unknown(hostname):
        return hostname
    if title and device_type and device_type.lower() not in title.lower():
        return f'{device_type} · {title}'
    if title:
        return title
    if vendor and device_type and device_type.lower() not in vendor.lower():
        return f'{vendor} {device_type}'
    if vendor:
        return vendor
    if device_type and device_type != 'General Host':
        return device_type
    return ip or 'Unknown Host'


def enrich_devices(devices: list[dict], findings: list[dict]) -> tuple[list[dict], list[dict]]:
    if not devices:
        return devices, findings

    log('Running enrichment: reverse DNS, MAC vendor lookup, HTTP title checks, and device-type heuristics.')
    enriched_dns = 0
    enriched_vendor = 0
    enriched_title = 0

    for device in devices:
        ip = device.get('ip', '')
        if not ip:
            continue

        hostname = reverse_dns(ip)
        if hostname and hostname != device.get('hostname'):
            device['hostname'] = hostname
            enriched_dns += 1

        mac = get_mac_from_neighbor_table(ip)
        if mac:
            device['mac'] = mac
            vendor = lookup_vendor_by_mac(mac)
            if vendor:
                device['vendor'] = vendor
                enriched_vendor += 1

        http_title = fetch_http_title(ip, device.get('ports', []))
        if http_title:
            device['http_title'] = http_title
            enriched_title += 1

        device['device_type'] = infer_device_type(device)
        device['display_name'] = build_display_name(device)

        if device.get('http_title'):
            findings.append({
                'host': ip,
                'title': f"HTTP title detected: {device['http_title']}",
                'severity': 'low'
            })

        if device.get('vendor') and device.get('device_type'):
            findings.append({
                'host': ip,
                'title': f"Enriched as {device['device_type']} from vendor/service clues",
                'severity': 'low'
            })

    log(f'Enrichment finished. Reverse DNS: {enriched_dns} | Vendor matches: {enriched_vendor} | HTTP titles: {enriched_title}')
    return devices, findings


def run_scan(target: str, launched_by: str = 'manual') -> None:
    reset_state(target)
    settings = current_settings()
    log(f'Starting {launched_by} scan for target: {target}')
    try:
        cmd = build_nmap_command(target, settings)
    except ValueError as exc:
        log(str(exc))
        finish_state()
        return

    command_preview = ' '.join(shlex.quote(x) for x in cmd)
    log(f'Running command: {command_preview}')

    if settings['port_mode'] == 'all':
        log('Settings mode: scanning all ports with service detection. This is the slowest option.')
    elif settings['port_mode'] == 'custom':
        log(f"Settings mode: scanning custom ports {settings['custom_ports']} with service detection.")
    else:
        log(f'Settings mode: scanning the top {DEFAULT_TOP_PORTS} ports with service detection.')

    log('This scan checks the selected ports, identifies common services, and adds light enrichment for host naming and device labeling.')

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if proc.stderr.strip():
            log(proc.stderr.strip())
        devices, findings, total_ports = parse_grepable_output(proc.stdout)
        devices, findings = enrich_devices(devices, findings)

        with LOCK:
            SCAN_STATE['devices'] = devices
            SCAN_STATE['findings'] = findings
            SCAN_STATE['summary']['hosts_up'] = len(devices)
            SCAN_STATE['summary']['open_ports'] = total_ports
            SCAN_STATE['summary']['alerts'] = len(findings)

        log(f'Scan finished. Hosts up: {len(devices)} | Open ports: {total_ports} | Alerts: {len(findings)}')
        if not devices:
            log('No responding hosts were found for that target.')
    except subprocess.TimeoutExpired:
        log('Scan timed out before completion.')
    except FileNotFoundError:
        log('nmap is not installed inside the container.')
    except Exception as exc:
        log(f'Unexpected error: {exc}')
    finally:
        finish_state()


def scheduler_loop() -> None:
    while True:
        try:
            settings = current_settings()
            if settings.get('scheduled_enabled') and settings.get('scheduled_targets'):
                with LOCK:
                    running = SCAN_STATE['running']
                    next_run_at = SETTINGS_STATE['scheduler']['next_run_at']
                now = time.time()
                if next_run_at is None:
                    with LOCK:
                        SETTINGS_STATE['scheduler']['next_run_at'] = now + settings['scheduled_interval_minutes'] * 60
                elif now >= next_run_at and not running:
                    target = settings['scheduled_targets'].strip()
                    if target:
                        try:
                            target = validate_target(target)
                            with LOCK:
                                SETTINGS_STATE['scheduler']['last_run_at'] = datetime.now().isoformat()
                                SETTINGS_STATE['scheduler']['last_target'] = target
                                SETTINGS_STATE['scheduler']['next_run_at'] = now + settings['scheduled_interval_minutes'] * 60
                            threading.Thread(target=run_scan, args=(target, 'scheduled'), daemon=True).start()
                        except Exception as exc:
                            log(f'Scheduler could not start scan: {exc}')
                            with LOCK:
                                SETTINGS_STATE['scheduler']['next_run_at'] = now + settings['scheduled_interval_minutes'] * 60
            time.sleep(5)
        except Exception as exc:
            log(f'Scheduler error: {exc}')
            time.sleep(10)


@app.route('/')
def index():
    return render_template('index.html', default_target=infer_local_subnet(), top_ports=DEFAULT_TOP_PORTS)


@app.route('/api/status')
def status():
    with LOCK:
        payload = dict(SCAN_STATE)
        payload['summary'] = dict(SCAN_STATE['summary'])
        payload['devices'] = list(SCAN_STATE['devices'])
        payload['findings'] = list(SCAN_STATE['findings'])
        payload['logs'] = list(SCAN_STATE['logs'])
        scheduler = dict(SETTINGS_STATE['scheduler'])
        settings = dict(SETTINGS_STATE['settings'])

    next_run_at = scheduler.get('next_run_at')
    scheduler['next_run_at_iso'] = datetime.fromtimestamp(next_run_at).isoformat() if next_run_at else None
    payload['scheduler'] = scheduler
    payload['settings'] = settings
    return jsonify(payload)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json(silent=True) or {}
    target = data.get('target', '')
    try:
        target = validate_target(target)
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400

    with LOCK:
        if SCAN_STATE['running']:
            return jsonify({'ok': False, 'error': 'A scan is already running.'}), 409

    thread = threading.Thread(target=run_scan, args=(target, 'manual'), daemon=True)
    thread.start()
    return jsonify({'ok': True, 'message': 'Scan started.', 'target': target})


@app.route('/api/reset', methods=['POST'])
def reset_scan_results():
    with LOCK:
        if SCAN_STATE['running']:
            return jsonify({'ok': False, 'error': 'A scan is currently running. Wait for it to finish before clearing results.'}), 409
    clear_state()
    return jsonify({'ok': True, 'message': 'Results cleared.'})


@app.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify({'ok': True, 'settings': current_settings(), 'scheduler': scheduler_snapshot()})


@app.route('/api/settings', methods=['POST'])
def update_settings():
    data = request.get_json(silent=True) or {}
    proposed = {
        'port_mode': data.get('port_mode', 'top200'),
        'custom_ports': data.get('custom_ports', ''),
        'scheduled_enabled': data.get('scheduled_enabled', False),
        'scheduled_targets': data.get('scheduled_targets', ''),
        'scheduled_interval_minutes': data.get('scheduled_interval_minutes', 60),
    }

    try:
        normalized = normalize_settings(proposed)
        if normalized['port_mode'] == 'custom':
            normalized['custom_ports'] = validate_custom_ports(normalized['custom_ports'])
        if normalized['scheduled_enabled'] and not normalized['scheduled_targets']:
            raise ValueError('Scheduled targets are required when interval scanning is enabled.')
        if normalized['scheduled_targets']:
            validate_target(normalized['scheduled_targets'])
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400

    saved = save_settings(normalized)
    log('Settings updated from the dashboard.')
    return jsonify({'ok': True, 'settings': saved, 'scheduler': scheduler_snapshot()})


@app.route('/api/export.csv')
def export_csv():
    with LOCK:
        devices = list(SCAN_STATE['devices'])
        findings = list(SCAN_STATE['findings'])
        target = SCAN_STATE['target'] or 'no-target'
        finished_at = SCAN_STATE['finished_at'] or datetime.now().isoformat()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'section', 'target', 'host', 'display_name', 'hostname_or_title', 'severity', 'port', 'protocol', 'service', 'version',
        'device_type', 'vendor', 'mac', 'http_title', 'finished_at'
    ])

    for device in devices:
        common = [
            'device', target, device.get('ip', ''), device.get('display_name', ''), device.get('hostname', ''), device.get('severity', ''),
        ]
        tail = [device.get('device_type', ''), device.get('vendor', ''), device.get('mac', ''), device.get('http_title', ''), finished_at]
        if device.get('ports'):
            for port in device['ports']:
                writer.writerow(common + [port.get('port', ''), port.get('proto', ''), port.get('service', ''), port.get('version', '')] + tail)
        else:
            writer.writerow(common + ['', '', '', ''] + tail)

    for finding in findings:
        writer.writerow([
            'finding', target, finding.get('host', ''), '', finding.get('title', ''), finding.get('severity', ''),
            '', '', '', '', '', '', '', '', finished_at
        ])

    csv_data = output.getvalue()
    safe_target = re.sub(r'[^0-9A-Za-z._-]+', '-', target)[:60].strip('-') or 'scan'
    filename = f'netwatch-{safe_target}-{datetime.now().strftime("%Y%m%d-%H%M%S")}.csv'

    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


load_settings()
threading.Thread(target=scheduler_loop, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=APP_PORT, debug=False)
