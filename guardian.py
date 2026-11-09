"""Persistent, local-only Network Guardian scan history and device inventory."""
import json
import os
import sqlite3
from contextlib import contextmanager
import threading
from datetime import datetime, timezone

DB_PATH = os.path.join(os.getenv("SETTINGS_DIR", "/app/data"), "guardian.sqlite3")
DB_LOCK = threading.RLock()


@contextmanager
def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=15)
    try:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=15000")
        with con:
            yield con
    finally:
        con.close()


def init_db():
    with DB_LOCK, connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY, target TEXT NOT NULL, finished_at TEXT NOT NULL,
            devices_json TEXT NOT NULL, findings_json TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS profiles (
            device_key TEXT PRIMARY KEY, display_name TEXT NOT NULL DEFAULT '',
            trusted INTEGER NOT NULL DEFAULT 0, notes TEXT NOT NULL DEFAULT '',
            last_ip TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL DEFAULT ''
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, target TEXT NOT NULL,
            event_type TEXT NOT NULL, severity TEXT NOT NULL,
            device_key TEXT NOT NULL, ip TEXT NOT NULL, detail TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, id)")


def device_key(device):
    mac = str(device.get("mac") or "").strip().upper()
    if mac and mac not in ("UNKNOWN", "00:00:00:00:00:00"):
        return "mac:" + mac
    return "ip:" + str(device.get("ip") or "").strip()


def port_set(device):
    return {str(p.get("proto", "tcp")) + "/" + str(p.get("port")) for p in device.get("ports", [])}


def record_scan(target, devices, findings):
    """Save completed successful scans. Compare only against the previous scan of the same target."""
    stamp = datetime.now(timezone.utc).isoformat()
    with DB_LOCK, connect() as con:
        previous = con.execute(
            "SELECT devices_json FROM scans WHERE target=? ORDER BY id DESC LIMIT 1", (target,)
        ).fetchone()
        before = {device_key(d): d for d in json.loads(previous["devices_json"])} if previous else {}
        current = {device_key(d): d for d in devices}
        cursor = con.execute(
            "INSERT INTO scans(target, finished_at, devices_json, findings_json) VALUES(?,?,?,?)",
            (target, stamp, json.dumps(devices), json.dumps(findings))
        )
        scan_id = cursor.lastrowid
        events = []

        def event(kind, severity, key, ip, detail):
            events.append((scan_id, target, kind, severity, key, ip, detail, stamp))

        for key, device in current.items():
            ip = str(device.get("ip") or "")
            con.execute("""INSERT INTO profiles(device_key,last_ip,last_seen) VALUES(?,?,?)
                ON CONFLICT(device_key) DO UPDATE SET
                last_ip=excluded.last_ip, last_seen=excluded.last_seen""", (key, ip, stamp))
            if previous and key not in before:
                event("new_device", "warning", key, ip, "New device discovered: " + (device.get("display_name") or ip))
            if key in before:
                old_ports = port_set(before[key])
                new_ports = port_set(device)
                for port in sorted(new_ports - old_ports):
                    event("opened_port", "warning", key, ip, "New open port: " + port)
                for port in sorted(old_ports - new_ports):
                    event("closed_port", "info", key, ip, "Port no longer open: " + port)
                old_ip = str(before[key].get("ip") or "")
                if old_ip != ip:
                    event("ip_changed", "info", key, ip, "IP changed: " + old_ip + " → " + ip)
        if previous:
            for key, device in before.items():
                if key not in current:
                    event("disappeared", "info", key, str(device.get("ip") or ""),
                          "Device no longer found: " + (device.get("display_name") or key))
        if events:
            con.executemany("""INSERT INTO events(
                scan_id,target,event_type,severity,device_key,ip,detail,created_at
            ) VALUES(?,?,?,?,?,?,?,?)""", events)
        # Keep up to 100 history snapshots per target and 2000 events overall.
        con.execute("""DELETE FROM scans WHERE id IN (
            SELECT id FROM scans WHERE target=? ORDER BY id DESC LIMIT -1 OFFSET 100
        )""", (target,))
        con.execute("""DELETE FROM events WHERE id NOT IN (
            SELECT id FROM events ORDER BY id DESC LIMIT 2000
        )""")
        return len(events)


def guardian_status(target=None):
    with DB_LOCK, connect() as con:
        if target:
            row = con.execute("SELECT * FROM scans WHERE target=? ORDER BY id DESC LIMIT 1", (target,)).fetchone()
        else:
            row = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        devices = json.loads(row["devices_json"]) if row else []
        profiles = {r["device_key"]: dict(r) for r in con.execute("SELECT * FROM profiles").fetchall()}
        for d in devices:
            profile = profiles.get(device_key(d), {})
            d["device_key"] = device_key(d)
            d["trusted"] = bool(profile.get("trusted", 0))
            d["guardian_name"] = profile.get("display_name", "")
            d["guardian_notes"] = profile.get("notes", "")
        if row:
            event_rows = con.execute(
                "SELECT * FROM events WHERE target=? ORDER BY id DESC LIMIT 50", (row["target"],)
            ).fetchall()
            history = con.execute(
                "SELECT id, target, finished_at FROM scans WHERE target=? ORDER BY id DESC LIMIT 30",
                (row["target"],)
            ).fetchall()
        else:
            event_rows, history = [], []
        return {
            "target": row["target"] if row else "",
            "last_scan": row["finished_at"] if row else None,
            "devices": devices,
            "counts": {
                "online": len(devices),
                "trusted": sum(bool(d["trusted"]) for d in devices),
                "unknown": sum(not d["trusted"] for d in devices),
            },
            "events": [dict(r) for r in event_rows],
            "history": [dict(r) for r in history],
        }


def update_profile(key, trusted, display_name="", notes=""):
    if not isinstance(key, str) or not key.startswith(("mac:", "ip:")) or len(key) > 100:
        raise ValueError("Invalid device key")
    if not isinstance(trusted, bool):
        raise ValueError("Trusted must be true or false")
    if not isinstance(display_name, str) or len(display_name) > 80:
        raise ValueError("Display name must be at most 80 characters")
    if not isinstance(notes, str) or len(notes) > 300:
        raise ValueError("Notes must be at most 300 characters")
    with DB_LOCK, connect() as con:
        result = con.execute("""UPDATE profiles SET trusted=?, display_name=?, notes=?
            WHERE device_key=?""", (int(trusted), display_name.strip(), notes.strip(), key))
        if result.rowcount != 1:
            raise ValueError("Device profile not found")
    return True
