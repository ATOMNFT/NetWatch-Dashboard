"""Guardian regression tests. Run: python -m unittest discover -s tests -v"""
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="netwatch-tests-"))
import guardian
import app as server


class GuardianTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original_path = guardian.DB_PATH
        guardian.DB_PATH = os.path.join(self.temp.name, "history.sqlite3")
        self.addCleanup(setattr, guardian, "DB_PATH", self.original_path)
        guardian.init_db()

    def host(self, ip, ports=(), mac=""):
        return {"ip": ip, "mac": mac, "display_name": ip, "ports": [
            {"port": str(p), "proto": "tcp", "service": "test"} for p in ports
        ]}

    def test_baseline_and_changes_are_scoped_to_target(self):
        self.assertEqual(guardian.record_scan("192.168.1.0/24",
            [self.host("192.168.1.10", [80], "AA:BB:CC:11:22:33")], []), 0)
        self.assertEqual(guardian.record_scan("10.0.0.0/24",
            [self.host("10.0.0.2", [22])], []), 0)
        changes = guardian.record_scan("192.168.1.0/24", [
            self.host("192.168.1.11", [80, 443], "AA:BB:CC:11:22:33"),
            self.host("192.168.1.50", [22])
        ], [])
        self.assertEqual(changes, 3)
        state = guardian.guardian_status("192.168.1.0/24")
        self.assertEqual(state["counts"], {"online": 2, "trusted": 0, "unknown": 2})
        self.assertEqual(len(state["history"]), 2)
        self.assertEqual({e["event_type"] for e in state["events"]},
                         {"ip_changed", "new_device", "opened_port"})

    def test_trust_persists_between_scans(self):
        host = self.host("192.168.1.20", [80])
        guardian.record_scan("192.168.1.20", [host], [])
        guardian.update_profile("ip:192.168.1.20", True, "Office printer")
        guardian.record_scan("192.168.1.20", [host], [])
        state = guardian.guardian_status("192.168.1.20")
        self.assertEqual(state["counts"]["trusted"], 1)
        self.assertEqual(state["devices"][0]["guardian_name"], "Office printer")

    def test_failed_profile_updates_are_rejected(self):
        with self.assertRaises(ValueError):
            guardian.update_profile("ip:missing", True)
        with self.assertRaises(ValueError):
            guardian.update_profile("ip:127.0.0.1", "yes")
        with self.assertRaises(ValueError):
            guardian.update_profile("../etc/passwd", True)

    def test_api_and_optional_basic_auth(self):
        client = server.app.test_client()
        with patch.object(server, "NETWATCH_PASSWORD", "test-secret"), patch.object(
            server, "NETWATCH_USERNAME", "admin"
        ):
            self.assertEqual(client.get("/api/guardian").status_code, 401)
            import base64
            auth = {"Authorization": "Basic " + base64.b64encode(b"admin:test-secret").decode()}
            self.assertEqual(client.get("/api/guardian", headers=auth).status_code, 200)
            self.assertEqual(client.get("/healthz", environ_overrides={
                "REMOTE_ADDR": "127.0.0.1"
            }).status_code, 200)
            blocked = client.post("/api/guardian/profile", headers={
                **auth, "Origin": "https://attacker.example"
            }, json={"device_key": "ip:192.168.1.20", "trusted": True})
            self.assertEqual(blocked.status_code, 403)

    def test_scan_command_uses_argument_list(self):
        cmd = server.build_nmap_command("192.168.1.1", {"port_mode": "custom", "custom_ports": "22,443"})
        self.assertEqual(cmd[-1], "192.168.1.1")
        self.assertIn("22,443", cmd)
        with self.assertRaises(ValueError):
            server.validate_custom_ports("22; rm -rf /")


if __name__ == "__main__":
    unittest.main()
