#!/usr/bin/env python3
"""Pure offline tests for private Caddy forward-auth rate guard."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("flood_guard", Path(__file__).resolve().parents[1] / "flood_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class FloodGuardTests(unittest.TestCase):
    def test_strict_config_defaults(self):
        self.assertEqual(guard.safe_config(None)["mode"], "monitor")
        self.assertEqual(guard.safe_config({"enabled": True, "mode": "protect", "ipPerMinute": 0})["mode"], "monitor")
        self.assertEqual(guard.safe_config({"enabled": True, "mode": "protect", "ipPerMinute": 120,
                                            "extra": "bad"})["mode"], "monitor")

    def test_real_peer_not_client_headers(self):
        self.assertEqual(guard.peer_key("203.0.113.7"), "203.0.113.7")
        self.assertIsNone(guard.peer_key("198.51.100.3, 203.0.113.7"))
        self.assertEqual(guard.peer_key("2001:db8:42::1"), guard.peer_key("2001:db8:42::abcd"))

    def test_monitor_mode_never_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "flood.json"
            file.write_text(json.dumps({"enabled": True, "mode": "monitor", "ipPerMinute": 30}))
            policy = guard.FloodGuard(file)
            self.assertFalse(any(policy.check("203.0.113.1", 120 + i / 1000) for i in range(90)))
            self.assertGreater(policy.exceeded, 0)
            self.assertEqual(policy.blocked, 0)

    def test_protect_mode_blocks_after_ip_limit_and_burst(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "flood.json"
            file.write_text(json.dumps({"enabled": True, "mode": "protect", "ipPerMinute": 30}))
            policy = guard.FloodGuard(file)
            for i in range(50):
                self.assertFalse(policy.check("203.0.113.1", 120 + i / 1000))
            self.assertTrue(policy.check("203.0.113.1", 120.06))
            self.assertFalse(policy.check("203.0.113.2", 120.07))
            self.assertGreater(policy.blocked, 0)

    def test_disabled_mode_and_bounded_peer_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "flood.json"
            file.write_text(json.dumps({"enabled": False, "mode": "protect", "ipPerMinute": 30}))
            policy = guard.FloodGuard(file)
            self.assertFalse(any(policy.check("203.0.113.7", 120 + i / 1000) for i in range(100)))
            self.assertEqual(len(policy.counters), 0)
            file.write_text(json.dumps({"enabled": True, "mode": "monitor", "ipPerMinute": 120}))
            policy.last_read = -100
            for i in range(6100):
                policy.check(f"2001:db8:{i:x}::1", 240 + i / 100000)
            self.assertLessEqual(len(policy.counters), guard.MAX_IDENTITIES)

    def test_server_has_bounded_workers_and_queue(self):
        self.assertLessEqual(guard.BoundedHTTPServer.max_active_workers, 64)
        self.assertLessEqual(guard.BoundedHTTPServer.request_queue_size, 128)

    def test_missing_policy_is_monitor_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = guard.FloodGuard(Path(tmp) / "missing.json")
            for i in range(200):
                self.assertFalse(policy.check("198.51.100.6", 120 + i / 1000))
            self.assertEqual(policy.settings["mode"], "monitor")


if __name__ == "__main__":
    unittest.main()
