#!/usr/bin/env python3
"""No network or root required; agent must never execute arbitrary panel commands."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("sub_manager", ROOT / "manager.py")
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class ManagerTest(unittest.TestCase):
    def setUp(self):
        self.config = {
            "panel": "https://panel.example.org",
            "domain": "sub.example.org",
            "path": "/s",
            "agentToken": "a" * 64,
        }

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "config.json"
            file.write_text(json.dumps(self.config))
            self.assertEqual(manager.read_config(file), self.config)
            for key, bad in [
                ("panel", "http://panel.example.org"),
                ("panel", "https://panel.example.org@evil.net"),
                ("domain", "sub.example.org;curl"),
                ("path", "/s;rm"),
                ("agentToken", "short")
            ]:
                config = dict(self.config)
                config[key] = bad
                file.write_text(json.dumps(config))
                with self.assertRaises(ValueError):
                    manager.read_config(file)

    def test_unknown_command_is_ignored(self):
        with patch.object(manager, "service_request", return_value={
            "command": "shell", "commandLine": "rm -rf /"
        }), patch.object(manager, "perform_update") as run:
            self.assertFalse(manager.cycle(self.config))
            run.assert_not_called()

    def test_update_uses_only_valid_job_id(self):
        with patch.object(manager, "service_request", return_value={
            "command": "update", "jobId": "../../etc/passwd"
        }), patch.object(manager, "perform_update") as run:
            with self.assertRaises(ValueError):
                manager.cycle(self.config)
            run.assert_not_called()

    def test_update_reports_and_restores(self):
        with patch.object(manager, "service_request", return_value={
            "command": "update", "jobId": "f" * 32
        }), patch.object(manager, "perform_update") as run, patch.object(manager, "report") as report:
            self.assertTrue(manager.cycle(self.config))
            run.assert_called_once_with(self.config)
            self.assertEqual([x.args[2] for x in report.call_args_list], ["running", "completed"])

    def test_update_errors_fail_closed(self):
        with patch.object(manager, "service_request", return_value={
            "command": "update", "jobId": "f" * 32
        }), patch.object(manager, "perform_update", side_effect=OSError("secret in message")):
            with patch.object(manager, "report") as report:
                self.assertFalse(manager.cycle(self.config))
                self.assertEqual(report.call_args_list[-1].args[2], "failed")
                self.assertNotIn("secret", report.call_args_list[-1].args[3])


if __name__ == "__main__":
    unittest.main()
