#!/usr/bin/env python3
"""No network or root required; agent must never execute arbitrary panel commands."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
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


    def test_redirects_are_rejected_even_with_authorization(self):
        from urllib.request import Request
        request = Request("https://panel.example.org/api/v1/sub-server/agent/poll",
                          headers={"Authorization": "Bearer " + "a" * 64})
        self.assertIsNone(manager.RejectRedirect().redirect_request(
            request, None, 302, "Moved", {}, "https://evil.example.org"))

    def test_ed25519_signed_manifest_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "private.pem"
            pub = Path(tmp) / "public.pem"
            metadata = Path(tmp) / "release.json"
            sig = Path(tmp) / "release.sig"
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key)],
                           check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                           check=True, capture_output=True)
            valid = {
                "schema": 1, "version": "0.3.0",
                "installSha256": "a" * 64, "managerSha256": "b" * 64,
            }
            metadata.write_text(json.dumps(valid, sort_keys=True, separators=(",", ":")))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key),
                            "-rawin", "-in", str(metadata), "-out", str(sig)],
                           check=True, capture_output=True)
            with patch.object(manager, "get_public_bytes", side_effect=[
                metadata.read_bytes(), base64.b64encode(sig.read_bytes())
            ]):
                self.assertEqual(manager.signed_release(pub), valid)
            poisoned = metadata.read_bytes().replace(b"0.3.0", b"9.9.9")
            with patch.object(manager, "get_public_bytes", side_effect=[
                poisoned, base64.b64encode(sig.read_bytes())
            ]):
                with self.assertRaises(subprocess.CalledProcessError):
                    manager.signed_release(pub)

    def test_edge_policy_accepts_authenticated_bounded_settings_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "flood.json"
            payload = {"enabled": True, "mode": "protect", "ipPerMinute": 120}
            manager.update_edge_policy(payload, path)
            self.assertEqual(json.loads(path.read_text()), payload)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            manager.update_edge_policy({
                "enabled": True, "mode": "protect", "ipPerMinute": 0
            }, path)
            self.assertEqual(json.loads(path.read_text()), payload)
            manager.update_edge_policy({
                "enabled": True, "mode": "protect", "ipPerMinute": 120,
                "command": "arbitrary"
            }, path)
            self.assertEqual(json.loads(path.read_text()), payload)

    def test_backup_and_rollback_restore_original_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compose.yaml").write_text("services: original")
            (root / "manager.json").write_text("original service credential")
            backup = manager.backup_installation(root)
            (root / "compose.yaml").write_text("services: broken")
            (root / "manager.json").unlink()
            (root / "VERSION").write_text("9.9.9")
            with patch.object(manager.subprocess, "run") as run:
                manager.restore_installation(backup, root)
            self.assertEqual((root / "compose.yaml").read_text(), "services: original")
            self.assertEqual((root / "manager.json").read_text(), "original service credential")
            self.assertFalse((root / "VERSION").exists())
            self.assertEqual(run.call_args.args[0][0:2], ["docker", "compose"])

    def test_update_requires_signed_digest_before_running_installer(self):
        release = {"schema": 1, "version": "9.9.9",
                   "installSha256": "0" * 64, "managerSha256": "1" * 64}
        with (
            patch.object(manager, "signed_release", return_value=release),
            patch.object(manager, "get_public_bytes", return_value=b"#!/usr/bin/env bash\necho good\n"),
            patch.object(manager.subprocess, "run") as execute,
        ):
            with self.assertRaises(ValueError):
                manager.perform_update(self.config)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
