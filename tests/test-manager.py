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
        }
        self._policy_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._policy_tmp.cleanup)
        self._policy_patch = patch.object(manager, "EDGE_POLICY_FILE", Path(self._policy_tmp.name) / "policy.json")
        self._policy_patch.start()
        self.addCleanup(self._policy_patch.stop)
        self.flood = {"enabled": True, "mode": "protect", "ipPerMinute": 120}

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "config.json"
            file.write_text(json.dumps(self.config))
            self.assertEqual(manager.read_config(file), self.config)
            # The real installer ALWAYS writes publicKey after successful
            # enrollment; accepting only the three legacy fields made the
            # running agent reject its own configuration on every poll.
            enrolled = {**self.config, "publicKey": "a" * 64}
            file.write_text(json.dumps(enrolled))
            self.assertEqual(manager.read_config(file), enrolled)
            for invalid_key in ("", "a" * 63, "A" * 64, "../evil", None, 1):
                file.write_text(json.dumps({**self.config, "publicKey": invalid_key}))
                with self.subTest(publicKey=invalid_key), self.assertRaises(ValueError):
                    manager.read_config(file)
            file.write_text(json.dumps({**enrolled, "unexpected": "value"}))
            with self.assertRaises(ValueError):
                manager.read_config(file)
            file.write_text(json.dumps({**self.config, "agentToken": "a" * 64}))
            with self.assertRaises(ValueError):
                manager.read_config(file)
            file.write_text(json.dumps(self.config))
            for key, bad in [
                ("panel", "http://panel.example.org"),
                ("panel", "https://panel.example.org@evil.net"),
                ("domain", "sub.example.org;curl"),
                ("path", "/s;rm")
            ]:
                config = dict(self.config)
                config[key] = bad
                file.write_text(json.dumps(config))
                with self.assertRaises(ValueError):
                    manager.read_config(file)

    def test_installer_enrollment_file_can_poll(self):
        # The installer writes a publicKey selector. Prove it survives config
        # validation and reaches the authenticated poll rather than looping.
        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "manager.json"
            installed = {**self.config, "publicKey": "e" * 64}
            config_file.write_text(json.dumps(installed), encoding="utf-8")
            with patch.object(manager, "service_request", return_value={
                "command": "none", "flood": self.flood
            }) as poll:
                self.assertFalse(manager.cycle(manager.read_config(config_file)))
                poll.assert_called_once_with(installed, "poll", {"version": manager.current_version()})

    def test_unknown_command_is_ignored(self):
        with patch.object(manager, "service_request", return_value={
            "command": "shell", "commandLine": "rm -rf /", "flood": self.flood
        }), patch.object(manager, "perform_update") as run:
            self.assertFalse(manager.cycle(self.config))
            run.assert_not_called()

    def test_update_uses_only_valid_job_id(self):
        with patch.object(manager, "service_request", return_value={
            "command": "update", "jobId": "../../etc/passwd", "flood": self.flood
        }), patch.object(manager, "perform_update") as run:
            with self.assertRaises(ValueError):
                manager.cycle(self.config)
            run.assert_not_called()

    def test_update_reports_and_restores(self):
        with patch.object(manager, "service_request", return_value={
            "command": "update", "jobId": "f" * 32, "flood": self.flood
        }), patch.object(manager, "perform_update") as run, patch.object(manager, "report") as report:
            self.assertTrue(manager.cycle(self.config))
            run.assert_called_once_with(self.config)
            self.assertEqual([x.args[2] for x in report.call_args_list], ["running", "completed"])

    def test_update_errors_fail_closed(self):
        with patch.object(manager, "service_request", return_value={
            "command": "update", "jobId": "f" * 32, "flood": self.flood
        }), patch.object(manager, "perform_update", side_effect=OSError("secret in message")):
            with patch.object(manager, "report") as report:
                self.assertFalse(manager.cycle(self.config))
                self.assertEqual(report.call_args_list[-1].args[2], "failed")
                self.assertNotIn("secret", report.call_args_list[-1].args[3])


    def test_redirects_are_rejected_even_with_authorization(self):
        from urllib.request import Request
        request = Request("https://panel.example.org/api/v1/sub-server/agent/poll",
                          headers={"X-XMesh-Sub-Signature": "a" * 128})
        self.assertIsNone(manager.RejectRedirect().redirect_request(
            request, None, 302, "Moved", {}, "https://evil.example.org"))

    def test_mirror_header_pins_public_ed25519_key(self):
        key = "a" * 64
        config = {**self.config, "publicKey": key}
        with patch.object(manager, "signed_agent_headers", return_value={}) as signing, \
             patch.object(manager, "verified_open") as opening:
            opening.return_value.__enter__.return_value.read.return_value = b'{"command":"none","flood":{"enabled":true,"mode":"protect","ipPerMinute":120}}'
            manager.service_request(config, "poll", {"version":"0.4.2"})
            request = opening.call_args.args[0]
            self.assertEqual(request.get_header("X-xmesh-sub-public-key"), key)
            signing.assert_called_once()
        with self.assertRaises(ValueError):
            manager.service_request({**self.config, "publicKey": "../evil"}, "poll", {"version":"0.4.2"})

    def test_agent_signatures_bind_route_time_nonce_and_body(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / "agent-key.pem"
            public = Path(tmp) / "public.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                            "-out", str(private)], check=True, capture_output=True)
            private.chmod(0o600)
            subprocess.run(["openssl", "pkey", "-in", str(private),
                            "-pubout", "-out", str(public)],
                           check=True, capture_output=True)
            payload = b'{"version":"1.0.0"}'
            h = manager.signed_agent_headers("poll", payload, private)
            self.assertEqual(set(h), {
                "X-XMesh-Sub-Timestamp", "X-XMesh-Sub-Nonce",
                "X-XMesh-Sub-Signature"
            })
            canonical = (
                "XMESH-SUB1\nPOST\n/api/v1/sub-server/agent/poll\n"
                + h["X-XMesh-Sub-Timestamp"] + "\n"
                + h["X-XMesh-Sub-Nonce"] + "\n"
                + hashlib.sha256(payload).hexdigest() + "\n"
            ).encode("ascii")
            message = Path(tmp) / "canonical"
            signature = Path(tmp) / "signature"
            message.write_bytes(canonical)
            signature.write_bytes(bytes.fromhex(h["X-XMesh-Sub-Signature"]))
            def verify():
                return subprocess.run([
                    "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public),
                    "-rawin", "-in", str(message), "-sigfile", str(signature)
                ], capture_output=True).returncode
            self.assertEqual(verify(), 0)
            message.write_bytes(canonical.replace(b"/agent/poll\n", b"/agent/report\n"))
            self.assertNotEqual(verify(), 0)
            message.write_bytes(canonical.replace(hashlib.sha256(payload).hexdigest().encode(),
                                                  hashlib.sha256(b"{}").hexdigest().encode()))
            self.assertNotEqual(verify(), 0)
            private.chmod(0o644)
            with self.assertRaises(PermissionError):
                manager.signed_agent_headers("poll", payload, private)
            private.chmod(0o600)
            with self.assertRaises(ValueError):
                manager.signed_agent_headers("unknown", payload, private)

    def test_authenticated_poll_enforces_local_edge_policy(self):
        with patch.object(manager, "service_request", return_value={
            "command": "none", "flood": self.flood
        }):
            self.assertFalse(manager.cycle(self.config))
            policy_file = manager.EDGE_POLICY_FILE
            self.assertEqual(json.loads(policy_file.read_text()), self.flood)
            self.assertEqual(policy_file.stat().st_mode & 0o777, 0o644)

    def test_missing_or_corrupt_edge_policy_fails_closed(self):
        for reply in [
            {"command": "none"},
            {"command": "none", "flood": {"enabled": True, "mode": "off", "ipPerMinute": 0}},
            {"command": "none", "flood": {"enabled": True, "mode": "protect", "ipPerMinute": "120"}},
        ]:
            with patch.object(manager, "service_request", return_value=reply), patch.object(
                manager, "perform_update"
            ) as update:
                with self.assertRaises((ValueError, KeyError)):
                    manager.cycle(self.config)
                update.assert_not_called()

    def test_release_trust_is_bound_to_exact_main_commit(self):
        # Updater only delegates to the strictly pinned and attested verifier.
        self.assertEqual(manager.release_verify.SOURCE_REF,'refs/heads/main')
        self.assertIn('.github/workflows/attested-release.yml',
                      manager.release_verify.CERT_IDENTITY)

    def test_backup_and_rollback_restore_original_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compose.yaml").write_text("services: original")
            (root / "manager.json").write_text("original server settings")
            (root / "agent-key.pem").write_text("original private key")
            backup = manager.backup_installation(root)
            (root / "compose.yaml").write_text("services: broken")
            (root / "manager.json").unlink()
            (root / "agent-key.pem").write_text("tampered")
            (root / "VERSION").write_text("9.9.9")
            with patch.object(manager.subprocess, "run") as run:
                manager.restore_installation(backup, root)
            self.assertEqual((root / "compose.yaml").read_text(), "services: original")
            self.assertEqual((root / "manager.json").read_text(), "original server settings")
            self.assertEqual((root / "agent-key.pem").read_text(), "original private key")
            self.assertFalse((root / "VERSION").exists())
            self.assertEqual(run.call_args.args[0][0:2], ["docker", "compose"])

    def test_update_rejects_unattested_revision_before_execution(self):
        with patch.object(manager.release_verify,'latest_source_sha',return_value='a'*40), \
             patch.object(manager.release_verify,'stage_revision',
                          side_effect=subprocess.CalledProcessError(1,'gh attestation verify')), \
             patch.object(manager.subprocess,'run') as exec_script:
            with self.assertRaises(subprocess.CalledProcessError):
                manager.perform_update(self.config)
            exec_script.assert_not_called()

    def test_update_blocks_attested_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            version=Path(tmp)/'VERSION'
            version.write_text('0.3.0\n')
            install=Path(tmp)/'install.sh'
            install.write_text('#!/usr/bin/env bash\n')
            with patch.object(manager.release_verify,'latest_source_sha',return_value='b'*40), \
                 patch.object(manager.release_verify,'stage_revision',return_value={
                     'VERSION':version,'install.sh':install}), \
                 patch.object(manager,'current_version',return_value='0.4.1'), \
                 patch.object(manager.subprocess,'run') as exec_script:
                with self.assertRaises(ValueError):
                    manager.perform_update(self.config)
                exec_script.assert_not_called()


if __name__ == "__main__":
    unittest.main()
