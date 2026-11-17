#!/usr/bin/env python3
"""Negative tests for exact-commit, signed release provenance (offline)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('release_verify',ROOT/'release_verify.py')
release=importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseVerifyTests(unittest.TestCase):
    def test_reject_malformed_sha_and_untrusted_source(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'install.sh'
            f.write_text('ok')
            for bad in ('main','A'*40,'0'*39,'0'*40+'/etc/passwd'):
                with self.assertRaises(ValueError):
                    release.verify_file(f,bad)
            with self.assertRaises(ValueError):
                release.fetch_bytes('http://evil.example.org/whatever',1024)

    def test_enforce_exact_identity_ref_commit_and_no_self_hosted(self):
        sha='a'*40
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'install.sh'
            f.write_text('safe')
            with patch.object(release,'ensure_gh'),patch.object(release,'public_bundles',return_value=[{'verificationMaterial':{},'dsseEnvelope':{}}]),patch.object(release.subprocess,'run') as call:
                release.verify_file(f,sha)
                args=call.call_args.args[0]
                self.assertIn('--bundle',args)
                self.assertNotIn('GH_TOKEN', ' '.join(args))
                self.assertIn('--cert-identity',args)
                self.assertEqual(args[args.index('--cert-identity')+1],release.CERT_IDENTITY)
                self.assertEqual(args[args.index('--source-ref')+1],'refs/heads/main')
                self.assertEqual(args[args.index('--source-digest')+1],sha)
                self.assertIn('--deny-self-hosted-runners',args)
                self.assertEqual(args[args.index('--repo')+1],release.REPO)

    def test_untrusted_public_bundle_url_is_rejected(self):
        sha='a'*40
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/'install.sh'
            file.write_text('test')
            with patch.object(release,'fetch_bytes',return_value=(
                b'{"attestations":[{"bundle_url":"http://169.254.169.254/metadata"}]}'
            )):
                with self.assertRaises(ValueError):
                    release.public_bundles(file)

    def test_ci_token_is_restricted_to_attestation_index_get(self):
        index = ("https://api.github.com/repos/" + release.REPO
                 + "/attestations/sha256:" + "a" * 64)
        with patch.object(release.urllib.request, "build_opener") as make_opener:
            reply = make_opener.return_value.open.return_value.__enter__.return_value
            reply.read.return_value = b'{"attestations":[]}'
            self.assertEqual(
                release.fetch_bytes(index, 1024,
                                    attestations_read_token="ghs_test-safe_123"),
                b'{"attestations":[]}')
            req = make_opener.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url, index)
            self.assertEqual(req.get_header("Authorization"),
                             "Bearer ghs_test-safe_123")
            make_opener.return_value.open.reset_mock()
            release.fetch_bytes(index, 1024)
            unauthenticated = make_opener.return_value.open.call_args.args[0]
            self.assertIsNone(unauthenticated.get_header("Authorization"))
            for url in (
                "https://raw.githubusercontent.com/" + release.REPO + "/main/VERSION",
                "https://api.github.com/repos/" + release.REPO + "/commits/main",
                "http://api.github.com/repos/" + release.REPO + "/attestations/sha256:" + "a" * 64,
            ):
                with self.assertRaises(ValueError):
                    release.fetch_bytes(url, 1024,
                                        attestations_read_token="ghs_test-safe_123")
            self.assertEqual(make_opener.return_value.open.call_count, 1)
            for invalid in ("token with spaces", "bad\r\nInjected: true", ""):
                with self.assertRaises(ValueError):
                    release.fetch_bytes(index, 1024,
                                        attestations_read_token=invalid)

    def test_optional_api_token_never_reaches_offline_verifier(self):
        sha = "f" * 40
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "install.sh"
            file.write_text("release")
            with patch.object(release, "ensure_gh"), patch.object(
                release, "public_bundles",
                return_value=[{"verificationMaterial": {}, "dsseEnvelope": {}}]
            ) as bundles, patch.object(release.subprocess, "run") as runner, patch.dict(
                release.os.environ,
                {"XMESH_ATTESTATION_INDEX_TOKEN": "ghs_test-safe_123",
                 "GH_TOKEN": "fake-gh", "GITHUB_TOKEN": "fake-github"},
            ):
                release.verify_file(
                    file, sha, attestations_read_token="ghs_test-safe_123")
                bundles.assert_called_once_with(
                    file, attestations_read_token="ghs_test-safe_123")
                args = runner.call_args.args[0]
                self.assertIn("--bundle", args)
                self.assertEqual(args[args.index("--source-digest") + 1], sha)
                self.assertEqual(args[args.index("--cert-identity") + 1],
                                 release.CERT_IDENTITY)
                self.assertEqual(args[args.index("--source-ref") + 1],
                                 release.SOURCE_REF)
                self.assertNotIn("XMESH_ATTESTATION_INDEX_TOKEN",
                                 runner.call_args.kwargs["env"])
                self.assertNotIn("GH_TOKEN", runner.call_args.kwargs["env"])
                self.assertNotIn("GITHUB_TOKEN", runner.call_args.kwargs["env"])

    def test_reject_vulnerable_cli(self):
        for raw in ('gh version 2.45.0 (Ubuntu)\n','gh version 2.101.9\n','nonsense\n'):
            with patch.object(release.subprocess,'run') as call:
                call.return_value.stdout=raw
                with self.assertRaises(RuntimeError):
                    release.ensure_gh()
        with patch.object(release.subprocess,'run') as call:
            call.return_value.stdout='gh version 2.102.0 (2026)\n'
            release.ensure_gh()

    def test_verify_every_file_and_reject_legacy_version(self):
        sha='f'*40
        source={name:(ROOT/name).read_bytes() for name in release.FILES}
        source['VERSION']=b'0.4.1\n'
        with tempfile.TemporaryDirectory() as d,patch.object(
            release,'fetch_bytes',side_effect=lambda url,limit: source[url.split('/')[-1]]
        ), patch.object(release,'verify_file') as verify:
            result=release.stage_revision(sha,Path(d))
            self.assertEqual(set(result),set(release.FILES))
            self.assertEqual(verify.call_count,len(release.FILES))
        source['VERSION']=b'0.3.0\n'
        with tempfile.TemporaryDirectory() as d,patch.object(
            release,'fetch_bytes',side_effect=lambda url,limit: source[url.split('/')[-1]]
        ),patch.object(release,'verify_file'):
            with self.assertRaises(ValueError):
                release.stage_revision(sha,Path(d))


if __name__=='__main__':
    unittest.main()
