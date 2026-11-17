#!/usr/bin/env python3
"""Keep attestation publisher actions immutable; no third-party parser needed."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


def unpinned_actions(text):
    uses = re.findall(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", text, re.MULTILINE)
    # This one local reusable workflow is protected by the same reviewed
    # commit as the publisher; arbitrary local includes are not allowed.
    reviewed_local = {"./.github/workflows/image-security.yml"}
    return [value for value in uses if value not in reviewed_local and not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}", value
    )]


class WorkflowSecurityTests(unittest.TestCase):
    def test_tags_and_branches_are_rejected(self):
        for ref in ("v4", "main", "a" * 39, "A" * 40):
            self.assertTrue(unpinned_actions("- uses: actions/attest@" + ref))

    def test_full_commit_with_comment_is_accepted(self):
        self.assertEqual(unpinned_actions(
            "- uses: actions/attest@" + "a" * 40 + " # reviewed v4\n"
        ), [])

    def test_only_reviewed_local_reusable_gate_is_allowed(self):
        self.assertEqual(unpinned_actions(
            "    uses: ./.github/workflows/image-security.yml\n"
        ), [])
        self.assertTrue(unpinned_actions("    uses: ./.github/workflows/unsafe.yml\n"))

    def test_attester_cannot_publish_before_two_architecture_security_gates(self):
        publisher = (ROOT / ".github/workflows/attested-release.yml").read_text()
        gate = (ROOT / ".github/workflows/image-security.yml").read_text()
        self.assertIn("uses: ./.github/workflows/image-security.yml", publisher)
        self.assertRegex(publisher, r"(?m)^  publish:\n    needs: runtime-image-security\n")
        self.assertRegex(gate, r"(?m)^  workflow_call:$")
        self.assertIn("arch: amd64", gate)
        self.assertIn("arch: arm64", gate)
        self.assertIn("fail-fast: false", gate)
        self.assertIn("Fail closed on unresolved High and Critical vulnerabilities", gate)
        self.assertIn('raise SystemExit(f"{count} High/Critical issues remain in Sub runtime images")', gate)
        self.assertNotIn("continue-on-error: true", gate)
        self.assertNotIn("|| true", gate)
        self.assertNotIn("secrets: inherit", publisher)

    def test_all_checked_in_actions_are_pinned(self):
        workflows = list((ROOT / ".github/workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for file in workflows:
            with self.subTest(workflow=file.name):
                text = file.read_text()
                self.assertEqual(unpinned_actions(text), [])
                self.assertIn("contents: read", text)

    def test_publisher_remains_main_only_without_browser_pr_trigger(self):
        text = (ROOT / ".github/workflows/attested-release.yml").read_text()
        self.assertIn("branches: [main]", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertNotRegex(text, r"(?m)^\s*(?:pull_request|pull_request_target|workflow_dispatch):")
        self.assertIn("--source-digest", text)
        self.assertIn("--deny-self-hosted-runners", text)


if __name__ == "__main__":
    unittest.main()
