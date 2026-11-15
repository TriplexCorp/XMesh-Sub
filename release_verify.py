#!/usr/bin/env python3
"""Verify immutable XMesh Sub source artifacts using GitHub Actions OIDC provenance.

This module is itself verified before its first execution on the VPS.
Only the trusted main-branch release workflow can authorize privileged code.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import ssl
import subprocess
import urllib.request

REPO = "TriplexCorp/XMesh-Sub"
SOURCE_REF = "refs/heads/main"
CERT_IDENTITY = (
    "https://github.com/TriplexCorp/XMesh-Sub/"
    ".github/workflows/attested-release.yml@refs/heads/main"
)
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
FILES = ("install.sh", "manager.py", "release_verify.py", "VERSION")
MAX_FILE_BYTES = 160 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_bytes(url: str, limit: int) -> bytes:
    if not url.startswith(("https://api.github.com/", "https://raw.githubusercontent.com/")):
        raise ValueError("Untrusted source host")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    with opener.open(urllib.request.Request(url, headers={
            "User-Agent": "XMesh-Sub-Release-Verifier/1",
            "Accept": "application/vnd.github+json",
    }), timeout=25) as reply:
        data = reply.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Oversized release response")
    return data


def ensure_gh() -> None:
    # gh 2.102 fixed signer workflow prefix and case-insensitive source-ref
    # comparison vulnerabilities. Older distro packages must not verify releases.
    line = subprocess.run(["gh", "version"], check=True, capture_output=True,
                          text=True, timeout=10).stdout.splitlines()[0]
    match = re.fullmatch(r"gh version (\d+)\.(\d+)\.(\d+).*", line)
    if not match or tuple(map(int, match.groups())) < (2, 102, 0):
        raise RuntimeError("GitHub CLI v2.102.0 or newer is required")


def latest_source_sha() -> str:
    payload = json.loads(fetch_bytes(
        f"https://api.github.com/repos/{REPO}/commits/main", 64 * 1024))
    sha = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        raise ValueError("Invalid trusted main commit")
    return sha


def verify_file(file: Path, sha: str) -> None:
    if not SHA_RE.fullmatch(sha) or not file.is_file() or file.is_symlink():
        raise ValueError("Invalid release artifact")
    ensure_gh()
    subprocess.run([
        "gh", "attestation", "verify", str(file),
        "--repo", REPO,
        "--cert-identity", CERT_IDENTITY,
        "--source-ref", SOURCE_REF,
        "--source-digest", sha,
        "--deny-self-hosted-runners",
    ], check=True, timeout=90, stdout=subprocess.DEVNULL,
       stderr=subprocess.DEVNULL)


def stage_revision(sha: str, directory: Path) -> dict[str, Path]:
    if not SHA_RE.fullmatch(sha) or not directory.is_dir() or directory.is_symlink():
        raise ValueError("Invalid release staging")
    result = {}
    for name in FILES:
        data = fetch_bytes(
            f"https://raw.githubusercontent.com/{REPO}/{sha}/{name}",
            1024 if name == "VERSION" else MAX_FILE_BYTES,
        )
        file = directory / name
        if file.exists() or file.is_symlink():
            raise ValueError("Refusing existing release staging target")
        file.write_bytes(data)
        verify_file(file, sha)
        result[name] = file
    version = result["VERSION"].read_text("ascii").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Invalid attested version")
    if tuple(map(int, version.split("."))) < (0, 4, 1):
        raise ValueError("Unapproved pre-attestation release")
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4 or sys.argv[1] != "stage":
        raise SystemExit("Usage: release_verify.py stage SHA DIRECTORY")
    stage_revision(sys.argv[2], Path(sys.argv[3]))
