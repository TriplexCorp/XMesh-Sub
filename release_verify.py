#!/usr/bin/env python3
"""Verify immutable XMesh Sub source artifacts using GitHub Actions OIDC provenance.

This module is itself verified before its first execution on the VPS.
Only the trusted main-branch release workflow can authorize privileged code.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from urllib.parse import urlparse
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


def fetch_bytes(url: str, limit: int, *, attestations_read_token: str | None = None) -> bytes:
    if not url.startswith(("https://api.github.com/", "https://raw.githubusercontent.com/")):
        raise ValueError("Untrusted source host")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    headers = {
        "User-Agent": "XMesh-Sub-Release-Verifier/1",
        "Accept": "application/vnd.github+json",
    }
    # GitHub Actions shares its unauthenticated 60/hour IP quota with other
    # runners. Its short-lived token can fetch the *public attestation index*
    # without granting the attestation any trust. This is never used for raw
    # source downloads and never passed to the offline signature verifier.
    index_prefix = f"https://api.github.com/repos/{REPO}/attestations/sha256:"
    if attestations_read_token is not None:
        if not url.startswith(index_prefix) or not attestations_read_token.isascii() or not (
                1 <= len(attestations_read_token) <= 1024
        ) or any(not (ch.isalnum() or ch in "-_.") for ch in attestations_read_token):
            raise ValueError("Invalid attestation index read credential or endpoint")
        headers["Authorization"] = "Bearer " + attestations_read_token
    with opener.open(urllib.request.Request(url, headers=headers), timeout=25) as reply:
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


def public_bundles(file: Path, *, attestations_read_token: str | None = None) -> list[dict]:
    """Fetch public Sigstore bundles without a GitHub login or access token.

    The API response and bundle URLs are untrusted. The actual signature,
    signer identity, artifact digest and source SHA are checked by gh offline.
    """
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    index = json.loads(fetch_bytes(
        f"https://api.github.com/repos/{REPO}/attestations/sha256:{digest}", 256 * 1024,
        attestations_read_token=attestations_read_token))
    entries = index.get("attestations") if isinstance(index, dict) else None
    if not isinstance(entries, list) or not 1 <= len(entries) <= 30:
        raise ValueError("No public attestation bundles")
    bundles: list[dict] = []
    for entry in entries[:12]:
        if not isinstance(entry, dict):
            continue
        bundle = entry.get("bundle")
        if bundle is None:
            link = entry.get("bundle_url")
            if not isinstance(link, str):
                continue
            url = urlparse(link)
            host = (url.hostname or "").lower()
            if (url.scheme != "https" or url.username or url.password
                    or url.port not in (None, 443)
                    or not (host.endswith(".blob.core.windows.net")
                            or host.endswith(".githubusercontent.com"))):
                raise ValueError("Untrusted attestation bundle endpoint")
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                NoRedirect(),
            )
            with opener.open(link, timeout=25) as response:
                data = response.read(256 * 1024 + 1)
            if len(data) > 256 * 1024:
                raise ValueError("Oversized attestation bundle")
            bundle = json.loads(data)
        if isinstance(bundle, dict) and "verificationMaterial" in bundle and "dsseEnvelope" in bundle:
            bundles.append(bundle)
    if not bundles:
        raise ValueError("No usable signed provenance bundles")
    return bundles


def verify_file(file: Path, sha: str, *, attestations_read_token: str | None = None) -> None:
    if not SHA_RE.fullmatch(sha) or not file.is_file() or file.is_symlink():
        raise ValueError("Invalid release artifact")
    ensure_gh()
    bundles = public_bundles(file, attestations_read_token=attestations_read_token)
    with tempfile.TemporaryDirectory(prefix="xmesh-attestation-") as tmp:
        path = Path(tmp) / "bundles.jsonl"
        path.write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in bundles))
        # --bundle performs signature verification OFFLINE: no GH_TOKEN,
        # gh auth login, credential store, or privileged GitHub API is needed.
        subprocess.run([
            "gh", "attestation", "verify", str(file), "--bundle", str(path),
            "--repo", REPO,
            "--cert-identity", CERT_IDENTITY,
            "--source-ref", SOURCE_REF,
            "--source-digest", sha,
            "--deny-self-hosted-runners",
        ], check=True, timeout=90, stdout=subprocess.DEVNULL,
           stderr=subprocess.DEVNULL,
           # Even the optional CI GET token must not reach the gh process.
           env={key: value for key, value in os.environ.items()
                if key not in ("GH_TOKEN", "GITHUB_TOKEN", "XMESH_ATTESTATION_INDEX_TOKEN")})

def stage_revision(sha: str, directory: Path, *, attestations_read_token: str | None = None) -> dict[str, Path]:
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
        verify_file(file, sha, attestations_read_token=attestations_read_token)
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
