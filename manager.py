#!/usr/bin/env python3
"""XMesh Sub pull-only manager.

Only an enrolled agent can poll a fixed, TLS-verified Nexus API. Nexus can
request ONE hardcoded operation ("update"), never arbitrary shell commands.
There is no management listener, public admin endpoint, or Docker socket exposed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shutil
import ssl
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_verify
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path("/opt/xmesh-sub")
CONFIG_FILE = ROOT / "manager.json"
VERSION_FILE = ROOT / "VERSION"
RELEASE_SHA_FILE = ROOT / "RELEASE_SHA"
PRIVATE_KEY_FILE = ROOT / "agent-key.pem"
EDGE_POLICY_FILE = ROOT / "edge-policy" / "config.json"
BACKUPS = ROOT / "backups"
POLL_INTERVAL_SECONDS = 20
MAX_INSTALLER_BYTES = 128 * 1024
JOB_RE = re.compile(r"^[0-9a-f]{32}$")


def read_config(path: Path = CONFIG_FILE) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    panel = config.get("panel")
    domain = config.get("domain")
    sub_path = config.get("path")
    if (not isinstance(panel, str) or not re.fullmatch(r"https://[A-Za-z0-9.-]+", panel)
            or not isinstance(domain, str) or not re.fullmatch(r"[A-Za-z0-9.-]+", domain)
            or not isinstance(sub_path, str) or not re.fullmatch(r"/[A-Za-z0-9_/-]+", sub_path)):
        raise ValueError("Invalid manager configuration")
    if set(config) != {"panel", "domain", "path"}:
        raise ValueError("Unexpected manager configuration fields")
    return config


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    # Never replay signed machine requests across HTTP redirects.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verified_open(request: urllib.request.Request, *, timeout: int = 20):
    if not request.full_url.startswith("https://"):
        raise ValueError("HTTPS is required")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        RejectRedirect(),
    )
    return opener.open(request, timeout=timeout)


def version_tuple(version: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    return tuple(map(int, match.groups())) if match else (0, 0, 0)


def backup_installation(root: Path = ROOT) -> Path:
    destination = root / "backups"
    destination.mkdir(mode=0o700, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix="pre-update-", dir=str(destination)))
    backup.chmod(0o700)
    files = ("Caddyfile", "compose.yaml", "manager.py", "manager.json", "agent-key.pem", "limiter.py",
             "release_verify.py", "RELEASE_SHA", "VERSION")
    for name in files:
        old = root / name
        if old.is_file():
            shutil.copy2(old, backup / name)
        else:
            (backup / (".absent-" + name)).touch()
    return backup


def restore_installation(backup: Path, root: Path = ROOT) -> None:
    for name in ("Caddyfile", "compose.yaml", "manager.py", "manager.json", "agent-key.pem", "limiter.py",
                 "release_verify.py", "RELEASE_SHA", "VERSION"):
        saved = backup / name
        target = root / name
        if saved.is_file():
            shutil.copy2(saved, target)
        elif (backup / (".absent-" + name)).is_file():
            target.unlink(missing_ok=True)
    subprocess.run(["docker", "compose", "-f", str(root / "compose.yaml"),
                    "up", "-d", "--remove-orphans"], cwd=root, check=True, timeout=180)


def signed_agent_headers(route: str, payload: bytes, key: Path = PRIVATE_KEY_FILE) -> dict:
    """Proof of possession for each exact request. No reusable bearer credential."""
    if route not in {"poll", "report"} or len(payload) > 4096:
        raise ValueError("Unsupported signed agent request")
    # Root-owned private key, not a symlink/hardlink. Fail closed if permissions drift.
    metadata = key.lstat()
    if (not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1):
        raise PermissionError("Agent private key permissions invalid")
    timestamp = str(int(time.time()))
    nonce = os.urandom(16).hex()
    digest = hashlib.sha256(payload).hexdigest()
    canonical = (f"XMESH-SUB1\nPOST\n/api/v1/sub-server/agent/{route}\n"
                 f"{timestamp}\n{nonce}\n{digest}\n").encode("ascii")
    # OpenSSL Ed25519 requires a regular input file for one-shot signing.
    with tempfile.TemporaryDirectory(prefix="xmesh-sub-sign-") as location:
        message = Path(location) / "message"
        message.write_bytes(canonical)
        signature = subprocess.run([
            "openssl", "pkeyutl", "-sign", "-inkey", str(key),
            "-rawin", "-in", str(message),
        ], check=True, timeout=10, capture_output=True).stdout
    if len(signature) != 64:
        raise ValueError("Invalid agent signature length")
    return {
        "X-XMesh-Sub-Timestamp": timestamp,
        "X-XMesh-Sub-Nonce": nonce,
        "X-XMesh-Sub-Signature": signature.hex(),
    }


def accept_edge_policy(config: dict, policy: object, path: Path = EDGE_POLICY_FILE) -> None:
    """Commit only a bounded, authenticated policy from the Nexus poll reply."""
    if not isinstance(policy, dict) or set(policy) != {"enabled", "mode", "ipPerMinute"}:
        raise ValueError("Invalid Nexus edge policy")
    enabled, mode, limit = policy["enabled"], policy["mode"], policy["ipPerMinute"]
    if type(enabled) is not bool or mode not in ("monitor", "protect") or type(limit) is not int or not 1 <= limit <= 100_000:
        raise ValueError("Invalid edge flood limit")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, mode="w", encoding="utf-8", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            json.dump({"enabled": enabled, "mode": mode, "ipPerMinute": limit}, tmp)
            tmp.flush()
            os.fsync(tmp.fileno())
            os.chmod(tmp_path, 0o644)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
    os.replace(tmp_path, path)


def service_request(config: dict, route: str, body: dict) -> dict:
    # Route set is local and fixed, never server-controlled.
    if route not in {"poll", "report"}:
        raise ValueError("Unsupported agent endpoint")
    url = config["panel"] + "/api/v1/sub-server/agent/" + route
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = signed_agent_headers(route, payload)
    # Public (non-secret) key selects the exact Sub gateway identity in Nexus.
    # The existing Ed25519 signature still proves private-key possession.
    public_key = config.get("publicKey", "")
    if public_key:
        if not isinstance(public_key, str) or not re.fullmatch(r"[0-9a-f]{64}", public_key):
            raise ValueError("Invalid pinned gateway public key")
        headers["X-XMesh-Sub-Public-Key"] = public_key
    headers.update({"Content-Type": "application/json", "Accept": "application/json"})
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with verified_open(request, timeout=20) as response:
        raw = response.read(16384 + 1)
        if len(raw) > 16384:
            raise ValueError("Oversized response")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Unexpected API reply")
    return value


def report(config: dict, job: str, stage: str, detail: str = "") -> None:
    if not JOB_RE.fullmatch(job) or stage not in {"running", "completed", "failed"}:
        raise ValueError("Invalid update report")
    service_request(config, "report", {
        "jobId": job, "stage": stage, "detail": detail[:160]
    })


def perform_update(config: dict) -> None:
    # Only the main branch's trusted OIDC release workflow can publish root code.
    # Both installer and manager are attested for the exact Git commit. This
    # verification is done again inside the installer (defense in depth).
    sha = release_verify.latest_source_sha()
    with tempfile.TemporaryDirectory(prefix="xmesh-sub-update-") as location:
        assets = release_verify.stage_revision(sha, Path(location))
        version = assets["VERSION"].read_text("ascii").strip()
        if version_tuple(version) < version_tuple(current_version()):
            raise ValueError("Refusing an attested release rollback")
        script = assets["install.sh"]
        if not script.read_bytes().startswith(b"#!/usr/bin/env bash\n"):
            raise ValueError("Unexpected installer format")
        subprocess.run(["bash", "-n", str(script)], check=True, timeout=10,
                       stdout=subprocess.DEVNULL)
        backup = backup_installation()
        try:
            subprocess.run([
                "bash", str(script), "--panel", config["panel"],
                "--domain", config["domain"], "--path", config["path"],
                "--release-sha", sha, "--skip-manager-restart",
            ], check=True, timeout=900, stdout=subprocess.DEVNULL)
        except Exception as original:
            try:
                restore_installation(backup)
            except Exception as rollback_error:
                raise RuntimeError("Update failed and rollback could not restore gateway") from rollback_error
            raise original


def current_version(path: Path = VERSION_FILE) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()[:40]
        return value if re.fullmatch(r"[A-Za-z0-9._-]+", value) else "unknown"
    except OSError:
        return "unknown"


def cycle(config: dict) -> bool:
    """Return True if updated, so systemd restarts the agent from newest file."""
    reply = service_request(config, "poll", {"version": current_version()})
    # The signed Nexus policy must be present and valid on every poll.
    # Never silently disable the local edge limit on missing/malformed data.
    accept_edge_policy(config, reply["flood"], path=EDGE_POLICY_FILE)
    if reply.get("command") != "update":
        return False
    job = reply.get("jobId")
    if not isinstance(job, str) or not JOB_RE.fullmatch(job):
        raise ValueError("Rejected malformed job ID")
    report(config, job, "running")
    try:
        perform_update(config)
    except Exception as error:
        # Fixed message; never leak paths, signed request data or subprocess args.
        try:
            report(config, job, "failed", type(error).__name__[:50])
        except Exception:
            pass
        return False
    report(config, job, "completed")
    return True


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("XMesh Sub manager requires systemd root permissions")
    while True:
        try:
            config = read_config()
            if cycle(config):
                # Restart=always loads newly installed code. Avoid killing the
                # parent during the installer subprocess so the success report
                # is not silently lost.
                return
        except Exception as error:
            # Do not log access tokens or exception string bodies.
            print("XMesh Sub manager: transient error: " + type(error).__name__, flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
