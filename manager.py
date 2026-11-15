#!/usr/bin/env python3
"""XMesh Sub pull-only manager.

Only an enrolled agent can poll a fixed, TLS-verified Nexus API. Nexus can
request ONE hardcoded operation ("update"), never arbitrary shell commands.
There is no management listener, public admin endpoint, or Docker socket exposed.
"""
from __future__ import annotations

import base64
import stat
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path("/opt/xmesh-sub")
CONFIG_FILE = ROOT / "manager.json"
VERSION_FILE = ROOT / "VERSION"
SCRIPT_URL = "https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/main/install.sh"
RELEASE_MANIFEST_URL = "https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/main/release.json"
RELEASE_SIGNATURE_URL = RELEASE_MANIFEST_URL + ".sig"
PUBLIC_KEY_FILE = ROOT / "release.pub"
AGENT_PROOF_KEY = ROOT / "agent-proof.pem"
EDGE_POLICY_FILE = ROOT / "edge-policy" / "config.json"
BACKUPS = ROOT / "backups"
POLL_INTERVAL_SECONDS = 20
MAX_INSTALLER_BYTES = 128 * 1024
JOB_RE = re.compile(r"^[0-9a-f]{32}$")


def read_config(path: Path = CONFIG_FILE) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    panel = config.get("panel")
    token = config.get("agentToken")
    domain = config.get("domain")
    sub_path = config.get("path")
    if (not isinstance(panel, str) or not re.fullmatch(r"https://[A-Za-z0-9.-]+", panel)
            or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token)
            or not isinstance(domain, str) or not re.fullmatch(r"[A-Za-z0-9.-]+", domain)
            or not isinstance(sub_path, str) or not re.fullmatch(r"/[A-Za-z0-9_/-]+", sub_path)):
        raise ValueError("Invalid manager configuration")
    proof = config.get("proofKey")
    if proof is not None:
        if proof != str(AGENT_PROOF_KEY) or not AGENT_PROOF_KEY.is_file():
            raise ValueError("Invalid agent proof key path")
        info = AGENT_PROOF_KEY.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Agent proof key permissions must be 0600")
    return config


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    # Never replay long-lived bearer credentials across redirects.
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


def get_public_bytes(url: str, max_bytes: int = 128 * 1024) -> bytes:
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with verified_open(request, timeout=30) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("Oversized release asset")
    return data


def signed_release(public_key: Path = PUBLIC_KEY_FILE) -> dict:
    """Reject all updates unless an offline-signed release manifest is valid."""
    metadata = get_public_bytes(RELEASE_MANIFEST_URL, 4096)
    signature_b64 = get_public_bytes(RELEASE_SIGNATURE_URL, 512)
    signature = base64.b64decode(signature_b64.strip(), validate=True)
    if len(signature) != 64:
        raise ValueError("Invalid Ed25519 signature size")
    if not public_key.is_file():
        raise ValueError("Release signing trust anchor is missing")
    with tempfile.TemporaryDirectory(prefix="xmesh-sub-verify-") as folder:
        manifest = Path(folder) / "release.json"
        sig = Path(folder) / "release.sig"
        manifest.write_bytes(metadata)
        sig.write_bytes(signature)
        subprocess.run([
            "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
            "-rawin", "-in", str(manifest), "-sigfile", str(sig),
        ], check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    payload = json.loads(metadata)
    if (not isinstance(payload, dict) or set(payload) != {
            "schema", "version", "installSha256", "managerSha256"}
            or payload["schema"] != 1
            or not isinstance(payload["version"], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", payload["version"])):
        raise ValueError("Invalid signed release manifest")
    for key in ("installSha256", "managerSha256"):
        digest = payload[key]
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid signed release digest")
    return payload


def version_tuple(version: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    return tuple(map(int, match.groups())) if match else (0, 0, 0)


def backup_installation(root: Path = ROOT) -> Path:
    destination = root / "backups"
    destination.mkdir(mode=0o700, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix="pre-update-", dir=str(destination)))
    backup.chmod(0o700)
    files = ("Caddyfile", "compose.yaml", "manager.py", "manager.json",
             "agent-proof.pem", "limiter.py", "release.pub", "release.json", "VERSION")
    for name in files:
        old = root / name
        if old.is_file():
            shutil.copy2(old, backup / name)
        else:
            (backup / (".absent-" + name)).touch()
    return backup


def restore_installation(backup: Path, root: Path = ROOT) -> None:
    for name in ("Caddyfile", "compose.yaml", "manager.py", "manager.json",
                 "agent-proof.pem", "limiter.py", "release.pub", "release.json", "VERSION"):
        saved = backup / name
        target = root / name
        if saved.is_file():
            shutil.copy2(saved, target)
        elif (backup / (".absent-" + name)).is_file():
            target.unlink(missing_ok=True)
    subprocess.run(["docker", "compose", "-f", str(root / "compose.yaml"),
                    "up", "-d", "--remove-orphans"], cwd=root, check=True, timeout=180)


def proof_headers(config: dict, route: str, wire: bytes, key_file: Path = AGENT_PROOF_KEY) -> dict:
    """Sign exact request bytes. Bearer+private key are both required."""
    ts = str(int(time.time()))
    nonce = os.urandom(16).hex()
    path = "/api/v1/sub-server/agent/" + route
    token_hash = hashlib.sha256(config["agentToken"].encode("ascii")).hexdigest()
    body_hash = hashlib.sha256(wire).hexdigest()
    message = "\n".join((
        "xmesh-sub-proof-v1", token_hash, "POST", path, ts, nonce, body_hash,
    )).encode("ascii")
    # OpenSSL Ed25519 pkeyutl requires seekable input (-rawin).
    with tempfile.NamedTemporaryFile(prefix="xmesh-sub-proof-") as tmp:
        tmp.write(message)
        tmp.flush()
        signature = subprocess.run([
            "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key_file),
            "-in", tmp.name,
        ], check=True, capture_output=True, timeout=10).stdout
    if len(signature) != 64:
        raise ValueError("Invalid Ed25519 signature from local signer")
    return {
        "X-XMesh-Proof-Ts": ts,
        "X-XMesh-Proof-Nonce": nonce,
        "X-XMesh-Proof-Sig": signature.hex(),
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
    # route is fixed in source code, never server-controlled.
    url = config["panel"] + "/api/v1/sub-server/agent/" + route
    wire = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Authorization": "Bearer " + config["agentToken"],
               "Content-Type": "application/json",
               "Accept": "application/json"}
    if config.get("proofKey"):
        headers.update(proof_headers(config, route, wire))
    request = urllib.request.Request(url, data=wire, headers=headers, method="POST")
    with verified_open(request, timeout=20) as response:
        payload = response.read(16384 + 1)
        if len(payload) > 16384:
            raise ValueError("Oversized response")
    value = json.loads(payload)
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
    # Nexus only triggers a fixed action. Artifacts MUST match an Ed25519-
    # authenticated manifest signed by the offline owner key, never GitHub alone.
    release = signed_release()
    if version_tuple(release["version"]) < version_tuple(current_version()):
        raise ValueError("Refusing a signed release rollback")
    script = get_public_bytes(SCRIPT_URL, MAX_INSTALLER_BYTES)
    if (not script.startswith(b"#!/usr/bin/env bash\n")
            or hashlib.sha256(script).hexdigest() != release["installSha256"]):
        raise ValueError("Installer SHA-256 is not approved by the release signer")
    with tempfile.TemporaryDirectory(prefix="xmesh-sub-update-") as location:
        file = Path(location) / "install.sh"
        file.write_bytes(script)
        file.chmod(0o700)
        subprocess.run(["bash", "-n", str(file)], check=True, timeout=10,
                       stdout=subprocess.DEVNULL)
        backup = backup_installation()
        # Only constant flags and validated saved config are ever forwarded.
        try:
            subprocess.run([
                "bash", str(file), "--panel", config["panel"],
                "--domain", config["domain"], "--path", config["path"],
                "--skip-manager-restart",
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
    # Before processing commands, persist signed Nexus flood policy for the
    # local Caddy socket-auth gate. Invalid policy never disables protection.
    if "flood" in reply:
        accept_edge_policy(config, reply["flood"])
    if reply.get("command") != "update":
        return False
    job = reply.get("jobId")
    if not isinstance(job, str) or not JOB_RE.fullmatch(job):
        raise ValueError("Rejected malformed job ID")
    report(config, job, "running")
    try:
        perform_update(config)
    except Exception as error:
        # Fixed message; never leak paths, headers, bearer tokens or subprocess args.
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
