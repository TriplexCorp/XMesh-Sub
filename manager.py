#!/usr/bin/env python3
"""XMesh Sub pull-only manager.

Only an enrolled agent can poll a fixed, TLS-verified Nexus API. Nexus can
request ONE hardcoded operation ("update"), never arbitrary shell commands.
There is no management listener, public admin endpoint, or Docker socket exposed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
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
    return config


def service_request(config: dict, route: str, body: dict) -> dict:
    # route is fixed in source code, never server-controlled.
    url = config["panel"] + "/api/v1/sub-server/agent/" + route
    request = urllib.request.Request(
        url,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={"Authorization": "Bearer " + config["agentToken"],
                 "Content-Type": "application/json",
                 "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
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
    # Do not follow arbitrary update commands or URLs supplied by the panel.
    # Always download the audited installer from the official XMesh-Sub repo.
    with urllib.request.urlopen(SCRIPT_URL, timeout=30, context=ssl.create_default_context()) as response:
        script = response.read(MAX_INSTALLER_BYTES + 1)
    if not script.startswith(b"#!/usr/bin/env bash\n") or len(script) > MAX_INSTALLER_BYTES:
        raise ValueError("Invalid installer payload")
    with tempfile.TemporaryDirectory(prefix="xmesh-sub-update-") as location:
        file = Path(location) / "install.sh"
        file.write_bytes(script)
        file.chmod(0o700)
        subprocess.run(["bash", "-n", str(file)], check=True, timeout=10, stdout=subprocess.DEVNULL)
        # No extra flags, hostnames or executable strings from API responses.
        subprocess.run([
            "bash", str(file), "--panel", config["panel"],
            "--domain", config["domain"], "--path", config["path"],
            "--skip-manager-restart",
        ], check=True, timeout=900, stdout=subprocess.DEVNULL)


def current_version(path: Path = VERSION_FILE) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()[:40]
        return value if re.fullmatch(r"[A-Za-z0-9._-]+", value) else "unknown"
    except OSError:
        return "unknown"


def cycle(config: dict) -> bool:
    """Return True if updated, so systemd restarts the agent from newest file."""
    reply = service_request(config, "poll", {"version": current_version()})
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
