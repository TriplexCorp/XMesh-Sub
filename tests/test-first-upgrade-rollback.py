#!/usr/bin/env python3
"""Real Docker proof of an old-manager FIRST upgrade and installer rollback.

The old manager cannot save image IDs. Exercise the literal backup and EXIT
rollback functions extracted from the signed install.sh, with a disposable
Compose project and private dummy files. Production /opt and systemd untouched.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import uuid

HERE = Path(__file__).resolve().parent.parent
INSTALL = (HERE / "install.sh").read_text()
SNAP_START = "# Old images are preserved by revision-specific tags; verify they still exist.\n"
SNAP_END = "# From this point onward, failure restores both the old files"
OLD_CADDY = os.environ.get("XMESH_SUB_CADDY_IMAGE", "xmesh-sub-caddy:2.11.9-josev4r1")
OLD_LIMITER = os.environ.get("XMESH_SUB_LIMITER_IMAGE", "xmesh-sub-limiter:3.12.16-krb5r1")


def docker(*args, cwd=None):
    return subprocess.run(["docker", *args], check=True, capture_output=True,
                          text=True, timeout=90, cwd=cwd).stdout.strip()


def image_for(root, service):
    cid = docker("compose", "-f", str(root / "compose.yaml"), "ps", "-q", service)
    if not cid:
        raise AssertionError(f"Missing running service: {service}")
    return docker("inspect", "--format", "{{.Image}}", cid)


def compose_image(caddy, limiter):
    # Two running process containers, but no real public listening ports.
    return (
        f"services:\n"
        f"  xmesh-sub:\n"
        f"    image: {caddy}\n"
        f"    pull_policy: never\n"
        f"    entrypoint: ['sh', '-c', 'sleep 300']\n"
        f"    command: []\n"
        f"  xmesh-sub-limiter:\n"
        f"    image: {limiter}\n"
        f"    pull_policy: never\n"
        f"    entrypoint: ['sh', '-c', 'sleep 300']\n"
        f"    command: []\n"
    )


def main():
    assert INSTALL.count(SNAP_START) == INSTALL.count(SNAP_END) == 1
    before = INSTALL.split(SNAP_START, 1)[1].split(SNAP_END, 1)[0]
    rollback = re.search(r"(?ms)^installer_exit\(\) \{.*?^\}$", INSTALL)
    assert rollback, "Signed installer EXIT rollback function missing"
    assert 'docker compose up -d --no-build --force-recreate --remove-orphans' in rollback.group()
    assert "sub_caddy_image()" in INSTALL and "sub_limiter_image()" in INSTALL
    assert 'if ! docker image inspect "$caddy_image"' in INSTALL

    suffix = uuid.uuid4().hex[:12]
    old_caddy = f"xmesh-sub-old-caddy:{suffix}"
    old_limiter = f"xmesh-sub-old-limiter:{suffix}"
    new_caddy = f"xmesh-sub-caddy:rev-{'a' * 40}"
    new_limiter = f"xmesh-sub-limiter:rev-{'a' * 40}"
    created = [old_caddy, old_limiter, new_caddy, new_limiter]
    with tempfile.TemporaryDirectory(prefix="xmesh-sub-first-upgrade-") as directory:
        root = Path(directory)
        temp = root / "staging"
        temp.mkdir(mode=0o700)
        service = root / "manager-unit.service"
        bin_dir = root / "mock-bin"
        bin_dir.mkdir()
        script = bin_dir / "systemctl"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o700)
        try:
            # Old image refs and IDs exist before the first signed new install.
            docker("image", "tag", OLD_CADDY, old_caddy)
            docker("image", "tag", OLD_LIMITER, old_limiter)
            expected = {
                "xmesh-sub": docker("image", "inspect", "--format", "{{.Id}}", old_caddy),
                "xmesh-sub-limiter": docker("image", "inspect", "--format", "{{.Id}}", old_limiter),
            }
            assert len(set(expected.values())) == 2

            # New revision tags deliberately point to the *opposite* binaries.
            # An old manager that overwrites old tags cannot safely recover.
            docker("image", "tag", OLD_LIMITER, new_caddy)
            docker("image", "tag", OLD_CADDY, new_limiter)
            (root / "compose.yaml").write_text(compose_image(old_caddy, old_limiter))
            (root / "VERSION").write_text("0.1.0\n")
            (root / "manager.json").write_text('{"dummy":"secret"}\n')
            (root / "manager.json").chmod(0o600)
            service.write_text("original systemd unit\n")
            docker("compose", "-f", str(root / "compose.yaml"), "up", "-d", "--no-build")
            for name, old_id in expected.items():
                assert image_for(root, name) == old_id

            mutated_compose = root / "new-compose.fixture"
            mutated_compose.write_text(compose_image(new_caddy, new_limiter))
            test = (
                "set -Eeuo pipefail\n"
                f"ROOT={shlex.quote(str(root))}\n"
                f"temp={shlex.quote(str(temp))}\n"
                f"SERVICE_UNIT={shlex.quote(str(service))}\n"
                "SKIP_MANAGER_RESTART=1\n"
                "existing_install=0\n"
                "install_mutated=0\n"
                + rollback.group() + "\n"
                + SNAP_START + "\n" + before + "\n"
                "test \"$existing_install\" = 1\n"
                "install_mutated=1\n"
                "trap 'installer_exit \"$?\"' EXIT\n"
                "printf 'BROKEN\\n' > \"$ROOT/VERSION\"\n"
                "printf 'BROKEN\\n' > \"$ROOT/manager.json\"\n"
                "printf 'BROKEN\\n' > \"$SERVICE_UNIT\"\n"
                f"cp {shlex.quote(str(mutated_compose))} \"$ROOT/compose.yaml\"\n"
                "docker compose -f \"$ROOT/compose.yaml\" up -d --no-build --force-recreate\n"
                "exit 51\n"
            )
            env = dict(os.environ, PATH=str(bin_dir) + ":" + os.environ["PATH"])
            result = subprocess.run(["bash", "-c", test], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=120)
            if result.returncode != 51:
                raise AssertionError("Installer rollback did not preserve injected error "
                                     + str(result.returncode) + "\n" + result.stderr[-5000:])
            assert "restoring previous gateway deployment" in result.stderr
            assert (root / "VERSION").read_text() == "0.1.0\n"
            assert (root / "manager.json").read_text() == '{"dummy":"secret"}\n'
            assert (root / "manager.json").stat().st_mode & 0o777 == 0o600
            assert service.read_text() == "original systemd unit\n"
            assert (root / "compose.yaml").read_text() == compose_image(old_caddy, old_limiter)
            for name, old_id in expected.items():
                assert image_for(root, name) == old_id, (name, old_id)
            assert not temp.exists(), "Private rollback staging directory not cleaned"
            # Installing another SHA must never change the identity of a
            # previous revision's Docker tag.
            assert docker("image", "inspect", "--format", "{{.Id}}", old_caddy) == expected["xmesh-sub"]
            assert docker("image", "inspect", "--format", "{{.Id}}", old_limiter) == expected["xmesh-sub-limiter"]
            print("PASS: real old-manager first-upgrade rollback restores files, "
                  "manager settings and both original running Docker images")
        finally:
            if (root / "compose.yaml").exists():
                subprocess.run(["docker", "compose", "-f", str(root / "compose.yaml"),
                                "down", "--remove-orphans"], capture_output=True, timeout=60)
            for tag in created:
                subprocess.run(["docker", "image", "rm", tag],
                               capture_output=True, timeout=20)


if __name__ == "__main__":
    main()
