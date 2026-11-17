#!/usr/bin/env python3
"""CI-only Docker proof: keep/recover old image IDs after mutable tags change.

Uses disposable Compose project, temporary tags and no public ports, credentials,
network services, or production data. Requires locally built candidate images.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("xmesh_sub_manager", ROOT / "manager.py")
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


def docker(*args):
    return subprocess.run(["docker", *args], text=True, capture_output=True,
                          check=True, timeout=180).stdout.strip()


def container_image(compose: Path, service: str) -> str:
    cid = docker("compose", "-f", str(compose), "ps", "-q", service)
    if not cid:
        raise RuntimeError(f"{service} did not start")
    return docker("inspect", "--format", "{{.Image}}", cid)


def main():
    suffix = uuid.uuid4().hex[:16]
    original_caddy = f"xmesh-sub-ci-caddy:{suffix}"
    original_limiter = f"xmesh-sub-ci-limiter:{suffix}"
    created = []
    backup = None
    with tempfile.TemporaryDirectory(prefix="xmesh-sub-rollback-") as directory:
        root = Path(directory)
        compose = root / "compose.yaml"
        try:
            docker("image", "tag", "xmesh-sub-caddy:2.11.9-josev4r1", original_caddy)
            created.append(original_caddy)
            docker("image", "tag", "xmesh-sub-limiter:3.12.16-krb5r1", original_limiter)
            created.append(original_limiter)
            caddy_image = docker("image", "inspect", "--format", "{{.Id}}", original_caddy)
            limiter_image = docker("image", "inspect", "--format", "{{.Id}}", original_limiter)
            if caddy_image == limiter_image:
                raise RuntimeError("Cannot test rollback with identical images")
            compose.write_text(
                f"services:\n"
                f"  xmesh-sub:\n"
                f"    image: {original_caddy}\n"
                f"    pull_policy: never\n"
                f"    entrypoint: ['sh', '-c']\n"
                f"    command: 'sleep 300'\n"
                f"  xmesh-sub-limiter:\n"
                f"    image: {original_limiter}\n"
                f"    pull_policy: never\n"
                f"    entrypoint: ['sh', '-c']\n"
                f"    command: 'sleep 300'\n", encoding="utf-8")
            docker("compose", "-f", str(compose), "up", "-d", "--no-build")
            assert container_image(compose, "xmesh-sub") == caddy_image
            assert container_image(compose, "xmesh-sub-limiter") == limiter_image

            backup = manager.backup_installation(root)
            manifest = json.loads((backup / "images.json").read_text())
            assert len(manifest) == 2, manifest
            assert set(x["image_id"] for x in manifest) == {caddy_image, limiter_image}

            # Model what install.sh does on upgrade: replace both original
            # mutable tags with new image bytes. The Docker daemon must retain
            # the old *image IDs* through private rollback tags.
            docker("image", "tag", limiter_image, original_caddy)
            docker("image", "tag", caddy_image, original_limiter)
            docker("compose", "-f", str(compose), "up", "-d", "--no-build",
                   "--force-recreate")
            assert container_image(compose, "xmesh-sub") == limiter_image
            assert container_image(compose, "xmesh-sub-limiter") == caddy_image

            manager.restore_installation(backup, root)
            assert container_image(compose, "xmesh-sub") == caddy_image
            assert container_image(compose, "xmesh-sub-limiter") == limiter_image
            assert docker("image", "inspect", "--format", "{{.Id}}",
                          original_caddy) == caddy_image
            assert docker("image", "inspect", "--format", "{{.Id}}",
                          original_limiter) == limiter_image
            print("PASS: real Docker rollback restored original image IDs and recreated both services")
        finally:
            if compose.exists():
                subprocess.run(["docker", "compose", "-f", str(compose),
                                "down", "--remove-orphans"], capture_output=True,
                               timeout=120, check=False)
            if backup is not None:
                for image in json.loads((backup / "images.json").read_text()):
                    subprocess.run(["docker", "image", "rm", image["rescue_tag"]],
                                   capture_output=True, timeout=30, check=False)
            for ref in created:
                subprocess.run(["docker", "image", "rm", ref], capture_output=True,
                               timeout=30, check=False)


if __name__ == "__main__":
    main()
