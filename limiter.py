#!/usr/bin/env python3
"""A private UNIX-socket authorization gate for Caddy subscription requests.

Caddy overwrites X-XMesh-Peer-IP with the *direct TCP peer* ({remote_host})
and connects to this service only through a shared Unix-domain socket.
Never accept untrusted X-Forwarded-For, or expose this service on TCP.
Request paths and subscription bearer tokens never enter this gate.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler

SOCKET_FILE = Path("/run/xmesh-sub/rate.sock")
POLICY_FILE = Path("/etc/xmesh-sub/policy/config.json")
MAX_IPS = 50_000
IDLE_SECONDS = 120
DEFAULT_LIMIT = 120


def load_policy(path: Path | None = None) -> tuple[bool, str, int]:
    path = POLICY_FILE if path is None else path
    # Broken/missing policy must never silently disable enforcement.
    # Fresh installs create a local protected policy before starting Caddy.
    with path.open("rb") as stream:
        raw = stream.read(1025)
    if len(raw) > 1024:
        raise ValueError("Oversized edge policy")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"enabled", "mode", "ipPerMinute"}:
        raise ValueError("Invalid edge policy")
    enabled, mode, limit = value["enabled"], value["mode"], value["ipPerMinute"]
    if type(enabled) is not bool or mode not in ("protect", "monitor") or type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError("Invalid edge policy limits")
    return enabled, mode, limit


def normalized_address(text: str) -> bytes:
    """IPv4 remains /32. IPv4-mapped IPv6 maps to IPv4; native IPv6 to /64."""
    if not text or len(text) > 64 or any(c in text for c in ("%", "/", ",", " ")):
        raise ValueError("Invalid direct peer IP")
    addr = ipaddress.ip_address(text)
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        else:
            addr = ipaddress.IPv6Network((addr, 64), strict=False).network_address
    return addr.packed


class BucketLimiter:
    """Bounded in-memory token bucket; opaque ephemeral HMAC keys, no IP logs."""

    def __init__(self, max_ips: int = MAX_IPS):
        self._lock = threading.Lock()
        self._salt = os.urandom(32)
        self._buckets: dict[bytes, tuple[float, float]] = {}
        self._max_ips = max_ips
        self._last_prune = time.monotonic()

    def allow(self, peer: str, max_per_minute: int, now: float | None = None) -> bool:
        address = normalized_address(peer)
        key = hmac.digest(self._salt, address, "sha256")
        now = time.monotonic() if now is None else now
        with self._lock:
            if now - self._last_prune >= 30:
                self._buckets = {
                    key: entry for key, entry in self._buckets.items()
                    if now - entry[1] < IDLE_SECONDS
                }
                self._last_prune = now
            previous = self._buckets.get(key)
            if previous is None:
                if len(self._buckets) >= self._max_ips:
                    # Fail closed under cardinality abuse, never unbounded RAM.
                    raise OverflowError("Too many distinct peer networks")
                tokens = float(max_per_minute)
            else:
                tokens = min(float(max_per_minute),
                             previous[0] + max(0.0, now - previous[1]) * max_per_minute / 60.0)
            allowed = tokens >= 1
            self._buckets[key] = (tokens - 1.0 if allowed else tokens, now)
            return allowed


LIMITER = BucketLimiter()


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 256
    allow_reuse_address = True


class PolicyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format_string, *args):
        # Never log headers, client addresses, subscription URLs or tokens.
        return

    def respond(self, code: int):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if code == 429:
            self.send_header("Retry-After", "5")
        self.end_headers()

    def do_GET(self):
        if self.path != "/check":
            self.respond(404)
            return
        ips = self.headers.get_all("X-XMesh-Peer-IP", [])
        if len(ips) != 1:
            self.respond(400)
            return
        try:
            enabled, mode, max_per_minute = load_policy()
        except (OSError, ValueError):
            self.respond(503)
            return
        try:
            if enabled:
                allowed = LIMITER.allow(ips[0], max_per_minute)
                if not allowed and mode == "protect":
                    self.respond(429)
                    return
            else:
                normalized_address(ips[0])
        except ValueError:
            self.respond(400)
            return
        except OverflowError:
            self.respond(503)
            return
        self.respond(204)

    def do_POST(self):
        self.respond(405)


def main() -> None:
    SOCKET_FILE.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if os.path.lexists(SOCKET_FILE):
        if not stat.S_ISSOCK(SOCKET_FILE.lstat().st_mode):
            raise ValueError("Refusing to replace a non-socket entry")
        SOCKET_FILE.unlink()
    # Read and validate before accepting requests; a broken policy never
    # permits unlimited subscription downloads.
    load_policy()
    with UnixHTTPServer(str(SOCKET_FILE), PolicyHandler) as server:
        SOCKET_FILE.chmod(0o660)
        server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
