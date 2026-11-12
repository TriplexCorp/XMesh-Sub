#!/usr/bin/env python3
"""Private XMesh Sub forward_auth sidecar: bound request rates by real TCP peer.

Caddy supplies X-XMesh-Peer from {remote_host}; NEVER trust client-supplied
X-Forwarded-For, CF-Connecting-IP or arbitrary requested URLs for identity.
This sidecar listens only on the private Compose network, with no host port.
"""
from __future__ import annotations

from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import threading
import time

CONFIG = Path("/etc/xmesh/flood.json")
MAX_IDENTITIES = 6000
GLOBAL_MAX_PER_MINUTE = 25000
IP_BURST = 20


def safe_config(value: object) -> dict:
    defaults = {"enabled": True, "mode": "monitor", "ipPerMinute": 120}
    if not isinstance(value, dict) or set(value) - {"enabled", "mode", "ipPerMinute"}:
        return defaults
    enabled = value.get("enabled", True)
    mode = value.get("mode", "monitor")
    rate = value.get("ipPerMinute", 120)
    if not isinstance(enabled, bool) or mode not in ("monitor", "protect"):
        return defaults
    if type(rate) is not int or rate not in range(30, 601, 30):
        return defaults
    return {"enabled": enabled, "mode": mode, "ipPerMinute": rate}


def peer_key(value: str) -> str | None:
    # Caddy overwrites this header from the actual remote TCP peer. Never use
    # forwarded headers: CDN clients can share a peer address until a trusted
    # proxy CIDR and trusted real-IP chain are explicitly configured.
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


class FloodGuard:
    def __init__(self, config_file: Path = CONFIG):
        self.config_file = config_file
        self.settings = safe_config({})
        self.last_read = 0.0
        self.window = -1
        self.counters: OrderedDict[str, int] = OrderedDict()
        self.total = 0
        self.requests = 0
        self.exceeded = 0
        self.blocked = 0
        self.lock = threading.Lock()

    def reload(self, current: float) -> None:
        if current - self.last_read < 5:
            return
        self.last_read = current
        try:
            payload = json.loads(self.config_file.read_text(encoding="utf-8"))
            self.settings = safe_config(payload)
        except (OSError, ValueError):
            # Fail safe for existing subscriptions: missing/malformed config
            # is monitor-only, never an accidental mass block.
            self.settings = safe_config({})

    def check(self, peer: str, current: float | None = None) -> bool:
        """Return True for 429. Do not log, return or store raw request URLs."""
        now = time.monotonic() if current is None else current
        key = peer_key(peer)
        with self.lock:
            self.reload(now)
            if int(now // 60) != self.window:
                self.window = int(now // 60)
                self.counters.clear()
                self.total = 0
            self.requests += 1
            self.total += 1
            config = self.settings
            if not config["enabled"] or not key:
                return False
            if self.total > GLOBAL_MAX_PER_MINUTE:
                self.exceeded += 1
                if config["mode"] == "protect":
                    self.blocked += 1
                    return True
                return False
            if key not in self.counters and len(self.counters) >= MAX_IDENTITIES:
                # Protect memory under large peer-cardinality attacks.
                return False
            self.counters[key] = self.counters.get(key, 0) + 1
            self.counters.move_to_end(key)
            if self.counters[key] > config["ipPerMinute"] + IP_BURST:
                self.exceeded += 1
                if config["mode"] == "protect":
                    self.blocked += 1
                    return True
        return False


class BoundedHTTPServer(ThreadingHTTPServer):
    # An attacker must not be able to create an unbounded number of Python
    # threads using slow or parallel HTTP connections to the private sidecar.
    daemon_threads = True
    request_queue_size = 128
    max_active_workers = 64

    def __init__(self, *args: object, **kwargs: object):
        super().__init__(*args, **kwargs)
        self._workers = threading.BoundedSemaphore(self.max_active_workers)

    def process_request(self, request, client_address) -> None:
        if not self._workers.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Cache-Control: private, no-store\r\n"
                    b"Retry-After: 1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._workers.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._workers.release()


class Handler(BaseHTTPRequestHandler):
    guard = FloodGuard()
    server_version = "XMesh-Sub"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(4)

    def do_GET(self) -> None:
        if self.path != "/check":
            self.send_response(404)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        peer = self.headers.get("X-XMesh-Peer", "")
        blocked = self.guard.check(peer)
        self.send_response(429 if blocked else 204)
        self.send_header("Cache-Control", "private, no-store")
        if blocked:
            self.send_header("Retry-After", "60")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        self.do_GET()

    def log_message(self, *_args: object) -> None:
        # Never log URL, IP, token, User-Agent or proxy authentication headers.
        return


def main() -> None:
    BoundedHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
