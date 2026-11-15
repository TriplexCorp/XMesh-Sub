#!/usr/bin/env python3
"""Tests for socket-only peer limiter, run without root, Docker or network."""
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location("xmesh_sub_limiter", ROOT/"limiter.py")
edge=importlib.util.module_from_spec(spec)
spec.loader.exec_module(edge)


class LimiterTest(unittest.TestCase):
    def test_ipv4_mapped_and_ipv6_prefix(self):
        self.assertEqual(edge.normalized_address("192.0.2.5"),
                         edge.normalized_address("::ffff:192.0.2.5"))
        self.assertEqual(edge.normalized_address("2001:db8:a:b::1"),
                         edge.normalized_address("2001:db8:a:b:ffff::7"))
        self.assertNotEqual(edge.normalized_address("2001:db8:a:b::1"),
                            edge.normalized_address("2001:db8:a:c::1"))
        for invalid in ("192.0.2.4, 10.1.2.3", "host.name", "[::1]", "::1%eth0", ""):
            with self.assertRaises(ValueError):
                edge.normalized_address(invalid)

    def test_token_bucket_refill_and_bound(self):
        limit=edge.BucketLimiter(max_ips=2)
        self.assertTrue(limit.allow("192.0.2.1",2,now=100))
        self.assertTrue(limit.allow("192.0.2.1",2,now=100))
        self.assertFalse(limit.allow("192.0.2.1",2,now=100))
        self.assertTrue(limit.allow("192.0.2.1",2,now=130))
        self.assertTrue(limit.allow("192.0.2.2",2,now=130))
        with self.assertRaises(OverflowError):
            limit.allow("192.0.2.3",2,now=130)

    def test_invalid_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            policy=Path(temp)/"policy.json"
            for malformed in ('{}', '{"enabled":"true","mode":"protect","ipPerMinute":1}',
                              '{"enabled":true,"mode":"off","ipPerMinute":1}',
                              '{"enabled":true,"mode":"protect","ipPerMinute":0}'):
                policy.write_text(malformed)
                with self.assertRaises(ValueError):
                    edge.load_policy(policy)
            policy.write_text('{"enabled":true,"mode":"protect","ipPerMinute":2}')
            self.assertEqual(edge.load_policy(policy),(True,"protect",2))

    def test_socket_is_private_policy_gate_and_ignores_spoofed_forwarded_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            policy=p/"config.json"
            sock=p/"edge.sock"
            policy.write_text(json.dumps({"enabled":True,"mode":"protect","ipPerMinute":1}))
            with patch.object(edge,"POLICY_FILE",policy), patch.object(edge,"LIMITER",edge.BucketLimiter()):
                server=edge.UnixHTTPServer(str(sock),edge.PolicyHandler)
                thread=threading.Thread(target=server.serve_forever,daemon=True)
                thread.start()
                try:
                    def ask(extra: str, path="/check"):
                        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                            client.settimeout(2)
                            client.connect(str(sock))
                            client.sendall((
                                f"GET {path} HTTP/1.1\r\nHost: limiter\r\n"
                                f"{extra}Connection: close\r\n\r\n"
                            ).encode())
                            data=b""
                            while True:
                                part=client.recv(8192)
                                if not part: break
                                data+=part
                            return data.decode("latin-1").split("\r\n",1)[0]
                    self.assertIn("204",ask("X-XMesh-Peer-IP: 192.0.2.1\r\n"))
                    self.assertIn("429",ask("X-XMesh-Peer-IP: 192.0.2.1\r\nX-Forwarded-For: 198.51.100.55\r\n"))
                    self.assertIn("400",ask("X-XMesh-Peer-IP: 192.0.2.1\r\nX-XMesh-Peer-IP: 198.51.100.1\r\n"))
                    self.assertIn("400",ask("X-Forwarded-For: 198.51.100.55\r\n"))
                    self.assertIn("404",ask("X-XMesh-Peer-IP: 192.0.2.2\r\n",path="/foo"))
                    policy.write_text('{"enabled":true,"mode":"monitor","ipPerMinute":1}')
                    self.assertIn("204",ask("X-XMesh-Peer-IP: 192.0.2.1\r\n"))
                    policy.write_text("broken")
                    self.assertIn("503",ask("X-XMesh-Peer-IP: 192.0.2.1\r\n"))
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)


if __name__=="__main__":
    unittest.main()
