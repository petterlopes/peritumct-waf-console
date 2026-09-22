#!/usr/bin/env python3
"""Network hardening helpers."""
from __future__ import annotations

import time
import unittest

import netguard
import status as statusmod


class NetguardTests(unittest.TestCase):
    def test_loopback_urls(self):
        self.assertTrue(netguard.assert_loopback_http_url("http://127.0.0.1:6060/metrics").endswith("/metrics"))
        self.assertTrue(netguard.assert_loopback_http_url("http://localhost:8080/api").endswith("/api"))
        with self.assertRaises(ValueError):
            netguard.assert_loopback_http_url("http://example.com/metrics")
        with self.assertRaises(ValueError):
            netguard.assert_loopback_http_url("http://user:pass@127.0.0.1/x")

    def test_probe_server_literal_ip(self):
        self.assertEqual(netguard.assert_probe_server("203.0.113.9"), "203.0.113.9")
        self.assertEqual(netguard.assert_probe_server(""), "")
        with self.assertRaises(ValueError):
            netguard.assert_probe_server("evil.example")

    def test_sanitize_hostname(self):
        self.assertEqual(netguard.sanitize_hostname("Grafana.Example.COM"), "grafana.example.com")
        with self.assertRaises(ValueError):
            netguard.sanitize_hostname("evil\r\nHost: x")
        with self.assertRaises(ValueError):
            netguard.sanitize_hostname("a/b")

    def test_ttl_cache(self):
        cache = netguard.TtlCache()
        cache.set("k", "v", 0.05)
        self.assertEqual(cache.get("k"), "v")
        time.sleep(0.2)
        self.assertIsNone(cache.get("k"))

    def test_rate_limiter(self):
        lim = netguard.RateLimiter(3, 60.0)
        self.assertTrue(lim.allow("a"))
        self.assertTrue(lim.allow("a"))
        self.assertTrue(lim.allow("a"))
        self.assertFalse(lim.allow("a"))
        self.assertTrue(lim.allow("b"))

    def test_read_limited(self):
        class Fake:
            def __init__(self, data: bytes):
                self._data = data
                self._pos = 0

            def read(self, n: int = -1):
                if self._pos >= len(self._data):
                    return b""
                if n < 0:
                    n = len(self._data) - self._pos
                chunk = self._data[self._pos : self._pos + n]
                self._pos += len(chunk)
                return chunk

        self.assertEqual(netguard.read_limited(Fake(b"abc"), 10), b"abc")
        with self.assertRaises(RuntimeError):
            netguard.read_limited(Fake(b"x" * 100), 50)

    def test_version_and_status(self):
        self.assertTrue(statusmod.APP_NAME.startswith("waf-console/"))
        self.assertTrue(statusmod.http_status_ok(302))
        self.assertFalse(statusmod.http_status_ok(503))


if __name__ == "__main__":
    unittest.main()
