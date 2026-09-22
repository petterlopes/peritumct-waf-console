#!/usr/bin/env python3
"""HTTP probe health helpers used by Domains / overview KPIs."""
from __future__ import annotations

import unittest

import app as waf_app
import dashboard
import status as statusmod


class HttpStatusOkTests(unittest.TestCase):
    def test_2xx_and_3xx_healthy(self):
        for code in (200, 201, 204, 301, 302, 304, "200", "302"):
            self.assertTrue(statusmod.http_status_ok(code), code)
            self.assertTrue(waf_app.http_status_ok(code), code)
            self.assertTrue(dashboard._probe_ok(code), code)

    def test_4xx_5xx_zero_unhealthy(self):
        for code in (0, 400, 403, 404, 500, 503, None, "", "fail"):
            self.assertFalse(statusmod.http_status_ok(code), code)
            self.assertFalse(waf_app.http_status_ok(code), code)
            self.assertFalse(dashboard._probe_ok(code), code)


if __name__ == "__main__":
    unittest.main()
