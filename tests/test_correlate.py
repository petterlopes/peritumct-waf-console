from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

import correlate


class ClassifyTests(unittest.TestCase):
    def test_sqli_a03(self) -> None:
        self.assertEqual(correlate.classify("crowdsecurity/http-generic-sqli")["code"], "A03")

    def test_xss_a03(self) -> None:
        self.assertEqual(correlate.classify("crs/941110-xss")["code"], "A03")

    def test_ssrf_a10(self) -> None:
        self.assertEqual(correlate.classify("ssrf-probe")["code"], "A10")
        self.assertEqual(correlate.classify("crs-934100")["code"], "A10")

    def test_wordpress_uploads_listing_a01(self) -> None:
        hit = correlate.classify("crowdsecurity/generic-wordpress-uploads-listing")
        self.assertEqual(hit["code"], "A01")

    def test_probing_a05(self) -> None:
        self.assertEqual(correlate.classify("http-probing")["code"], "A05")
        self.assertEqual(correlate.classify("scanner-detect")["code"], "A05")

    def test_empty_none(self) -> None:
        self.assertEqual(correlate.classify("")["code"], "none")
        self.assertEqual(correlate.classify(None)["code"], "none")


class CorrelateTests(unittest.TestCase):
    def test_correlate_counts(self) -> None:
        alerts = [
            {
                "scenario": "crowdsecurity/http-generic-sqli",
                "source": {"ip": "203.0.113.10"},
                "created_at": "2026-01-01T00:00:00Z",
            },
            {
                "scenario": "xss-attempt",
                "source": {"ip": "203.0.113.11"},
                "created_at": "2026-01-01T00:00:01Z",
            },
            {
                "scenario": "ssrf",
                "source": {"ip": "203.0.113.12"},
                "created_at": "2026-01-01T00:00:02Z",
            },
        ]
        data = correlate.correlate(
            alerts,
            hub_rules=["crowdsecurity/generic-wordpress-uploads-listing", "crowdsecurity/vpatch-cve-2024-1234"],
        )
        by_code = {item["code"]: item for item in data["owasp"]}
        self.assertEqual(len(data["owasp"]), 10)
        self.assertEqual(by_code["A03"]["count"], 2)
        self.assertEqual(by_code["A10"]["count"], 1)
        self.assertEqual(by_code["A01"]["count"], 0)
        self.assertTrue(
            any("wordpress-uploads-listing" in rule for rule in by_code["A01"]["hub_rules"])
        )
        self.assertTrue(any("vpatch" in rule for rule in by_code["A06"]["hub_rules"]))
        self.assertEqual(len(data["findings"]), 3)
        self.assertFalse(data["push"])

    def test_stix_bundle_type(self) -> None:
        payload = correlate.correlate(
            [{"scenario": "sqli", "source": {"ip": "198.51.100.9"}, "created_at": "2026-01-01T00:00:00Z"}]
        )
        bundle = correlate.stix_bundle(payload)
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(str(bundle.get("id") or "").startswith("bundle--"))
        types = {obj.get("type") for obj in bundle.get("objects") or []}
        self.assertIn("identity", types)
        self.assertIn("indicator", types)


class ConnectorTests(unittest.TestCase):
    def test_unconfigured_without_env(self) -> None:
        env = {
            "WAF_MISP_URL": "",
            "WAF_MISP_KEY": "",
            "WAF_THEHIVE_URL": "",
            "WAF_THEHIVE_KEY": "",
            "WAF_OPENCTI_URL": "",
            "WAF_OPENCTI_TOKEN": "",
        }
        with patch.dict(os.environ, env, clear=False):
            items = correlate.connectors()
        names = {item["name"]: item for item in items}
        self.assertEqual(names["MISP"]["status"], "unconfigured")
        self.assertEqual(names["TheHive"]["status"], "unconfigured")
        self.assertEqual(names["OpenCTI"]["status"], "unconfigured")
        self.assertFalse(any(item.get("push") for item in items))
        classes = {item["type"] for item in items}
        self.assertEqual(
            classes,
            {"INTERNAL_ENRICHMENT", "EXTERNAL_IMPORT", "STREAM", "INTERNAL_EXPORT_FILE"},
        )

    def test_misp_url_configured(self) -> None:
        secret = "super-secret-misp-key-value"
        with patch.dict(
            os.environ,
            {"WAF_MISP_URL": "https://misp.example.invalid", "WAF_MISP_KEY": secret},
            clear=False,
        ):
            items = correlate.connectors()
            payload = correlate.correlate([])
            bundle = correlate.stix_bundle(payload)
            misp = correlate.misp_event(payload)
            hive = correlate.thehive_alert(payload)
        misp_conn = next(item for item in items if item["name"] == "MISP")
        self.assertEqual(misp_conn["status"], "configured")
        blob = json.dumps({"connectors": items, "payload": payload, "stix": bundle, "misp": misp, "thehive": hive})
        self.assertNotIn(secret, blob)
        self.assertNotIn("https://misp.example.invalid", blob)
        self.assertNotIn("WAF_MISP_KEY", blob)
        for doc in (items, payload, bundle, misp, hive):
            self._assert_no_token_fields(doc)

    def _assert_no_token_fields(self, value) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).lower()
                self.assertFalse(
                    any(part in lowered for part in ("token", "key", "password", "secret")),
                    msg="secret-looking key leaked: %s" % key,
                )
                self._assert_no_token_fields(item)
        elif isinstance(value, list):
            for item in value:
                self._assert_no_token_fields(item)


if __name__ == "__main__":
    unittest.main()
