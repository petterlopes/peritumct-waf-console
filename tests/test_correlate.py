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

    def test_sqli_attack_is_t1190_only(self) -> None:
        hit = correlate.classify("crowdsecurity/http-generic-sqli")
        self.assertEqual(hit["attack"], ["T1190"])

    def test_xss_not_drive_by(self) -> None:
        hit = correlate.classify("crs/941110-xss")
        self.assertEqual(hit["attack"], ["T1190"])
        self.assertNotIn("T1189", hit["attack"])
        self.assertNotIn("T1059", hit["attack"])

    def test_ssrf_not_c2_proxy(self) -> None:
        hit = correlate.classify("crs-934100")
        self.assertEqual(hit["code"], "A10")
        self.assertEqual(hit["attack"], ["T1190"])
        self.assertNotIn("T1090", hit["attack"])

    def test_cve_9341_is_not_ssrf(self) -> None:
        hit = correlate.classify("crowdsecurity/vpatch-CVE-2024-9341")
        self.assertEqual(hit["code"], "A06")
        self.assertNotEqual(hit["code"], "A10")

    def test_http_generic_bf_a07(self) -> None:
        hit = correlate.classify("crowdsecurity/http-generic-bf")
        self.assertEqual(hit["code"], "A07")
        self.assertEqual(hit["attack"], ["T1110"])

    def test_ssh_cve_is_not_brute(self) -> None:
        hit = correlate.classify("crowdsecurity/ssh-cve-2024-6387")
        self.assertEqual(hit["code"], "A06")
        self.assertNotIn("T1110", hit["attack"])

    def test_wordpress_login_a07(self) -> None:
        hit = correlate.classify("crowdsecurity/http-wordpress-login")
        self.assertEqual(hit["code"], "A07")

    def test_env_access_a01_not_a06(self) -> None:
        hit = correlate.classify("crowdsecurity/vpatch-env-access")
        self.assertEqual(hit["code"], "A01")

    def test_git_config_a01_not_a06(self) -> None:
        hit = correlate.classify("crowdsecurity/vpatch-git-config")
        self.assertEqual(hit["code"], "A01")
        self.assertEqual(hit["attack"], ["T1190"])
        self.assertNotEqual(hit["code"], "A06")

    def test_path_traversal_a01(self) -> None:
        hit = correlate.classify("crowdsecurity/http-path-traversal")
        self.assertEqual(hit["code"], "A01")
        self.assertEqual(hit["attack"], ["T1190"])

    def test_local_file_without_inclusion_is_not_lfi(self) -> None:
        self.assertEqual(correlate.classify("local file storage")["code"], "none")
        self.assertEqual(correlate.classify("local-file-inclusion")["code"], "A01")

    def test_xmlrpc_scan_is_not_brute(self) -> None:
        hit = correlate.classify("crowdsecurity/http-wordpress-xmlrpc")
        self.assertEqual(hit["code"], "A05")
        self.assertEqual(hit["attack"], ["T1595"])

    def test_xmlrpc_bf_is_brute(self) -> None:
        hit = correlate.classify("crowdsecurity/http-xmlrpc-bf")
        self.assertEqual(hit["code"], "A07")
        self.assertEqual(hit["attack"], ["T1110"])

    def test_http_crawl_not_bare_crawl(self) -> None:
        self.assertEqual(correlate.classify("crowdsecurity/http-crawl-non_statics")["code"], "A05")
        self.assertEqual(correlate.classify("screen-crawl-test")["code"], "none")

    def test_ssl_generic_not_weaken_encryption(self) -> None:
        self.assertEqual(correlate.classify("http-generic-ssl")["code"], "none")
        self.assertEqual(correlate.classify("wordpress-ssl-redirect")["code"], "A06")

    def test_oob_log_only_not_impair_defenses(self) -> None:
        hit = correlate.classify("appsec-oob-log-only")
        self.assertEqual(hit["code"], "none")
        self.assertNotIn("T1562", hit["attack"])

    def test_lfi_oob_medium_not_t1083(self) -> None:
        hit = correlate.classify("anomaly score out-of-band: lfi: 5, anomaly: 5")
        self.assertEqual(hit["code"], "A01")
        self.assertEqual(hit["attack"], ["T1595"])
        self.assertEqual(hit["confidence"], "medium")
        self.assertNotIn("T1083", hit["attack"])
        self.assertNotIn("T1190", hit["attack"])

    def test_oob_hub_label_keeps_exploit(self) -> None:
        hit = correlate.classify(
            "anomaly score out-of-band: lfi: 5, anomaly: 5",
            {"labels": ["T1190"]},
        )
        self.assertEqual(hit["code"], "A01")
        self.assertEqual(hit["attack"], ["T1190"])
        self.assertEqual(hit["confidence"], "medium")

    def test_probing_not_t1046(self) -> None:
        hit = correlate.classify("http-probing")
        self.assertEqual(hit["attack"], ["T1595"])
        self.assertNotIn("T1046", hit["attack"])

    def test_body_inspect_is_noise(self) -> None:
        self.assertTrue(correlate.is_noise_event("Enabling body inspection"))
        self.assertEqual(correlate.classify("Enabling body inspection")["code"], "none")

    def test_capi_update_is_noise(self) -> None:
        self.assertTrue(correlate.is_noise_event("update : +15000/-0 IPs"))

    def test_t1046_tactic_is_discovery(self) -> None:
        self.assertEqual(correlate.ATTACK["T1046"]["tactic"], "Discovery")

    def test_hub_mitre_labels_override_attack(self) -> None:
        hit = correlate.classify(
            "crowdsecurity/http-generic-sqli",
            {"labels": ["mitre:T1190", "T1110"]},
        )
        self.assertEqual(hit["code"], "A03")
        self.assertEqual(hit["attack"], ["T1190", "T1110"])


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
        for finding in data["findings"]:
            self.assertIn("cn", finding)
            self.assertIsInstance(finding["cn"], str)
        self.assertIn("mitre", data)
        self.assertTrue(data["mitre"]["techniques"])

    def test_noise_alerts_are_dropped(self) -> None:
        data = correlate.correlate(
            [
                {"scenario": "Enabling body inspection", "source": {"ip": "203.0.113.1"}},
                {"scenario": "update : +15000/-0 IPs", "source": {"ip": ""}},
                {"scenario": "crowdsecurity/http-generic-sqli", "source": {"ip": "203.0.113.10"}},
            ]
        )
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["scenario"], "crowdsecurity/http-generic-sqli")
        self.assertFalse(any("body inspection" in str(item.get("scenario")) for item in data["findings"]))

    def test_unclassified_oob_anomaly_dropped(self) -> None:
        data = correlate.correlate(
            [
                {"scenario": "anomaly score out-of-band: anomaly: 5,"},
                {"scenario": "anomaly score out-of-band: lfi: 5, anomaly: 5,"},
            ]
        )
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["owasp"], "A01")
        self.assertEqual(data["findings"][0]["attack"], ["T1595"])

    def test_unclassified_generic_dropped(self) -> None:
        data = correlate.correlate(
            [{"scenario": "http-generic-ssl", "source": {"ip": "203.0.113.1"}}]
        )
        self.assertEqual(data["findings"], [])

    def test_repeat_alerts_collapse_to_unique_ip(self) -> None:
        alerts = [
            {
                "scenario": "anomaly score out-of-band: lfi: 5, anomaly: 5,",
                "source": {"ip": "203.0.113.10"},
                "created_at": "2026-01-01T00:00:0%dZ" % idx,
            }
            for idx in range(5)
        ]
        alerts.extend(
            [
                {
                    "scenario": "crowdsecurity/vpatch-env-access",
                    "source": {"ip": "203.0.113.10"},
                    "created_at": "2026-01-01T01:00:00Z",
                },
                {
                    "scenario": "crowdsecurity/vpatch-env-access",
                    "source": {"ip": "203.0.113.10"},
                    "created_at": "2026-01-01T01:00:01Z",
                },
                {
                    "scenario": "crowdsecurity/http-generic-sqli",
                    "source": {"ip": "198.51.100.9"},
                    "created_at": "2026-01-01T02:00:00Z",
                },
            ]
        )
        data = correlate.correlate(alerts)
        self.assertEqual(len(data["findings"]), 2)
        a01 = next(item for item in data["findings"] if item["owasp"] == "A01")
        self.assertEqual(a01["events"], 7)
        self.assertEqual(a01["attack"], ["T1190", "T1595"])
        self.assertIn("env-access", a01["scenario"])
        self.assertEqual(a01["confidence"], "high")
        by_code = {item["code"]: item for item in data["owasp"]}
        self.assertEqual(by_code["A01"]["count"], 1)
        self.assertEqual(by_code["A03"]["count"], 1)
        t1190 = next(item for item in data["mitre"]["techniques"] if item["id"] == "T1190")
        t1595 = next(item for item in data["mitre"]["techniques"] if item["id"] == "T1595")
        self.assertEqual(t1190["count"], 2)
        self.assertEqual(t1595["count"], 1)

    def test_findings_cn_and_mitre_mapping(self) -> None:
        data = correlate.correlate(
            [
                {
                    "scenario": "crowdsecurity/http-generic-sqli",
                    "source": {"ip": "203.0.113.10", "cn": "br", "city": "São Paulo"},
                    "created_at": "2026-01-01T00:00:00Z",
                },
                {
                    "scenario": "crowdsecurity/ssh-bf",
                    "source": {"ip": "203.0.113.20"},
                    "created_at": "2026-01-01T00:00:01Z",
                },
            ]
        )
        for finding in data["findings"]:
            self.assertIn("cn", finding)
            self.assertIsInstance(finding["cn"], str)
        self.assertIn("mitre", data)
        self.assertTrue(data["mitre"]["techniques"])
        sqli = next(item for item in data["findings"] if "sqli" in item["scenario"])
        self.assertEqual(sqli["cn"], "BR")
        self.assertIn("T1190", sqli["attack"])
        brute = next(item for item in data["findings"] if "ssh" in item["scenario"])
        self.assertEqual(brute["cn"], "")
        self.assertIn("T1110", brute["attack"])

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
