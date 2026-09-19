from __future__ import annotations

import unittest
from datetime import datetime, timezone

import dashboard


class DashboardTests(unittest.TestCase):
    def test_http_of_target_fqdn(self) -> None:
        alert = {
            "scenario": "crowdsecurity/crowdsec-appsec-outofband",
            "events": [
                {
                    "meta": [
                        {"key": "target_fqdn", "value": "personalidade.neurofocus.com.br"},
                        {"key": "target_uri", "value": "/.env"},
                        {"key": "rule_name", "value": "native_rule:901340"},
                    ]
                }
            ],
        }
        http = dashboard.http_of(alert)
        self.assertEqual(http["host"], "personalidade.neurofocus.com.br")
        self.assertEqual(http["path"], "/.env")
        self.assertEqual(dashboard.action_of(alert), "Log")

    def test_unwraps_json_list_meta_and_ja4h_http_version(self) -> None:
        alert = {
            "meta": [
                {"key": "method", "value": '["GET"]'},
                {"key": "user_agent", "value": '["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"]'},
                {"key": "ja4h", "value": '["ge11nn150000_3927a0e69"]'},
            ],
            "source": {"ip": "203.0.113.10", "cn": "NL", "as_name": "Example ASN"},
            "events": [{"meta": [{"key": "target_fqdn", "value": "periciacomputacional.com"}]}],
        }
        http = dashboard.http_of(alert)
        self.assertEqual(http["method"], "GET")
        self.assertEqual(http["http_version"], "HTTP/1.1")
        self.assertIn("Chrome", dashboard.classify_ua(http["ua"])[0])
        self.assertEqual(http["ja4h"].split("_", 1)[0], "ge11nn150000")

    def test_build_filters_host_and_honest_missing_dims(self) -> None:
        now = datetime(2026, 9, 17, 22, 0, tzinfo=timezone.utc)
        alerts = [
            {
                "created_at": "2026-09-17T21:10:00Z",
                "scenario": "crowdsecurity/vpatch-env-access",
                "source": {"ip": "203.0.113.10", "cn": "ID"},
                "events": [
                    {
                        "meta": [
                            {"key": "target_fqdn", "value": "periciacomputacional.com"},
                            {"key": "target_uri", "value": "/.env"},
                        ]
                    }
                ],
            },
            {
                "created_at": "2026-09-17T21:11:00Z",
                "scenario": "crowdsecurity/http-generic-sqli",
                "source": {"ip": "198.51.100.8", "cn": "US"},
                "decisions": [{"type": "ban"}],
                "events": [
                    {
                        "meta": [
                            {"key": "target_fqdn", "value": "hexaco.neurofocus.com.br"},
                            {"key": "uri", "value": "/wp-login.php"},
                        ]
                    }
                ],
            },
        ]
        data = dashboard.build(
            alerts,
            engine={"appsec_listen": True, "oob_log_only": True, "fail_closed": True},
            hosts=["periciacomputacional.com", "hexaco.neurofocus.com.br"],
            host="periciacomputacional.com",
            origin_probes=[{"host": "periciacomputacional.com", "status": 200}],
            now=now,
        )
        self.assertEqual(data["source"], "crowdsec-lapi")
        self.assertEqual(data["kpis"]["events"], 1)
        self.assertEqual(data["logs"][0]["host"], "periciacomputacional.com")
        self.assertEqual(data["logs"][0]["path"], "/.env")
        self.assertFalse(data["top"]["browsers"]["available"])
        self.assertFalse(data["top"]["cache"]["available"])
        self.assertFalse(data["top"]["status"]["available"])
        self.assertFalse(data["bot_challenge"])
        self.assertFalse(data["crs_inband"])
        tools = {t["id"]: t for t in data["detection_tools"]}
        self.assertFalse(tools["bot"]["running"])
        self.assertEqual(tools["exploits"]["count"], 0)
        env = next(item for item in data["action_items"] if item["id"] == "env-probe")
        self.assertIn("1 source", env["title"])
        self.assertNotIn("in window", env["title"])
        self.assertIn("Active scanning", env["tags"])
        scanners = data.get("scanners") or {}
        self.assertEqual(scanners.get("events_total"), 1)
        self.assertEqual(scanners.get("sources"), 1)
        self.assertEqual(len(scanners.get("hours") or []), 24)
        self.assertEqual((scanners.get("stats") or {}).get("hours_active"), 1)
        self.assertEqual((scanners.get("stats") or {}).get("peak_events"), 1)
        self.assertTrue(data["logs"][0].get("scanner"))
        self.assertNotIn("tools", scanners)
        self.assertNotIn("named_events", scanners)


class ScannerDetectTests(unittest.TestCase):
    def test_chrome_ordinary_path_is_not_scanner(self) -> None:
        self.assertFalse(
            dashboard.is_scanner_event(
                "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0.0.0 Safari/537.36",
                "http-generic-ssl",
                "/",
            )
        )

    def test_chrome_env_probe_is_scanner_without_naming_tool(self) -> None:
        self.assertTrue(
            dashboard.is_scanner_event(
                "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0.0.0 Safari/537.36",
                "crowdsecurity/vpatch-env-access",
                "/.env",
            )
        )

    def test_named_ua_counts_as_scanner_anonymously(self) -> None:
        self.assertTrue(
            dashboard.is_scanner_event(
                "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
                "",
                "/",
            )
        )
        self.assertTrue(dashboard.is_scanner_event("ZAP/2.14.0", "", "/"))
        self.assertTrue(dashboard.is_scanner_event("hping3 packet", "", "/"))

    def test_lookalike_uas_are_not_scanners(self) -> None:
        self.assertFalse(dashboard.is_scanner_event("Zapier-Client/1.0", "", "/"))
        self.assertFalse(dashboard.is_scanner_event("NucleicClient/1.0", "", "/"))
        self.assertFalse(dashboard.is_scanner_event("Mozilla/5.0", "", "/"))

    def test_scanner_hourly_stats_without_tool_names(self) -> None:
        now = datetime(2026, 9, 17, 22, 0, tzinfo=timezone.utc)

        def alert(ts: str, ip: str) -> dict:
            return {
                "created_at": ts,
                "scenario": "crowdsecurity/vpatch-env-access",
                "source": {"ip": ip, "cn": "NL"},
                "events": [
                    {
                        "meta": [
                            {"key": "target_fqdn", "value": "periciacomputacional.com"},
                            {"key": "target_uri", "value": "/.env"},
                        ]
                    }
                ],
            }

        data = dashboard.build(
            [
                alert("2026-09-17T21:10:00Z", "203.0.113.10"),
                alert("2026-09-17T21:40:00Z", "203.0.113.11"),
                alert("2026-09-17T12:00:00Z", "198.51.100.8"),
            ],
            hosts=["periciacomputacional.com"],
            now=now,
        )
        pack = data["scanners"]
        self.assertNotIn("tools", pack)
        self.assertNotIn("named_events", pack)
        self.assertEqual(pack["events_total"], 3)
        self.assertEqual(pack["sources"], 3)
        self.assertEqual(len(pack["hours"]), 24)
        self.assertEqual(pack["stats"]["hours_active"], 2)
        self.assertEqual(pack["stats"]["peak_events"], 2)
        self.assertEqual(pack["stats"]["last_hour_events"], 2)
        self.assertEqual(pack["last_hour"]["sources"], 2)
        self.assertEqual(pack["stats"]["mean_events"], round(3 / 24, 2))
        self.assertEqual(pack["hours"][pack["stats"]["peak_idx"]]["label"], pack["stats"]["peak_label"])
        self.assertTrue(str(pack["stats"]["peak_label"]).endswith(":00"))
        self.assertEqual(len(pack["blocked_hourly"]), 24)
        self.assertEqual(len(pack["logged_hourly"]), 24)
        self.assertEqual(sum(pack["events"]), 3)
        blob = str(pack).lower()
        self.assertNotIn("nmap", blob)
        self.assertNotIn("acunetix", blob)
        self.assertNotIn("zaproxy", blob)

    def test_ip_filter_and_ja4h_tiles(self) -> None:
        now = datetime(2026, 9, 17, 22, 0, tzinfo=timezone.utc)
        alerts = [
            {
                "created_at": "2026-09-17T21:10:00Z",
                "scenario": "crowdsecurity/vpatch-env-access",
                "source": {"ip": "203.0.113.10", "cn": "ID", "as_name": "Example ASN"},
                "meta": [
                    {"key": "method", "value": '["GET"]'},
                    {"key": "ja4h", "value": '["ge11nn150000_abc"]'},
                    {"key": "user_agent", "value": '["Mozilla/5.0 (Windows NT 10.0) Chrome/120"]'},
                ],
                "events": [
                    {"meta": [{"key": "target_fqdn", "value": "periciacomputacional.com"}, {"key": "target_uri", "value": "/.env"}]}
                ],
            },
            {
                "created_at": "2026-09-17T21:11:00Z",
                "scenario": "crowdsecurity/vpatch-env-access",
                "source": {"ip": "198.51.100.8", "cn": "US"},
                "events": [
                    {"meta": [{"key": "target_fqdn", "value": "periciacomputacional.com"}, {"key": "uri", "value": "/"}]}
                ],
            },
        ]
        data = dashboard.build(
            alerts,
            hosts=["periciacomputacional.com"],
            host="periciacomputacional.com",
            filters={"ip": "203.0.113.10"},
            appsec={"cs_appsec_reqs_total": 10194, "cs_appsec_block_total": 4},
            edge={"label": "Nuremberg"},
            now=now,
        )
        self.assertEqual(data["kpis"]["events"], 1)
        self.assertEqual(data["logs"][0]["method"], "GET")
        self.assertTrue(data["top"]["methods"]["available"])
        self.assertEqual(data["top"]["http_versions"]["items"][0]["label"], "HTTP/1.1")
        self.assertTrue(data["top"]["user_agents"]["available"])
        self.assertTrue(data["top"]["asns"]["available"])
        self.assertFalse(data["top"]["cache"]["available"])
        self.assertTrue(data["top"]["datacenters"]["available"])
        self.assertEqual(data["appsec"]["inspected"], 10194)
        self.assertTrue(data["appsec"]["lifetime"])
        self.assertFalse(data["bot_challenge"])

    def test_unknown_host_filter_ignored(self) -> None:
        data = dashboard.build(
            [],
            hosts=["www.example.com"],
            host="evil.example.net",
        )
        self.assertEqual(data["host"], "")
