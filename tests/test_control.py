from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class CatalogTests(unittest.TestCase):
    def test_empty_without_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "WAF_CONTROL": tmp,
                "WAF_SITES_FILE": str(Path(tmp) / "missing.json"),
            }
            with patch.dict(os.environ, env, clear=False):
                import importlib
                import catalog

                importlib.reload(catalog)
                data = catalog.load_catalog()
                self.assertEqual(data["sites"], {})
                self.assertEqual(data["hosts"], [])

    def test_file_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sites.json"
            path.write_text(
                json.dumps(
                    {
                        "sites": {
                            "www.example.com": {
                                "kind": "web",
                                "chain": "security-chain",
                                "bouncer": True,
                                "appsec": True,
                                "in_scope": True,
                            }
                        },
                        "out_of_scope": {"grpc.example.com": "gRPC"},
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"WAF_SITES_FILE": str(path), "WAF_CONTROL": tmp}, clear=False):
                import importlib
                import catalog

                importlib.reload(catalog)
                data = catalog.load_catalog()
                self.assertIn("www.example.com", data["sites"])
                self.assertEqual(data["out_of_scope"]["grpc.example.com"], "gRPC")
                self.assertEqual(data["hosts"], ["www.example.com"])


class ControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        sites = Path(self.tmp.name) / "sites.json"
        sites.write_text(
            json.dumps(
                {
                    "sites": {
                        "www.example.com": {
                            "kind": "web",
                            "chain": "security-chain",
                            "bouncer": True,
                            "appsec": True,
                            "in_scope": True,
                        }
                    },
                    "out_of_scope": {"grpc.example.com": "gRPC — keep AppSec off"},
                }
            ),
            encoding="utf-8",
        )
        self.env = patch.dict(
            os.environ,
            {
                "WAF_CONTROL": self.tmp.name,
                "WAF_SITES_FILE": str(sites),
                "CROWDSEC_CONFIG": self.tmp.name,
            },
            clear=False,
        )
        self.env.start()
        import importlib
        import catalog
        import control

        importlib.reload(catalog)
        importlib.reload(control)
        self.control = control

    def tearDown(self) -> None:
        self.env.stop()
        self.tmp.cleanup()

    def test_validate_path(self) -> None:
        self.assertEqual(self.control.validate_path("/ads.txt"), "/ads.txt")
        with self.assertRaises(ValueError):
            self.control.validate_path("/")
        with self.assertRaises(ValueError):
            self.control.validate_path("../etc")

    def test_out_of_scope(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.control.validate_host("grpc.example.com")
        self.assertIn("out of WAF scope", str(ctx.exception))

    def test_unknown_host(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.control.validate_host("evil.example.net")
        self.assertIn("not in catalog", str(ctx.exception))

    def test_duration(self) -> None:
        self.assertEqual(self.control.validate_duration("4h"), "4h")
        with self.assertRaises(ValueError):
            self.control.validate_duration("200h")

    def test_forbidden(self) -> None:
        with self.assertRaises(ValueError):
            self.control.validate_path("/crs-inband")

    def test_compose_allow(self) -> None:
        item = self.control.compose_policy(
            {
                "name": "ads-txt",
                "host": "www.example.com",
                "action": "allow_match",
                "path_prefix": "/ads.txt",
                "reason": "publisher",
            }
        )
        self.assertEqual(item["path_prefix"], "/ads.txt")
        yaml_text = self.control.render_yaml([item])
        self.assertIn("SetRemediation", yaml_text)
        self.assertNotIn("crs-inband", yaml_text)


if __name__ == "__main__":
    unittest.main()
