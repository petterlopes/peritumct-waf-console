from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class RoutesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dyn = Path(self.tmp.name) / "dynamic"
        self.dyn.mkdir()
        self.env = patch.dict(
            os.environ,
            {
                "WAF_CONTROL": self.tmp.name,
                "WAF_TRAEFIK_DYNAMIC_DIR": str(self.dyn),
                "WAF_ROUTE_DENY_HOSTS": "bird.expertsforensic.com,birdsso.expertsforensic.com,farmlinkstage",
            },
            clear=False,
        )
        self.env.start()
        import importlib
        import routes

        importlib.reload(routes)
        self.routes = routes

    def tearDown(self) -> None:
        self.env.stop()
        self.tmp.cleanup()

    def test_create_http_route_does_not_write_traefik_dir(self) -> None:
        out = self.routes.upsert_route(
            {
                "name": "lab-web",
                "host": "lab.example.com",
                "path_prefix": "/app",
                "service_url": "http://127.0.0.1:3000",
                "chain": "domain-security-chain",
            }
        )
        self.assertTrue(out["ok"])
        self.assertFalse(out["applied"])
        self.assertFalse((self.dyn / "waf-admin-routes.yaml").is_file())
        yaml_text = (Path(self.tmp.name) / "waf-admin-routes.yaml").read_text(encoding="utf-8")
        self.assertIn("Host(`lab.example.com`)", yaml_text)
        self.assertNotIn("crowdsec-bouncer", yaml_text)

    def test_waf_path_cannot_use_bouncer_chain(self) -> None:
        with self.assertRaises(ValueError):
            self.routes.upsert_route(
                {
                    "name": "waf-lab",
                    "host": "ops.example.com",
                    "path_prefix": "/waf",
                    "service_url": "http://127.0.0.1:18990",
                    "chain": "domain-security-chain",
                }
            )

    def test_reserved_and_deny(self) -> None:
        with self.assertRaises(ValueError):
            self.routes.upsert_route(
                {
                    "name": "waf-admin",
                    "host": "expertsforensic.com",
                    "service_url": "http://127.0.0.1:18990",
                    "chain": "expertsforensic-admin-only",
                }
            )
        with self.assertRaises(ValueError):
            self.routes.upsert_route(
                {
                    "name": "bird-public",
                    "host": "bird.expertsforensic.com",
                    "service_url": "http://127.0.0.1:33080",
                    "chain": "none",
                }
            )

    def test_reject_lapi_backend(self) -> None:
        with self.assertRaises(ValueError):
            self.routes.upsert_route(
                {
                    "name": "lapi-leak",
                    "host": "lab.example.com",
                    "service_url": "http://127.0.0.1:18080",
                    "chain": "none",
                }
            )

    def test_local_tunnel_command(self) -> None:
        out = self.routes.upsert_tunnel(
            {
                "name": "waf-local",
                "kind": "local",
                "local_port": 18990,
                "remote": "127.0.0.1:18990",
                "node": "root@localhost",
            }
        )
        self.assertEqual(out["item"]["command"], "tsh ssh -N -L 18990:127.0.0.1:18990 root@localhost")
        self.assertFalse((self.dyn / "waf-admin-routes.yaml").is_file())
        local_yaml = (Path(self.tmp.name) / "waf-admin-routes.yaml").read_text(encoding="utf-8")
        self.assertNotIn("tcp:", local_yaml)

    def test_tcp_tunnel_and_farmlink_blocked(self) -> None:
        out = self.routes.upsert_tunnel(
            {
                "name": "lab-tcp",
                "kind": "tcp",
                "sni": "lab-tcp.example.com",
                "target": "127.0.0.1:9443",
                "passthrough": True,
            }
        )
        self.assertFalse(out["applied"])
        self.assertFalse((self.dyn / "waf-admin-routes.yaml").is_file())
        yaml_text = (Path(self.tmp.name) / "waf-admin-routes.yaml").read_text(encoding="utf-8")
        self.assertIn("HostSNI(`lab-tcp.example.com`)", yaml_text)
        self.assertIn("passthrough: true", yaml_text)
        with self.assertRaises(ValueError):
            self.routes.upsert_tunnel(
                {
                    "name": "farm",
                    "kind": "local",
                    "local_port": 2222,
                    "remote": "127.0.0.1:22",
                    "node": "root@farmlinkstage",
                }
            )

    def test_empty_store_yaml_has_no_http_tcp_maps(self) -> None:
        text = self.routes.render_yaml({"routes": [], "tunnels": []})
        self.assertNotIn("\nhttp:", "\n" + text)
        self.assertNotIn("\ntcp:", "\n" + text)
        self.assertNotIn("routers: {}", text)
        self.assertNotIn("services: {}", text)

    def test_populated_yaml_still_has_no_empty_maps(self) -> None:
        text = self.routes.render_yaml(
            {
                "routes": [
                    {
                        "name": "lab-web",
                        "kind": "http",
                        "enabled": True,
                        "host": "lab.example.com",
                        "path_prefix": "/app",
                        "service_url": "http://127.0.0.1:3000",
                        "chain": "domain-security-chain",
                        "priority": 90,
                        "tls": True,
                    }
                ],
                "tunnels": [],
            }
        )
        self.assertIn("http:", text)
        self.assertIn("Host(`lab.example.com`)", text)
        self.assertNotIn("routers: {}", text)
        self.assertNotIn("services: {}", text)
        self.assertNotIn("\ntcp:", "\n" + text)

    def test_admin_payload_lists_actions(self) -> None:
        data = self.routes.admin_payload()
        views = [a["view"] for a in data["actions"]]
        self.assertNotIn("routes", views)
        self.assertNotIn("tunnels", views)
        self.assertIn("sites", views)
        self.assertIn("18990", data["local_tunnel"]["command"])
        self.assertTrue(data["policy"]["no_traefik_mutate"])


if __name__ == "__main__":
    unittest.main()
