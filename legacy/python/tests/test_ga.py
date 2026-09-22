from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ga


def _write_snapshot(payload: dict) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(payload, handle)
    handle.close()
    return handle.name


class LoadSnapshotTests(unittest.TestCase):
    def test_load_snapshot_empty(self) -> None:
        with patch.dict(os.environ, {"WAF_GA_SNAPSHOT_FILE": ""}, clear=False):
            snap = ga.load_snapshot()
        self.assertFalse(snap["configured"])
        self.assertEqual(snap["property"], "G-EWYYWP65FN")
        self.assertEqual(snap["hosts"], [])
        self.assertEqual(snap["countries"], [])
        self.assertFalse(ga.public(snap)["contributes"])

    def test_load_from_temp_file_countries_hosts(self) -> None:
        path = _write_snapshot(
            {
                "property": "G-EWYYWP65FN",
                "window_days": 7,
                "hosts": [
                    {"host": "hexaco.neurofocus.com.br", "sessions": 420},
                    {"host": "personalidade.neurofocus.com.br", "sessions": 310},
                ],
                "countries": [
                    {"cn": "BR", "sessions": 980},
                    {"cn": "US", "sessions": 240},
                    {"cn": "GB", "sessions": 18},
                    {"cn": "FR", "sessions": 42},
                ],
                "api_secret": "must-never-leak",
                "measurement_protocol_secret": "nope",
            }
        )
        try:
            snap = ga.load_snapshot(path)
            self.assertTrue(snap["configured"])
            self.assertEqual(snap["property"], "G-EWYYWP65FN")
            self.assertEqual(snap["window_days"], 7)
            hosts = {item["host"]: item["sessions"] for item in snap["hosts"]}
            self.assertEqual(hosts["hexaco.neurofocus.com.br"], 420)
            self.assertEqual(hosts["personalidade.neurofocus.com.br"], 310)
            countries = {item["cn"]: item["sessions"] for item in snap["countries"]}
            self.assertEqual(countries["BR"], 980)
            self.assertEqual(countries["GB"], 18)
            blob = json.dumps(snap)
            self.assertNotIn("must-never-leak", blob)
            self.assertNotIn("api_secret", blob)
            self.assertNotIn("measurement_protocol", blob)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_snapshot_host_waf_ignored(self) -> None:
        path = _write_snapshot(
            {
                "property": "G-EWYYWP65FN",
                "hosts": [
                    {"host": "/waf", "sessions": 99},
                    {"host": "/waf/", "sessions": 12},
                    {"host": "hexaco.neurofocus.com.br", "sessions": 10},
                ],
                "countries": [{"cn": "BR", "sessions": 4}],
            }
        )
        try:
            snap = ga.load_snapshot(path)
            hosts = [item["host"] for item in snap["hosts"]]
            self.assertNotIn("/waf", hosts)
            self.assertNotIn("/waf/", hosts)
            self.assertEqual(hosts, ["hexaco.neurofocus.com.br"])
        finally:
            Path(path).unlink(missing_ok=True)


class DensityVerdictTests(unittest.TestCase):
    def test_density_and_verdict(self) -> None:
        self.assertEqual(ga.density(10, 5), 2.0)
        self.assertEqual(ga.density(10, 0), 10.0)
        self.assertEqual(ga.density(0, 0), 0.0)
        self.assertEqual(ga.verdict(12, 0), "scanner-heavy")
        self.assertEqual(ga.verdict(12, 100), "user-impact-risk")
        self.assertEqual(ga.verdict(0, 80), "clean-traffic")
        self.assertEqual(ga.verdict(2, 8), "mixed")


class AttachMapTests(unittest.TestCase):
    def test_attach_map_adds_ga_sessions(self) -> None:
        path = _write_snapshot(
            {
                "property": "G-EWYYWP65FN",
                "window_days": 7,
                "hosts": [{"host": "periciacomputacional.com", "sessions": 860}],
                "countries": [
                    {"cn": "BR", "sessions": 980},
                    {"cn": "GB", "sessions": 0},
                ],
            }
        )
        try:
            with patch.dict(os.environ, {"WAF_GA_SNAPSHOT_FILE": path}, clear=False):
                payload = ga.attach_map(
                    {
                        "points": [],
                        "countries": [
                            {"cn": "BR", "count": 4, "lat": -14.2, "lon": -51.9},
                            {"cn": "GB", "count": 40, "lat": 55.4, "lon": -3.4},
                        ],
                        "geo_source": "crowdsec-lapi",
                    }
                )
            by_cn = {item["cn"]: item for item in payload["countries"]}
            self.assertEqual(by_cn["BR"]["ga_sessions"], 980)
            self.assertEqual(by_cn["GB"]["ga_sessions"], 0)
            self.assertEqual(by_cn["GB"]["ga_verdict"], "scanner-heavy")
            self.assertEqual(by_cn["BR"]["ga_verdict"], "mixed")
            self.assertEqual(payload["geo_source"], "crowdsec-lapi")
            self.assertTrue(payload["ga"]["configured"])
            self.assertEqual(payload["ga"]["property"], "G-EWYYWP65FN")
            blob = json.dumps(payload)
            self.assertNotIn("token", blob.lower())
        finally:
            Path(path).unlink(missing_ok=True)


class ContributesTests(unittest.TestCase):
    def test_contributes_false_when_empty(self) -> None:
        with patch.dict(os.environ, {"WAF_GA_SNAPSHOT_FILE": ""}, clear=False):
            snap = ga.load_snapshot()
        self.assertFalse(ga.public(snap)["contributes"])
        self.assertFalse(ga.public(snap)["configured"])

    def test_contributes_true_when_example_snapshot_loaded(self) -> None:
        example = Path(__file__).resolve().parents[1] / "examples" / "ga-snapshot.example.json"
        snap = ga.load_snapshot(str(example))
        self.assertTrue(snap["configured"])
        self.assertTrue(ga.public(snap)["contributes"])


if __name__ == "__main__":
    unittest.main()
