#!/usr/bin/env python3
"""Atomic persist helpers."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import persist


class PersistTests(unittest.TestCase):
    def test_atomic_write_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "store.json"
            persist.atomic_write_text(path, json.dumps({"ok": True}) + "\n")
            self.assertTrue(path.is_file())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["ok"], True)
            with mock.patch.object(persist, "CONTROL_DIR", Path(tmp)):
                with mock.patch.object(persist, "AUDIT_LOG", Path(tmp) / "audit.jsonl"):
                    persist.audit("test.event", {"n": 1})
                    lines = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
                    self.assertEqual(len(lines), 1)
                    self.assertEqual(json.loads(lines[0])["event"], "test.event")


if __name__ == "__main__":
    unittest.main()
