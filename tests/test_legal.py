#!/usr/bin/env python3
"""Legal pages, author links, and locale keys must stay in the OSS console."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
KEYS = [
    "nav.credits",
    "nav.privacy",
    "nav.terms",
    "credits.author",
    "privacy.controller",
    "terms.accept",
]


class LegalPagesTest(unittest.TestCase):
    def test_html_views_and_author_links(self):
        for token in (
            'data-view="credits"',
            'data-view="privacy"',
            'data-view="terms"',
            "https://periciacomputacional.com/sobre/",
            "https://www.linkedin.com/in/petter-anderson-lopes/",
            "https://www.instagram.com/peritopetterlopes/",
            "@peritopetterlopes",
        ):
            self.assertIn(token, HTML, token)

    def test_locale_keys(self):
        for name in ("en.json", "pt-BR.json"):
            data = json.loads((ROOT / "static" / "locales" / name).read_text(encoding="utf-8"))
            for key in KEYS:
                self.assertTrue(data.get(key), f"{name} missing {key}")


if __name__ == "__main__":
    unittest.main()
