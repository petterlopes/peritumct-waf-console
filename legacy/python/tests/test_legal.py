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
    "nav.admin",
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
            'data-view="admin"',
            "https://periciacomputacional.com/sobre/",
            "https://www.linkedin.com/in/petter-anderson-lopes/",
            "https://www.instagram.com/peritopetterlopes/",
            "/waf/logo.png",
            'class="brand-logo"',
            'src="/waf/logo.png"',
            'class="legal-bar"',
            'class="legal-link"',
        ):
            self.assertIn(token, HTML, token)
        png = ROOT / "static" / "logo.png"
        self.assertTrue(png.is_file())
        self.assertGreater(png.stat().st_size, 2000)
        self.assertNotIn('id="peritum-shield"', HTML)

    def test_i18n_keeps_visible_label_if_key_missing(self):
        src = (ROOT / "static" / "i18n.js").read_text(encoding="utf-8")
        self.assertIn("t(key, el.textContent || key)", src)

    def test_locale_keys(self):
        for name in ("en.json", "pt-BR.json"):
            data = json.loads((ROOT / "static" / "locales" / name).read_text(encoding="utf-8"))
            for key in KEYS:
                self.assertTrue(data.get(key), f"{name} missing {key}")

    def test_pt_br_not_european_portuguese(self):
        """pt-BR copy must stay Brazilian; block common European-Portuguese tokens."""
        forbidden = (
            "consola",
            "actualizar",
            "ficheiro",
            "utilizador",
            "contacto",
            "excepto",
            "acção",
            "acções",
            "projecto",
            "directo",
            "correcção",
            "por omissão",
            "activar",
            "activas",
            "activo",
            "inactivo",
            "controlos",
            "sítio",
            "sítios",
            "a ligar",
            "selector",
            "monitorizar",
            "inatingível",
            "sistemas operativos",
            "táctica",
            "tácticas",
            "selecção",
            "seleccionado",
            "projecção",
            "separadores",
            "separador",
            "clique num",
            "canónica",
            "contentor",
            "registados",
            "inspeccionados",
            "âmbito",
            "guardar política",
            "actividade",
        )
        paths = [
            ROOT / "static" / "locales" / "pt-BR.json",
            ROOT / "README.pt-BR.md",
            ROOT / "docs" / "CREDITS.pt-BR.md",
            ROOT / "docs" / "PRIVACY.pt-BR.md",
            ROOT / "docs" / "TERMS.pt-BR.md",
            ROOT / "docs" / "INTEGRATION.pt-BR.md",
        ]
        blob = "\n".join(p.read_text(encoding="utf-8") for p in paths).lower()
        for token in forbidden:
            self.assertNotIn(token, blob, f"European Portuguese token in pt-BR copy: {token}")


if __name__ == "__main__":
    unittest.main()
