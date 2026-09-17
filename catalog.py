#!/usr/bin/env python3
"""Site catalog: JSON file or WAF_SITES_JSON. No production hosts in source."""
from __future__ import annotations

import json
import os
from pathlib import Path

CONTROL_DIR = Path(os.environ.get("WAF_CONTROL", "/var/lib/waf-control"))


def _parse(raw: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def load_catalog() -> dict:
    env = os.environ.get("WAF_SITES_JSON", "").strip()
    if env:
        data = _parse(env)
    else:
        path = Path(os.environ.get("WAF_SITES_FILE", str(CONTROL_DIR / "sites.json")))
        if path.is_file():
            data = _parse(path.read_text(encoding="utf-8", errors="replace"))
        else:
            data = {}
    sites = data.get("sites") if isinstance(data.get("sites"), dict) else {}
    oos = data.get("out_of_scope") if isinstance(data.get("out_of_scope"), dict) else {}
    hosts = data.get("hosts")
    if not isinstance(hosts, list):
        hosts = [h for h, meta in sites.items() if isinstance(meta, dict) and meta.get("in_scope", True)]
    hosts = [str(h).strip().lower() for h in hosts if str(h).strip()]
    return {"sites": sites, "out_of_scope": oos, "hosts": hosts}


def in_scope_hosts() -> list[str]:
    env = os.environ.get("WAF_HOSTS", "").strip()
    if env:
        return [h.strip().lower() for h in env.split(",") if h.strip()]
    return load_catalog()["hosts"]
