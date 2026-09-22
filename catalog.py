#!/usr/bin/env python3
"""Site catalog: JSON file or WAF_SITES_JSON. No production hosts in source."""
from __future__ import annotations

import json
import os
from pathlib import Path

import netguard

CONTROL_DIR = Path(os.environ.get("WAF_CONTROL", "/var/lib/waf-control"))


def _parse(raw: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _clean_host(value: str) -> str | None:
    try:
        return netguard.sanitize_hostname(str(value))
    except ValueError:
        return None


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
    sites_raw = data.get("sites") if isinstance(data.get("sites"), dict) else {}
    oos_raw = data.get("out_of_scope") if isinstance(data.get("out_of_scope"), dict) else {}
    sites = {}
    for host, meta in sites_raw.items():
        clean = _clean_host(host)
        if clean and isinstance(meta, dict):
            sites[clean] = meta
    oos = {}
    for host, why in oos_raw.items():
        clean = _clean_host(host)
        if clean:
            oos[clean] = why
    hosts = data.get("hosts")
    if not isinstance(hosts, list):
        hosts = [h for h, meta in sites.items() if meta.get("in_scope", True)]
    cleaned_hosts = []
    for h in hosts:
        clean = _clean_host(h)
        if clean:
            cleaned_hosts.append(clean)
    return {"sites": sites, "out_of_scope": oos, "hosts": cleaned_hosts}


def in_scope_hosts() -> list[str]:
    env = os.environ.get("WAF_HOSTS", "").strip()
    if env:
        out = []
        for h in env.split(","):
            clean = _clean_host(h)
            if clean:
                out.append(clean)
        return out
    return load_catalog()["hosts"]
