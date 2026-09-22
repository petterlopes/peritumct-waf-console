#!/usr/bin/env python3
"""CSO-safe GA4 snapshot for WAF finding precision.

Reads an operator-exported aggregate JSON (hostname + country sessions).
Never calls the Google Data API. Never Measurement Protocol. Never includes
tokens. Does not replace LAPI coordinates (geo_source stays crowdsec-lapi).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

DEFAULT_PROPERTY = "G-EWYYWP65FN"
SNAPSHOT_ENV = "WAF_GA_SNAPSHOT_FILE"
_SECRET_KEY_RE = re.compile(
    r"(token|key|password|secret|authorization|credential|api.?secret|measurement.?protocol)",
    re.I,
)
_PROPERTY_RE = re.compile(r"^G-[A-Z0-9]+$")
_HIGH_LAPI = 5
_HIGH_GA = 20


def _as_int(value: Any, default: int = 0) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number >= 0 else default


def density(lapi_count: Any, ga_sessions: Any) -> float:
    """Threat density: lapi_count / ga_sessions (LAPI-only when sessions are 0)."""
    lapi = _as_int(lapi_count)
    sessions = _as_int(ga_sessions)
    if sessions <= 0:
        return float(lapi)
    return round(lapi / float(sessions), 4)


def verdict(lapi_count: Any, ga_sessions: Any) -> str:
    """Classify LAPI vs real-user volume.

    scanner-heavy: LAPI activity with zero GA sessions (scanner origin).
    user-impact-risk: high LAPI and high GA (real users in the same country).
    clean-traffic: no LAPI findings.
    mixed: some LAPI and some GA without both being high.
    """
    lapi = _as_int(lapi_count)
    sessions = _as_int(ga_sessions)
    if lapi <= 0:
        return "clean-traffic"
    if sessions <= 0:
        return "scanner-heavy"
    if lapi >= _HIGH_LAPI and sessions >= _HIGH_GA:
        return "user-impact-risk"
    return "mixed"


def _empty_snapshot() -> dict[str, Any]:
    return {
        "configured": False,
        "property": DEFAULT_PROPERTY,
        "window_days": 0,
        "hosts": [],
        "countries": [],
        "note": (
            "Drop an aggregate GA4 snapshot at WAF_GA_SNAPSHOT_FILE. "
            "No Data API. No gtag on /waf."
        ),
    }


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _SECRET_KEY_RE.search(str(key)):
                continue
            out[key] = _scrub(item)
        return out
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


def _skip_host(host: str) -> bool:
    return str(host or "").strip().lower().startswith("/waf")


def _normalize_hosts(raw: Any) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw or []:
        if isinstance(item, str):
            host = item.strip()
            sessions = 0
        elif isinstance(item, dict):
            host = str(item.get("host") or item.get("hostname") or "").strip()
            sessions = _as_int(item.get("sessions"))
        else:
            continue
        key = host.lower()
        if not host or _skip_host(host) or key in seen:
            continue
        seen.add(key)
        hosts.append({"host": host, "sessions": sessions})
    return hosts


def _normalize_countries(raw: Any) -> list[dict[str, Any]]:
    countries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        cn = str(item.get("cn") or item.get("country") or "").strip().upper()
        if not cn or cn in seen or not re.fullmatch(r"[A-Z]{2}", cn):
            continue
        seen.add(cn)
        countries.append({"cn": cn, "sessions": _as_int(item.get("sessions"))})
    return countries


def load_snapshot(path: str | None = None) -> dict[str, Any]:
    """Load WAF_GA_SNAPSHOT_FILE JSON. Unset/missing => configured false."""
    raw_path = (path if path is not None else os.environ.get(SNAPSHOT_ENV) or "").strip()
    if not raw_path:
        return _empty_snapshot()
    file = Path(raw_path)
    if not file.is_file():
        return _empty_snapshot()
    try:
        data = json.loads(file.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return _empty_snapshot()
    if not isinstance(data, dict):
        return _empty_snapshot()
    data = _scrub(data)
    property_id = str(data.get("property") or DEFAULT_PROPERTY).strip() or DEFAULT_PROPERTY
    if not _PROPERTY_RE.match(property_id):
        property_id = DEFAULT_PROPERTY
    window_days = _as_int(data.get("window_days"), 7) or 7
    return {
        "configured": True,
        "property": property_id,
        "window_days": window_days,
        "hosts": _normalize_hosts(data.get("hosts")),
        "countries": _normalize_countries(data.get("countries")),
        "note": (
            "Aggregate GA4 sessions (hostname + country). No client_id. "
            "LAPI geo unchanged."
        ),
    }


def _country_sessions(snap: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in snap.get("countries") or []:
        cn = str(item.get("cn") or "").upper()
        if cn:
            out[cn] = _as_int(item.get("sessions"))
    return out


def _has_sessions(snap: dict[str, Any]) -> bool:
    for item in list(snap.get("hosts") or []) + list(snap.get("countries") or []):
        if isinstance(item, dict) and _as_int(item.get("sessions")) > 0:
            return True
    return False


def public(snap: dict[str, Any] | None = None) -> dict[str, Any]:
    """Operator-facing GA label. contributes only when a snapshot has sessions > 0."""
    snap = snap if isinstance(snap, dict) else load_snapshot()
    configured = bool(snap.get("configured"))
    return {
        "configured": configured,
        "contributes": bool(configured and _has_sessions(snap)),
        "property": snap.get("property") or DEFAULT_PROPERTY,
        "window_days": snap.get("window_days") or 0,
        "hosts": list(snap.get("hosts") or []),
        "note": snap.get("note") or "",
    }


def attach_map(payload: dict | None) -> dict:
    """Annotate map countries with GA sessions. geo_source stays crowdsec-lapi."""
    payload = dict(payload or {})
    snap = load_snapshot()
    by_cn = _country_sessions(snap)
    countries = []
    for row in payload.get("countries") or []:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        if snap.get("configured"):
            cn = str(item.get("cn") or "").upper()
            sessions = by_cn.get(cn, 0)
            item["ga_sessions"] = sessions
            item["ga_density"] = density(item.get("count"), sessions)
            item["ga_verdict"] = verdict(item.get("count"), sessions)
        countries.append(item)
    payload["countries"] = countries
    payload["ga"] = public(snap)
    if not payload.get("geo_source"):
        payload["geo_source"] = "crowdsec-lapi"
    return _scrub(payload)


def _ga_connector(configured: bool) -> dict[str, Any]:
    return {
        "type": "INTERNAL_IMPORT",
        "name": "Google Analytics 4",
        "scope": "aggregate-snapshot",
        "status": "configured" if configured else "unconfigured",
        "note": (
            "Operator-exported hostname+country sessions. No Data API. "
            "No Measurement Protocol. No gtag on /waf."
        ),
        "push": False,
    }


def _lapi_by_country(map_payload: dict | None, payload: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    sources = []
    if isinstance(map_payload, dict):
        sources.append(map_payload.get("countries") or [])
    if isinstance(payload.get("map"), dict):
        sources.append((payload.get("map") or {}).get("countries") or [])
    for rows in sources:
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            cn = str(row.get("cn") or "").upper()
            if not cn:
                continue
            out[cn] = _as_int(row.get("count"))
    return out


def attach_correlation(payload: dict | None, map_payload: dict | None = None) -> dict:
    """Append GA precision + INTERNAL_IMPORT connector. Never duplicate the connector."""
    payload = dict(payload or {})
    snap = load_snapshot()
    by_cn = _country_sessions(snap)
    lapi = _lapi_by_country(map_payload, payload)
    countries = []
    if snap.get("configured"):
        seen: set[str] = set()
        for cn in list(by_cn.keys()) + list(lapi.keys()):
            if cn in seen:
                continue
            seen.add(cn)
            sessions = by_cn.get(cn, 0)
            count = lapi.get(cn, 0)
            countries.append(
                {
                    "cn": cn,
                    "sessions": sessions,
                    "lapi_count": count,
                    "density": density(count, sessions),
                    "verdict": verdict(count, sessions),
                }
            )
    exposed = public(snap)
    exposed["countries"] = countries
    payload["ga"] = exposed
    payload.pop("map", None)
    connectors = [c for c in (payload.get("connectors") or []) if isinstance(c, dict)]
    if not any(
        str(c.get("name") or "") == "Google Analytics 4"
        and str(c.get("type") or "") == "INTERNAL_IMPORT"
        for c in connectors
    ):
        connectors.append(_ga_connector(bool(snap.get("configured"))))
    payload["connectors"] = connectors
    return _scrub(payload)
