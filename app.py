#!/usr/bin/env python3
"""CrowdSec WAF console API + static UI. Bind loopback only. Stdlib only.

UI language: English default, pt-BR secondary (static/locales).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
from pathlib import Path

import control
import catalog as catalog_mod
import correlate
import dashboard as dashmod
import ga

BIND = os.environ.get("WAF_BIND", "127.0.0.1")
PORT = int(os.environ.get("WAF_PORT", "18990"))
CREDS_PATH = Path(os.environ.get("CROWDSEC_CREDS", "/etc/crowdsec/local_api_credentials.yaml"))
PROFILES_PATH = Path(os.environ.get("CROWDSEC_PROFILES", "/etc/crowdsec/profiles.yaml"))
BOUNCER_KEY_PATH = Path(os.environ.get("CROWDSEC_BOUNCER_KEY", "/run/lapi_key"))
CONFIG_ROOT = Path(os.environ.get("CROWDSEC_CONFIG", "/etc/crowdsec"))
METRICS_URL = os.environ.get("CROWDSEC_METRICS", "http://127.0.0.1:6060/metrics")
STATIC = Path(__file__).resolve().parent / "static"
TOKEN = {"value": None, "exp": 0.0}
PUBLIC_IP = os.environ.get("PUBLIC_IP", "")
LOCAL_ORIGINS = {"crowdsec", "cscli", "console", "cscli-import"}
COUNTRY_CENTROID = {
    "AD": (42.5, 1.5), "AE": (23.4, 53.8), "AF": (33.9, 67.7), "AL": (41.2, 20.2),
    "AM": (40.1, 45.0), "AO": (-11.2, 17.9), "AR": (-38.4, -63.6), "AT": (47.5, 14.6),
    "AU": (-25.3, 133.8), "AZ": (40.1, 47.6), "BA": (43.9, 17.7), "BD": (23.7, 90.4),
    "BE": (50.5, 4.5), "BG": (42.7, 25.5), "BH": (26.0, 50.6), "BO": (-16.3, -63.6),
    "BR": (-14.2, -51.9), "BY": (53.7, 27.9), "CA": (56.1, -106.3), "CH": (46.8, 8.2),
    "CL": (-35.7, -71.5), "CN": (35.9, 104.2), "CO": (4.6, -74.3), "CR": (9.7, -83.8),
    "CU": (21.5, -78.0), "CY": (35.1, 33.4), "CZ": (49.8, 15.5), "DE": (51.2, 10.5),
    "DK": (56.3, 9.5), "DO": (18.7, -70.2), "DZ": (28.0, 1.7), "EC": (-1.8, -78.2),
    "EE": (58.6, 25.0), "EG": (26.8, 30.8), "ES": (40.5, -3.7), "ET": (9.1, 40.5),
    "FI": (61.9, 25.7), "FR": (46.2, 2.2), "GB": (55.4, -3.4), "GE": (42.3, 43.4),
    "GH": (7.9, -1.0), "GR": (39.1, 21.8), "GT": (15.8, -90.2), "HK": (22.4, 114.1),
    "HN": (15.2, -86.2), "HR": (45.1, 15.2), "HU": (47.2, 19.5), "ID": (-0.8, 113.9),
    "IE": (53.1, -8.2), "IL": (31.0, 34.9), "IN": (20.6, 79.0), "IQ": (33.2, 43.7),
    "IR": (32.4, 53.7), "IS": (64.96, -19.0), "IT": (41.9, 12.6), "JM": (18.1, -77.3),
    "JO": (30.6, 36.2), "JP": (36.2, 138.3), "KE": (-0.02, 37.9), "KG": (41.2, 74.8),
    "KH": (12.6, 105.0), "KR": (35.9, 127.8), "KW": (29.3, 47.5), "KZ": (48.0, 67.0),
    "LA": (19.9, 102.5), "LB": (33.9, 35.9), "LK": (7.9, 80.8), "LT": (55.2, 23.9),
    "LU": (49.8, 6.1), "LV": (56.9, 24.6), "LY": (26.3, 17.2), "MA": (31.8, -7.1),
    "MD": (47.4, 28.4), "ME": (42.7, 19.4), "MK": (41.6, 21.7), "MM": (21.9, 95.9),
    "MN": (46.9, 103.8), "MX": (23.6, -102.6), "MY": (4.2, 101.98), "NG": (9.1, 8.7),
    "NL": (52.1, 5.3), "NO": (60.5, 8.5), "NP": (28.4, 84.1), "NZ": (-40.9, 174.9),
    "OM": (21.5, 55.9), "PA": (8.5, -80.8), "PE": (-9.2, -75.0), "PH": (12.9, 121.8),
    "PK": (30.4, 69.3), "PL": (51.9, 19.1), "PR": (18.2, -66.6), "PS": (31.95, 35.2),
    "PT": (39.4, -8.2), "PY": (-23.4, -58.4), "QA": (25.4, 51.2), "RO": (45.9, 24.97),
    "RS": (44.0, 21.0), "RU": (61.5, 105.3), "SA": (23.9, 45.1), "SE": (60.1, 18.6),
    "SG": (1.35, 103.8), "SI": (46.2, 14.99), "SK": (48.7, 19.7), "SN": (14.5, -14.5),
    "SV": (13.8, -88.9), "SY": (34.8, 38.99), "TH": (15.9, 100.99), "TJ": (38.9, 71.3),
    "TN": (33.9, 9.5), "TR": (38.96, 35.2), "TW": (23.7, 121.0), "TZ": (-6.4, 34.9),
    "UA": (48.4, 31.2), "UG": (1.4, 32.3), "US": (37.1, -95.7), "UY": (-32.5, -55.8),
    "UZ": (41.4, 64.6), "VE": (6.4, -66.6), "VN": (14.1, 108.3), "YE": (15.6, 48.5),
    "ZA": (-30.6, 22.9), "ZW": (-19.0, 29.2),
}


def parse_simple_yaml(path: Path) -> dict:
    data = {}
    if not path.is_file():
        return data
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, val = line.split(":", 1)
        data[key.strip()] = val.strip().strip("\"'")
    return data


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def lapi_login() -> str:
    now = time.time()
    if TOKEN["value"] and TOKEN["exp"] > now + 30:
        return TOKEN["value"]
    creds = parse_simple_yaml(CREDS_PATH)
    url = creds.get("url") or os.environ.get("CROWDSEC_LAPI", "http://127.0.0.1:18080")
    login = creds.get("login") or creds.get("machine_id") or ""
    password = creds.get("password") or ""
    body = json.dumps({"machine_id": login, "password": password}).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/watchers/login",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        payload = json.loads(resp.read().decode())
    token = payload.get("token") or payload.get("code")
    if not token:
        raise RuntimeError("LAPI login returned no token")
    TOKEN["value"] = token
    TOKEN["exp"] = now + 8 * 60
    TOKEN["url"] = url.rstrip("/")
    return token


def bouncer_key() -> str:
    if BOUNCER_KEY_PATH.is_file():
        return BOUNCER_KEY_PATH.read_text(encoding="utf-8", errors="replace").strip()
    return ""


def lapi_bouncer(path: str, query: dict | None = None):
    key = bouncer_key()
    if not key:
        raise RuntimeError("bouncer key missing")
    creds = parse_simple_yaml(CREDS_PATH)
    base = (creds.get("url") or os.environ.get("CROWDSEC_LAPI", "http://127.0.0.1:18080")).rstrip("/")
    qs = ("?" + urllib.parse.urlencode(query, doseq=True)) if query else ""
    req = urllib.request.Request(
        base + path + qs,
        headers={"X-Api-Key": key, "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
        return json.loads(raw.decode() or "{}")


def lapi(method: str, path: str, query: dict | None = None, body: dict | None = None):
    token = lapi_login()
    base = TOKEN.get("url") or "http://127.0.0.1:18080"
    qs = ("?" + urllib.parse.urlencode(query, doseq=True)) if query else ""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        base + path + qs,
        data=data,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            if not raw:
                return {"ok": True, "status": resp.status}
            try:
                return json.loads(raw.decode())
            except json.JSONDecodeError:
                return {"raw": raw.decode("utf-8", "replace"), "status": resp.status}
    except urllib.error.HTTPError as exc:
        TOKEN["value"] = None
        detail = exc.read().decode("utf-8", "replace")[:800]
        raise RuntimeError(f"LAPI {exc.code} {path}: {detail}") from exc


def lapi_soft(method: str, path: str, query: dict | None = None):
    try:
        return 200, lapi(method, path, query=query)
    except Exception as exc:
        msg = str(exc)
        code = 0
        match = re.search(r"LAPI (\d{3}) ", msg)
        if match:
            code = int(match.group(1))
        return code, {"error": msg}


def tcp_open(host: str, port: int, timeout: float = 1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_text(url: str, timeout: float = 4.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, str(exc)


def http_probe(host: str, server: str) -> dict:
    ctx = ssl._create_unverified_context()
    try:
        sock = ctx.wrap_socket(socket.create_connection((server, 443), timeout=8), server_hostname=host)
        sock.sendall(
            f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: waf-console/1.0.6\r\n"
            f"Accept-Encoding: identity\r\nConnection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            chunk = sock.recv(2048)
            if not chunk:
                break
            data += chunk
            if len(data) > 400:
                break
        sock.close()
        status = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
        code = 0
        parts = status.split()
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
        return {"host": host, "via": server, "status": code, "line": status}
    except Exception as exc:
        return {"host": host, "via": server, "status": 0, "error": str(exc)}


def engine_status() -> dict:
    profiles = read_text(PROFILES_PATH)
    acquis = read_text(CONFIG_ROOT / "acquis.d" / "appsec.yaml")
    return {
        "lapi_listen": tcp_open("127.0.0.1", 18080),
        "appsec_listen": tcp_open("127.0.0.1", 7422),
        "metrics_listen": tcp_open("127.0.0.1", 6060),
        "oob_log_only": "appsec_outofband_log_only" in profiles,
        "crs_inband_present": "crs-inband" in profiles and "name: crs-inband" in profiles,
        "fail_closed": True,
        "include_large_uploads": bool(re.search(r"INCLUDE_LARGE_UPLOADS\s*[:=]\s*(1|true|yes)", acquis, re.I)),
        "creds_present": CREDS_PATH.is_file(),
        "bouncer_key_present": bool(bouncer_key()),
        "version": "waf-console/1.0.6",
        "locale": {"default": "en", "supported": ["en", "pt-BR"]},
    }


def flatten_decisions(payload):
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        items = []
        for key in ("new", "decisions"):
            if isinstance(payload.get(key), list):
                items.extend(payload[key])
        return items
    return []


def is_local_decision(item) -> bool:
    origin = str(item.get("origin") or "").lower()
    return origin in LOCAL_ORIGINS


def prefer_local_decisions(items, limit=120):
    local = [d for d in items if is_local_decision(d)]
    return local[:limit]


def fetch_local_decisions():
    try:
        items = flatten_decisions(
            lapi_bouncer(
                "/v1/decisions/stream",
                query={"startup": "true", "origins": "crowdsec,cscli", "dedup": "false"},
            )
        )
        return items, None
    except Exception as first:
        try:
            items = flatten_decisions(lapi_bouncer("/v1/decisions/stream", query={"startup": "true"}))
            return prefer_local_decisions(items, 500), str(first)
        except Exception as exc:
            return [], "%s | %s" % (first, exc)


def source_of(alert: dict) -> dict:
    src = alert.get("source") or {}
    if not isinstance(src, dict):
        src = {}
    event0 = ((alert.get("events") or [{}])[0] or {}).get("source") or {}
    if not isinstance(event0, dict):
        event0 = {}
    src = {**event0, **src}
    ip = src.get("ip") or src.get("value") or ""
    cn = str(src.get("cn") or src.get("country") or alert.get("cn") or "").upper()
    lat, lon = src.get("latitude"), src.get("longitude")
    try:
        lat_f = float(lat) if lat not in (None, "") else None
        lon_f = float(lon) if lon not in (None, "") else None
    except (TypeError, ValueError):
        lat_f = lon_f = None
    approx = False
    if (lat_f is None or lon_f is None) and cn in COUNTRY_CENTROID:
        lat_f, lon_f = COUNTRY_CENTROID[cn]
        approx = True
    city = ""
    if isinstance(event0, dict):
        city = str(event0.get("city") or "")
    city = str(src.get("city") or city)
    return {
        "ip": ip,
        "cn": cn,
        "city": city,
        "as_name": src.get("as_name") or src.get("asname") or "",
        "lat": lat_f,
        "lon": lon_f,
        "approx": approx,
        "scenario": alert.get("scenario") or "",
        "created_at": alert.get("created_at") or "",
        "id": alert.get("id"),
        "capacity": alert.get("events_count") if alert.get("events_count") is not None else 1,
    }


def yaml_names(text: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(r"(?m)^name:\s*([^\n#]+)", text or "")]


def yaml_kv(text: str, key: str) -> list[str]:
    return [m.group(1).strip().strip("\"'") for m in re.finditer(rf"(?m)^{re.escape(key)}:\s*(.+)$", text or "")]


def extract_cidrs(text: str) -> list[str]:
    found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", text or "")
    out = []
    for item in found:
        try:
            ipaddress.ip_network(item, strict=False)
            out.append(item)
        except ValueError:
            continue
    return list(dict.fromkeys(out))


def hub_summary(kind: str, list_n: int = 40) -> dict:
    root = CONFIG_ROOT / "hub" / kind
    if not root.is_dir():
        root = CONFIG_ROOT / kind
    items: list[str] = []
    count = 0
    truncated = False
    if root.is_dir():
        for path in root.rglob("*"):
            if path.suffix.lower() not in {".yaml", ".yml"}:
                continue
            count += 1
            if len(items) < list_n:
                try:
                    items.append(str(path.relative_to(root)).replace("\\", "/"))
                except ValueError:
                    items.append(path.name)
            if count >= 8000:
                truncated = True
                break
    return {"count": count, "items": sorted(items), "truncated": truncated}


def parse_prom(text: str) -> dict:
    decisions: dict[str, float] = {}
    alerts: dict[str, float] = {}
    appsec: dict[str, float] = {}
    other: dict[str, float] = {}
    line_re = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+0-9.eE]+)$")
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "le=" in line or "quantile=" in line:
            continue
        match = line_re.match(line)
        if not match:
            continue
        name, labels, value_s = match.groups()
        if name.endswith("_bucket"):
            continue
        try:
            value = float(value_s)
        except ValueError:
            continue
        label_map = {}
        if labels:
            for pair in labels.split(","):
                if "=" not in pair:
                    continue
                key, val = pair.split("=", 1)
                label_map[key.strip()] = val.strip().strip('"')
        if name == "cs_active_decisions":
            origin = label_map.get("origin") or "unknown"
            decisions[origin] = decisions.get(origin, 0) + value
        elif name == "cs_alerts":
            reason = label_map.get("reason") or "unknown"
            if reason.startswith("anomaly score out-of-band"):
                reason = "crowdsecurity/crowdsec-appsec-outofband"
            alerts[reason] = alerts.get(reason, 0) + value
        elif name.startswith("cs_appsec_"):
            appsec[name] = appsec.get(name, 0) + value
        elif name.startswith("cs_") and not name.endswith(("_sum", "_count", "_created")):
            other[name] = other.get(name, 0) + value
    top_alerts = sorted(alerts.items(), key=lambda kv: kv[1], reverse=True)[:16]
    return {
        "decisions_by_origin": decisions,
        "local_decisions": sum(v for k, v in decisions.items() if k.lower() in LOCAL_ORIGINS),
        "capi_decisions": sum(v for k, v in decisions.items() if k.lower() == "capi"),
        "top_alerts": [{"reason": k, "count": v} for k, v in top_alerts],
        "appsec": appsec,
        "gauges": {k: other[k] for k in sorted(other)[:24]},
    }


def fetch_alerts(limit: int = 80) -> list:
    data = lapi("GET", "/v1/alerts", query={"limit": limit}) or []
    return data if isinstance(data, list) else []


def edge_point():
    lat = os.environ.get("WAF_EDGE_LAT")
    lon = os.environ.get("WAF_EDGE_LON")
    if not lat or not lon:
        return None
    try:
        return {
            "lat": float(lat),
            "lon": float(lon),
            "label": os.environ.get("WAF_EDGE_LABEL") or "edge",
        }
    except ValueError:
        return None


def build_map(alerts: list) -> dict:
    points = []
    countries: dict[str, dict] = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        src = source_of(alert)
        if src["lat"] is None or src["lon"] is None:
            continue
        points.append(src)
        cn = src["cn"] or "??"
        slot = countries.setdefault(cn, {"cn": cn, "count": 0, "lat": src["lat"], "lon": src["lon"], "city": src.get("city") or ""})
        slot["count"] += int(src.get("capacity") or 1)
        if src.get("city") and not slot.get("city"):
            slot["city"] = src["city"]
    points.sort(key=lambda p: p.get("created_at") or "", reverse=True)
    payload = {
        "points": points[:80],
        "countries": sorted(countries.values(), key=lambda c: c["count"], reverse=True)[:40],
        "geo_source": "crowdsec-lapi",
        "note": "LAPI coordinates (source.latitude/longitude) or ISO centroid. No third-party GeoIP.",
        "edge": edge_point(),
    }
    return ga.attach_map(payload)


def build_rules() -> dict:
    profiles = read_text(PROFILES_PATH)
    acquis = read_text(CONFIG_ROOT / "acquis.d" / "appsec.yaml")
    operators = read_text(CONFIG_ROOT / "parsers" / "s02-enrich" / "cso-operators.yaml")
    return {
        "profiles": {
            "names": yaml_names(profiles),
            "on_success": yaml_kv(profiles, "on_success")[:12],
            "filters": yaml_kv(profiles, "filters")[:12],
        },
        "appsec": {
            "listen_addr": (yaml_kv(acquis, "listen_addr") or ["127.0.0.1:7422"])[0],
            "configs": re.findall(r"(crowdsecurity/[a-zA-Z0-9._-]+)", acquis),
            "raw": acquis[:1600],
        },
        "operators_parser": {
            "present": bool(operators.strip()),
            "cidrs": extract_cidrs(operators),
        },
        "hub": {
            "collections": hub_summary("collections"),
            "scenarios": hub_summary("scenarios"),
            "appsec_configs": hub_summary("appsec-configs"),
            "appsec_rules": hub_summary("appsec-rules", list_n=24),
            "parsers": hub_summary("parsers", list_n=24),
        },
        "policy": {
            "crs_inband": False,
            "fail_closed": True,
            "include_large_uploads": False,
            "mutations": [
                "unban-ip",
                "ban-ip",
                "allowlist-add",
                "allowlist-remove",
                "policy-create",
                "policy-update",
                "policy-delete",
                "site-filter-allow_match",
                "site-filter-skip_rule",
                "site-filter-bypass_host",
            ],
            "note": "The UI never enables CRS in-band, INCLUDE_LARGE_UPLOADS or fail-closed changes. Per-host filters use AppSec hooks.",
        },
    }


def build_allowlists() -> dict:
    status, payload = lapi_soft("GET", "/v1/allowlists", query={"with_content": "true"})
    lapi_lists = payload if isinstance(payload, list) else []
    if isinstance(payload, dict) and not lapi_lists:
        lapi_lists = payload.get("allowlists") or payload.get("items") or []
        if not isinstance(lapi_lists, list):
            lapi_lists = []
    operators = read_text(CONFIG_ROOT / "parsers" / "s02-enrich" / "cso-operators.yaml")
    return {
        "lapi_status": status,
        "lapi": lapi_lists,
        "parser_cidrs": extract_cidrs(operators),
        "parser_file": "parsers/s02-enrich/cso-operators.yaml",
        "note": "LAPI allowlist add/remove CIDR. Operator parser remains IaC.",
    }


def scrape_metrics() -> dict:
    status, text = http_text(METRICS_URL)
    if status != 200:
        return {"ok": False, "status": status, "error": text[:300], "listen": "127.0.0.1:6060"}
    parsed = parse_prom(text)
    parsed.update({"ok": True, "status": 200, "listen": "127.0.0.1:6060"})
    return parsed


def check_allowlist_ip(ip: str) -> dict:
    status, body = lapi_soft("GET", f"/v1/allowlists/check/{ip}")
    operators = extract_cidrs(read_text(CONFIG_ROOT / "parsers" / "s02-enrich" / "cso-operators.yaml"))
    in_parser = False
    addr = ipaddress.ip_address(ip)
    for cidr in operators:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                in_parser = True
                break
        except ValueError:
            continue
    return {
        "ok": True,
        "ip": ip,
        "lapi_status": status,
        "lapi": body,
        "parser_match": in_parser,
        "parser_cidrs": operators,
    }


def add_ban(payload: dict) -> dict:
    ip = str(payload.get("ip") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("invalid ip") from exc
    duration = control.validate_duration(str(payload.get("duration") or "4h"))
    reason = str(payload.get("reason") or "cso-console")[:120]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = [
        {
            "scenario": "manual/cso-ban",
            "scenario_hash": "",
            "scenario_version": "1.2",
            "message": reason,
            "events_count": 1,
            "start_at": now,
            "stop_at": now,
            "capacity": 0,
            "leakspeed": "0",
            "simulated": False,
            "events": [],
            "source": {"scope": "Ip", "value": ip, "ip": ip},
            "decisions": [
                {
                    "duration": duration,
                    "reason": reason,
                    "origin": "cscli",
                    "scenario": "manual/cso-ban",
                    "type": "ban",
                    "scope": "Ip",
                    "value": ip,
                }
            ],
        }
    ]
    result = lapi("POST", "/v1/alerts", body=body)
    control.audit("ban.add", {"ip": ip, "duration": duration, "reason": reason})
    return {"ok": True, "ip": ip, "duration": duration, "result": result}


class Handler(BaseHTTPRequestHandler):
    server_version = "waf-console/1.0.6"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body, content_type="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            raw = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, bytes):
            raw = body
        else:
            raw = str(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.end_headers()
        self.wfile.write(raw)

    def _send_download(self, body, filename, content_type="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            raw = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, bytes):
            raw = body
        else:
            raw = str(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % filename)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.end_headers()
        self.wfile.write(raw)

    def _json_error(self, code: int, message: str):
        self._send(code, {"ok": False, "error": message})

    def _correlation_payload(self) -> dict:
        alerts = fetch_alerts(80)
        return ga.attach_correlation(correlate.correlate(alerts, control.hub_appsec_rules()), build_map(alerts))

    def _route_path(self) -> str:
        path = urllib.parse.urlparse(self.path).path
        if path in ("/waf", "/waf/"):
            return "/"
        if path.startswith("/waf/"):
            return path[4:] or "/"
        return path

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/waf":
            self.send_response(302)
            self.send_header("Location", "/waf/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = self._route_path()
        if path in ("/", "/index.html"):
            return self._static("index.html", "text/html; charset=utf-8")
        if path.startswith("/static/"):
            name = path.split("/")[-1]
            ctype = "text/css" if name.endswith(".css") else "application/javascript" if name.endswith(".js") else "application/octet-stream"
            return self._static(name, ctype)
        if path in ("/app.css", "/app.js", "/i18n.js", "/world.js", "/map.js"):
            ctype = "text/css" if path.endswith(".css") else "application/javascript"
            return self._static(path.lstrip("/"), ctype)
        if path.startswith("/locales/"):
            name = path.split("/")[-1]
            if name not in ("en.json", "pt-BR.json"):
                return self._json_error(404, "not found")
            return self._static("locales/" + name, "application/json; charset=utf-8")
        if path == "/api/health":
            eng = engine_status()
            return self._send(200, {"ok": True, **eng})
        if path == "/api/overview":
            return self._overview()
        if path == "/api/dashboard":
            return self._dashboard(parsed)
        if path == "/api/decisions":
            return self._decisions()
        if path == "/api/alerts":
            return self._alerts()
        if path == "/api/domains":
            return self._domains()
        if path == "/api/engine":
            return self._engine()
        if path == "/api/map":
            try:
                return self._send(200, {"ok": True, **build_map(fetch_alerts(80))})
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/rules":
            return self._send(200, {"ok": True, **build_rules()})
        if path == "/api/allowlists":
            return self._send(200, {"ok": True, **build_allowlists()})
        if path == "/api/metrics":
            return self._send(200, scrape_metrics())
        if path == "/api/coverage":
            return self._coverage()
        if path == "/api/correlation":
            try:
                return self._send(200, self._correlation_payload())
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/correlation/stix":
            try:
                return self._send_download(correlate.stix_bundle(self._correlation_payload()), "waf-findings.stix.json")
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/correlation/misp":
            try:
                return self._send_download(correlate.misp_event(self._correlation_payload()), "waf-findings.misp.json")
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/correlation/thehive":
            try:
                return self._send_download(correlate.thehive_alert(self._correlation_payload()), "waf-findings.thehive.json")
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/sites":
            return self._send(200, control.sites_payload())
        if path == "/api/filters":
            return self._send(200, {"ok": True, **control.load_filters()})
        if path == "/api/policies":
            return self._send(200, {"ok": True, **control.load_filters()})
        if path == "/api/hub/appsec-rules":
            return self._send(200, {"ok": True, "items": control.hub_appsec_rules()})
        self._json_error(404, "not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        if length > 32768:
            return self._json_error(413, "payload too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            return self._json_error(400, "invalid json")
        path = self._route_path()
        if path == "/api/decisions/delete":
            ip = str(payload.get("ip") or "").strip()
            if not ip:
                return self._json_error(400, "ip required")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return self._json_error(400, "invalid ip")
            try:
                result = lapi("DELETE", "/v1/decisions", query={"ip": ip})
                return self._send(200, {"ok": True, "ip": ip, "result": result})
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/allowlists/check":
            ip = str(payload.get("ip") or "").strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return self._json_error(400, "invalid ip")
            try:
                return self._send(200, check_allowlist_ip(ip))
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path in ("/api/filters", "/api/policies"):
            try:
                if payload.get("id"):
                    item = control.update_filter(payload)
                    return self._send(200, {"ok": True, "item": item, "op": "update"})
                item = control.add_filter(payload)
                return self._send(200, {"ok": True, "item": item, "op": "create"})
            except ValueError as cop:
                return self._json_error(400, str(cop))
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path in ("/api/filters/update", "/api/policies/update"):
            try:
                return self._send(200, {"ok": True, "item": control.update_filter(payload), "op": "update"})
            except ValueError as cop:
                return self._json_error(400, str(cop))
            except Exception as cop:
                return self._json_error(502, str(cop))
        if path in ("/api/filters/delete", "/api/policies/delete"):
            try:
                return self._send(200, control.delete_filter(str(payload.get("id") or "")))
            except ValueError as cop:
                return self._json_error(400, str(cop))
            except Exception as cop:
                return self._json_error(502, str(cop))
        if path == "/api/filters/toggle":
            try:
                return self._send(200, {"ok": True, "item": control.toggle_filter(str(payload.get("id") or ""), bool(payload.get("enabled")))})
            except ValueError as exc:
                return self._json_error(400, str(exc))
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/allowlists/items":
            try:
                return self._send(200, control.allowlist_add(str(payload.get("cidr") or payload.get("ip") or ""), str(payload.get("reason") or "cso-console")))
            except ValueError as exc:
                return self._json_error(400, str(exc))
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/allowlists/items/delete":
            try:
                return self._send(200, control.allowlist_remove(str(payload.get("cidr") or payload.get("ip") or "")))
            except ValueError as exc:
                return self._json_error(400, str(exc))
            except Exception as exc:
                return self._json_error(502, str(exc))
        if path == "/api/decisions":
            try:
                return self._send(200, add_ban(payload))
            except ValueError as exc:
                return self._json_error(400, str(exc))
            except Exception as exc:
                return self._json_error(502, str(exc))
        self._json_error(404, "not found")

    def _static(self, name: str, content_type: str):
        target = (STATIC / name).resolve()
        if STATIC not in target.parents and target != STATIC:
            return self._json_error(403, "forbidden")
        if not target.is_file():
            return self._json_error(404, "asset missing")
        self._send(200, target.read_bytes(), content_type)

    def _overview(self):
        eng = engine_status()
        decisions, alerts = [], []
        err = None
        try:
            decisions, derr = fetch_local_decisions()
            if derr and not decisions:
                err = derr
            alerts = fetch_alerts(40)
        except Exception as exc:
            err = str(exc)
        hosts = catalog_mod.in_scope_hosts()
        domains = [http_probe(h, "127.0.0.1") for h in hosts]
        ok_hosts = sum(1 for d in domains if d.get("status") == 200)
        return self._send(
            200,
            {
                "ok": err is None,
                "error": err,
                "engine": eng,
                "counts": {
                    "decisions": len(decisions),
                    "decisions_local": len(decisions),
                    "community_omitted": True,
                    "alerts": len(alerts),
                    "domains_ok": ok_hosts,
                    "domains": len(hosts),
                    "filters": len(control.load_filters().get("items") or []),
                },
                "decisions": prefer_local_decisions(decisions, 8),
                "alerts": alerts[:8],
                "domains": domains,
                "map": build_map(alerts),
                "generated_at": int(time.time()),
            },
        )


    def _dashboard(self, parsed):
        qs = urllib.parse.parse_qs(parsed.query)
        host = (qs.get("host") or [""])[0]
        filters = {k: (qs.get(k) or [""])[0] for k in ("ip", "path", "country", "action", "method")}
        try:
            alerts = fetch_alerts(200)
        except Exception as exc:
            return self._json_error(502, str(exc))
        decisions, _err = fetch_local_decisions()
        hosts = catalog_mod.in_scope_hosts()
        origin = [http_probe(h, "127.0.0.1") for h in hosts]
        try:
            mx = scrape_metrics()
        except Exception:
            mx = {}
        payload = dashmod.build(
            alerts,
            decisions=prefer_local_decisions(decisions),
            engine=engine_status(),
            hosts=hosts,
            host=host,
            origin_probes=origin,
            hub_rules=control.hub_appsec_rules(),
            filters=filters,
            appsec=(mx.get("appsec") if isinstance(mx, dict) else None),
            edge=edge_point(),
        )
        return self._send(200, payload)

    def _decisions(self):
        try:
            data, err = fetch_local_decisions()
            if err and not data:
                return self._json_error(502, err)
            return self._send(200, {"ok": True, "total": len(data), "community_omitted": True, "items": prefer_local_decisions(data)})
        except Exception as exc:
            return self._json_error(502, str(exc))

    def _alerts(self):
        try:
            data = fetch_alerts(80)
            items = []
            for alert in data:
                if isinstance(alert, dict):
                    cn = source_of(alert).get("cn") or ""
                    if cn:
                        alert["cn"] = cn
                    dashmod.enrich_alert(alert)
                items.append(alert)
            return self._send(200, {"ok": True, "items": items})
        except Exception as exc:
            return self._json_error(502, str(exc))

    def _domains(self):
        hosts = catalog_mod.in_scope_hosts()
        origin = [http_probe(h, "127.0.0.1") for h in hosts]
        public = [http_probe(h, PUBLIC_IP) for h in hosts] if PUBLIC_IP else []
        return self._send(200, {"ok": True, "origin": origin, "public": public})

    def _engine(self):
        rules = build_rules()
        return self._send(200, {"ok": True, **engine_status(), "profiles": rules["profiles"]["names"], "policy": rules["policy"], "appsec": rules["appsec"]})

    def _coverage(self):
        try:
            alerts = fetch_alerts(80)
        except Exception:
            alerts = []
        return self._send(
            200,
            {
                "ok": True,
                "map": build_map(alerts),
                "rules": build_rules(),
                "allowlists": build_allowlists(),
                "metrics": scrape_metrics(),
                "engine": engine_status(),
                "sites": control.sites_payload(),
                "filters": control.load_filters(),
                "correlation": ga.attach_correlation(correlate.correlate(alerts, control.hub_appsec_rules()), build_map(alerts)),
            },
        )


def main():
    if BIND not in ("127.0.0.1", "::1"):
        raise SystemExit("WAF_BIND must be loopback")
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"waf-console listening http://{BIND}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
