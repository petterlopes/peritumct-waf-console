#!/usr/bin/env python3
"""CrowdSec LAPI/AppSec dashboard aggregates.

Operator views (domain filter, extra filters, traffic, security tiles,
sampled logs, events, origin probes, AppSec performance). Counts come from
LAPI alerts and CrowdSec metrics. Cache, bytes, visits and 5xx stay
unavailable unless a local source actually provides them.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import status as statusmod

SOURCE = "crowdsec-lapi"
NOTE = (
    "LAPI/AppSec events in this window. "
    "HTTP method/UA/JA4H come from CrowdSec alert meta when present. "
    "Cache, bytes, visits and 5xx are listed only when present in local sources."
)
GMT3 = timezone(timedelta(hours=-3))
_BOT_RE = re.compile(r"(googlebot|bingbot|yandexbot|applebot|gptbot|claudebot|bytespider|semrush|ahrefs)", re.I)
_HTTP_VER = {"09": "HTTP/0.9", "10": "HTTP/1.0", "11": "HTTP/1.1", "20": "HTTP/2", "30": "HTTP/3"}
_FILTER_KEYS = ("ip", "path", "country", "action", "method")


def _probe_ok(code: Any) -> bool:
    return statusmod.http_status_ok(code)


def _unwrap(raw: Any) -> str:
    text = str(raw if raw is not None else "").strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        first = inner.split(",", 1)[0].strip().strip('"').strip("'")
        text = first or inner.strip('"').strip("'")
    return text.strip().strip('"').strip("'")


def _meta_pairs(blob: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(blob, dict):
        for key, val in blob.items():
            out.append((str(key), _unwrap(val)))
        return out
    if not isinstance(blob, list):
        return out
    for row in blob:
        if isinstance(row, dict):
            key = str(row.get("key") or row.get("name") or "")
            val = row.get("value")
            if val is None:
                val = row.get("val")
            out.append((key, _unwrap(val)))
    return out


def meta_map(alert: dict) -> dict[str, str]:
    merged: dict[str, str] = {}
    for key, val in _meta_pairs(alert.get("meta")):
        if key and val and key not in merged:
            merged[key] = val
    for event in alert.get("events") or []:
        if not isinstance(event, dict):
            continue
        for key, val in _meta_pairs(event.get("meta")):
            if key and val:
                merged[key] = val
    return merged


def _clean_host(raw: str) -> str:
    host = _unwrap(raw).lower()
    host = host.split(",")[0].strip()
    if host.startswith("http://") or host.startswith("https://"):
        host = (urlparse(host).hostname or host)
    if ":" in host and not host.count(":") > 1:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def _clean_path(raw: str) -> str:
    text = _unwrap(raw)
    path = text.split("?", 1)[0].strip() or "/"
    if len(path) > 180:
        path = path[:177] + "..."
    return path


def http_version_from_ja4h(ja4h: str) -> str:
    head = _unwrap(ja4h).split("_", 1)[0].lower()
    if len(head) < 4:
        return ""
    return _HTTP_VER.get(head[2:4], "")


def http_of(alert: dict) -> dict[str, str]:
    meta = meta_map(alert)
    host = _clean_host(
        meta.get("target_fqdn")
        or meta.get("target_host")
        or meta.get("http_host")
        or meta.get("host")
        or ""
    )
    path = _clean_path(
        meta.get("target_uri")
        or meta.get("uri")
        or meta.get("http_path")
        or ""
    )
    method = _unwrap(meta.get("http_verb") or meta.get("verb") or meta.get("method") or "").upper()
    if method.startswith("[") or " " in method:
        method = re.sub(r"[^A-Z]", "", method)
    ua = _unwrap(meta.get("http_user_agent") or meta.get("user_agent") or "")
    ja4h = _unwrap(meta.get("ja4h") or meta.get("ja4") or "")
    status = _unwrap(meta.get("http_status") or meta.get("status") or "")
    if status and not status.isdigit():
        status = ""
    service = meta.get("rule_name") or meta.get("service") or (alert.get("scenario") or "")
    src = alert.get("source") if isinstance(alert.get("source"), dict) else {}
    asn = _unwrap(meta.get("ASNOrg") or src.get("as_name") or src.get("asname") or "")
    return {
        "host": host,
        "path": path if path else "",
        "method": method,
        "ua": ua,
        "ja4h": ja4h,
        "http_version": http_version_from_ja4h(ja4h),
        "status": status,
        "service": str(service),
        "rule": meta.get("rule_name") or "",
        "rule_ids": _unwrap(meta.get("rule_ids") or ""),
        "zones": _unwrap(meta.get("matched_zones") or ""),
        "data": _unwrap(meta.get("data") or "")[:120],
        "asn": asn,
        "appsec_action": (_unwrap(meta.get("appsec_action") or "")).lower(),
    }


def action_of(alert: dict, http: dict | None = None) -> str:
    http = http or http_of(alert)
    if alert.get("decisions"):
        return "Block"
    appsec = http.get("appsec_action") or ""
    if appsec in {"ban", "block", "deny"}:
        return "Block"
    scenario = str(alert.get("scenario") or "").lower()
    if "outofband" in scenario or scenario.startswith("anomaly score out-of-band"):
        return "Log"
    if "manual/cso-ban" in scenario:
        return "Block"
    return "Alert"


def enrich_alert(alert: dict) -> dict:
    if not isinstance(alert, dict):
        return alert
    http = http_of(alert)
    if http.get("host"):
        alert["host"] = http["host"]
    if http.get("path"):
        alert["path"] = http["path"]
    if http.get("method"):
        alert["method"] = http["method"]
    alert["action"] = action_of(alert, http)
    alert["service"] = http.get("rule") or http.get("service") or alert.get("scenario") or ""
    return alert


def _parse_time(alert: dict) -> datetime | None:
    raw = alert.get("created_at") or alert.get("start_at") or ""
    if isinstance(raw, (int, float)):
        ts = float(raw)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    text = str(raw).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _match_host(alert: dict, host: str) -> bool:
    if not host:
        return True
    want = _clean_host(host)
    got = _clean_host(alert.get("host") or http_of(alert).get("host") or "")
    return bool(got) and (got == want or got.endswith("." + want) or want.endswith("." + got))


def _match_filters(row: dict, filters: dict[str, str]) -> bool:
    for key in _FILTER_KEYS:
        want = (filters.get(key) or "").strip()
        if not want:
            continue
        got = str(row.get(key) or "")
        if key == "path":
            if want not in got:
                return False
        elif key == "ip":
            if want not in got:
                return False
        elif got.lower() != want.lower():
            return False
    return True


def _top(counter: Counter, n: int = 10) -> list[dict]:
    items = [{"label": k, "count": int(v)} for k, v in counter.most_common(n) if k]
    total = sum(item["count"] for item in items) or 1
    for item in items:
        item["pct"] = round(100.0 * item["count"] / total, 2)
    return items


def _pack(counter: Counter, available: bool, n: int = 8) -> dict:
    return {"available": available, "items": _top(counter, n) if available else []}


def classify_ua(ua: str) -> tuple[str, str, str]:
    text = _unwrap(ua)
    low = text.lower()
    if not text:
        return "", "", ""
    hit = _BOT_RE.search(text)
    if hit:
        browser = hit.group(1)
        browser = browser[0].upper() + browser[1:]
    elif "edg/" in low:
        browser = "Edge"
    elif "chrome" in low and "chromium" not in low:
        browser = "ChromeMobile" if "mobile" in low else "Chrome"
    elif "firefox" in low:
        browser = "Firefox"
    elif "safari" in low and "chrome" not in low:
        browser = "Safari"
    else:
        browser = "Unknown/Other"
    if "android" in low:
        os_name = "Android"
    elif "iphone" in low or "ipad" in low or "ios" in low:
        os_name = "iOS"
    elif "mac os" in low or "macintosh" in low:
        os_name = "MacOSX"
    elif "windows" in low:
        os_name = "Windows"
    elif "linux" in low:
        os_name = "Linux"
    else:
        os_name = "Unknown/Other"
    if "ipad" in low or "tablet" in low:
        device = "Tablet"
    elif "mobile" in low or "iphone" in low or "android" in low:
        device = "Mobile"
    else:
        device = "Desktop"
    return browser, os_name, device


# Scanner detection is anonymous: one series, no tool names.
# Chrome/Firefox browsing is not a scanner. Secret-file probes and Hub scan
# scenarios are. Known tool UAs count as scanner activity without identifying them.
_SCANNER_UA_RE = re.compile(
    r"(?i)(?<![a-z])nmap(?![a-z])"
    r"|(?<![a-z])hping3?(?![a-z])"
    r"|(?<![a-z])masscan(?![a-z])"
    r"|acunetix"
    r"|owasp[\s-]?zap|(?<![a-z])zaproxy(?![a-z])|(?<![a-z])zap/\d"
    r"|(?<![a-z])nessus(?![a-z])"
    r"|openvas|(?<![a-z])greenbone(?![a-z])"
    r"|(?<![a-z])nikto(?![a-z])"
    r"|(?<![a-z])sqlmap(?![a-z])"
    r"|(?<![a-z])nuclei(?![a-z])"
    r"|(?<![a-z])wpscan(?![a-z])"
    r"|(?<![a-z])burp(?:suite)?(?![a-z])"
    r"|(?<![a-z])gobuster(?![a-z])"
    r"|(?<![a-z])ffuf(?![a-z])"
    r"|dirbuster"
    r"|(?<![a-z])jscrawler(?![a-z])"
)
_SCANNER_SCENARIO_RE = re.compile(
    r"(?i)probing|scanner|http-crawl|http-scan|bad-user-agent|open-proxy"
    r"|env-access|git-config|uploads-listing"
)
_SECRET_SCAN_PATH = re.compile(
    r"(?i)(?:^|/)(?:\.env|\.git(?:/|$)|\.aws(?:/|$)|\.docker(?:/|$))"
)
_SCANNER_NOTE = (
    "HTTP AppSec/LAPI scanner detections in this window. "
    "Hover or click an hour for time, quantity and action split. "
    "The graph does not name the tool. Chrome/Firefox on ordinary paths are not counted. "
    "L3/L4 scans (SYN/hping) are invisible here. Updates every 15s."
)


def is_scanner_event(ua: str = "", scenario: str = "", path: str = "") -> bool:
    """True for HTTP scanner/recon activity. Never names the tool."""
    if _SCANNER_UA_RE.search(ua or ""):
        return True
    if _SCANNER_SCENARIO_RE.search(scenario or ""):
        return True
    if _SECRET_SCAN_PATH.search(path or ""):
        return True
    return False


def _hour_bucket(dt: datetime | None, now: datetime) -> int | None:
    if not dt:
        return None
    local = now.astimezone(GMT3)
    hours = int((local - dt.astimezone(GMT3)).total_seconds() // 3600)
    if hours < 0 or hours > 23:
        return None
    return 23 - hours


def _hour_series(rows: list[dict], now: datetime) -> dict:
    local = now.astimezone(GMT3)
    events = [0] * 24
    blocked = [0] * 24
    logged = [0] * 24
    for row in rows:
        idx = _hour_bucket(row.get("_dt"), now)
        if idx is None:
            continue
        events[idx] += 1
        if row["action"] == "Block":
            blocked[idx] += 1
        elif row["action"] == "Log":
            logged[idx] += 1
    labels = []
    for i in range(24):
        hour = (local.hour - (23 - i)) % 24
        labels.append(f"{hour:02d}:00")
    return {"labels": labels, "events": events, "blocked": blocked, "logged": logged, "tz": "GMT-3"}


def _median(nums: list[int]) -> float:
    if not nums:
        return 0.0
    ordered = sorted(nums)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _scanner_pack(rows: list[dict], now: datetime, labels: list[str]) -> dict[str, Any]:
    events = [0] * 24
    blocked = [0] * 24
    logged = [0] * 24
    hour_ips: list[set[str]] = [set() for _ in range(24)]
    all_ips: set[str] = set()
    total = 0
    blocked_total = 0
    logged_total = 0
    if not labels or len(labels) != 24:
        labels = list((_hour_series([], now).get("labels") or []))
        if len(labels) != 24:
            labels = [f"{i:02d}:00" for i in range(24)]
    for row in rows:
        if not is_scanner_event(row.get("ua") or "", row.get("scenario") or "", row.get("path") or ""):
            row["scanner"] = False
            continue
        row["scanner"] = True
        total += 1
        ip = str(row.get("ip") or "")
        if ip:
            all_ips.add(ip)
        action = row.get("action") or ""
        if action == "Block":
            blocked_total += 1
        elif action == "Log":
            logged_total += 1
        idx = _hour_bucket(row.get("_dt"), now)
        if idx is None:
            continue
        events[idx] += 1
        if ip:
            hour_ips[idx].add(ip)
        if action == "Block":
            blocked[idx] += 1
        elif action == "Log":
            logged[idx] += 1
    sources_hourly = [len(slot) for slot in hour_ips]
    peak_idx = 0
    for i, count in enumerate(events):
        if count >= events[peak_idx]:
            peak_idx = i
    hours = [
        {
            "i": i,
            "label": labels[i],
            "events": events[i],
            "sources": sources_hourly[i],
            "blocked": blocked[i],
            "logged": logged[i],
        }
        for i in range(24)
    ]
    last = hours[-1]
    peak = hours[peak_idx]
    n_src = len(all_ips)
    return {
        "ok": True,
        "source": SOURCE,
        "note": _SCANNER_NOTE,
        "poll_s": 15,
        "tz": "GMT-3",
        "labels": labels,
        "events": events,
        "sources_hourly": sources_hourly,
        "blocked_hourly": blocked,
        "logged_hourly": logged,
        "hours": hours,
        "events_total": total,
        "sources": n_src,
        "blocked_total": blocked_total,
        "logged_total": logged_total,
        "last_hour": last,
        "peak": peak,
        "stats": {
            "mean_events": round(sum(events) / 24.0, 2),
            "median_events": _median(events),
            "max_events": events[peak_idx],
            "hours_active": sum(1 for count in events if count),
            "events_per_source": round(total / n_src, 2) if n_src else 0.0,
            "last_hour_events": last["events"],
            "last_hour_sources": last["sources"],
            "peak_idx": peak_idx,
            "peak_label": peak["label"],
            "peak_events": peak["events"],
            "peak_sources": peak["sources"],
        },
    }


def _action_items(engine: dict, rows: list[dict], origin: list[dict]) -> list[dict]:
    items = [
        {
            "id": "bot-off",
            "severity": "Low",
            "title": "Bot detection/challenge stays OFF",
            "tags": ["Operator policy", "Bot traffic"],
            "kind": "policy",
            "view": "engine",
        },
        {
            "id": "crs-oob",
            "severity": "Low",
            "title": "CRS stays out-of-band (detect/log, do not ban)",
            "tags": ["Operator policy", "Web app exploits"],
            "kind": "policy",
            "view": "engine",
        },
    ]
    if not engine.get("fail_closed"):
        items.insert(0, {
            "id": "fail-open",
            "severity": "High",
            "title": "Fail-closed is not reported by the engine",
            "tags": ["Engine"],
            "kind": "insight",
            "view": "engine",
        })
    env_ips = {
        str(r.get("ip") or "")
        for r in rows
        if "/.env" in (r.get("path") or "") or "/.aws/" in (r.get("path") or "")
    }
    env_ips.discard("")
    if env_ips:
        n = len(env_ips)
        items.append({
            "id": "env-probe",
            "severity": "Medium",
            "title": "Secret-file probes (/.env, /.aws) — %s source%s" % (n, "" if n == 1 else "s"),
            "tags": ["Security insight", "Active scanning"],
            "kind": "insight",
            "view": "alerts",
        })
    down = [p.get("host") for p in origin if isinstance(p, dict) and not _probe_ok(p.get("status"))]
    if down:
        items.append({
            "id": "origin-down",
            "severity": "High",
            "title": "Origin probe failed: " + ", ".join(str(h) for h in down[:4]),
            "tags": ["Origin"],
            "kind": "insight",
            "view": "domains",
        })
    ja4 = Counter(r.get("ja4h") for r in rows if r.get("ja4h"))
    if ja4:
        label, count = ja4.most_common(1)[0]
        sources = len({str(r.get("ip") or "") for r in rows if r.get("ja4h") == label and r.get("ip")})
        if count >= 8 and count >= max(4, int(0.4 * len(rows))):
            items.append({
                "id": "ja4-repeat",
                "severity": "Medium",
                "title": "Repeated JA4H fingerprint (%s events, %s source%s)" % (
                    count, sources, "" if sources == 1 else "s"
                ),
                "tags": ["Security insight", "Client fingerprint"],
                "kind": "insight",
                "view": "alerts",
                "detail": label[:48],
            })
    return items


def _detection_tools(engine: dict, rows: list[dict], hub: list[str]) -> list[dict]:
    hub_l = " ".join(hub).lower()
    appsec = bool(engine.get("appsec_listen"))
    oob = bool(engine.get("oob_log_only"))
    blocked_ips = {str(r.get("ip") or "") for r in rows if r.get("action") == "Block"}
    blocked_ips.discard("")
    exploits = len(blocked_ips)
    return [
        {
            "id": "bot",
            "name": "Bot traffic",
            "status": "off",
            "running": False,
            "count": 0,
            "note": "CrowdSec 1.8 bot challenge remains OFF (operator policy).",
        },
        {
            "id": "exploits",
            "name": "Web app exploits",
            "status": "running" if appsec else "down",
            "running": appsec,
            "count": exploits,
            "note": "Unique source IPs with a Block decision. OOB log-only matches are not counted as exploits.",
        },
        {
            "id": "ddos",
            "name": "HTTP floods",
            "status": "running" if ("http-dos" in hub_l or "ddos" in hub_l) else "limited",
            "running": "http-dos" in hub_l or "ddos" in hub_l,
            "count": 0,
            "note": "No volumetric DDoS feed. Local HTTP scenarios only.",
        },
        {
            "id": "api",
            "name": "API abuse",
            "status": "running" if appsec else "down",
            "running": appsec,
            "count": 0,
            "note": "Covered by AppSec on in-scope FQDNs.",
        },
        {
            "id": "client",
            "name": "Client-side abuse",
            "status": "off",
            "running": False,
            "count": 0,
            "note": "Not in the CrowdSec band.",
        },
        {
            "id": "fraud",
            "name": "Fraud protection",
            "status": "off",
            "running": False,
            "count": 0,
            "note": "Not in the CrowdSec band.",
        },
        {
            "id": "crs",
            "name": "CRS out-of-band",
            "status": "running" if oob else "check",
            "running": oob,
            "count": sum(1 for r in rows if r.get("action") == "Log"),
            "note": "Detect/log only. UI cannot enable in-band CRS.",
        },
    ]


def _appsec_perf(appsec: dict | None) -> dict:
    mx = appsec or {}
    in_sum = float(mx.get("cs_appsec_inband_parsing_time_seconds_sum") or 0)
    in_n = float(mx.get("cs_appsec_inband_parsing_time_seconds_count") or 0)
    out_sum = float(mx.get("cs_appsec_outband_parsing_time_seconds_sum") or 0)
    out_n = float(mx.get("cs_appsec_outband_parsing_time_seconds_count") or 0)
    inspected = int(mx.get("cs_appsec_reqs_total") or 0)
    return {
        "available": bool(mx),
        "lifetime": True,
        "inspected": inspected,
        "blocks": int(mx.get("cs_appsec_block_total") or mx.get("cs_appsec_blocks_total") or 0),
        "rule_hits": int(mx.get("cs_appsec_rule_hits") or 0),
        "inband_ms": round(1000.0 * in_sum / in_n, 3) if in_n else 0,
        "outband_ms": round(1000.0 * out_sum / out_n, 3) if out_n else 0,
        "note": "CrowdSec AppSec process lifetime — not 24 h request volume.",
    }


def build(
    alerts: list,
    *,
    decisions: list | None = None,
    engine: dict | None = None,
    hosts: list[str] | None = None,
    host: str = "",
    origin_probes: list | None = None,
    public_probes: list | None = None,
    hub_rules: list[str] | None = None,
    now: datetime | None = None,
    filters: dict | None = None,
    appsec: dict | None = None,
    edge: dict | None = None,
) -> dict:
    engine = engine or {}
    filters = {k: str((filters or {}).get(k) or "").strip() for k in _FILTER_KEYS}
    hosts = [_clean_host(h) for h in (hosts or []) if h]
    host = _clean_host(host)
    if host and hosts and host not in hosts and not any(host.endswith("." + h) or h.endswith("." + host) for h in hosts):
        host = ""
    now = now or datetime.now(timezone.utc)
    decisions = [d for d in (decisions or []) if isinstance(d, dict)]
    origin = [p for p in (origin_probes or []) if isinstance(p, dict)]
    public = [p for p in (public_probes or []) if isinstance(p, dict)]
    hub_rules = [str(x) for x in (hub_rules or [])]

    rows = []
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        alert = enrich_alert(dict(alert))
        if not _match_host(alert, host):
            continue
        dt = _parse_time(alert)
        src = alert.get("source") if isinstance(alert.get("source"), dict) else {}
        ip = src.get("ip") or src.get("value") or ""
        cn = str(alert.get("cn") or src.get("cn") or src.get("country") or "").upper()
        http = http_of(alert)
        row = {
            "when": alert.get("created_at") or "",
            "ip": ip,
            "host": alert.get("host") or http.get("host") or "",
            "path": alert.get("path") or http.get("path") or "",
            "country": cn,
            "action": alert.get("action") or "Alert",
            "service": alert.get("service") or http.get("service") or "",
            "method": http.get("method") or "",
            "ua": http.get("ua") or "",
            "ja4h": http.get("ja4h") or "",
            "http_version": http.get("http_version") or "",
            "status": http.get("status") or "",
            "asn": http.get("asn") or src.get("as_name") or "",
            "zones": http.get("zones") or "",
            "data": http.get("data") or "",
            "rule_ids": http.get("rule_ids") or "",
            "scenario": alert.get("scenario") or "",
            "scanner": "",
            "_dt": dt,
        }
        if not _match_filters(row, filters):
            continue
        rows.append(row)

    ips, paths, countries, host_counts = Counter(), Counter(), Counter(), Counter()
    browsers, oses, devices, methods, versions, cache, statuses = Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    services, actions, uas, asns, ja4s, zones = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    ua_present = method_present = status_present = version_present = ja4_present = asn_present = False
    for row in rows:
        if row["ip"]:
            ips[row["ip"]] += 1
        if row["path"]:
            paths[row["path"]] += 1
        if row["country"]:
            countries[row["country"]] += 1
        if row["host"]:
            host_counts[row["host"]] += 1
        if row["service"]:
            services[row["service"]] += 1
        actions[row["action"]] += 1
        if row["method"]:
            method_present = True
            methods[row["method"]] += 1
        if row["status"]:
            status_present = True
            statuses[row["status"]] += 1
        if row["http_version"]:
            version_present = True
            versions[row["http_version"]] += 1
        if row["ja4h"]:
            ja4_present = True
            ja4s[row["ja4h"][:40]] += 1
        if row["asn"]:
            asn_present = True
            asns[row["asn"]] += 1
        if row["zones"]:
            zones[row["zones"]] += 1
        if row["ua"]:
            ua_present = True
            uas[row["ua"][:72]] += 1
            browser, os_name, device = classify_ua(row["ua"])
            if browser:
                browsers[browser] += 1
            if os_name:
                oses[os_name] += 1
            if device:
                devices[device] += 1

    blocked = actions.get("Block", 0)
    logged = actions.get("Log", 0)
    total = len(rows)
    origin_ok = sum(1 for p in origin if _probe_ok(p.get("status")))
    origin_n = len(origin)
    series = _hour_series(rows, now)
    scanners = _scanner_pack(rows, now, series.get("labels") or [])
    logs = [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows[:100]]
    edge_pack = None
    if isinstance(edge, dict) and edge.get("label"):
        edge_pack = {
            "available": True,
            "items": [{"label": str(edge.get("label")), "count": total, "pct": 100.0}],
        }
    else:
        edge_pack = _pack(Counter(), False)

    return {
        "ok": True,
        "source": SOURCE,
        "note": NOTE,
        "window": "24h",
        "window_label": "Last 24 hours · GMT-3",
        "host": host,
        "hosts": hosts,
        "filters": {k: v for k, v in filters.items() if v},
        "generated_at": int(now.timestamp()),
        "kpis": {
            "events": total,
            "blocked": blocked,
            "logged": logged,
            "alerts": actions.get("Alert", 0),
            "local_decisions": len(decisions),
            "origin_ok": origin_ok,
            "origin_n": origin_n,
        },
        "traffic": {
            "total": total,
            "blocked": blocked,
            "logged": logged,
            "alerted": actions.get("Alert", 0),
        },
        "series": series,
        "scanners": scanners,
        "top": {
            "ips": _pack(ips, True),
            "paths": _pack(paths, True),
            "countries": _pack(countries, True),
            "hosts": _pack(host_counts, True),
            "browsers": _pack(browsers, ua_present),
            "os": _pack(oses, ua_present),
            "devices": _pack(devices, ua_present),
            "user_agents": _pack(uas, ua_present, 6),
            "methods": _pack(methods, method_present),
            "http_versions": _pack(versions, version_present),
            "cache": _pack(cache, False),
            "status": _pack(statuses, status_present),
            "asns": _pack(asns, asn_present),
            "ja4h": _pack(ja4s, ja4_present),
            "zones": _pack(zones, bool(zones)),
            "services": _pack(services, True),
            "actions": _pack(actions, True),
            "datacenters": edge_pack if edge_pack.get("available") else _pack(Counter(), False),
        },
        "logs": logs,
        "events": logs,
        "origin": origin,
        "public": public,
        "appsec": _appsec_perf(appsec),
        "action_items": _action_items(engine, rows, origin),
        "detection_tools": _detection_tools(engine, rows, hub_rules),
        "bot_challenge": False,
        "crs_inband": False,
    }
