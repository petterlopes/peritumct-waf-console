#!/usr/bin/env python3
"""OWASP Top 10:2021 correlation + OpenCTI-inspired local CTI export.

CrowdSec LAPI/AppSec findings are classified against OWASP Top 10:2021 and a
local MITRE ATT&CK catalog. Connectors follow OpenCTI class names
(INTERNAL_ENRICHMENT, EXTERNAL_IMPORT, STREAM, INTERNAL_EXPORT_FILE) but only
perform local enrichment and file export. Findings are never pushed outbound.
API tokens/keys are never included in JSON payloads.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

OWASP_SOURCE = "https://owasp.org/Top10/2021/"

OWASP_2021: list[dict[str, str]] = [
    {
        "code": "A01",
        "id": "A01:2021",
        "name": "Broken Access Control",
        "url": "https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control.html",
    },
    {
        "code": "A02",
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "url": "https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures.html",
    },
    {
        "code": "A03",
        "id": "A03:2021",
        "name": "Injection",
        "url": "https://owasp.org/Top10/2021/A03_2021-Injection.html",
    },
    {
        "code": "A04",
        "id": "A04:2021",
        "name": "Insecure Design",
        "url": "https://owasp.org/Top10/2021/A04_2021-Insecure_Design.html",
    },
    {
        "code": "A05",
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration.html",
    },
    {
        "code": "A06",
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "url": "https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components.html",
    },
    {
        "code": "A07",
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "url": "https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures.html",
    },
    {
        "code": "A08",
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "url": "https://owasp.org/Top10/2021/A08_2021-Software_and_Data_Integrity_Failures.html",
    },
    {
        "code": "A09",
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "url": "https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures.html",
    },
    {
        "code": "A10",
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "url": "https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29.html",
    },
]

# Local ATT&CK catalog — do not download MITRE GitHub at runtime.
# Tactics are ATT&CK Enterprise; tiles stay listed even when count is 0.
ATTACK: dict[str, dict[str, str]] = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1083": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1189": {
        "id": "T1189",
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1189/",
    },
    "T1505": {
        "id": "T1505",
        "name": "Server Software Component",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1505/",
    },
    "T1090": {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1090/",
    },
    "T1562": {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1562/",
    },
    "T1600": {
        "id": "T1600",
        "name": "Weaken Encryption",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1600/",
    },
    "T1068": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1505.003": {
        "id": "T1505.003",
        "name": "Web Shell",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
    },
}

_TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Command and Control",
]

# Engine / CAPI chatter — never an OWASP or ATT&CK finding.
_NOISE_RE = re.compile(
    r"(?is)^\s*(?:"
    r"enabling body inspection"
    r"|disabl(?:e|ing) body inspection"
    r"|update\s*:\s*[+-]\d+"
    r"|(?:capi|community).{0,48}(?:blocklist|ips)"
    r"|synced \d+"
    r"|loading (?:parsers|scenarios|collections)"
    r"|crowdsec (?:started|version)"
    r"|capacity overflow"
    r"|bucket overflow"
    r")"
)

# CRS 3.x IDs are six digits (934100). Do not match CVE-2024-9341.
_CRS_ID_RE = re.compile(
    r"\b(?P<gid>913|920|921|930|931|932|933|934|941|942|943|944)\d{3}\b"
)
_CRS_CLASS: dict[str, tuple[str, list[str], str]] = {
    "913": ("A05", ["T1595"], "medium"),
    "920": ("A05", ["T1595"], "medium"),
    "921": ("A05", ["T1595"], "medium"),
    "930": ("A01", ["T1190"], "high"),
    "931": ("A03", ["T1190"], "high"),
    "932": ("A03", ["T1190", "T1059", "T1068"], "high"),
    "933": ("A03", ["T1190", "T1059"], "high"),
    "934": ("A10", ["T1190"], "high"),
    "941": ("A03", ["T1190"], "high"),
    "942": ("A03", ["T1190"], "high"),
    "943": ("A07", ["T1110"], "medium"),
    "944": ("A03", ["T1190"], "high"),
}

# Specific Hub / AppSec names first. No bare CRS digits, ssh, ssl, oob, or upload.
_CLASSIFY_RULES: list[tuple[re.Pattern[str], str, list[str], str]] = [
    (re.compile(r"ssrf", re.I), "A10", ["T1190"], "high"),
    (re.compile(r"sqli|sql.?inject", re.I), "A03", ["T1190"], "high"),
    (re.compile(r"xss|cross.?site.?script", re.I), "A03", ["T1190"], "high"),
    (re.compile(r"rce|remote.?code|command.?inject|php.?inject|log4j|jndi", re.I), "A03", ["T1190", "T1059", "T1068"], "high"),
    (re.compile(r"lfi|path.?traversal|directory.?traversal|local.?file.?inclusion", re.I), "A01", ["T1190"], "high"),
    (re.compile(r"rfi|remote.?file.?inclusion", re.I), "A03", ["T1190"], "high"),
    (re.compile(r"webshell|backdoor", re.I), "A01", ["T1505", "T1505.003"], "high"),
    (re.compile(r"wordpress-uploads-listing", re.I), "A01", ["T1190"], "high"),
    (re.compile(r"env-access|sensitive.?files|admin.?interface|git-config", re.I), "A01", ["T1190"], "high"),
    (re.compile(r"wordpress.?login", re.I), "A07", ["T1110"], "high"),
    (re.compile(r"brute(?:[-_ ]?force)?|\bbf\b|[-_/]bf(?:[-_/]|$)|ssh-slow-bf|ssh-bf", re.I), "A07", ["T1110"], "high"),
    (re.compile(r"xmlrpc", re.I), "A05", ["T1595"], "medium"),
    (re.compile(r"waf.?bypass|disable.?security|impair.?defense", re.I), "A05", ["T1562"], "medium"),
    (re.compile(r"weak.?crypto|insecure.?tls", re.I), "A02", ["T1600"], "medium"),
    (re.compile(r"vpatch|cve-\d{4}", re.I), "A06", ["T1190"], "medium"),
    (re.compile(r"wordpress.?scan|http-wordpress", re.I), "A05", ["T1595"], "medium"),
    (re.compile(r"wordpress", re.I), "A06", ["T1190"], "medium"),
    (re.compile(r"probing|scanner|http-crawl|bad-user-agent|open-proxy|http-scan", re.I), "A05", ["T1595"], "medium"),
]
_MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_OOB_RE = re.compile(r"out-of-band|outofband|\boob\b|log-only", re.I)

_NONE: dict[str, Any] = {
    "code": "none",
    "id": "",
    "name": "",
    "url": "",
    "attack": [],
    "confidence": "none",
}

_OWASP_BY_CODE = {item["code"]: item for item in OWASP_2021}

_SECRET_KEY_RE = re.compile(r"(token|key|password|secret|authorization|credential)", re.I)


def _scenario_family(name: str) -> str:
    """Collapse repeated AppSec OOB score lines into one incident family."""
    text = str(name or "").strip()
    low = text.lower()
    if "out-of-band" in low or "outofband" in low or re.search(r"\boob\b", low):
        for token, family in (
            ("lfi", "appsec-oob-lfi"),
            ("rfi", "appsec-oob-rfi"),
            ("xss", "appsec-oob-xss"),
            ("sqli", "appsec-oob-sqli"),
            ("ssrf", "appsec-oob-ssrf"),
            ("rce", "appsec-oob-rce"),
        ):
            if token in low:
                return family
        return "appsec-oob"
    return text


def _collapse_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per source IP + OWASP; merge ATT&CK ids and event tallies."""
    merged: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    rank = {"high": 3, "medium": 2, "low": 1, "none": 0}
    for item in findings:
        key = (str(item.get("ip") or ""), str(item.get("owasp") or ""))
        if key not in merged:
            row = dict(item)
            row["events"] = int(item.get("events") or 1)
            row["attack"] = [tid for tid in ATTACK if tid in set(item.get("attack") or [])]
            merged[key] = row
            order.append(key)
            continue
        row = merged[key]
        row["events"] = int(row.get("events") or 1) + int(item.get("events") or 1)
        seen = set(row.get("attack") or []) | set(item.get("attack") or [])
        row["attack"] = [tid for tid in ATTACK if tid in seen]
        incoming = str(item.get("when") or "")
        if incoming > str(row.get("when") or ""):
            row["when"] = incoming
        if rank.get(str(item.get("confidence") or ""), 0) > rank.get(str(row.get("confidence") or ""), 0):
            row["confidence"] = item.get("confidence")
        incoming_name = str(item.get("scenario") or "")
        current_name = str(row.get("scenario") or "")
        # Prefer the in-band Hub name over CrowdSec OOB "lfi" on /.env probes.
        if _OOB_RE.search(current_name) and incoming_name and not _OOB_RE.search(incoming_name):
            row["scenario"] = incoming_name
    return [merged[key] for key in order]


def _recount(catalog: dict[str, dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, int]:
    """OWASP/ATT&CK tiles count unique source IPs, not repeated LAPI rows."""
    for item in catalog.values():
        item["count"] = 0
    owasp_ips: dict[str, set[str]] = {code: set() for code in catalog}
    attack_ips: dict[str, set[str]] = {tid: set() for tid in ATTACK}
    for finding in findings:
        ip = str(finding.get("ip") or "").strip()
        token = ip or "finding:%s|%s" % (finding.get("scenario"), finding.get("when"))
        code = str(finding.get("owasp") or "")
        if code in owasp_ips:
            owasp_ips[code].add(token)
        for tid in finding.get("attack") or []:
            if tid in attack_ips:
                attack_ips[tid].add(token)
    for code, seen in owasp_ips.items():
        catalog[code]["count"] = len(seen)
    return {tid: len(seen) for tid, seen in attack_ips.items()}


def _owasp_meta(code: str) -> dict[str, str]:
    return dict(_OWASP_BY_CODE.get(code) or {"code": code, "id": "", "name": "", "url": ""})


def _hit(code: str, attack: list[str], confidence: str) -> dict[str, Any]:
    meta = _owasp_meta(code)
    seen: set[str] = set()
    techniques: list[str] = []
    for tid in attack:
        if tid in ATTACK and tid not in seen:
            seen.add(tid)
            techniques.append(tid)
    return {
        "code": code,
        "id": meta.get("id") or "",
        "name": meta.get("name") or "",
        "url": meta.get("url") or "",
        "attack": techniques,
        "confidence": confidence,
    }


def is_noise_event(name: str | None) -> bool:
    """True for CrowdSec engine/CAPI chatter that is not an attack finding."""
    text = str(name or "").strip()
    if not text:
        return True
    return bool(_NOISE_RE.search(text))


def _mitre_from_alert(alert: dict | None) -> list[str]:
    """Hub/LAPI MITRE IDs already in the local catalog. Ignore unknown IDs."""
    if not isinstance(alert, dict):
        return []
    chunks: list[str] = []
    for key in ("labels", "tags"):
        val = alert.get(key)
        if isinstance(val, list):
            chunks.extend(str(item) for item in val)
        elif val:
            chunks.append(str(val))
    meta = alert.get("meta")
    if isinstance(meta, list):
        for item in meta:
            if isinstance(item, dict):
                chunks.append(str(item.get("key") or ""))
                chunks.append(str(item.get("value") or ""))
    elif isinstance(meta, dict):
        for key, val in meta.items():
            chunks.append(str(key))
            chunks.append(str(val))
    found: list[str] = []
    seen: set[str] = set()
    for chunk in chunks:
        for match in _MITRE_ID_RE.findall(str(chunk)):
            parsed = re.match(r"t(\d{4}(?:\.\d{3})?)$", match, re.I)
            if not parsed:
                continue
            tid = "T" + parsed.group(1)
            if tid in ATTACK and tid not in seen:
                seen.add(tid)
                found.append(tid)
    return found


def classify(name: str | None, alert: dict | None = None) -> dict[str, Any]:
    """Map a CrowdSec scenario / AppSec / CRS name to OWASP Top 10:2021.

    Engine chatter returns none. CRS IDs must be six digits. Hub MITRE labels
    in the alert override regex ATT&CK IDs when they are in the local catalog.
    """
    text = str(name or "").strip()
    if not text or is_noise_event(text):
        return dict(_NONE)
    hit: dict[str, Any] | None = None
    crs = _CRS_ID_RE.search(text)
    if crs:
        mapped = _CRS_CLASS.get(crs.group("gid"))
        if mapped:
            hit = _hit(*mapped)
    if hit is None:
        for pattern, code, attack, confidence in _CLASSIFY_RULES:
            if pattern.search(text):
                hit = _hit(code, attack, confidence)
                break
    if hit is None:
        hit = dict(_NONE)
    hub = _mitre_from_alert(alert)
    if hub:
        hit["attack"] = hub
        if hit["confidence"] == "none":
            hit["confidence"] = "medium"
    if hit["code"] != "none" and _OOB_RE.search(text):
        if hit["confidence"] == "high":
            hit["confidence"] = "medium"
        # Log-only AppSec matches are detections, not confirmed exploits.
        # Hub MITRE labels already applied above still win.
        if not hub and hit.get("attack"):
            hit["attack"] = ["T1595"]
    return hit


def _alert_ip(alert: dict) -> str:
    src = alert.get("source") if isinstance(alert.get("source"), dict) else {}
    ip = src.get("ip") or src.get("value") or ""
    if ip:
        return str(ip)
    events = alert.get("events") or []
    if events and isinstance(events[0], dict):
        ev_src = events[0].get("source") if isinstance(events[0].get("source"), dict) else {}
        return str(ev_src.get("ip") or ev_src.get("value") or "")
    return ""


def _alert_geo(alert: dict) -> tuple[str, str]:
    """Country ISO + city from LAPI source (cheap; empty string when absent)."""
    src = alert.get("source") if isinstance(alert.get("source"), dict) else {}
    cn = src.get("cn") or src.get("country") or ""
    city = src.get("city") or ""
    if not cn or not city:
        events = alert.get("events") or []
        if events and isinstance(events[0], dict):
            ev_src = events[0].get("source") if isinstance(events[0].get("source"), dict) else {}
            if not cn:
                cn = ev_src.get("cn") or ev_src.get("country") or ""
            if not city:
                city = ev_src.get("city") or ""
    return str(cn or "").strip().upper(), str(city or "").strip()


def _alert_name(alert: dict) -> str:
    name = alert.get("scenario") or alert.get("reason") or ""
    if name:
        return str(name)
    decisions = alert.get("decisions") or []
    if decisions and isinstance(decisions[0], dict):
        return str(decisions[0].get("scenario") or decisions[0].get("reason") or "")
    return ""


def _env_url(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _connector(
    ctype: str,
    name: str,
    scope: str,
    status: str,
    note: str,
) -> dict[str, Any]:
    return {
        "type": ctype,
        "name": name,
        "scope": scope,
        "status": status,
        "note": note,
        "push": False,
    }


def connectors() -> list[dict[str, Any]]:
    """OpenCTI-style connector inventory. Local enrichment + file export only.

    Status is ``configured`` only when the matching env URL is set.
    Keys/tokens are read solely to decide nothing about status and are never
    copied into the payload. ``push`` is always False.
    """
    misp = "configured" if _env_url("WAF_MISP_URL") else "unconfigured"
    hive = "configured" if _env_url("WAF_THEHIVE_URL") else "unconfigured"
    opencti = "configured" if _env_url("WAF_OPENCTI_URL") else "unconfigured"
    # Touch key env names so operators can set them without leaking values.
    _env_url("WAF_MISP_KEY")
    _env_url("WAF_THEHIVE_KEY")
    _env_url("WAF_OPENCTI_TOKEN")
    return [
        _connector(
            "INTERNAL_ENRICHMENT",
            "MITRE ATT&CK",
            "local-catalog",
            "configured",
            "Local ATT&CK Enterprise subset. Tactics match attack.mitre.org. No GitHub download.",
        ),
        _connector(
            "INTERNAL_ENRICHMENT",
            "OWASP Top 10:2021",
            "local-catalog",
            "configured",
            "CrowdSec scenario/AppSec/CRS IDs mapped to A01–A10. " + OWASP_SOURCE,
        ),
        _connector(
            "INTERNAL_EXPORT_FILE",
            "MISP",
            "file-export",
            misp,
            "Download MISP event JSON. No outbound push of findings.",
        ),
        _connector(
            "INTERNAL_EXPORT_FILE",
            "TheHive",
            "file-export",
            hive,
            "Download TheHive alert JSON. No outbound push of findings.",
        ),
        _connector(
            "INTERNAL_EXPORT_FILE",
            "OpenCTI",
            "file-export",
            opencti,
            "Download STIX 2.1 bundle. No outbound push of findings.",
        ),
        _connector(
            "EXTERNAL_IMPORT",
            "OpenCTI import",
            "disabled",
            "unconfigured",
            "Inbound connector import is not enabled.",
        ),
        _connector(
            "STREAM",
            "OpenCTI stream",
            "disabled",
            "unconfigured",
            "Live stream push is not enabled.",
        ),
    ]


def _scrub(value: Any) -> Any:
    """Drop secret-looking keys so tokens never appear in JSON."""
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


def correlate(alerts, hub_rules=None) -> dict[str, Any]:
    """Correlate CrowdSec alerts with OWASP Top 10:2021 and local ATT&CK."""
    catalog: dict[str, dict[str, Any]] = {}
    for item in OWASP_2021:
        catalog[item["code"]] = {
            "code": item["code"],
            "id": item["id"],
            "name": item["name"],
            "url": item["url"],
            "count": 0,
            "hub_rules": [],
        }
    for rule in hub_rules or []:
        hit = classify(str(rule))
        if hit["code"] in catalog:
            catalog[hit["code"]]["hub_rules"].append(str(rule))
    findings: list[dict[str, Any]] = []
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        name = _alert_name(alert)
        if is_noise_event(name):
            continue
        hit = classify(name, alert)
        if hit["code"] == "none" and not hit.get("attack"):
            continue
        cn, city = _alert_geo(alert)
        finding = {
            "when": alert.get("created_at") or alert.get("start_at") or "",
            "ip": _alert_ip(alert),
            "cn": cn,
            "city": city,
            "scenario": name,
            "owasp": hit["code"],
            "attack": list(hit.get("attack") or []),
            "confidence": hit.get("confidence") or "none",
        }
        findings.append(finding)
    findings = _collapse_findings(findings)
    attack_counts = _recount(catalog, findings)
    attack_list = [
        {
            "id": tid,
            "name": ATTACK[tid]["name"],
            "url": ATTACK[tid]["url"],
            "count": attack_counts[tid],
        }
        for tid in ATTACK
    ]
    payload = {
        "ok": True,
        "source": OWASP_SOURCE,
        "push": False,
        "owasp": list(catalog.values()),
        "findings": findings,
        "attack": attack_list,
        "mitre": _mitre_block(findings, attack_counts),
        "connectors": connectors(),
    }
    return _scrub(payload)


def _mitre_block(findings: list[dict[str, Any]], attack_counts: dict[str, int]) -> dict[str, Any]:
    """Full local ATT&CK catalog with counts (0 = uncovered tile) plus tactic rollup."""
    tech_owasp: dict[str, set[str]] = {tid: set() for tid in ATTACK}
    for finding in findings:
        code = str(finding.get("owasp") or "")
        for tid in finding.get("attack") or []:
            if tid in tech_owasp and code and code != "none":
                tech_owasp[tid].add(code)
    techniques: list[dict[str, Any]] = []
    for tid, meta in ATTACK.items():
        techniques.append(
            {
                "id": tid,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "url": meta["url"],
                "count": attack_counts.get(tid, 0),
                "owasp": sorted(tech_owasp[tid]),
            }
        )
    tactic_map: dict[str, dict[str, Any]] = {}
    for tech in techniques:
        name = tech["tactic"]
        bucket = tactic_map.setdefault(name, {"name": name, "count": 0, "techniques": []})
        bucket["count"] += int(tech["count"] or 0)
        bucket["techniques"].append(tech["id"])
    tactics = [tactic_map[name] for name in _TACTIC_ORDER if name in tactic_map]
    uncovered = [tech["id"] for tech in techniques if not tech["count"]]
    return {
        "techniques": techniques,
        "tactics": tactics,
        "findings": findings,
        "uncovered": uncovered,
    }


def _stix_id(kind: str, seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8", "replace")).hexdigest()
    packed = digest[:32]
    uid = str(uuid.UUID(packed))
    return f"{kind}--{uid}"


def _now_stix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_bundle(payload) -> dict[str, Any]:
    """STIX 2.1 bundle for OpenCTI file import. Local export only."""
    payload = payload if isinstance(payload, dict) else {}
    now = _now_stix()
    identity_id = _stix_id("identity", "waf-console")
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "WAF Console",
            "identity_class": "system",
            "description": "Local CrowdSec WAF console. File export only; push=False.",
        }
    ]
    seen_attack: set[str] = set()
    seen_owasp: set[str] = set()
    for cat in payload.get("owasp") or []:
        code = str(cat.get("code") or "")
        if not code or code == "none":
            continue
        ap_id = _stix_id("attack-pattern", "owasp-" + code)
        seen_owasp.add(code)
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": f"{code}:2021 {cat.get('name') or ''}".strip(),
                "description": cat.get("url") or OWASP_SOURCE,
                "external_references": [
                    {
                        "source_name": "owasp",
                        "external_id": cat.get("id") or f"{code}:2021",
                        "url": cat.get("url") or OWASP_SOURCE,
                    }
                ],
            }
        )
    for tech in payload.get("attack") or []:
        tid = str(tech.get("id") or "")
        if not tid or tid in seen_attack:
            continue
        seen_attack.add(tid)
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": _stix_id("attack-pattern", "mitre-" + tid),
                "created": now,
                "modified": now,
                "name": tech.get("name") or tid,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": tech.get("url") or ATTACK.get(tid, {}).get("url") or "",
                    }
                ],
            }
        )
    for finding in payload.get("findings") or []:
        ip = str(finding.get("ip") or "").strip()
        scenario = str(finding.get("scenario") or "")
        seed = "|".join([str(finding.get("when") or ""), ip, scenario])
        indicator_id = _stix_id("indicator", seed or scenario or "finding")
        pattern = f"[ipv4-addr:value = '{ip}']" if ip else f"[x-waf-scenario:value = '{scenario or 'unknown'}']"
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": scenario or ip or "waf-finding",
                "description": "OWASP %s · ATT&CK %s · confidence %s"
                % (
                    finding.get("owasp") or "none",
                    ",".join(finding.get("attack") or []) or "none",
                    finding.get("confidence") or "none",
                ),
                "indicator_types": ["malicious-activity"],
                "pattern_type": "stix",
                "pattern": pattern,
                "valid_from": now,
            }
        )
        owasp_code = str(finding.get("owasp") or "")
        if owasp_code and owasp_code != "none":
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _stix_id("relationship", indicator_id + owasp_code),
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": _stix_id("attack-pattern", "owasp-" + owasp_code),
                }
            )
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", json.dumps(payload.get("findings") or [], sort_keys=True)[:800]),
        "objects": objects,
    }
    return _scrub(bundle)


def misp_event(payload) -> dict[str, Any]:
    """MISP event JSON for file import. Local export only."""
    payload = payload if isinstance(payload, dict) else {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    attributes: list[dict[str, Any]] = []
    tags = [{"name": "owasp:top10:2021"}, {"name": "tlp:amber"}]
    for finding in payload.get("findings") or []:
        ip = str(finding.get("ip") or "").strip()
        scenario = str(finding.get("scenario") or "")
        owasp = str(finding.get("owasp") or "none")
        comment = "%s · %s · %s" % (scenario, owasp, finding.get("confidence") or "")
        if ip:
            attributes.append(
                {
                    "type": "ip-src",
                    "category": "Network activity",
                    "value": ip,
                    "comment": comment,
                    "to_ids": True,
                }
            )
        if scenario:
            attributes.append(
                {
                    "type": "text",
                    "category": "Other",
                    "value": scenario,
                    "comment": comment,
                    "to_ids": False,
                }
            )
        for tid in finding.get("attack") or []:
            attributes.append(
                {
                    "type": "text",
                    "category": "External analysis",
                    "value": str(tid),
                    "comment": (ATTACK.get(str(tid)) or {}).get("name") or "ATT&CK",
                    "to_ids": False,
                }
            )
    event = {
        "Event": {
            "info": "WAF console CrowdSec findings (OWASP Top 10:2021)",
            "date": now,
            "threat_level_id": "2",
            "analysis": "1",
            "distribution": "0",
            "published": False,
            "Attribute": attributes,
            "Tag": tags,
            "Galaxy": [],
        },
        "push": False,
    }
    return _scrub(event)


def thehive_alert(payload) -> dict[str, Any]:
    """TheHive alert JSON for file import. Local export only."""
    payload = payload if isinstance(payload, dict) else {}
    findings = payload.get("findings") or []
    artifacts = []
    tags = ["waf-console", "crowdsec", "owasp-top10-2021"]
    for finding in findings:
        ip = str(finding.get("ip") or "").strip()
        scenario = str(finding.get("scenario") or "")
        if ip:
            artifacts.append(
                {
                    "dataType": "ip",
                    "data": ip,
                    "message": scenario or "crowdsec-alert",
                    "tags": [str(finding.get("owasp") or "none")],
                }
            )
        owasp = str(finding.get("owasp") or "")
        if owasp and owasp != "none" and owasp not in tags:
            tags.append("owasp:" + owasp)
        for tid in finding.get("attack") or []:
            tag = "attack:" + str(tid)
            if tag not in tags:
                tags.append(tag)
    alert = {
        "type": "waf-console",
        "source": "crowdsec-lapi",
        "sourceRef": "waf-findings-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "title": "WAF console CrowdSec findings",
        "description": "Local export of CrowdSec LAPI/AppSec findings correlated with OWASP Top 10:2021. push=False.",
        "severity": 2,
        "status": "New",
        "follow": False,
        "tags": tags,
        "artifacts": artifacts,
        "push": False,
    }
    return _scrub(alert)
