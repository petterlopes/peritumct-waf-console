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
        "tactic": "Reconnaissance",
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

# First-match CrowdSec scenario / AppSec / CRS ID mapping.
_CLASSIFY_RULES: list[tuple[re.Pattern[str], str, list[str], str]] = [
    (re.compile(r"ssrf|934", re.I), "A10", ["T1190", "T1090"], "high"),
    (re.compile(r"tls|ssl|weak.?crypto", re.I), "A02", ["T1600"], "medium"),
    (re.compile(r"sqli|942", re.I), "A03", ["T1190", "T1059"], "high"),
    (re.compile(r"xss|941", re.I), "A03", ["T1189", "T1059"], "high"),
    (re.compile(r"rce|932|933", re.I), "A03", ["T1190", "T1059", "T1068"], "high"),
    (re.compile(r"lfi|930", re.I), "A01", ["T1083", "T1190"], "high"),
    (re.compile(r"rfi|931", re.I), "A01", ["T1190", "T1505"], "high"),
    (re.compile(r"wordpress-uploads-listing|backdoor", re.I), "A01", ["T1505", "T1505.003"], "high"),
    (re.compile(r"vpatch|cve|wordpress", re.I), "A06", ["T1190"], "medium"),
    (re.compile(r"brute|ssh", re.I), "A07", ["T1110"], "high"),
    (re.compile(r"body.?inspect|upload", re.I), "A08", ["T1505", "T1505.003"], "medium"),
    (re.compile(r"oob|log-only|outofband", re.I), "A09", ["T1562"], "low"),
    (re.compile(r"probing|scanner", re.I), "A05", ["T1595", "T1046"], "medium"),
]

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


def _owasp_meta(code: str) -> dict[str, str]:
    return dict(_OWASP_BY_CODE.get(code) or {"code": code, "id": "", "name": "", "url": ""})


def classify(name: str | None) -> dict[str, Any]:
    """Map a CrowdSec scenario / AppSec / CRS name to OWASP Top 10:2021."""
    text = str(name or "").strip()
    if not text:
        return dict(_NONE)
    for pattern, code, attack, confidence in _CLASSIFY_RULES:
        if pattern.search(text):
            meta = _owasp_meta(code)
            return {
                "code": code,
                "id": meta.get("id") or "",
                "name": meta.get("name") or "",
                "url": meta.get("url") or "",
                "attack": list(attack),
                "confidence": confidence,
            }
    return dict(_NONE)


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
            "Local ATT&CK Enterprise catalog (T1190–T1505.003). No GitHub download.",
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
    attack_counts: dict[str, int] = {tid: 0 for tid in ATTACK}
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        name = _alert_name(alert)
        hit = classify(name)
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
        if hit["code"] in catalog:
            catalog[hit["code"]]["count"] += 1
        for tid in finding["attack"]:
            if tid in attack_counts:
                attack_counts[tid] += 1
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
