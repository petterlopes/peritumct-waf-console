#!/usr/bin/env python3
"""Operator WAF control plane: per-site AppSec filters, LAPI allowlists, manual bans.

Safe mutations only. Never CRS in-band, fail-closed, INCLUDE_LARGE_UPLOADS,
DisableBodyInspection, or CrowdSec 1.8 bot detection / challenge.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import catalog as catalog_mod
import netguard
import persist

CONFIG_ROOT = Path(os.environ.get("CROWDSEC_CONFIG", "/etc/crowdsec"))
CONTROL_DIR = Path(os.environ.get("WAF_CONTROL", "/var/lib/waf-control"))
FILTERS_JSON = CONTROL_DIR / "site-filters.json"
AUDIT_LOG = CONTROL_DIR / "audit.jsonl"
APPSEC_FILE = os.environ.get("WAF_APPSEC_FILE", "peritumct-site-filters.yaml")
APPSEC_NAME = os.environ.get("WAF_APPSEC_NAME", "peritumct/site-filters")
FILTERS_YAML = CONFIG_ROOT / "appsec-configs" / APPSEC_FILE
ACQUIS_PATH = CONFIG_ROOT / "acquis.d" / "appsec.yaml"
NOMAD = os.environ.get("NOMAD_BIN", "")
NOMAD_ADDR = os.environ.get("NOMAD_ADDR", "http://127.0.0.1:4646")
NOMAD_JOB = os.environ.get("WAF_CROWDSEC_JOB", "crowdsec")
CSCLI_BIN = os.environ.get("CROWDSEC_CSCLI", "")
ALLOWLIST_NAME = os.environ.get("WAF_ALLOWLIST", "cso-operators")
TRAEFIK_API = netguard.assert_loopback_http_url(
    os.environ.get("TRAEFIK_API", "http://127.0.0.1:8080/api/http/routers"),
    name="TRAEFIK_API",
)
APPSEC_PORT = int(os.environ.get("CROWDSEC_APPSEC_PORT", "7422"))


def catalog() -> dict:
    return catalog_mod.load_catalog()


def SITES() -> dict:
    return catalog()["sites"]


def OUT_OF_SCOPE() -> dict:
    return catalog()["out_of_scope"]


ACTIONS = ("allow_match", "skip_rule", "bypass_host")
HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,80}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/=-]{0,127}$")
RULE_RE = re.compile(r"^(crowdsecurity|peritumct)/[A-Za-z0-9._-]+$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")
DURATION_RE = re.compile(r"^(\d+)([hm])$")
FORBIDDEN = (
    "disablebodyinspection",
    "include_large_uploads",
    "crs-inband",
    "droprequest",
    "default_remediation",
    "nomad job run",
    "fail_closed",
)


def _utc() -> str:
    return persist.utc_now()


def audit(event: str, payload: dict) -> None:
    persist.audit(event, payload)


def load_filters() -> dict:
    if not FILTERS_JSON.is_file():
        return {"version": 1, "items": []}
    try:
        data = json.loads(FILTERS_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"version": 1, "items": []}
    if not isinstance(data, dict):
        return {"version": 1, "items": []}
    items = data.get("items") if isinstance(data.get("items"), list) else []
    return {"version": 1, "items": items}


def save_filters(store: dict) -> None:
    persist.atomic_write_text(FILTERS_JSON, json.dumps(store, ensure_ascii=False, indent=2) + "\n")


def _reject_forbidden(*parts: str) -> None:
    blob = " ".join(parts).lower()
    for token in FORBIDDEN:
        if token in blob:
            raise ValueError("forbidden operation: " + token)


def validate_host(host: str) -> str:
    host = (host or "").strip().lower()
    oos = OUT_OF_SCOPE()
    sites = SITES()
    if host in oos:
        raise ValueError("host out of WAF scope: " + host)
    if host not in sites:
        raise ValueError("host not in catalog")
    if not HOST_RE.match(host):
        raise ValueError("invalid host")
    return host


def validate_path(path: str) -> str:
    path = (path or "").strip()
    if not PATH_RE.match(path) or path == "/":
        raise ValueError("invalid path_prefix (must start with / and must not be only /)")
    if "//" in path or ".." in path:
        raise ValueError("invalid path_prefix")
    _reject_forbidden(path)
    return path


def validate_rule(name: str) -> str:
    name = (name or "").strip()
    if not RULE_RE.match(name):
        raise ValueError("invalid AppSec rule")
    _reject_forbidden(name)
    return name


def validate_cidr(value: str) -> str:
    raw = (value or "").strip()
    if "/" not in raw:
        raw += "/32"
    net = ipaddress.ip_network(raw, strict=False)
    if net.version != 4:
        raise ValueError("IPv4 only")
    if net.prefixlen < 16:
        raise ValueError("prefix too broad (minimum /16)")
    return str(net)


def validate_duration(value: str) -> str:
    match = DURATION_RE.match((value or "").strip())
    if not match:
        raise ValueError("invalid duration (e.g. 4h, 30m)")
    amount, unit = int(match.group(1)), match.group(2)
    hours = amount / 60 if unit == "m" else amount
    if hours <= 0 or hours > 168:
        raise ValueError("maximum duration is 168h")
    return f"{amount}{unit}"


def render_yaml(items: list) -> str:
    pre_eval = []
    on_match = []
    for item in items:
        if not item.get("enabled", True):
            continue
        host = validate_host(item["host"])
        action = item.get("action")
        reason = str(item.get("reason") or "cso")[:120].replace('"', "")
        pname = str(item.get("name") or item.get("id") or "policy")[:48]
        if action == "skip_rule":
            rule = validate_rule(item.get("rule") or "")
            path = item.get("path_prefix")
            filt = f'IsInBand == true && req.Host == "{host}"'
            if path:
                path = validate_path(path)
                filt += f' && req.URL.Path startsWith "{path}"'
            pre_eval.append((filt, rule, f"{pname}: {reason}"))
        elif action == "allow_match":
            path = validate_path(item.get("path_prefix") or "")
            filt = f'req.Host == "{host}" && req.URL.Path startsWith "{path}"'
            on_match.append((filt, f"{pname}: {reason}"))
        elif action == "bypass_host":
            filt = f'req.Host == "{host}"'
            on_match.append((filt, f"{pname}: {reason or 'bypass host'}"))
        else:
            raise ValueError("unknown action")
    lines = [
        "# Generated by peritumct-waf-console. Hooks only: allow path, skip named rule, host bypass.",
        f"name: {APPSEC_NAME}",
    ]
    if pre_eval:
        lines.append("pre_eval:")
        for filt, rule, reason in pre_eval:
            lines.append(f"  # {reason}")
            lines.append("  - filter: |")
            lines.append(f"      {filt}")
            lines.append("    apply:")
            lines.append(f'      - RemoveInBandRuleByName("{rule}")')
    if on_match:
        lines.append("on_match:")
        for filt, reason in on_match:
            lines.append(f"  # {reason}")
            lines.append("  - filter: |")
            lines.append(f"      {filt}")
            lines.append("    apply:")
            lines.append('      - SetRemediation("allow")')
            lines.append("      - CancelAlert()")
            lines.append("      - CancelEvent()")
    lines.append("")
    text = "\n".join(lines)
    _reject_forbidden(text)
    return text


def ensure_acquis() -> bool:
    text = ACQUIS_PATH.read_text(encoding="utf-8") if ACQUIS_PATH.is_file() else ""
    if re.search(r"^\s*-\s*crowdsecurity/crs-inband\b", text, re.M):
        raise RuntimeError("acquis lists crs-inband — refused")
    if APPSEC_NAME in text:
        return False
    if "crowdsecurity/crs" not in text:
        raise RuntimeError("unexpected AppSec acquis")
    backup = ACQUIS_PATH.with_suffix(".yaml.bak")
    backup.write_text(text, encoding="utf-8")
    updated = text.replace(
        "  - crowdsecurity/crs\n",
        "  - crowdsecurity/crs\n  - " + APPSEC_NAME + "\n",
        1,
    )
    if updated == text:
        updated = text.rstrip() + "\n  - " + APPSEC_NAME + "\n"
    persist.atomic_write_text(ACQUIS_PATH, updated)
    return True


def crowdsec_pids() -> list[int]:
    found = []
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmd = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if cmd.startswith("crowdsec ") or cmd.startswith("crowdsec\t"):
            found.append(int(entry.name))
    return found


def sighup_crowdsec() -> list[int]:
    pids = crowdsec_pids()
    if not pids:
        raise RuntimeError("CrowdSec PID missing (pid: host required)")
    for pid in pids:
        os.kill(pid, signal.SIGHUP)
    return pids


def wait_appsec(timeout: float = 12.0) -> bool:
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", APPSEC_PORT), timeout=1.2):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def apply_filters(store: dict) -> dict:
    yaml_text = render_yaml(store.get("items") or [])
    FILTERS_YAML.parent.mkdir(parents=True, exist_ok=True)
    previous = FILTERS_YAML.read_text(encoding="utf-8") if FILTERS_YAML.is_file() else ""
    persist.atomic_write_text(FILTERS_YAML, yaml_text)
    acquis_changed = ensure_acquis()
    try:
        pids = sighup_crowdsec()
        if not wait_appsec():
            raise RuntimeError("AppSec did not come back after HUP")
    except Exception:
        if previous:
            persist.atomic_write_text(FILTERS_YAML, previous)
            try:
                sighup_crowdsec()
            except OSError:
                pass
        raise
    result = {"ok": True, "pids": pids, "acquis_changed": acquis_changed, "yaml": str(FILTERS_YAML)}
    audit("filters.apply", {"count": len(store.get("items") or []), "acquis_changed": acquis_changed})
    return result


def validate_name(name: str) -> str:
    name = (name or "").strip().lower()
    if not name:
        return ""
    if not NAME_RE.match(name):
        raise ValueError("invalid policy name (a-z, 0-9, ._-; max 48)")
    _reject_forbidden(name)
    return name


def compose_policy(payload: dict, existing: dict | None = None) -> dict:
    action = str(payload.get("action") or (existing or {}).get("action") or "").strip()
    if action not in ACTIONS:
        raise ValueError("action must be allow_match, skip_rule or bypass_host")
    host = validate_host(str(payload.get("host") or (existing or {}).get("host") or ""))
    reason = str(payload.get("reason") or (existing or {}).get("reason") or "cso-console")[:120]
    _reject_forbidden(reason)
    name = validate_name(str(payload.get("name") or (existing or {}).get("name") or ""))
    item = {
        "id": (existing or {}).get("id") or uuid.uuid4().hex[:12],
        "name": name or f"{action}-{host.split('.')[0]}",
        "enabled": bool(payload["enabled"]) if "enabled" in payload else (existing or {}).get("enabled", True),
        "action": action,
        "host": host,
        "reason": reason,
        "created_at": (existing or {}).get("created_at") or _utc(),
        "updated_at": _utc(),
    }
    item.pop("path_prefix", None)
    item.pop("rule", None)
    item.pop("confirm", None)
    if action == "allow_match":
        item["path_prefix"] = validate_path(str(payload.get("path_prefix") or (existing or {}).get("path_prefix") or ""))
    elif action == "skip_rule":
        item["rule"] = validate_rule(str(payload.get("rule") or (existing or {}).get("rule") or ""))
        path = str(payload.get("path_prefix") if "path_prefix" in payload else (existing or {}).get("path_prefix") or "").strip()
        if path:
            item["path_prefix"] = validate_path(path)
    elif action == "bypass_host":
        if not payload.get("confirm") and not (existing or {}).get("confirm"):
            raise ValueError("bypass_host requires confirm=true")
        item["confirm"] = True
    return item


def _assert_unique_name(store: dict, name: str, exclude_id: str | None = None) -> None:
    for item in store.get("items") or []:
        if str(item.get("name") or "") != name:
            continue
        if exclude_id and str(item.get("id")) == str(exclude_id):
            continue
        raise ValueError("a policy with this name already exists")


def add_filter(payload: dict) -> dict:
    item = compose_policy(payload)
    store = load_filters()
    given = validate_name(str(payload.get("name") or ""))
    try:
        _assert_unique_name(store, item["name"])
    except ValueError:
        if given:
            raise
        item["name"] = f"{item['name']}-{item['id'][:6]}"
        _assert_unique_name(store, item["name"])
    store["items"].append(item)
    apply_filters(store)
    save_filters(store)
    audit("policy.create", item)
    return item


def update_filter(payload: dict) -> dict:
    fid = str(payload.get("id") or "").strip()
    if not fid:
        raise ValueError("id required to edit")
    store = load_filters()
    idx = next((i for i, x in enumerate(store["items"]) if str(x.get("id")) == fid), None)
    if idx is None:
        raise ValueError("policy not found")
    item = compose_policy(payload, existing=store["items"][idx])
    _assert_unique_name(store, item["name"], exclude_id=fid)
    store["items"][idx] = item
    apply_filters(store)
    save_filters(store)
    audit("policy.update", item)
    return item


def delete_filter(fid: str) -> dict:
    fid = str(fid or "").strip()
    store = load_filters()
    before = len(store["items"])
    store["items"] = [i for i in store["items"] if str(i.get("id")) != fid]
    if len(store["items"]) == before:
        raise ValueError("policy not found")
    apply_filters(store)
    save_filters(store)
    audit("policy.delete", {"id": fid})
    return {"ok": True, "id": fid}


def toggle_filter(fid: str, enabled: bool) -> dict:
    store = load_filters()
    found = None
    for item in store["items"]:
        if str(item.get("id")) == fid:
            item["enabled"] = bool(enabled)
            found = item
            break
    if not found:
        raise ValueError("policy not found")
    apply_filters(store)
    save_filters(store)
    audit("policy.toggle", {"id": fid, "enabled": enabled})
    return found


def nomad_alloc() -> str:
    if not NOMAD:
        raise RuntimeError("set CROWDSEC_CSCLI or NOMAD_BIN to run cscli")
    env = os.environ.copy()
    env["NOMAD_ADDR"] = NOMAD_ADDR
    raw = subprocess.check_output(
        [NOMAD, "job", "allocs", "-json", NOMAD_JOB],
        env=env,
        timeout=20,
        stderr=subprocess.STDOUT,
    )
    data = json.loads(raw.decode())
    running = [a for a in data if a.get("ClientStatus") == "running"]
    if not running:
        raise RuntimeError("no running CrowdSec Nomad alloc")
    running.sort(key=lambda a: a.get("ModifyIndex", 0), reverse=True)
    return running[0]["ID"]


def cscli(args: list[str]) -> str:
    env = os.environ.copy()
    if CSCLI_BIN:
        cmd = [CSCLI_BIN, *args]
    elif NOMAD:
        env["NOMAD_ADDR"] = NOMAD_ADDR
        alloc = nomad_alloc()
        cmd = [NOMAD, "alloc", "exec", "-task", NOMAD_JOB, alloc, "cscli", *args]
    else:
        raise RuntimeError("set CROWDSEC_CSCLI to the cscli binary, or NOMAD_BIN for alloc exec")
    proc = subprocess.run(cmd, env=env, timeout=30, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "cscli fail")[:800])
    return (proc.stdout or "").strip()


def allowlist_add(cidr: str, reason: str) -> dict:
    cidr = validate_cidr(cidr)
    reason = str(reason or "cso-console")[:80]
    _reject_forbidden(reason)
    try:
        cscli(["allowlists", "create", ALLOWLIST_NAME, "-d", "operator allowlist"])
    except Exception:
        pass
    out = cscli(["allowlists", "add", ALLOWLIST_NAME, cidr, "-d", reason])
    audit("allowlist.add", {"cidr": cidr, "reason": reason})
    return {"ok": True, "cidr": cidr, "out": out}


def allowlist_remove(cidr: str) -> dict:
    cidr = validate_cidr(cidr)
    out = cscli(["allowlists", "remove", ALLOWLIST_NAME, cidr])
    audit("allowlist.remove", {"cidr": cidr})
    return {"ok": True, "cidr": cidr, "out": out}


def hub_appsec_rules() -> list[str]:
    root = CONFIG_ROOT / "hub" / "appsec-rules"
    names = []
    if root.is_dir():
        for path in sorted(root.rglob("*.yaml")):
            rel = path.relative_to(root).as_posix()
            if rel.endswith(".yaml"):
                rel = rel[:-5]
            names.append(rel if "/" in rel else "crowdsecurity/" + rel)
            if len(names) >= 250:
                break
    return names


def traefik_site_map() -> dict:
    import urllib.request

    try:
        with urllib.request.urlopen(TRAEFIK_API, timeout=5) as resp:
            routers = json.loads(netguard.read_limited(resp, 4_000_000).decode() or "[]")
    except Exception:
        routers = []
    by_host = {}
    sites = SITES()
    for router in routers if isinstance(routers, list) else []:
        rule = str(router.get("rule") or "")
        mws = router.get("middlewares") or []
        for host in sites:
            if f"Host(`{host}`)" in rule:
                by_host.setdefault(host, {"routers": [], "middlewares": set()})
                by_host[host]["routers"].append(router.get("name"))
                by_host[host]["middlewares"].update(mws)
    return {
        host: {
            "routers": info["routers"],
            "middlewares": sorted(info["middlewares"]),
            "bouncer": any("crowdsec" in m or "security-chain" in m for m in info["middlewares"]),
        }
        for host, info in by_host.items()
    }


def sites_payload() -> dict:
    store = load_filters()
    traefik = traefik_site_map()
    rows = []
    for host, meta in SITES().items():
        if not isinstance(meta, dict):
            meta = {"kind": "web", "in_scope": True}
        rows.append(
            {
                "host": host,
                **meta,
                "traefik": traefik.get(host) or {},
                "filters": [i for i in store["items"] if i.get("host") == host],
            }
        )
    return {
        "ok": True,
        "sites": rows,
        "out_of_scope": OUT_OF_SCOPE(),
        "actions": ACTIONS,
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
        },
    }
