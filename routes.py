#!/usr/bin/env python3
"""Operator HTTP routes and TCP/local tunnels. Traefik file sidecar only.

Never rewrite the main reverse-proxy YAML. Never attach CrowdSec to /waf.
Never expose LAPI/AppSec/metrics. Never target farmlinkstage.
Does not restart Nomad.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import netguard

CONTROL_DIR = Path(os.environ.get("WAF_CONTROL", "/var/lib/waf-control"))
STORE = CONTROL_DIR / "routes.json"
FRAGMENT_NAME = os.environ.get("WAF_TRAEFIK_FRAGMENT", "waf-admin-routes.yaml")
DYNAMIC_DIR = Path(os.environ.get("WAF_TRAEFIK_DYNAMIC_DIR", "") or "")
TRAEFIK_HTTP = netguard.assert_loopback_http_url(
    os.environ.get("TRAEFIK_API", "http://127.0.0.1:8080/api/http/routers"),
    name="TRAEFIK_API",
)
TRAEFIK_TCP = netguard.assert_loopback_http_url(
    os.environ.get("TRAEFIK_TCP_API", "http://127.0.0.1:8080/api/tcp/routers"),
    name="TRAEFIK_TCP_API",
)
TSH_NODE = os.environ.get("WAF_TUNNEL_NODE", "root@localhost")

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")
HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,80}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/=-]{0,127}$")
NODE_RE = re.compile(r"^[A-Za-z0-9._@-]{3,80}$")
CHAINS = ("domain-security-chain", "expertsforensic-admin-only", "none")
HTTP_KINDS = ("http",)
TUNNEL_KINDS = ("tcp", "local")
RESERVED = {
    n.strip()
    for n in os.environ.get(
        "WAF_ROUTE_RESERVED",
        "waf-admin,waf-console,waf-admin-netbird,expertsforensic,expertsforensic-root,"
        "expertsforensic-netbird,web-catchall,netbird-grpc,netbird-device,netbird-api,"
        "netbird-dashboard,keycloak-legal,keycloak-admin-fix,keycloak-staging-root,"
        "keycloak-app,keycloak-root,teleport-auth-passthrough",
    ).split(",")
    if n.strip()
}
DENY_HOSTS = {
    h.strip().lower()
    for h in os.environ.get(
        "WAF_ROUTE_DENY_HOSTS",
        "bird.expertsforensic.com,birdsso.expertsforensic.com,farmlinkstage",
    ).split(",")
    if h.strip()
}
BLOCKED_PORTS = {18080, 7422, 6060}
FORBIDDEN = (
    "disablebodyinspection",
    "include_large_uploads",
    "crs-inband",
    "nomad job run",
    "fail_closed",
    "farmlinkstage",
    "crowdsec-bouncer",
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _audit(event: str, payload: dict) -> None:
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": _utc(), "event": event, **payload}, ensure_ascii=False)
    with (CONTROL_DIR / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _reject(*parts: str) -> None:
    blob = " ".join(parts).lower()
    for token in FORBIDDEN:
        if token in blob:
            raise ValueError("forbidden operation: " + token)
    if "farmlink" in blob:
        raise ValueError("farmlinkstage is out of scope")


def _empty() -> dict:
    return {"routes": [], "tunnels": []}


def load_store() -> dict:
    if not STORE.is_file():
        return _empty()
    try:
        data = json.loads(STORE.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return _empty()
    if not isinstance(data, dict):
        return _empty()
    routes = data.get("routes") if isinstance(data.get("routes"), list) else []
    tunnels = data.get("tunnels") if isinstance(data.get("tunnels"), list) else []
    return {"routes": routes, "tunnels": tunnels}


def _save(store: dict) -> None:
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STORE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(store, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STORE)


def _name(value: str) -> str:
    name = (value or "").strip().lower()
    if not NAME_RE.match(name):
        raise ValueError("invalid name")
    if name in RESERVED or name.startswith("netbird-") or name.startswith("keycloak-"):
        raise ValueError("reserved route name: " + name)
    _reject(name)
    return name


def _host(value: str) -> str:
    host = (value or "").strip().lower().rstrip(".")
    if not HOST_RE.match(host) or ".." in host:
        raise ValueError("invalid host")
    if host in DENY_HOSTS or host.endswith(".farmlinkstage") or "farmlink" in host:
        raise ValueError("host out of scope: " + host)
    _reject(host)
    return host


def _path(value: str) -> str:
    path = (value or "").strip()
    if not path or path == "/":
        return ""
    if not PATH_RE.match(path) or "//" in path or ".." in path:
        raise ValueError("invalid path_prefix")
    _reject(path)
    return path


def _loopback_url(raw: str) -> str:
    url = (raw or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https", "h2c"):
        raise ValueError("service URL must be http(s) or h2c on loopback")
    host = (parsed.hostname or "").lower()
    if host not in ("127.0.0.1", "::1"):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("service must be 127.0.0.1, ::1, or NetBird 100.74.0.0/16") from exc
        if ip not in ipaddress.ip_network("100.74.0.0/16"):
            raise ValueError("service must be 127.0.0.1, ::1, or NetBird 100.74.0.0/16")
    port = parsed.port
    if port is None:
        raise ValueError("service URL must include a port")
    if port in BLOCKED_PORTS:
        raise ValueError("refusing to publish LAPI/AppSec/metrics")
    if parsed.username or parsed.password:
        raise ValueError("service URL must not include credentials")
    _reject(url)
    return "%s://%s:%s%s" % (parsed.scheme, host if host != "::1" else "[::1]", port, parsed.path or "")


def _loopback_addr(raw: str) -> str:
    value = (raw or "").strip()
    if value.startswith("["):
        raise ValueError("use 127.0.0.1:port")
    if "://" in value:
        raise ValueError("TCP target is host:port, not a URL")
    host, sep, port_s = value.rpartition(":")
    if not sep:
        raise ValueError("TCP target must be host:port")
    host = host.lower()
    port = int(port_s)
    if port < 1 or port > 65535 or port in BLOCKED_PORTS:
        raise ValueError("invalid TCP port")
    if host not in ("127.0.0.1", "localhost"):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("TCP target must be 127.0.0.1 or NetBird 100.74.0.0/16") from exc
        if ip not in ipaddress.ip_network("100.74.0.0/16"):
            raise ValueError("TCP target must be 127.0.0.1 or NetBird 100.74.0.0/16")
        host = str(ip)
    else:
        host = "127.0.0.1"
    _reject(host, str(port))
    return "%s:%s" % (host, port)


def _chain(value: str, path: str, service_url: str) -> str:
    chain = (value or "domain-security-chain").strip()
    if chain not in CHAINS:
        raise ValueError("invalid chain")
    low = (path or "").lower()
    parsed = urlparse(service_url)
    if "/waf" in low or parsed.port == 18990:
        if chain == "domain-security-chain":
            raise ValueError("/waf and :18990 must stay off the CrowdSec bouncer")
        return "expertsforensic-admin-only"
    return chain


def _priority(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid priority") from exc
    if n < 1 or n > 1000:
        raise ValueError("priority must be 1-1000")
    return n


def _id() -> str:
    import uuid

    return uuid.uuid4().hex[:12]


def _fetch_json(url: str) -> list:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return []
    return data if isinstance(data, list) else []


def live_http() -> list[dict]:
    rows = []
    for item in _fetch_json(TRAEFIK_HTTP):
        rows.append(
            {
                "name": item.get("name"),
                "rule": item.get("rule"),
                "service": item.get("service"),
                "status": item.get("status"),
                "provider": item.get("provider"),
                "priority": item.get("priority"),
                "middlewares": item.get("middlewares") or [],
                "entry_points": item.get("using") or item.get("entryPoints") or [],
            }
        )
        if len(rows) >= 400:
            break
    return rows


def live_tcp() -> list[dict]:
    rows = []
    for item in _fetch_json(TRAEFIK_TCP):
        rows.append(
            {
                "name": item.get("name"),
                "rule": item.get("rule"),
                "service": item.get("service"),
                "status": item.get("status"),
                "provider": item.get("provider"),
            }
        )
        if len(rows) >= 200:
            break
    return rows


def _yaml_quote(value: str) -> str:
    if re.match(r"^[A-Za-z0-9._:/-]+$", value or ""):
        return value
    return json.dumps(value, ensure_ascii=False)


def _http_rule(host: str, path: str) -> str:
    rule = "Host(`%s`)" % host
    if path:
        rule += " && PathPrefix(`%s`)" % path
    return rule


def _middlewares(chain: str) -> list[str]:
    if chain == "none":
        return []
    if chain == "expertsforensic-admin-only":
        return ["expertsforensic-admin-only@file", "strip-backend-csp@file"]
    return ["%s@file" % chain, "strip-backend-csp@file"]


def render_yaml(store: dict | None = None) -> str:
    store = store or load_store()
    lines = [
        "# Managed by the WAF console. Do not edit by hand.",
        "# Sidecar file provider only. Main dynamic.yaml stays untouched.",
    ]
    http_items = [r for r in store["routes"] if r.get("enabled", True) and r.get("kind") == "http"]
    tcp_items = [t for t in store["tunnels"] if t.get("enabled", True) and t.get("kind") == "tcp"]
    if http_items:
        lines.append("http:")
        lines.append("  routers:")
        for item in http_items:
            rname = item["name"]
            lines.append("    %s:" % rname)
            lines.append("      rule: %s" % _yaml_quote(_http_rule(item["host"], item.get("path_prefix") or "")))
            lines.append("      priority: %s" % int(item.get("priority") or 90))
            lines.append("      entryPoints:")
            lines.append("        - websecure")
            lines.append("      service: %s" % rname)
            mws = _middlewares(item.get("chain") or "domain-security-chain")
            if mws:
                lines.append("      middlewares:")
                for mw in mws:
                    lines.append("        - %s" % mw)
            if item.get("tls", True):
                lines.append("      tls:")
                lines.append("        certResolver: letsencrypt-http")
        lines.append("  services:")
        for item in http_items:
            rname = item["name"]
            lines.append("    %s:" % rname)
            lines.append("      loadBalancer:")
            lines.append("        servers:")
            lines.append("          - url: %s" % _yaml_quote(item["service_url"]))
            lines.append("        passHostHeader: true")
    if tcp_items:
        lines.append("tcp:")
        lines.append("  routers:")
        for item in tcp_items:
            tname = item["name"]
            lines.append("    %s:" % tname)
            lines.append("      entryPoints:")
            lines.append("        - websecure")
            lines.append("      rule: %s" % _yaml_quote("HostSNI(`%s`)" % item["sni"]))
            lines.append("      service: %s" % tname)
            lines.append("      tls:")
            lines.append("        passthrough: %s" % ("true" if item.get("passthrough", True) else "false"))
        lines.append("  services:")
        for item in tcp_items:
            tname = item["name"]
            lines.append("    %s:" % tname)
            lines.append("      loadBalancer:")
            lines.append("        servers:")
            lines.append("          - address: %s" % _yaml_quote(item["target"]))
    if not http_items and not tcp_items:
        lines.append("# No operator HTTP/TCP items. This file must not define empty http/tcp maps.")
    yaml_text = "\n".join(lines) + "\n"
    if "routers: {}" in yaml_text or "services: {}" in yaml_text:
        raise RuntimeError("refusing empty Traefik http/tcp maps (sidecar would clobber HostSNI)")
    return yaml_text


def apply_fragment(store: dict | None = None) -> dict:
    """YAML preview under WAF_CONTROL only. Never write Traefik dynamic files."""
    store = store or load_store()
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    local = CONTROL_DIR / FRAGMENT_NAME
    yaml_text = render_yaml(store)
    tmp = local.with_suffix(".yaml.tmp")
    tmp.write_text(yaml_text, encoding="utf-8")
    tmp.replace(local)
    return {
        "ok": True,
        "applied": False,
        "fragment": str(local),
        "traefik_file": "",
        "error": "",
        "watch": "off — console does not mutate Traefik dynamic.yaml",
    }


def _tsh_cmd(item: dict) -> str:
    if item.get("kind") != "local":
        return ""
    return "tsh ssh -N -L %s:%s %s" % (item["local_port"], item["remote"], item["node"])


def _normalize_route(payload: dict, existing: dict | None = None) -> dict:
    item = dict(existing or {})
    name = _name(payload.get("name") or item.get("name") or "")
    host = _host(payload.get("host") or item.get("host") or "")
    path = _path(payload.get("path_prefix") if "path_prefix" in payload else item.get("path_prefix") or "")
    service_url = _loopback_url(payload.get("service_url") or item.get("service_url") or "")
    chain = _chain(payload.get("chain") if "chain" in payload else item.get("chain") or "domain-security-chain", path, service_url)
    item.update(
        {
            "id": item.get("id") or _id(),
            "kind": "http",
            "name": name,
            "host": host,
            "path_prefix": path,
            "service_url": service_url,
            "chain": chain,
            "tls": bool(payload["tls"]) if "tls" in payload else bool(item.get("tls", True)),
            "priority": _priority(payload.get("priority") if payload.get("priority") not in (None, "") else item.get("priority") or 90),
            "enabled": bool(payload["enabled"]) if "enabled" in payload else bool(item.get("enabled", True)),
            "updated": _utc(),
        }
    )
    if not item.get("created"):
        item["created"] = item["updated"]
    return item


def _normalize_tunnel(payload: dict, existing: dict | None = None) -> dict:
    item = dict(existing or {})
    name = _name(payload.get("name") or item.get("name") or "")
    kind = str(payload.get("kind") or item.get("kind") or "local").strip().lower()
    if kind not in TUNNEL_KINDS:
        raise ValueError("tunnel kind must be tcp or local")
    item.update(
        {
            "id": item.get("id") or _id(),
            "kind": kind,
            "name": name,
            "enabled": bool(payload["enabled"]) if "enabled" in payload else bool(item.get("enabled", True)),
            "updated": _utc(),
        }
    )
    if kind == "tcp":
        item["sni"] = _host(payload.get("sni") or item.get("sni") or "")
        item["target"] = _loopback_addr(payload.get("target") or item.get("target") or "")
        item["passthrough"] = bool(payload["passthrough"]) if "passthrough" in payload else bool(item.get("passthrough", True))
        item["local_port"] = 0
        item["remote"] = ""
        item["node"] = ""
        item["command"] = ""
    else:
        try:
            local_port = int(payload.get("local_port") if payload.get("local_port") not in (None, "") else item.get("local_port") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid local_port") from exc
        if local_port < 1024 or local_port > 65535:
            raise ValueError("local_port must be 1024-65535")
        node = str(payload.get("node") or item.get("node") or TSH_NODE).strip()
        if not NODE_RE.match(node) or "farmlink" in node.lower():
            raise ValueError("invalid Teleport node")
        _reject(node)
        item["local_port"] = local_port
        item["remote"] = _loopback_addr(payload.get("remote") or item.get("remote") or "")
        item["node"] = node
        item["sni"] = ""
        item["target"] = ""
        item["passthrough"] = False
        item["command"] = _tsh_cmd(item)
    if not item.get("created"):
        item["created"] = item["updated"]
    return item


def _find(items: list, ident: str) -> dict | None:
    ident = (ident or "").strip()
    for item in items:
        if item.get("id") == ident or item.get("name") == ident:
            return item
    return None


def upsert_route(payload: dict) -> dict:
    store = load_store()
    current = _find(store["routes"], str(payload.get("id") or payload.get("name") or ""))
    item = _normalize_route(payload, current)
    if current is None:
        clash = _find(store["routes"], item["name"])
        if clash:
            raise ValueError("route name already exists")
        store["routes"].append(item)
        op = "create"
    else:
        for other in store["routes"]:
            if other is not current and other.get("name") == item["name"]:
                raise ValueError("route name already exists")
        current.clear()
        current.update(item)
        item = current
        op = "update"
    _save(store)
    applied = apply_fragment(store)
    _audit("route." + op, {"name": item["name"], "host": item["host"]})
    return {"ok": True, "item": item, "op": op, **applied}


def delete_route(ident: str) -> dict:
    store = load_store()
    item = _find(store["routes"], ident)
    if not item:
        raise ValueError("route not found")
    store["routes"] = [r for r in store["routes"] if r is not item]
    _save(store)
    applied = apply_fragment(store)
    _audit("route.delete", {"name": item.get("name")})
    return {"ok": True, "deleted": item.get("id"), **applied}


def upsert_tunnel(payload: dict) -> dict:
    store = load_store()
    current = _find(store["tunnels"], str(payload.get("id") or payload.get("name") or ""))
    item = _normalize_tunnel(payload, current)
    if current is None:
        clash = _find(store["tunnels"], item["name"])
        if clash:
            raise ValueError("tunnel name already exists")
        store["tunnels"].append(item)
        op = "create"
    else:
        for other in store["tunnels"]:
            if other is not current and other.get("name") == item["name"]:
                raise ValueError("tunnel name already exists")
        current.clear()
        current.update(item)
        item = current
        op = "update"
    _save(store)
    applied = apply_fragment(store)
    _audit("tunnel." + op, {"name": item["name"], "kind": item["kind"]})
    return {"ok": True, "item": item, "op": op, **applied}


def delete_tunnel(ident: str) -> dict:
    store = load_store()
    item = _find(store["tunnels"], ident)
    if not item:
        raise ValueError("tunnel not found")
    store["tunnels"] = [t for t in store["tunnels"] if t is not item]
    _save(store)
    applied = apply_fragment(store)
    _audit("tunnel.delete", {"name": item.get("name")})
    return {"ok": True, "deleted": item.get("id"), **applied}


def payload() -> dict:
    store = load_store()
    applied = apply_fragment(store)
    http_live = live_http()
    tcp_live = live_tcp()
    for item in store["tunnels"]:
        if item.get("kind") == "local":
            item["command"] = _tsh_cmd(item)
    return {
        "ok": True,
        "routes": store["routes"],
        "tunnels": store["tunnels"],
        "live_http": http_live,
        "live_tcp": tcp_live,
        "reserved": sorted(RESERVED),
        "deny_hosts": sorted(DENY_HOSTS),
        "chains": list(CHAINS),
        "apply": applied,
        "policy": {
            "no_bouncer_on_waf": True,
            "no_nomad_restart": True,
            "no_traefik_mutate": True,
            "loopback_or_netbird_only": True,
            "sidecar_file": FRAGMENT_NAME,
        },
        "local_tunnel": {
            "command": "tsh ssh -N -L 18990:127.0.0.1:18990 root@localhost",
            "url": "http://127.0.0.1:18990/waf/",
            "script": ".\\scripts\\waf-admin.ps1 tunnel",
        },
    }


def admin_payload() -> dict:
    data = payload()
    return {
        "ok": True,
        "routes": len(data["routes"]),
        "tunnels": len(data["tunnels"]),
        "live_http": len(data["live_http"]),
        "live_tcp": len(data["live_tcp"]),
        "apply": data["apply"],
        "policy": data["policy"],
        "local_tunnel": data.get("local_tunnel") or {
            "command": "tsh ssh -N -L 18990:127.0.0.1:18990 root@localhost",
            "url": "http://127.0.0.1:18990/waf/",
            "script": ".\\scripts\\waf-admin.ps1 tunnel",
        },
        "actions": [
            {"view": "sites", "title": "WAF policies", "detail": "Per-FQDN AppSec allow/skip/bypass"},
            {"view": "allowlists", "title": "Allowlists", "detail": "Operator CIDR allowlist on LAPI"},
            {"view": "decisions", "title": "Decisions", "detail": "Local ban / unban"},
            {"view": "domains", "title": "Domains", "detail": "Origin vs public health"},
            {"view": "engine", "title": "Engine", "detail": "Fail-closed posture (read-only)"},
        ],
    }
