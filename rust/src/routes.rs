//! Operator HTTP routes and TCP/local tunnels (port of routes.py).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use regex::Regex;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::netguard;
use crate::persist;

static NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,47}$").expect("NAME_RE"));
static HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9.-]{0,80}$").expect("HOST_RE"));
static PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/[A-Za-z0-9._~/=-]{0,127}$").expect("PATH_RE"));
static NODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._@-]{3,80}$").expect("NODE_RE"));
static YAML_SAFE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._:/-]+$").expect("YAML_SAFE"));

const CHAINS: &[&str] = &[
    "domain-security-chain",
    "expertsforensic-admin-only",
    "none",
];
const TUNNEL_KINDS: &[&str] = &["tcp", "local"];
const BLOCKED_PORTS: &[u16] = &[18080, 7422, 6060];
const FORBIDDEN: &[&str] = &[
    "disablebodyinspection",
    "include_large_uploads",
    "crs-inband",
    "nomad job run",
    "fail_closed",
    "farmlinkstage",
    "crowdsec-bouncer",
];

fn control_dir() -> PathBuf {
    PathBuf::from(std::env::var("WAF_CONTROL").unwrap_or_else(|_| "/var/lib/waf-control".into()))
}

fn store_path() -> PathBuf {
    control_dir().join("routes.json")
}

fn fragment_name() -> String {
    std::env::var("WAF_TRAEFIK_FRAGMENT").unwrap_or_else(|_| "waf-admin-routes.yaml".into())
}

fn traefik_http() -> Result<String> {
    netguard::assert_loopback_http_url(
        &std::env::var("TRAEFIK_API")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/api/http/routers".into()),
        "TRAEFIK_API",
    )
}

fn traefik_tcp() -> Result<String> {
    netguard::assert_loopback_http_url(
        &std::env::var("TRAEFIK_TCP_API")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/api/tcp/routers".into()),
        "TRAEFIK_TCP_API",
    )
}

fn tsh_node() -> String {
    std::env::var("WAF_TUNNEL_NODE").unwrap_or_else(|_| "root@localhost".into())
}

fn reserved() -> HashSet<String> {
    std::env::var("WAF_ROUTE_RESERVED")
        .unwrap_or_else(|_| {
            "waf-admin,waf-console,waf-admin-netbird,expertsforensic,expertsforensic-root,\
expertsforensic-netbird,web-catchall,netbird-grpc,netbird-device,netbird-api,\
netbird-dashboard,keycloak-legal,keycloak-admin-fix,keycloak-staging-root,\
keycloak-app,keycloak-root,teleport-auth-passthrough"
                .into()
        })
        .split(',')
        .filter_map(|n| {
            let s = n.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .collect()
}

fn deny_hosts() -> HashSet<String> {
    std::env::var("WAF_ROUTE_DENY_HOSTS")
        .unwrap_or_else(|_| {
            "bird.expertsforensic.com,birdsso.expertsforensic.com,farmlinkstage".into()
        })
        .split(',')
        .filter_map(|h| {
            let s = h.trim().to_lowercase();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .collect()
}

fn utc() -> String {
    persist::utc_now()
}

fn audit(event: &str, payload: &Map<String, Value>) {
    persist::audit(event, payload);
}

fn reject(parts: &[&str]) -> Result<()> {
    let blob = parts.join(" ").to_lowercase();
    for token in FORBIDDEN {
        if blob.contains(token) {
            return Err(anyhow!("forbidden operation: {token}"));
        }
    }
    if blob.contains("farmlink") {
        return Err(anyhow!("farmlinkstage is out of scope"));
    }
    Ok(())
}

fn empty_store() -> Value {
    json!({ "routes": [], "tunnels": [] })
}

pub fn load_store() -> Value {
    let path = store_path();
    if !path.is_file() {
        return empty_store();
    }
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let data: Value = serde_json::from_str(&text).unwrap_or_else(|_| empty_store());
    let routes = data
        .get("routes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let tunnels = data
        .get("tunnels")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    json!({ "routes": routes, "tunnels": tunnels })
}

fn save_store(store: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(store)? + "\n";
    persist::atomic_write_text(&store_path(), &text);
    Ok(())
}

fn validate_name(value: &str) -> Result<String> {
    let name = value.trim().to_lowercase();
    if !NAME_RE.is_match(&name) {
        return Err(anyhow!("invalid name"));
    }
    let reserved = reserved();
    if reserved.contains(&name) || name.starts_with("netbird-") || name.starts_with("keycloak-") {
        return Err(anyhow!("reserved route name: {name}"));
    }
    reject(&[&name])?;
    Ok(name)
}

fn validate_host(value: &str) -> Result<String> {
    let host = value
        .trim()
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();
    if !HOST_RE.is_match(&host) || host.contains("..") {
        return Err(anyhow!("invalid host"));
    }
    let deny = deny_hosts();
    if deny.contains(&host) || host.ends_with(".farmlinkstage") || host.contains("farmlink") {
        return Err(anyhow!("host out of scope: {host}"));
    }
    reject(&[&host])?;
    Ok(host)
}

fn validate_path(value: &str) -> Result<String> {
    let path = value.trim();
    if path.is_empty() || path == "/" {
        return Ok(String::new());
    }
    if !PATH_RE.is_match(path) || path.contains("//") || path.contains("..") {
        return Err(anyhow!("invalid path_prefix"));
    }
    reject(&[path])?;
    Ok(path.to_string())
}

fn netbird_net() -> Result<IpNet> {
    "100.74.0.0/16".parse().context("netbird net")
}

fn loopback_url(raw: &str) -> Result<String> {
    let url = raw.trim();
    let parsed = parse_http_url(url)?;
    if !matches!(parsed.scheme.as_str(), "http" | "https" | "h2c") {
        return Err(anyhow!("service URL must be http(s) or h2c on loopback"));
    }
    let host = parsed.host.to_lowercase();
    let allowed = match host.as_str() {
        "127.0.0.1" | "::1" => true,
        _ => {
            if let Ok(ip) = host.parse::<IpAddr>() {
                if ip.is_loopback() {
                    true
                } else if let Ok(net) = netbird_net() {
                    net.contains(&ip)
                } else {
                    false
                }
            } else {
                false
            }
        }
    };
    if !allowed {
        return Err(anyhow!(
            "service must be 127.0.0.1, ::1, or NetBird 100.74.0.0/16"
        ));
    }
    let port = parsed
        .port
        .ok_or_else(|| anyhow!("service URL must include a port"))?;
    if BLOCKED_PORTS.contains(&port) {
        return Err(anyhow!("refusing to publish LAPI/AppSec/metrics"));
    }
    if parsed.user.is_some() {
        return Err(anyhow!("service URL must not include credentials"));
    }
    reject(&[url])?;
    let host_out = if host == "::1" {
        "[::1]".to_string()
    } else {
        host
    };
    Ok(format!(
        "{}://{}:{}{}",
        parsed.scheme, host_out, port, parsed.path
    ))
}

struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    user: Option<String>,
}

fn parse_http_url(raw: &str) -> Result<ParsedUrl> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| anyhow!("invalid URL"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    let (user, hostport) = match authority.rfind('@') {
        Some(i) => (Some(authority[..i].to_string()), &authority[i + 1..]),
        None => (None, authority),
    };
    let (host, port) = if hostport.starts_with('[') {
        let end = hostport
            .find(']')
            .ok_or_else(|| anyhow!("invalid IPv6 URL"))?;
        let host = hostport[1..end].to_string();
        let port = hostport[end + 1..]
            .strip_prefix(':')
            .map(|p| p.parse())
            .transpose()?;
        (host, port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        if h.is_empty() {
            return Err(anyhow!("invalid URL host"));
        }
        (h.to_string(), Some(p.parse()?))
    } else {
        (hostport.to_string(), None)
    };
    Ok(ParsedUrl {
        scheme: scheme.to_string(),
        host,
        port,
        path,
        user,
    })
}

fn loopback_addr(raw: &str) -> Result<String> {
    let value = raw.trim();
    if value.starts_with('[') {
        return Err(anyhow!("use 127.0.0.1:port"));
    }
    if value.contains("://") {
        return Err(anyhow!("TCP target is host:port, not a URL"));
    }
    let Some((host, port_s)) = value.rsplit_once(':') else {
        return Err(anyhow!("TCP target must be host:port"));
    };
    if host.is_empty() {
        return Err(anyhow!("TCP target must be host:port"));
    }
    let host = host.to_lowercase();
    let port: u16 = port_s.parse().map_err(|_| anyhow!("invalid TCP port"))?;
    if port < 1 || port > 65535 || BLOCKED_PORTS.contains(&port) {
        return Err(anyhow!("invalid TCP port"));
    }
    let host_out = if host == "127.0.0.1" || host == "localhost" {
        "127.0.0.1".to_string()
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        let net = netbird_net()?;
        if !net.contains(&ip) {
            return Err(anyhow!(
                "TCP target must be 127.0.0.1 or NetBird 100.74.0.0/16"
            ));
        }
        ip.to_string()
    } else {
        return Err(anyhow!(
            "TCP target must be 127.0.0.1 or NetBird 100.74.0.0/16"
        ));
    };
    reject(&[&host_out, &port.to_string()])?;
    Ok(format!("{host_out}:{port}"))
}

fn chain(value: &str, path: &str, service_url: &str) -> Result<String> {
    let chain = if value.trim().is_empty() {
        "domain-security-chain"
    } else {
        value.trim()
    };
    if !CHAINS.contains(&chain) {
        return Err(anyhow!("invalid chain"));
    }
    let low = path.to_lowercase();
    let port = parse_http_url(service_url).ok().and_then(|u| u.port);
    if low.contains("/waf") || port == Some(18990) {
        if chain == "domain-security-chain" {
            return Err(anyhow!(
                "/waf and :18990 must stay off the CrowdSec bouncer"
            ));
        }
        return Ok("expertsforensic-admin-only".into());
    }
    Ok(chain.to_string())
}

fn priority(value: &Value) -> Result<i64> {
    let n = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| anyhow!("invalid priority"))?;
    if n < 1 || n > 1000 {
        return Err(anyhow!("priority must be 1-1000"));
    }
    Ok(n)
}

fn new_id() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_string()
}

fn fetch_json(url: &str) -> Vec<Value> {
    match http_get_json(url, 4_000_000) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    }
}

fn read_limited(mut reader: impl Read, max_bytes: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > max_bytes {
            return Err(anyhow!("response exceeds size limit"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

fn http_get_json(url: &str, max_bytes: usize) -> Result<Vec<Value>> {
    let parsed = parse_http_url(url)?;
    let host = parsed.host.as_str();
    let port = parsed.port.unwrap_or(80);
    let addr: SocketAddr = if host == "::1" {
        format!("[::1]:{port}").parse()?
    } else {
        format!("{host}:{port}").parse()?
    };
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let path = if parsed.path.is_empty() {
        "/".to_string()
    } else {
        parsed.path.clone()
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let raw = read_limited(&mut stream, max_bytes)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let body = &raw[split..];
    let data: Value = serde_json::from_slice(body).unwrap_or(json!([]));
    Ok(data.as_array().cloned().unwrap_or_default())
}

pub fn live_http() -> Vec<Value> {
    let url = traefik_http().unwrap_or_default();
    if url.is_empty() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for item in fetch_json(&url) {
        let Some(obj) = item.as_object() else {
            continue;
        };
        rows.push(json!({
            "name": obj.get("name"),
            "rule": obj.get("rule"),
            "service": obj.get("service"),
            "status": obj.get("status"),
            "provider": obj.get("provider"),
            "priority": obj.get("priority"),
            "middlewares": obj.get("middlewares").cloned().unwrap_or(json!([])),
            "entry_points": obj.get("using").or_else(|| obj.get("entryPoints")).cloned().unwrap_or(json!([])),
        }));
        if rows.len() >= 400 {
            break;
        }
    }
    rows
}

pub fn live_tcp() -> Vec<Value> {
    let url = traefik_tcp().unwrap_or_default();
    if url.is_empty() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for item in fetch_json(&url) {
        let Some(obj) = item.as_object() else {
            continue;
        };
        rows.push(json!({
            "name": obj.get("name"),
            "rule": obj.get("rule"),
            "service": obj.get("service"),
            "status": obj.get("status"),
            "provider": obj.get("provider"),
        }));
        if rows.len() >= 200 {
            break;
        }
    }
    rows
}

fn yaml_quote(value: &str) -> String {
    if YAML_SAFE.is_match(value) {
        value.to_string()
    } else {
        serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
    }
}

fn http_rule(host: &str, path: &str) -> String {
    let mut rule = format!("Host(`{host}`)");
    if !path.is_empty() {
        rule.push_str(&format!(" && PathPrefix(`{path}`)"));
    }
    rule
}

fn middlewares(chain: &str) -> Vec<String> {
    match chain {
        "none" => Vec::new(),
        "expertsforensic-admin-only" => vec![
            "expertsforensic-admin-only@file".into(),
            "strip-backend-csp@file".into(),
        ],
        _ => vec![format!("{chain}@file"), "strip-backend-csp@file".into()],
    }
}

pub fn render_yaml(store: Option<&Value>) -> Result<String> {
    let loaded = load_store();
    let store = store.unwrap_or(&loaded);
    let routes = store
        .get("routes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let tunnels = store
        .get("tunnels")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut lines = vec![
        "# Managed by the WAF console. Do not edit by hand.".into(),
        "# Sidecar file provider only. Main dynamic.yaml stays untouched.".into(),
    ];
    let http_items: Vec<&Map<String, Value>> = routes
        .iter()
        .filter_map(|r| r.as_object())
        .filter(|r| {
            r.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)
                && r.get("kind").and_then(|v| v.as_str()) == Some("http")
        })
        .collect();
    let tcp_items: Vec<&Map<String, Value>> = tunnels
        .iter()
        .filter_map(|t| t.as_object())
        .filter(|t| {
            t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)
                && t.get("kind").and_then(|v| v.as_str()) == Some("tcp")
        })
        .collect();
    if !http_items.is_empty() {
        lines.push("http:".into());
        lines.push("  routers:".into());
        for item in &http_items {
            let rname = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            lines.push(format!("    {rname}:"));
            lines.push(format!(
                "      rule: {}",
                yaml_quote(&http_rule(
                    item.get("host").and_then(|v| v.as_str()).unwrap_or(""),
                    item.get("path_prefix")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                ))
            ));
            lines.push(format!(
                "      priority: {}",
                item.get("priority").and_then(|v| v.as_i64()).unwrap_or(90)
            ));
            lines.push("      entryPoints:".into());
            lines.push("        - websecure".into());
            lines.push(format!("      service: {rname}"));
            let mws = middlewares(
                item.get("chain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("domain-security-chain"),
            );
            if !mws.is_empty() {
                lines.push("      middlewares:".into());
                for mw in mws {
                    lines.push(format!("        - {mw}"));
                }
            }
            if item.get("tls").and_then(|v| v.as_bool()).unwrap_or(true) {
                lines.push("      tls:".into());
                lines.push("        certResolver: letsencrypt-http".into());
            }
        }
        lines.push("  services:".into());
        for item in &http_items {
            let rname = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            lines.push(format!("    {rname}:"));
            lines.push("      loadBalancer:".into());
            lines.push("        servers:".into());
            lines.push(format!(
                "          - url: {}",
                yaml_quote(
                    item.get("service_url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                )
            ));
            lines.push("        passHostHeader: true".into());
        }
    }
    if !tcp_items.is_empty() {
        lines.push("tcp:".into());
        lines.push("  routers:".into());
        for item in &tcp_items {
            let tname = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            lines.push(format!("    {tname}:"));
            lines.push("      entryPoints:".into());
            lines.push("        - websecure".into());
            lines.push(format!(
                "      rule: {}",
                yaml_quote(&format!(
                    "HostSNI(`{}`)",
                    item.get("sni").and_then(|v| v.as_str()).unwrap_or("")
                ))
            ));
            lines.push(format!("      service: {tname}"));
            lines.push("      tls:".into());
            lines.push(format!(
                "        passthrough: {}",
                if item
                    .get("passthrough")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
                {
                    "true"
                } else {
                    "false"
                }
            ));
        }
        lines.push("  services:".into());
        for item in &tcp_items {
            let tname = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            lines.push(format!("    {tname}:"));
            lines.push("      loadBalancer:".into());
            lines.push("        servers:".into());
            lines.push(format!(
                "          - address: {}",
                yaml_quote(item.get("target").and_then(|v| v.as_str()).unwrap_or(""))
            ));
        }
    }
    if http_items.is_empty() && tcp_items.is_empty() {
        lines.push(
            "# No operator HTTP/TCP items. This file must not define empty http/tcp maps.".into(),
        );
    }
    let yaml_text = lines.join("\n") + "\n";
    if yaml_text.contains("routers: {}") || yaml_text.contains("services: {}") {
        return Err(anyhow!(
            "refusing empty Traefik http/tcp maps (sidecar would clobber HostSNI)"
        ));
    }
    Ok(yaml_text)
}

pub fn apply_fragment(store: Option<&Value>) -> Result<Value> {
    let loaded = load_store();
    let store = store.unwrap_or(&loaded);
    let dir = control_dir();
    std::fs::create_dir_all(&dir)?;
    let local = dir.join(fragment_name());
    let yaml_text = render_yaml(Some(store))?;
    let tmp = local.with_extension("yaml.tmp");
    std::fs::write(&tmp, yaml_text)?;
    std::fs::rename(&tmp, &local)?;
    Ok(json!({
        "ok": true,
        "applied": false,
        "fragment": local.to_string_lossy(),
        "traefik_file": "",
        "error": "",
        "watch": "off — console does not mutate Traefik dynamic.yaml",
    }))
}

fn tsh_cmd(item: &Map<String, Value>) -> String {
    if item.get("kind").and_then(|v| v.as_str()) != Some("local") {
        return String::new();
    }
    format!(
        "tsh ssh -N -L {}:{} {}",
        item.get("local_port").and_then(|v| v.as_i64()).unwrap_or(0),
        item.get("remote").and_then(|v| v.as_str()).unwrap_or(""),
        item.get("node").and_then(|v| v.as_str()).unwrap_or(""),
    )
}

fn normalize_route(
    payload: &Map<String, Value>,
    existing: Option<&Map<String, Value>>,
) -> Result<Map<String, Value>> {
    let mut item = existing.cloned().unwrap_or_default();
    let name = validate_name(
        payload
            .get("name")
            .or_else(|| item.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    let host = validate_host(
        payload
            .get("host")
            .or_else(|| item.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    let path = if payload.contains_key("path_prefix") {
        validate_path(
            payload
                .get("path_prefix")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )?
    } else {
        validate_path(
            item.get("path_prefix")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )?
    };
    let service_url = loopback_url(
        payload
            .get("service_url")
            .or_else(|| item.get("service_url"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    let chain_val = if payload.contains_key("chain") {
        payload
            .get("chain")
            .and_then(|v| v.as_str())
            .unwrap_or("domain-security-chain")
    } else {
        item.get("chain")
            .and_then(|v| v.as_str())
            .unwrap_or("domain-security-chain")
    };
    let chain = chain(chain_val, &path, &service_url)?;
    let pri = if payload
        .get("priority")
        .map(|v| v.is_null() || v.as_str() == Some(""))
        .unwrap_or(true)
    {
        item.get("priority").cloned().unwrap_or(json!(90))
    } else {
        payload.get("priority").cloned().unwrap_or(json!(90))
    };
    item.insert(
        "id".into(),
        json!(item.get("id").and_then(|v| v.as_str()).unwrap_or(&new_id())),
    );
    item.insert("kind".into(), json!("http"));
    item.insert("name".into(), json!(name));
    item.insert("host".into(), json!(host));
    item.insert("path_prefix".into(), json!(path));
    item.insert("service_url".into(), json!(service_url));
    item.insert("chain".into(), json!(chain));
    item.insert(
        "tls".into(),
        json!(if payload.contains_key("tls") {
            payload.get("tls").and_then(|v| v.as_bool()).unwrap_or(true)
        } else {
            item.get("tls").and_then(|v| v.as_bool()).unwrap_or(true)
        }),
    );
    item.insert("priority".into(), json!(priority(&pri)?));
    item.insert(
        "enabled".into(),
        json!(if payload.contains_key("enabled") {
            payload
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
        } else {
            item.get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
        }),
    );
    let updated = utc();
    item.insert("updated".into(), json!(updated));
    if !item.contains_key("created") {
        item.insert("created".into(), json!(updated));
    }
    Ok(item)
}

fn normalize_tunnel(
    payload: &Map<String, Value>,
    existing: Option<&Map<String, Value>>,
) -> Result<Map<String, Value>> {
    let mut item = existing.cloned().unwrap_or_default();
    let name = validate_name(
        payload
            .get("name")
            .or_else(|| item.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    let kind = payload
        .get("kind")
        .or_else(|| item.get("kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("local")
        .trim()
        .to_lowercase();
    if !TUNNEL_KINDS.contains(&kind.as_str()) {
        return Err(anyhow!("tunnel kind must be tcp or local"));
    }
    item.insert(
        "id".into(),
        json!(item.get("id").and_then(|v| v.as_str()).unwrap_or(&new_id())),
    );
    item.insert("kind".into(), json!(kind));
    item.insert("name".into(), json!(name));
    item.insert(
        "enabled".into(),
        json!(if payload.contains_key("enabled") {
            payload
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
        } else {
            item.get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
        }),
    );
    let updated = utc();
    item.insert("updated".into(), json!(updated));
    if kind == "tcp" {
        item.insert(
            "sni".into(),
            json!(validate_host(
                payload
                    .get("sni")
                    .or_else(|| item.get("sni"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            )?),
        );
        item.insert(
            "target".into(),
            json!(loopback_addr(
                payload
                    .get("target")
                    .or_else(|| item.get("target"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            )?),
        );
        item.insert(
            "passthrough".into(),
            json!(if payload.contains_key("passthrough") {
                payload
                    .get("passthrough")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
            } else {
                item.get("passthrough")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
            }),
        );
        item.insert("local_port".into(), json!(0));
        item.insert("remote".into(), json!(""));
        item.insert("node".into(), json!(""));
        item.insert("command".into(), json!(""));
    } else {
        let lp_raw = if payload
            .get("local_port")
            .map(|v| v.is_null() || v.as_str() == Some(""))
            .unwrap_or(true)
        {
            item.get("local_port").cloned().unwrap_or(json!(0))
        } else {
            payload.get("local_port").cloned().unwrap_or(json!(0))
        };
        let local_port = lp_raw
            .as_i64()
            .or_else(|| lp_raw.as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| anyhow!("invalid local_port"))?;
        if local_port < 1024 || local_port > 65535 {
            return Err(anyhow!("local_port must be 1024-65535"));
        }
        let node = payload
            .get("node")
            .or_else(|| item.get("node"))
            .and_then(|v| v.as_str())
            .unwrap_or(&tsh_node())
            .trim()
            .to_string();
        if !NODE_RE.is_match(&node) || node.to_lowercase().contains("farmlink") {
            return Err(anyhow!("invalid Teleport node"));
        }
        reject(&[&node])?;
        item.insert("local_port".into(), json!(local_port));
        item.insert(
            "remote".into(),
            json!(loopback_addr(
                payload
                    .get("remote")
                    .or_else(|| item.get("remote"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            )?),
        );
        item.insert("node".into(), json!(node));
        item.insert("sni".into(), json!(""));
        item.insert("target".into(), json!(""));
        item.insert("passthrough".into(), json!(false));
        item.insert("command".into(), json!(tsh_cmd(&item)));
    }
    if !item.contains_key("created") {
        item.insert("created".into(), json!(updated));
    }
    Ok(item)
}

fn find_item<'a>(items: &'a [Value], ident: &str) -> Option<(usize, &'a Map<String, Value>)> {
    let ident = ident.trim();
    for (i, item) in items.iter().enumerate() {
        let Some(obj) = item.as_object() else {
            continue;
        };
        if obj.get("id").and_then(|v| v.as_str()) == Some(ident)
            || obj.get("name").and_then(|v| v.as_str()) == Some(ident)
        {
            return Some((i, obj));
        }
    }
    None
}

pub fn upsert_route(payload: Map<String, Value>) -> Result<Value> {
    let mut store = load_store();
    let ident = payload
        .get("id")
        .or_else(|| payload.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let routes = store
        .get_mut("routes")
        .and_then(|v| v.as_array_mut())
        .context("routes")?;
    let current_idx = find_item(routes, &ident).map(|(i, _)| i);
    let current = current_idx.and_then(|i| routes.get(i).and_then(|v| v.as_object()));
    let item = normalize_route(&payload, current)?;
    let op = if current_idx.is_none() {
        if find_item(
            routes,
            item.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        )
        .is_some()
        {
            return Err(anyhow!("route name already exists"));
        }
        routes.push(Value::Object(item.clone()));
        "create"
    } else {
        let idx = current_idx.unwrap();
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
        for (i, other) in routes.iter().enumerate() {
            if i != idx
                && other
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| n == name)
                    .unwrap_or(false)
            {
                return Err(anyhow!("route name already exists"));
            }
        }
        routes[idx] = Value::Object(item.clone());
        "update"
    };
    save_store(&store)?;
    let applied = apply_fragment(Some(&store))?;
    let mut audit_payload = Map::new();
    audit_payload.insert(
        "name".into(),
        item.get("name").cloned().unwrap_or(json!("")),
    );
    audit_payload.insert(
        "host".into(),
        item.get("host").cloned().unwrap_or(json!("")),
    );
    audit(&format!("route.{op}"), &audit_payload);
    let mut out = applied.as_object().cloned().unwrap_or_default();
    out.insert("ok".into(), json!(true));
    out.insert("item".into(), Value::Object(item));
    out.insert("op".into(), json!(op));
    Ok(Value::Object(out))
}

pub fn delete_route(ident: &str) -> Result<Value> {
    let mut store = load_store();
    let routes = store
        .get_mut("routes")
        .and_then(|v| v.as_array_mut())
        .context("routes")?;
    let Some((idx, item)) = find_item(routes, ident) else {
        return Err(anyhow!("route not found"));
    };
    let name = item.get("name").cloned();
    let deleted = item.get("id").cloned();
    routes.remove(idx);
    save_store(&store)?;
    let applied = apply_fragment(Some(&store))?;
    let mut audit_payload = Map::new();
    audit_payload.insert("name".into(), name.unwrap_or(json!("")));
    audit("route.delete", &audit_payload);
    let mut out = applied.as_object().cloned().unwrap_or_default();
    out.insert("ok".into(), json!(true));
    out.insert("deleted".into(), deleted.unwrap_or(json!("")));
    Ok(Value::Object(out))
}

pub fn upsert_tunnel(payload: Map<String, Value>) -> Result<Value> {
    let mut store = load_store();
    let ident = payload
        .get("id")
        .or_else(|| payload.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let tunnels = store
        .get_mut("tunnels")
        .and_then(|v| v.as_array_mut())
        .context("tunnels")?;
    let current_idx = find_item(tunnels, &ident).map(|(i, _)| i);
    let current = current_idx.and_then(|i| tunnels.get(i).and_then(|v| v.as_object()));
    let mut item = normalize_tunnel(&payload, current)?;
    let op = if current_idx.is_none() {
        if find_item(
            tunnels,
            item.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        )
        .is_some()
        {
            return Err(anyhow!("tunnel name already exists"));
        }
        tunnels.push(Value::Object(item.clone()));
        "create"
    } else {
        let idx = current_idx.unwrap();
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
        for (i, other) in tunnels.iter().enumerate() {
            if i != idx
                && other
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| n == name)
                    .unwrap_or(false)
            {
                return Err(anyhow!("tunnel name already exists"));
            }
        }
        if item.get("kind").and_then(|v| v.as_str()) == Some("local") {
            item.insert("command".into(), json!(tsh_cmd(&item)));
        }
        tunnels[idx] = Value::Object(item.clone());
        "update"
    };
    save_store(&store)?;
    let applied = apply_fragment(Some(&store))?;
    let mut audit_payload = Map::new();
    audit_payload.insert(
        "name".into(),
        item.get("name").cloned().unwrap_or(json!("")),
    );
    audit_payload.insert(
        "kind".into(),
        item.get("kind").cloned().unwrap_or(json!("")),
    );
    audit(&format!("tunnel.{op}"), &audit_payload);
    let mut out = applied.as_object().cloned().unwrap_or_default();
    out.insert("ok".into(), json!(true));
    out.insert("item".into(), Value::Object(item));
    out.insert("op".into(), json!(op));
    Ok(Value::Object(out))
}

pub fn delete_tunnel(ident: &str) -> Result<Value> {
    let mut store = load_store();
    let tunnels = store
        .get_mut("tunnels")
        .and_then(|v| v.as_array_mut())
        .context("tunnels")?;
    let Some((idx, item)) = find_item(tunnels, ident) else {
        return Err(anyhow!("tunnel not found"));
    };
    let name = item.get("name").cloned();
    let deleted = item.get("id").cloned();
    tunnels.remove(idx);
    save_store(&store)?;
    let applied = apply_fragment(Some(&store))?;
    let mut audit_payload = Map::new();
    audit_payload.insert("name".into(), name.unwrap_or(json!("")));
    audit("tunnel.delete", &audit_payload);
    let mut out = applied.as_object().cloned().unwrap_or_default();
    out.insert("ok".into(), json!(true));
    out.insert("deleted".into(), deleted.unwrap_or(json!("")));
    Ok(Value::Object(out))
}

pub fn payload() -> Result<Value> {
    let mut store = load_store();
    let applied = apply_fragment(Some(&store))?;
    let http_live = live_http();
    let tcp_live = live_tcp();
    if let Some(tunnels) = store.get_mut("tunnels").and_then(|v| v.as_array_mut()) {
        for item in tunnels.iter_mut() {
            if let Some(obj) = item.as_object_mut() {
                if obj.get("kind").and_then(|v| v.as_str()) == Some("local") {
                    obj.insert("command".into(), json!(tsh_cmd(obj)));
                }
            }
        }
    }
    let mut reserved: Vec<String> = reserved().into_iter().collect();
    reserved.sort();
    let mut deny: Vec<String> = deny_hosts().into_iter().collect();
    deny.sort();
    Ok(json!({
        "ok": true,
        "routes": store.get("routes").cloned().unwrap_or(json!([])),
        "tunnels": store.get("tunnels").cloned().unwrap_or(json!([])),
        "live_http": http_live,
        "live_tcp": tcp_live,
        "reserved": reserved,
        "deny_hosts": deny,
        "chains": CHAINS,
        "apply": applied,
        "policy": {
            "no_bouncer_on_waf": true,
            "no_nomad_restart": true,
            "no_traefik_mutate": true,
            "loopback_or_netbird_only": true,
            "sidecar_file": fragment_name(),
        },
        "local_tunnel": {
            "command": "tsh ssh -N -L 18990:127.0.0.1:18990 root@localhost",
            "url": "http://127.0.0.1:18990/waf/",
            "script": ".\\scripts\\waf-admin.ps1 tunnel",
        },
    }))
}

pub fn admin_payload() -> Result<Value> {
    let data = payload()?;
    Ok(json!({
        "ok": true,
        "routes": data.get("routes").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        "tunnels": data.get("tunnels").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        "live_http": data.get("live_http").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        "live_tcp": data.get("live_tcp").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        "apply": data.get("apply"),
        "policy": data.get("policy"),
        "local_tunnel": data.get("local_tunnel").cloned().unwrap_or(json!({
            "command": "tsh ssh -N -L 18990:127.0.0.1:18990 root@localhost",
            "url": "http://127.0.0.1:18990/waf/",
            "script": ".\\scripts\\waf-admin.ps1 tunnel",
        })),
        "actions": [
            {"view": "sites", "title": "WAF policies", "detail": "Per-FQDN AppSec allow/skip/bypass"},
            {"view": "allowlists", "title": "Allowlists", "detail": "Operator CIDR allowlist on LAPI"},
            {"view": "decisions", "title": "Decisions", "detail": "Local ban / unban"},
            {"view": "domains", "title": "Domains", "detail": "Origin vs public health"},
            {"view": "engine", "title": "Engine", "detail": "Fail-closed posture (read-only)"},
        ],
    }))
}
