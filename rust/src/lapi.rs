//! CrowdSec LAPI / probe / metrics helpers (port of app.py internals).

use std::collections::HashMap;
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use native_tls::TlsConnector;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::catalog;
use crate::control;
use crate::correlate;
use crate::dashboard;
use crate::ga;
use crate::netguard::{self, TtlCache};
use crate::status;

pub static CACHE: Lazy<TtlCache> = Lazy::new(TtlCache::new);

static TOKEN: Lazy<Mutex<TokenState>> = Lazy::new(|| {
    Mutex::new(TokenState {
        value: None,
        exp: Instant::now(),
        url: None,
    })
});

struct TokenState {
    value: Option<String>,
    exp: Instant,
    url: Option<String>,
}

static LOCAL_ORIGINS: &[&str] = &["crowdsec", "cscli", "console", "cscli-import"];

static COUNTRY_CENTROID: Lazy<HashMap<&'static str, (f64, f64)>> = Lazy::new(|| {
    [
        ("AD", (42.5, 1.5)),
        ("AE", (23.4, 53.8)),
        ("AF", (33.9, 67.7)),
        ("AL", (41.2, 20.2)),
        ("AM", (40.1, 45.0)),
        ("AO", (-11.2, 17.9)),
        ("AR", (-38.4, -63.6)),
        ("AT", (47.5, 14.6)),
        ("AU", (-25.3, 133.8)),
        ("AZ", (40.1, 47.6)),
        ("BA", (43.9, 17.7)),
        ("BD", (23.7, 90.4)),
        ("BE", (50.5, 4.5)),
        ("BG", (42.7, 25.5)),
        ("BH", (26.0, 50.6)),
        ("BO", (-16.3, -63.6)),
        ("BR", (-14.2, -51.9)),
        ("BY", (53.7, 27.9)),
        ("CA", (56.1, -106.3)),
        ("CH", (46.8, 8.2)),
        ("CL", (-35.7, -71.5)),
        ("CN", (35.9, 104.2)),
        ("CO", (4.6, -74.3)),
        ("CR", (9.7, -83.8)),
        ("CU", (21.5, -78.0)),
        ("CY", (35.1, 33.4)),
        ("CZ", (49.8, 15.5)),
        ("DE", (51.2, 10.5)),
        ("DK", (56.3, 9.5)),
        ("DO", (18.7, -70.2)),
        ("DZ", (28.0, 1.7)),
        ("EC", (-1.8, -78.2)),
        ("EE", (58.6, 25.0)),
        ("EG", (26.8, 30.8)),
        ("ES", (40.5, -3.7)),
        ("ET", (9.1, 40.5)),
        ("FI", (61.9, 25.7)),
        ("FR", (46.2, 2.2)),
        ("GB", (55.4, -3.4)),
        ("GE", (42.3, 43.4)),
        ("GH", (7.9, -1.0)),
        ("GR", (39.1, 21.8)),
        ("GT", (15.8, -90.2)),
        ("HK", (22.4, 114.1)),
        ("HN", (15.2, -86.2)),
        ("HR", (45.1, 15.2)),
        ("HU", (47.2, 19.5)),
        ("ID", (-0.8, 113.9)),
        ("IE", (53.1, -8.2)),
        ("IL", (31.0, 34.9)),
        ("IN", (20.6, 79.0)),
        ("IQ", (33.2, 43.7)),
        ("IR", (32.4, 53.7)),
        ("IS", (64.96, -19.0)),
        ("IT", (41.9, 12.6)),
        ("JM", (18.1, -77.3)),
        ("JO", (30.6, 36.2)),
        ("JP", (36.2, 138.3)),
        ("KE", (-0.02, 37.9)),
        ("KG", (41.2, 74.8)),
        ("KH", (12.6, 105.0)),
        ("KR", (35.9, 127.8)),
        ("KW", (29.3, 47.5)),
        ("KZ", (48.0, 67.0)),
        ("LA", (19.9, 102.5)),
        ("LB", (33.9, 35.9)),
        ("LK", (7.9, 80.8)),
        ("LT", (55.2, 23.9)),
        ("LU", (49.8, 6.1)),
        ("LV", (56.9, 24.6)),
        ("LY", (26.3, 17.2)),
        ("MA", (31.8, -7.1)),
        ("MD", (47.4, 28.4)),
        ("ME", (42.7, 19.4)),
        ("MK", (41.6, 21.7)),
        ("MM", (21.9, 95.9)),
        ("MN", (46.9, 103.8)),
        ("MX", (23.6, -102.6)),
        ("MY", (4.2, 101.98)),
        ("NG", (9.1, 8.7)),
        ("NL", (52.1, 5.3)),
        ("NO", (60.5, 8.5)),
        ("NP", (28.4, 84.1)),
        ("NZ", (-40.9, 174.9)),
        ("OM", (21.5, 55.9)),
        ("PA", (8.5, -80.8)),
        ("PE", (-9.2, -75.0)),
        ("PH", (12.9, 121.8)),
        ("PK", (30.4, 69.3)),
        ("PL", (51.9, 19.1)),
        ("PR", (18.2, -66.6)),
        ("PS", (31.95, 35.2)),
        ("PT", (39.4, -8.2)),
        ("PY", (-23.4, -58.4)),
        ("QA", (25.4, 51.2)),
        ("RO", (45.9, 24.97)),
        ("RS", (44.0, 21.0)),
        ("RU", (61.5, 105.3)),
        ("SA", (23.9, 45.1)),
        ("SE", (60.1, 18.6)),
        ("SG", (1.35, 103.8)),
        ("SI", (46.2, 14.99)),
        ("SK", (48.7, 19.7)),
        ("SN", (14.5, -14.5)),
        ("SV", (13.8, -88.9)),
        ("SY", (34.8, 38.99)),
        ("TH", (15.9, 100.99)),
        ("TJ", (38.9, 71.3)),
        ("TN", (33.9, 9.5)),
        ("TR", (38.96, 35.2)),
        ("TW", (23.7, 121.0)),
        ("TZ", (-6.4, 34.9)),
        ("UA", (48.4, 31.2)),
        ("UG", (1.4, 32.3)),
        ("US", (37.1, -95.7)),
        ("UY", (-32.5, -55.8)),
        ("UZ", (41.4, 64.6)),
        ("VE", (6.4, -66.6)),
        ("VN", (14.1, 108.3)),
        ("YE", (15.6, 48.5)),
        ("ZA", (-30.6, 22.9)),
        ("ZW", (-19.0, 29.2)),
    ]
    .into_iter()
    .collect()
});

pub fn config_root() -> PathBuf {
    PathBuf::from(std::env::var("CROWDSEC_CONFIG").unwrap_or_else(|_| "/etc/crowdsec".into()))
}

pub fn creds_path() -> PathBuf {
    PathBuf::from(
        std::env::var("CROWDSEC_CREDS")
            .unwrap_or_else(|_| "/etc/crowdsec/local_api_credentials.yaml".into()),
    )
}

pub fn profiles_path() -> PathBuf {
    PathBuf::from(
        std::env::var("CROWDSEC_PROFILES").unwrap_or_else(|_| "/etc/crowdsec/profiles.yaml".into()),
    )
}

pub fn bouncer_key_path() -> PathBuf {
    PathBuf::from(std::env::var("CROWDSEC_BOUNCER_KEY").unwrap_or_else(|_| "/run/lapi_key".into()))
}

pub fn metrics_url() -> Result<String> {
    netguard::assert_loopback_http_url(
        &std::env::var("CROWDSEC_METRICS")
            .unwrap_or_else(|_| "http://127.0.0.1:6060/metrics".into()),
        "CROWDSEC_METRICS",
    )
}

pub fn public_ip() -> Result<String> {
    netguard::assert_probe_server(&std::env::var("PUBLIC_IP").unwrap_or_default(), "PUBLIC_IP")
}

pub fn probe_cache_ttl() -> f64 {
    netguard::env_int("WAF_PROBE_CACHE_TTL", 20, 0, 300) as f64
}
pub fn metrics_cache_ttl() -> f64 {
    netguard::env_int("WAF_METRICS_CACHE_TTL", 10, 0, 120) as f64
}
pub fn alerts_cache_ttl() -> f64 {
    netguard::env_int("WAF_ALERTS_CACHE_TTL", 8, 0, 120) as f64
}

/// Max alerts pulled from LAPI per request (CrowdSec clamps server-side; we cap at 500).
pub fn alerts_fetch_limit(default: usize) -> usize {
    netguard::env_int("WAF_ALERTS_LIMIT", default as i64, 1, 500) as usize
}
pub fn engine_cache_ttl() -> f64 {
    netguard::env_int("WAF_ENGINE_CACHE_TTL", 3, 0, 60) as f64
}
pub fn probe_workers() -> usize {
    netguard::env_int("WAF_PROBE_WORKERS", 8, 1, 32) as usize
}

fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(status::app_name())
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| anyhow!(e))
}

pub fn parse_simple_yaml(path: &Path) -> HashMap<String, String> {
    let mut data = HashMap::new();
    let Ok(bytes) = std::fs::read(path) else {
        return data;
    };
    // Normalize CRLF / UTF-8 BOM so host-edited YAML matches Python's splitlines().
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    for raw in text.split('\n') {
        let line = raw.trim().trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') || !line.contains(':') {
            continue;
        }
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let val = val
            .trim()
            .trim_end_matches('\r')
            .trim_matches(|c| c == '"' || c == '\'');
        data.insert(key.to_string(), val.to_string());
    }
    data
}

pub fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

pub fn bouncer_key() -> String {
    let path = bouncer_key_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => String::new(),
    }
}

pub fn lapi_login() -> Result<String> {
    {
        let guard = TOKEN.lock().map_err(|_| anyhow!("token lock"))?;
        if let Some(ref v) = guard.value {
            if guard.exp > Instant::now() + Duration::from_secs(30) {
                return Ok(v.clone());
            }
        }
    }
    let creds = parse_simple_yaml(&creds_path());
    // Prefer explicit env remap (host publishes LAPI on 18080 while file may say :8080).
    let url = netguard::assert_loopback_http_url(
        std::env::var("CROWDSEC_LAPI")
            .ok()
            .or_else(|| creds.get("url").cloned())
            .as_deref()
            .unwrap_or("http://127.0.0.1:18080"),
        "CROWDSEC_LAPI",
    )?;
    let login = creds
        .get("login")
        .or_else(|| creds.get("machine_id"))
        .or_else(|| {
            creds
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("login") || k.eq_ignore_ascii_case("machine_id"))
                .map(|(_, v)| v)
        })
        .cloned()
        .unwrap_or_default();
    let password = creds
        .get("password")
        .or_else(|| {
            creds
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("password"))
                .map(|(_, v)| v)
        })
        .cloned()
        .unwrap_or_default();
    if login.is_empty() || password.is_empty() {
        return Err(anyhow!(
            "LAPI credentials missing login/password in {}",
            creds_path().display()
        ));
    }
    // Raw HTTP/1.0 login (Python urllib parity). Avoids reqwest edge-cases that
    // produced empty User-Agent + HTTP 401 against CrowdSec while urllib succeeded.
    let (status, payload) = watchers_login_raw(&url, &login, &password)?;
    if !(200..300).contains(&status) {
        let detail = payload
            .get("message")
            .or_else(|| payload.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect::<String>();
        return Err(anyhow!(
            "LAPI login HTTP {} {} {} (login_len={} pw_len={} url={})",
            status,
            path_hint(&payload),
            detail,
            login.len(),
            password.len(),
            url
        ));
    }
    // CrowdSec may return JWT in "token" or legacy "code".
    let token = payload
        .get("token")
        .or_else(|| payload.get("code"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "LAPI login returned no token (keys={})",
                path_hint(&payload)
            )
        })?
        .to_string();
    let mut guard = TOKEN.lock().map_err(|_| anyhow!("token lock"))?;
    guard.value = Some(token.clone());
    guard.exp = Instant::now() + Duration::from_secs(8 * 60);
    guard.url = Some(url);
    Ok(token)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn watchers_login_raw(base: &str, login: &str, password: &str) -> Result<(u16, Value)> {
    use std::io::{Read, Write};
    let parsed = url::Url::parse(base).map_err(|e| anyhow!("LAPI url: {e}"))?;
    let host = parsed.host_str().unwrap_or("127.0.0.1");
    let port = parsed.port_or_known_default().unwrap_or(80);
    let body = format!(
        "{{\"machine_id\":\"{}\",\"password\":\"{}\"}}",
        json_escape(login),
        json_escape(password)
    );
    let req = format!(
        "POST /v1/watchers/login HTTP/1.0\r\nHost: {host}:{port}\r\nUser-Agent: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status::app_name(),
        body.len(),
        body
    );
    let mut stream = TcpStream::connect_timeout(
        &format!("{host}:{port}")
            .parse()
            .map_err(|e| anyhow!("LAPI addr: {e}"))?,
        Duration::from_secs(12),
    )
    .map_err(|e| anyhow!("LAPI login connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(12)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(12)))
        .ok();
    stream
        .write_all(req.as_bytes())
        .map_err(|e| anyhow!("LAPI login write: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| anyhow!("LAPI login read: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let mut parts = text.splitn(2, "\r\n\r\n");
    let header = parts.next().unwrap_or("");
    let body_text = parts.next().unwrap_or("").trim();
    let status = header
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let payload = if body_text.is_empty() {
        json!({})
    } else {
        serde_json::from_str(body_text).unwrap_or_else(|_| json!({"raw": body_text.chars().take(400).collect::<String>()}))
    };
    Ok((status, payload))
}

fn path_hint(payload: &Value) -> String {
    payload
        .as_object()
        .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
        .unwrap_or_else(|| "?".into())
}

pub fn lapi_bouncer(path: &str, query: &[(&str, String)]) -> Result<Value> {
    let key = bouncer_key();
    if key.is_empty() {
        return Err(anyhow!("bouncer key missing"));
    }
    let creds = parse_simple_yaml(&creds_path());
    let base = netguard::assert_loopback_http_url(
        std::env::var("CROWDSEC_LAPI")
            .ok()
            .or_else(|| creds.get("url").cloned())
            .as_deref()
            .unwrap_or("http://127.0.0.1:18080"),
        "CROWDSEC_LAPI",
    )?;
    let client = http_client()?;
    let mut url = url::Url::parse(&format!("{base}{path}")).map_err(|e| anyhow!(e))?;
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in query {
            qp.append_pair(k, v);
        }
    }
    let resp = client
        .get(url)
        .header("X-Api-Key", key)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| anyhow!(e))?;
    let text = resp.text().map_err(|e| anyhow!(e))?;
    if text.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&text).map_err(|e| anyhow!(e))
}

pub fn lapi(
    method: &str,
    path: &str,
    query: &[(&str, String)],
    body: Option<Value>,
) -> Result<Value> {
    let token = lapi_login()?;
    let base = {
        let guard = TOKEN.lock().map_err(|_| anyhow!("token lock"))?;
        guard
            .url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:18080".into())
    };
    let client = http_client()?;
    let mut url = url::Url::parse(&format!("{base}{path}")).map_err(|e| anyhow!(e))?;
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in query {
            qp.append_pair(k, v);
        }
    }
    let mut builder = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "DELETE" => client.delete(url),
        "PUT" => client.put(url),
        other => return Err(anyhow!("unsupported method {other}")),
    };
    builder = builder
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json");
    if let Some(b) = body {
        builder = builder.json(&b);
    }
    let resp = builder.send().map_err(|e| anyhow!(e))?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        if let Ok(mut guard) = TOKEN.lock() {
            guard.value = None;
        }
        return Err(anyhow!(
            "LAPI {} {}: {}",
            status.as_u16(),
            path,
            text.chars().take(800).collect::<String>()
        ));
    }
    if text.is_empty() {
        return Ok(json!({"ok": true, "status": status.as_u16()}));
    }
    match serde_json::from_str(&text) {
        Ok(v) => Ok(v),
        Err(_) => Ok(json!({
            "raw": text.chars().take(2000).collect::<String>(),
            "status": status.as_u16()
        })),
    }
}

pub fn lapi_soft(method: &str, path: &str, query: &[(&str, String)]) -> (u16, Value) {
    match lapi(method, path, query, None) {
        Ok(v) => (200, v),
        Err(e) => {
            let msg = e.to_string();
            let code = Regex::new(r"LAPI (\d{3}) ")
                .ok()
                .and_then(|re| {
                    re.captures(&msg)
                        .and_then(|c| c.get(1))
                        .and_then(|m| m.as_str().parse().ok())
                })
                .unwrap_or(0);
            (code, json!({"error": msg}))
        }
    }
}

pub fn tcp_open(host: &str, port: u16, timeout: f64) -> bool {
    TcpStream::connect_timeout(
        &format!("{host}:{port}")
            .parse()
            .ok()
            .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], port))),
        Duration::from_secs_f64(timeout),
    )
    .is_ok()
}

pub fn http_text(url: &str, timeout: f64) -> (u16, String) {
    let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs_f64(timeout))
        .build()
    else {
        return (0, "client build failed".into());
    };
    match client.get(url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            let limited: String = text.chars().take(2_000_000).collect();
            (status, limited)
        }
        Err(e) => (0, e.to_string()),
    }
}

pub fn http_probe(host: &str, server: &str) -> Value {
    let host = match netguard::sanitize_hostname(host) {
        Ok(h) => h,
        Err(e) => {
            return json!({"host": host, "via": server, "status": 0, "error": e.to_string()});
        }
    };
    let server = match netguard::assert_probe_server(server, "probe_server") {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => server.to_string(),
        Err(e) => {
            return json!({"host": host, "via": server, "status": 0, "error": e.to_string()});
        }
    };
    let connector = match TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return json!({"host": host, "via": server, "status": 0, "error": e.to_string()});
        }
    };
    let result = (|| -> Result<Value> {
        let tcp = TcpStream::connect_timeout(
            &format!("{server}:443")
                .parse()
                .map_err(|e| anyhow!("{e}"))?,
            Duration::from_secs(8),
        )?;
        let mut stream = connector.connect(&host, tcp)?;
        let req = format!(
            "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            status::app_name()
        );
        use std::io::{Read, Write};
        stream.write_all(req.as_bytes())?;
        let mut data = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
            if data.len() > 400 {
                break;
            }
        }
        let status_line =
            String::from_utf8_lossy(data.split(|&b| b == b'\n').next().unwrap_or(&[]))
                .trim()
                .to_string();
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Ok(json!({"host": host, "via": server, "status": code, "line": status_line}))
    })();
    match result {
        Ok(v) => v,
        Err(e) => json!({"host": host, "via": server, "status": 0, "error": e.to_string()}),
    }
}

pub fn probe_hosts(hosts: &[String], server: &str) -> Vec<Value> {
    let key = format!("probe|{server}|{}", hosts.join(","));
    if let Some(hit) = CACHE.get(&key) {
        if let Some(arr) = hit.as_array() {
            return arr.clone();
        }
    }
    if hosts.is_empty() {
        return vec![];
    }
    let workers = probe_workers().min(hosts.len().max(1));
    let results: Vec<Value> = std::thread::scope(|scope| {
        let chunk = (hosts.len() + workers - 1) / workers;
        let mut handles = Vec::new();
        for part in hosts.chunks(chunk.max(1)) {
            let part: Vec<String> = part.to_vec();
            let server = server.to_string();
            handles.push(scope.spawn(move || {
                part.into_iter()
                    .map(|h| http_probe(&h, &server))
                    .collect::<Vec<_>>()
            }));
        }
        let mut out = Vec::new();
        for h in handles {
            if let Ok(part) = h.join() {
                out.extend(part);
            }
        }
        // restore host order
        let by_host: HashMap<String, Value> = out
            .into_iter()
            .filter_map(|v| {
                let host = v.get("host")?.as_str()?.to_string();
                Some((host, v))
            })
            .collect();
        hosts
            .iter()
            .map(|h| {
                by_host
                    .get(h)
                    .cloned()
                    .unwrap_or_else(|| json!({"host": h, "via": server, "status": 0}))
            })
            .collect()
    });
    CACHE.set(&key, Value::Array(results.clone()), probe_cache_ttl());
    results
}

pub fn engine_status() -> Value {
    if let Some(hit) = CACHE.get("engine_status") {
        return hit;
    }
    let profiles = read_text(&profiles_path());
    let acquis = read_text(&config_root().join("acquis.d").join("appsec.yaml"));
    let include_large = Regex::new(r"(?i)INCLUDE_LARGE_UPLOADS\s*[:=]\s*(1|true|yes)")
        .ok()
        .map(|re| re.is_match(&acquis))
        .unwrap_or(false);
    let creds = parse_simple_yaml(&creds_path());
    let url = std::env::var("CROWDSEC_LAPI")
        .ok()
        .or_else(|| creds.get("url").cloned())
        .unwrap_or_else(|| "http://127.0.0.1:18080".into());
    let login = creds
        .get("login")
        .or_else(|| creds.get("machine_id"))
        .cloned()
        .unwrap_or_default();
    let password = creds.get("password").cloned().unwrap_or_default();
    let payload = json!({
        "lapi_listen": tcp_open("127.0.0.1", 18080, 1.2),
        "appsec_listen": tcp_open("127.0.0.1", 7422, 1.2),
        "metrics_listen": tcp_open("127.0.0.1", 6060, 1.2),
        "oob_log_only": profiles.contains("appsec_outofband_log_only"),
        "crs_inband_present": profiles.contains("crs-inband") && profiles.contains("name: crs-inband"),
        // CSO policy constant (Traefik bouncer fail-closed) — not a live LAPI/TCP probe.
        "fail_closed": true,
        "fail_closed_mode": "cso_enforced",
        "fail_closed_source": "traefik_bouncer_policy",
        "fail_closed_mutable": false,
        "include_large_uploads": include_large,
        "creds_present": creds_path().is_file(),
        "bouncer_key_present": !bouncer_key().is_empty(),
        "lapi_creds": {
            "path": creds_path().display().to_string(),
            "login_len": login.len(),
            "password_len": password.len(),
            "url": url,
            "login_is_localhost": login.eq_ignore_ascii_case("localhost"),
        },
        "version": status::app_name(),
        "locale": {"default": "en", "supported": ["en", "pt-BR"]},
        "runtime": "rust",
        "tuning": {
            "probe_cache_ttl": probe_cache_ttl(),
            "metrics_cache_ttl": metrics_cache_ttl(),
            "alerts_cache_ttl": alerts_cache_ttl(),
            "alerts_fetch_limit": alerts_fetch_limit(500),
            "engine_cache_ttl": engine_cache_ttl(),
            "probe_workers": probe_workers(),
            "post_rate": netguard::env_int("WAF_POST_RATE", 60, 5, 600),
            "heavy_get_rate": netguard::env_int("WAF_HEAVY_GET_RATE", 40, 5, 600),
        },
    });
    CACHE.set("engine_status", payload.clone(), engine_cache_ttl());
    payload
}

pub fn flatten_decisions(payload: &Value) -> Vec<Value> {
    match payload {
        Value::Array(a) => a.clone(),
        Value::Object(o) => {
            let mut items = Vec::new();
            for key in ["new", "decisions"] {
                if let Some(Value::Array(a)) = o.get(key) {
                    items.extend(a.clone());
                }
            }
            items
        }
        _ => vec![],
    }
}

pub fn is_local_decision(item: &Value) -> bool {
    let origin = item
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    LOCAL_ORIGINS.iter().any(|o| *o == origin)
}

pub fn prefer_local_decisions(items: &[Value], limit: usize) -> Vec<Value> {
    items
        .iter()
        .filter(|d| is_local_decision(d))
        .take(limit)
        .cloned()
        .collect()
}

pub fn fetch_local_decisions() -> (Vec<Value>, Option<String>) {
    match lapi_bouncer(
        "/v1/decisions/stream",
        &[
            ("startup", "true".into()),
            ("origins", "crowdsec,cscli".into()),
            ("dedup", "false".into()),
        ],
    ) {
        Ok(payload) => (flatten_decisions(&payload), None),
        Err(first) => match lapi_bouncer("/v1/decisions/stream", &[("startup", "true".into())]) {
            Ok(payload) => {
                let items = flatten_decisions(&payload);
                (prefer_local_decisions(&items, 500), Some(first.to_string()))
            }
            Err(exc) => (vec![], Some(format!("{first} | {exc}"))),
        },
    }
}

pub fn source_of(alert: &Map<String, Value>) -> Map<String, Value> {
    let mut src = alert
        .get("source")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let event0 = alert
        .get("events")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|e| e.get("source"))
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    for (k, v) in event0.iter() {
        src.entry(k.clone()).or_insert_with(|| v.clone());
    }
    for (k, v) in alert
        .get("source")
        .and_then(|v| v.as_object())
        .into_iter()
        .flatten()
    {
        src.insert(k.clone(), v.clone());
    }
    let ip = src
        .get("ip")
        .or_else(|| src.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let cn = src
        .get("cn")
        .or_else(|| src.get("country"))
        .or_else(|| alert.get("cn"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_uppercase();
    let mut lat_f = src.get("latitude").and_then(|v| {
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    });
    let mut lon_f = src.get("longitude").and_then(|v| {
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    });
    let mut approx = false;
    if (lat_f.is_none() || lon_f.is_none()) && COUNTRY_CENTROID.contains_key(cn.as_str()) {
        let (la, lo) = COUNTRY_CENTROID[cn.as_str()];
        lat_f = Some(la);
        lon_f = Some(lo);
        approx = true;
    }
    let city = src
        .get("city")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut out = Map::new();
    out.insert("ip".into(), json!(ip));
    out.insert("cn".into(), json!(cn));
    out.insert("city".into(), json!(city));
    out.insert(
        "as_name".into(),
        json!(src
            .get("as_name")
            .or_else(|| src.get("asname"))
            .and_then(|v| v.as_str())
            .unwrap_or("")),
    );
    out.insert("lat".into(), json!(lat_f));
    out.insert("lon".into(), json!(lon_f));
    out.insert("approx".into(), json!(approx));
    out.insert(
        "scenario".into(),
        json!(alert.get("scenario").and_then(|v| v.as_str()).unwrap_or("")),
    );
    out.insert(
        "created_at".into(),
        json!(alert
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")),
    );
    out.insert("id".into(), alert.get("id").cloned().unwrap_or(Value::Null));
    out.insert(
        "capacity".into(),
        alert.get("events_count").cloned().unwrap_or(json!(1)),
    );
    out
}

fn yaml_names(text: &str) -> Vec<String> {
    Regex::new(r"(?m)^name:\s*([^\n#]+)")
        .ok()
        .map(|re| {
            re.captures_iter(text)
                .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn yaml_kv(text: &str, key: &str) -> Vec<String> {
    let pat = format!(r"(?m)^{}:\s*(.+)$", regex::escape(key));
    Regex::new(&pat)
        .ok()
        .map(|re| {
            re.captures_iter(text)
                .filter_map(|c| {
                    c.get(1).map(|m| {
                        m.as_str()
                            .trim()
                            .trim_matches(|ch| ch == '"' || ch == '\'')
                            .to_string()
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn extract_cidrs(text: &str) -> Vec<String> {
    let re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b").unwrap();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for m in re.find_iter(text) {
        let item = m.as_str();
        if item.parse::<ipnet::IpNet>().is_ok() || item.parse::<IpAddr>().is_ok() {
            if seen.insert(item.to_string()) {
                out.push(item.to_string());
            }
        }
    }
    out
}

fn hub_summary(kind: &str, list_n: usize) -> Value {
    let mut root = config_root().join("hub").join(kind);
    if !root.is_dir() {
        root = config_root().join(kind);
    }
    let mut items = Vec::new();
    let mut count = 0usize;
    let mut truncated = false;
    if root.is_dir() {
        if let Ok(walker) = walkdir_yaml(&root) {
            for path in walker {
                count += 1;
                if items.len() < list_n {
                    if let Ok(rel) = path.strip_prefix(&root) {
                        items.push(rel.to_string_lossy().replace('\\', "/"));
                    } else {
                        items.push(
                            path.file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .into(),
                        );
                    }
                }
                if count >= 8000 {
                    truncated = true;
                    break;
                }
            }
        }
    }
    items.sort();
    json!({"count": count, "items": items, "truncated": truncated})
}

fn walkdir_yaml(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out)?;
            } else {
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if ext == "yaml" || ext == "yml" {
                    out.push(path);
                }
            }
        }
        Ok(())
    }
    walk(root, &mut out)?;
    Ok(out)
}

pub fn parse_prom(text: &str) -> Value {
    let line_re =
        Regex::new(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+0-9.eE]+)$").unwrap();
    let mut decisions: HashMap<String, f64> = HashMap::new();
    let mut alerts: HashMap<String, f64> = HashMap::new();
    let mut appsec: HashMap<String, f64> = HashMap::new();
    let mut other: HashMap<String, f64> = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.contains("le=")
            || line.contains("quantile=")
        {
            continue;
        }
        let Some(caps) = line_re.captures(line) else {
            continue;
        };
        let name = caps.get(1).unwrap().as_str();
        if name.ends_with("_bucket") {
            continue;
        }
        let labels = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let Ok(value) = caps.get(3).unwrap().as_str().parse::<f64>() else {
            continue;
        };
        let mut label_map = HashMap::new();
        for pair in labels.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                label_map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
        if name == "cs_active_decisions" {
            let origin = label_map
                .get("origin")
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            *decisions.entry(origin).or_default() += value;
        } else if name == "cs_alerts" {
            let mut reason = label_map
                .get("reason")
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            if reason.starts_with("anomaly score out-of-band") {
                reason = "crowdsecurity/crowdsec-appsec-outofband".into();
            }
            *alerts.entry(reason).or_default() += value;
        } else if name.starts_with("cs_appsec_") {
            *appsec.entry(name.to_string()).or_default() += value;
        } else if name.starts_with("cs_")
            && !(name.ends_with("_sum") || name.ends_with("_count") || name.ends_with("_created"))
        {
            *other.entry(name.to_string()).or_default() += value;
        }
    }
    let mut top_alerts: Vec<_> = alerts.into_iter().collect();
    top_alerts.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    top_alerts.truncate(16);
    let local_decisions: f64 = decisions
        .iter()
        .filter(|(k, _)| LOCAL_ORIGINS.iter().any(|o| *o == k.to_lowercase()))
        .map(|(_, v)| *v)
        .sum();
    let capi_decisions: f64 = decisions
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("capi"))
        .map(|(_, v)| *v)
        .sum();
    let mut gauges: Map<String, Value> = Map::new();
    let mut keys: Vec<_> = other.keys().cloned().collect();
    keys.sort();
    for k in keys.into_iter().take(24) {
        gauges.insert(k.clone(), json!(other[&k]));
    }
    json!({
        "decisions_by_origin": decisions,
        "local_decisions": local_decisions,
        "capi_decisions": capi_decisions,
        "top_alerts": top_alerts.into_iter().map(|(k,v)| json!({"reason": k, "count": v})).collect::<Vec<_>>(),
        "appsec": appsec,
        "gauges": gauges,
    })
}

/// Fetch newest alerts from LAPI. When `since` is set (e.g. `"24h"`), CrowdSec
/// filters server-side; the console still applies a client-side 24h window in
/// `dashboard::build` so KPIs never claim more than the time window.
pub fn fetch_alerts(limit: usize) -> Result<Vec<Value>> {
    fetch_alerts_window(limit, Some("24h"))
}

pub fn fetch_alerts_window(limit: usize, since: Option<&str>) -> Result<Vec<Value>> {
    let limit = limit.clamp(1, 500);
    let since_key = since.unwrap_or("-");
    let key = format!("alerts|{limit}|{since_key}");
    if let Some(hit) = CACHE.get(&key) {
        if let Some(arr) = hit.as_array() {
            return Ok(arr.clone());
        }
    }
    let mut query: Vec<(&str, String)> = vec![("limit", limit.to_string())];
    if let Some(s) = since {
        if !s.is_empty() {
            query.push(("since", s.to_string()));
        }
    }
    let data = lapi("GET", "/v1/alerts", &query, None)?;
    let items = data.as_array().cloned().unwrap_or_default();
    CACHE.set(&key, Value::Array(items.clone()), alerts_cache_ttl());
    Ok(items)
}

pub fn edge_point() -> Option<Value> {
    let lat = std::env::var("WAF_EDGE_LAT").ok()?;
    let lon = std::env::var("WAF_EDGE_LON").ok()?;
    let lat_f: f64 = lat.parse().ok()?;
    let lon_f: f64 = lon.parse().ok()?;
    Some(json!({
        "lat": lat_f,
        "lon": lon_f,
        "label": std::env::var("WAF_EDGE_LABEL").unwrap_or_else(|_| "edge".into()),
    }))
}

pub fn build_map(alerts: &[Value]) -> Value {
    let mut points = Vec::new();
    let mut countries: HashMap<String, Map<String, Value>> = HashMap::new();
    for alert in alerts {
        let Some(obj) = alert.as_object() else {
            continue;
        };
        let src = source_of(obj);
        if src.get("lat").and_then(|v| v.as_f64()).is_none()
            || src.get("lon").and_then(|v| v.as_f64()).is_none()
        {
            continue;
        }
        points.push(Value::Object(src.clone()));
        let cn = src
            .get("cn")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("??")
            .to_string();
        let slot = countries.entry(cn.clone()).or_insert_with(|| {
            let mut m = Map::new();
            m.insert("cn".into(), json!(cn));
            m.insert("count".into(), json!(0));
            m.insert("lat".into(), src.get("lat").cloned().unwrap_or(Value::Null));
            m.insert("lon".into(), src.get("lon").cloned().unwrap_or(Value::Null));
            m.insert(
                "city".into(),
                json!(src.get("city").and_then(|v| v.as_str()).unwrap_or("")),
            );
            m
        });
        let cap = src
            .get("capacity")
            .and_then(|v| v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)))
            .unwrap_or(1);
        let count = slot.get("count").and_then(|v| v.as_i64()).unwrap_or(0) + cap;
        slot.insert("count".into(), json!(count));
        if let Some(city) = src.get("city").and_then(|v| v.as_str()) {
            if !city.is_empty()
                && slot
                    .get("city")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .is_empty()
            {
                slot.insert("city".into(), json!(city));
            }
        }
    }
    points.sort_by(|a, b| {
        let aa = a.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        let bb = b.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        bb.cmp(aa)
    });
    points.truncate(80);
    let mut country_list: Vec<Value> = countries.into_values().map(Value::Object).collect();
    country_list.sort_by(|a, b| {
        let aa = a.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
        let bb = b.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
        bb.cmp(&aa)
    });
    country_list.truncate(40);
    let mut payload = Map::new();
    payload.insert("points".into(), Value::Array(points));
    payload.insert("countries".into(), Value::Array(country_list));
    payload.insert("geo_source".into(), json!("crowdsec-lapi"));
    payload.insert(
        "note".into(),
        json!(
            "LAPI coordinates (source.latitude/longitude) or ISO centroid. No third-party GeoIP."
        ),
    );
    payload.insert("edge".into(), edge_point().unwrap_or(Value::Null));
    Value::Object(ga::attach_map(Some(&payload)))
}

pub fn build_rules() -> Value {
    let profiles = read_text(&profiles_path());
    let acquis = read_text(&config_root().join("acquis.d").join("appsec.yaml"));
    let operators = read_text(
        &config_root()
            .join("parsers")
            .join("s02-enrich")
            .join("cso-operators.yaml"),
    );
    let listen = yaml_kv(&acquis, "listen_addr");
    // Ignore YAML comments so "Do not enable crowdsecurity/crs-inband" is not treated as enabled.
    let acquis_nocomment: String = acquis
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let mut configs: Vec<String> = Regex::new(r"(crowdsecurity/[a-zA-Z0-9._-]+)")
        .ok()
        .map(|re| {
            re.captures_iter(&acquis_nocomment)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect()
        })
        .unwrap_or_default();
    configs.sort();
    configs.dedup();
    json!({
        "profiles": {
            "names": yaml_names(&profiles),
            "on_success": yaml_kv(&profiles, "on_success").into_iter().take(12).collect::<Vec<_>>(),
            "filters": yaml_kv(&profiles, "filters").into_iter().take(12).collect::<Vec<_>>(),
        },
        "appsec": {
            "listen_addr": listen.first().cloned().unwrap_or_else(|| "127.0.0.1:7422".into()),
            "configs": configs,
            "raw": acquis.chars().take(1600).collect::<String>(),
        },
        "operators_parser": {
            "present": !operators.trim().is_empty(),
            "cidrs": extract_cidrs(&operators),
        },
        "hub": {
            "collections": hub_summary("collections", 40),
            "scenarios": hub_summary("scenarios", 40),
            "appsec_configs": hub_summary("appsec-configs", 40),
            "appsec_rules": hub_summary("appsec-rules", 24),
            "parsers": hub_summary("parsers", 24),
        },
        "policy": {
            "crs_inband": false,
            "fail_closed": true,
            "include_large_uploads": false,
            "mutations": [
                "unban-ip", "ban-ip", "allowlist-add", "allowlist-remove",
                "policy-create", "policy-update", "policy-delete",
                "site-filter-allow_match", "site-filter-skip_rule", "site-filter-bypass_host",
            ],
            "note": "The UI never enables CRS in-band, INCLUDE_LARGE_UPLOADS or fail-closed changes. Per-host filters use AppSec hooks.",
        },
    })
}

pub fn build_allowlists() -> Value {
    let (status_code, payload) =
        lapi_soft("GET", "/v1/allowlists", &[("with_content", "true".into())]);
    let mut lapi_lists = payload.as_array().cloned().unwrap_or_default();
    if lapi_lists.is_empty() {
        if let Some(obj) = payload.as_object() {
            if let Some(arr) = obj
                .get("allowlists")
                .or_else(|| obj.get("items"))
                .and_then(|v| v.as_array())
            {
                lapi_lists = arr.clone();
            }
        }
    }
    let operators = read_text(
        &config_root()
            .join("parsers")
            .join("s02-enrich")
            .join("cso-operators.yaml"),
    );
    json!({
        "lapi_status": status_code,
        "lapi": lapi_lists,
        "parser_cidrs": extract_cidrs(&operators),
        "parser_file": "parsers/s02-enrich/cso-operators.yaml",
        "note": "LAPI allowlist add/remove CIDR. Operator parser remains IaC.",
    })
}

pub fn scrape_metrics() -> Value {
    if let Some(hit) = CACHE.get("metrics") {
        return hit;
    }
    let Ok(url) = metrics_url() else {
        return json!({"ok": false, "error": "metrics url invalid", "listen": "127.0.0.1:6060"});
    };
    let (status_code, text) = http_text(&url, 4.0);
    if status_code != 200 {
        let result = json!({
            "ok": false,
            "status": status_code,
            "error": text.chars().take(300).collect::<String>(),
            "listen": "127.0.0.1:6060"
        });
        let ttl = metrics_cache_ttl().min(5.0);
        CACHE.set("metrics", result.clone(), ttl);
        return result;
    }
    let mut parsed = parse_prom(&text);
    if let Some(obj) = parsed.as_object_mut() {
        obj.insert("ok".into(), json!(true));
        obj.insert("status".into(), json!(200));
        obj.insert("listen".into(), json!("127.0.0.1:6060"));
    }
    CACHE.set("metrics", parsed.clone(), metrics_cache_ttl());
    parsed
}

pub fn check_allowlist_ip(ip: &str) -> Result<Value> {
    let addr: IpAddr = ip.parse().map_err(|_| anyhow!("invalid ip"))?;
    let (status_code, body) = lapi_soft("GET", &format!("/v1/allowlists/check/{ip}"), &[]);
    let operators = extract_cidrs(&read_text(
        &config_root()
            .join("parsers")
            .join("s02-enrich")
            .join("cso-operators.yaml"),
    ));
    let mut in_parser = false;
    for cidr in &operators {
        if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
            if net.contains(&addr) {
                in_parser = true;
                break;
            }
        }
    }
    Ok(json!({
        "ok": true,
        "ip": ip,
        "lapi_status": status_code,
        "lapi": body,
        "parser_match": in_parser,
        "parser_cidrs": operators,
    }))
}

pub fn add_ban(payload: &Map<String, Value>) -> Result<Value> {
    let ip = payload
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    ip.parse::<IpAddr>().map_err(|_| anyhow!("invalid ip"))?;
    let duration = control::validate_duration(
        payload
            .get("duration")
            .and_then(|v| v.as_str())
            .unwrap_or("4h"),
    )?;
    let reason = payload
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("cso-console")
        .chars()
        .take(120)
        .collect::<String>();
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let body = json!([{
        "scenario": "manual/cso-ban",
        "scenario_hash": "",
        "scenario_version": "1.2",
        "message": reason,
        "events_count": 1,
        "start_at": now,
        "stop_at": now,
        "capacity": 0,
        "leakspeed": "0",
        "simulated": false,
        "events": [],
        "source": {"scope": "Ip", "value": ip, "ip": ip},
        "decisions": [{
            "duration": duration,
            "reason": reason,
            "origin": "cscli",
            "scenario": "manual/cso-ban",
            "type": "ban",
            "scope": "Ip",
            "value": ip,
        }]
    }]);
    let result = lapi("POST", "/v1/alerts", &[], Some(body))?;
    let mut audit = Map::new();
    audit.insert("ip".into(), json!(ip));
    audit.insert("duration".into(), json!(duration));
    audit.insert("reason".into(), json!(reason));
    control::audit("ban.add", &audit);
    Ok(json!({"ok": true, "ip": ip, "duration": duration, "result": result}))
}

pub fn correlation_payload() -> Result<Value> {
    let alerts = fetch_alerts(alerts_fetch_limit(200))?;
    let hub = control::hub_appsec_rules();
    let corr = correlate::correlate(&alerts, Some(&hub));
    let map = build_map(&alerts);
    Ok(Value::Object(ga::attach_correlation(
        Some(corr.as_object().unwrap_or(&Map::new())),
        Some(map.as_object().unwrap_or(&Map::new())),
    )))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn overview() -> Value {
    let eng = engine_status();
    let mut err: Option<String> = None;
    let mut decisions = vec![];
    let mut alerts = vec![];
    match fetch_local_decisions() {
        (d, Some(e)) if d.is_empty() => {
            err = Some(e);
            decisions = d;
        }
        (d, _) => decisions = d,
    }
    match fetch_alerts(alerts_fetch_limit(100)) {
        Ok(a) => alerts = a,
        Err(e) => err = Some(e.to_string()),
    }
    let hosts = catalog::in_scope_hosts();
    let domains = probe_hosts(&hosts, "127.0.0.1");
    let ok_hosts = domains
        .iter()
        .filter(|d| status::http_status_ok(d.get("status").unwrap_or(&Value::Null)))
        .count();
    let filters = control::load_filters();
    let filter_count = filters
        .get("items")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    json!({
        "ok": err.is_none(),
        "error": err,
        "engine": eng,
        "counts": {
            "decisions": decisions.len(),
            "decisions_local": decisions.len(),
            "community_omitted": true,
            "alerts": alerts.len(),
            "domains_ok": ok_hosts,
            "domains": hosts.len(),
            "filters": filter_count,
        },
        "decisions": prefer_local_decisions(&decisions, 8),
        "map": build_map(&alerts),
        "alerts": alerts.into_iter().take(8).collect::<Vec<_>>(),
        "domains": domains,
        "generated_at": now_unix(),
    })
}

pub fn dashboard_payload(host: &str, filters: HashMap<String, String>) -> Result<Value> {
    let fetch_limit = alerts_fetch_limit(500);
    let alerts = fetch_alerts(fetch_limit)?;
    let (decisions, _) = fetch_local_decisions();
    let hosts = catalog::in_scope_hosts();
    let origin = probe_hosts(&hosts, "127.0.0.1");
    let mx = scrape_metrics();
    let appsec_map = mx.get("appsec").and_then(|v| v.as_object()).cloned();
    let eng = engine_status();
    let eng_map = eng.as_object().cloned().unwrap_or_default();
    let local = prefer_local_decisions(&decisions, 120);
    let hub = control::hub_appsec_rules();
    let edge_val = edge_point();
    let edge_map = edge_val.as_ref().and_then(|v| v.as_object());
    let opts = dashboard::BuildOptions {
        decisions: Some(&local),
        engine: Some(&eng_map),
        hosts: Some(&hosts),
        host,
        origin_probes: Some(&origin),
        public_probes: None,
        hub_rules: Some(&hub),
        now: None,
        filters: Some(&filters),
        appsec: appsec_map.as_ref(),
        edge: edge_map,
        alerts_fetch_limit: Some(fetch_limit),
    };
    Ok(dashboard::build(&alerts, opts))
}
