//! CrowdSec LAPI/AppSec dashboard aggregates (port of dashboard.py).

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::{DateTime, FixedOffset, TimeZone, Timelike, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::status;

pub const SOURCE: &str = "crowdsec-lapi";
pub const NOTE: &str = "LAPI/AppSec events in this window. \
HTTP method/UA/JA4H come from CrowdSec alert meta when present. \
Cache, bytes, visits and 5xx are listed only when present in local sources.";

static GMT3: LazyLock<FixedOffset> =
    LazyLock::new(|| FixedOffset::west_opt(3 * 3600).expect("GMT-3 offset"));

static BOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(googlebot|bingbot|yandexbot|applebot|gptbot|claudebot|bytespider|semrush|ahrefs)",
    )
    .expect("BOT_RE")
});

static HTTP_VER: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("09", "HTTP/0.9"),
        ("10", "HTTP/1.0"),
        ("11", "HTTP/1.1"),
        ("20", "HTTP/2"),
        ("30", "HTTP/3"),
    ])
});

const FILTER_KEYS: &[&str] = &["ip", "path", "country", "action", "method"];

// `regex` crate has no look-around; use boundary-like classes instead of (?<![a-z]).
static SCANNER_UA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[^a-z])nmap(?:[^a-z]|$)\
|(?:^|[^a-z])hping3?(?:[^a-z]|$)\
|(?:^|[^a-z])masscan(?:[^a-z]|$)\
|acunetix\
|owasp[\s-]?zap|(?:^|[^a-z])zaproxy(?:[^a-z]|$)|(?:^|[^a-z])zap/\d\
|(?:^|[^a-z])nessus(?:[^a-z]|$)\
|openvas|(?:^|[^a-z])greenbone(?:[^a-z]|$)\
|(?:^|[^a-z])nikto(?:[^a-z]|$)\
|(?:^|[^a-z])sqlmap(?:[^a-z]|$)\
|(?:^|[^a-z])nuclei(?:[^a-z]|$)\
|(?:^|[^a-z])wpscan(?:[^a-z]|$)\
|(?:^|[^a-z])burp(?:suite)?(?:[^a-z]|$)\
|(?:^|[^a-z])gobuster(?:[^a-z]|$)\
|(?:^|[^a-z])ffuf(?:[^a-z]|$)\
|dirbuster\
|(?:^|[^a-z])jscrawler(?:[^a-z]|$)",
    )
    .expect("SCANNER_UA_RE")
});

static SCANNER_SCENARIO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)probing|scanner|http-crawl|http-scan|bad-user-agent|open-proxy\
|env-access|git-config|uploads-listing",
    )
    .expect("SCANNER_SCENARIO_RE")
});

static SECRET_SCAN_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|/)(?:\.env|\.git(?:/|$)|\.aws(?:/|$)|\.docker(?:/|$))")
        .expect("SECRET_SCAN_PATH")
});

const SCANNER_NOTE: &str = "HTTP AppSec/LAPI scanner detections in this window. \
Hover or click an hour for time, quantity and action split. \
The graph does not name the tool. Chrome/Firefox on ordinary paths are not counted. \
L3/L4 scans (SYN/hping) are invisible here. Updates every 15s.";

fn probe_ok(code: &Value) -> bool {
    status::http_status_ok(code)
}

pub fn unwrap(raw: &Value) -> String {
    let text = match raw {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    };
    let text = text.trim().to_string();
    if text.is_empty() {
        return String::new();
    }
    if text.starts_with('[') && text.ends_with(']') {
        let inner = text[1..text.len() - 1].trim();
        let first = inner
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        let text = if first.is_empty() {
            inner.trim_matches('"').trim_matches('\'').to_string()
        } else {
            first.to_string()
        };
        return text.trim().trim_matches('"').trim_matches('\'').to_string();
    }
    text.trim().trim_matches('"').trim_matches('\'').to_string()
}

fn meta_pairs(blob: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(obj) = blob.as_object() {
        for (key, val) in obj {
            out.push((key.clone(), unwrap(val)));
        }
        return out;
    }
    if let Some(list) = blob.as_array() {
        for row in list {
            if let Some(obj) = row.as_object() {
                let key = obj
                    .get("key")
                    .or_else(|| obj.get("name"))
                    .map(|v| unwrap(v))
                    .unwrap_or_default();
                let val = obj
                    .get("value")
                    .or_else(|| obj.get("val"))
                    .map(|v| unwrap(v))
                    .unwrap_or_default();
                out.push((key, val));
            }
        }
    }
    out
}

pub fn meta_map(alert: &Map<String, Value>) -> HashMap<String, String> {
    let mut merged = HashMap::new();
    if let Some(meta) = alert.get("meta") {
        for (key, val) in meta_pairs(meta) {
            if !key.is_empty() && !val.is_empty() && !merged.contains_key(&key) {
                merged.insert(key, val);
            }
        }
    }
    if let Some(events) = alert.get("events").and_then(|v| v.as_array()) {
        for event in events {
            if let Some(obj) = event.as_object() {
                if let Some(meta) = obj.get("meta") {
                    for (key, val) in meta_pairs(meta) {
                        if !key.is_empty() && !val.is_empty() {
                            merged.insert(key, val);
                        }
                    }
                }
            }
        }
    }
    merged
}

pub fn clean_host(raw: &str) -> String {
    let mut host = unwrap(&Value::String(raw.to_string())).to_lowercase();
    host = host.split(',').next().unwrap_or("").trim().to_string();
    if host.starts_with("http://") || host.starts_with("https://") {
        host = simple_hostname(&host).unwrap_or(host);
    }
    if host.contains(':') && host.matches(':').count() <= 1 {
        host = host.split(':').next().unwrap_or("").to_string();
    }
    if host.starts_with("www.") {
        host = host[4..].to_string();
    }
    host
}

fn simple_hostname(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split('/').next()?.split('@').last()?;
    let host = host.split(':').next()?.to_string();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

pub fn clean_path(raw: &str) -> String {
    let text = unwrap(&Value::String(raw.to_string()));
    let mut path = text.split('?').next().unwrap_or("").trim().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if path.len() > 180 {
        path = format!("{}...", &path[..177]);
    }
    path
}

pub fn http_version_from_ja4h(ja4h: &str) -> String {
    let head = unwrap(&Value::String(ja4h.to_string()))
        .split('_')
        .next()
        .unwrap_or("")
        .to_lowercase();
    if head.len() < 4 {
        return String::new();
    }
    HTTP_VER
        .get(&head[2..4])
        .map(|s| (*s).to_string())
        .unwrap_or_default()
}

pub fn http_of(alert: &Map<String, Value>) -> HashMap<String, String> {
    let meta = meta_map(alert);
    let host = clean_host(
        meta.get("target_fqdn")
            .or(meta.get("target_host"))
            .or(meta.get("http_host"))
            .or(meta.get("host"))
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    let path = clean_path(
        meta.get("target_uri")
            .or(meta.get("uri"))
            .or(meta.get("http_path"))
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    let mut method = unwrap(&Value::String(
        meta.get("http_verb")
            .or(meta.get("verb"))
            .or(meta.get("method"))
            .cloned()
            .unwrap_or_default(),
    ))
    .to_uppercase();
    if method.starts_with('[') || method.contains(' ') {
        method = method.chars().filter(|c| c.is_ascii_uppercase()).collect();
    }
    let ua = unwrap(&Value::String(
        meta.get("http_user_agent")
            .or(meta.get("user_agent"))
            .cloned()
            .unwrap_or_default(),
    ));
    let ja4h = unwrap(&Value::String(
        meta.get("ja4h")
            .or(meta.get("ja4"))
            .cloned()
            .unwrap_or_default(),
    ));
    let mut status = unwrap(&Value::String(
        meta.get("http_status")
            .or(meta.get("status"))
            .cloned()
            .unwrap_or_default(),
    ));
    if !status.is_empty() && !status.chars().all(|c| c.is_ascii_digit()) {
        status.clear();
    }
    let service = meta
        .get("rule_name")
        .or(meta.get("service"))
        .cloned()
        .unwrap_or_else(|| alert.get("scenario").map(|v| unwrap(v)).unwrap_or_default());
    let src = alert
        .get("source")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let asn = unwrap(&Value::String(meta.get("ASNOrg").cloned().unwrap_or_else(
        || {
            src.get("as_name")
                .or(src.get("asname"))
                .map(|v| unwrap(v))
                .unwrap_or_default()
        },
    )));
    let mut out = HashMap::new();
    out.insert("host".into(), host);
    out.insert(
        "path".into(),
        if path.is_empty() { String::new() } else { path },
    );
    out.insert("method".into(), method);
    out.insert("ua".into(), ua);
    out.insert("ja4h".into(), ja4h.clone());
    out.insert("http_version".into(), http_version_from_ja4h(&ja4h));
    out.insert("status".into(), status);
    out.insert("service".into(), service);
    out.insert(
        "rule".into(),
        meta.get("rule_name").cloned().unwrap_or_default(),
    );
    out.insert(
        "rule_ids".into(),
        unwrap(&Value::String(
            meta.get("rule_ids").cloned().unwrap_or_default(),
        )),
    );
    out.insert(
        "zones".into(),
        unwrap(&Value::String(
            meta.get("matched_zones").cloned().unwrap_or_default(),
        )),
    );
    let data = unwrap(&Value::String(
        meta.get("data").cloned().unwrap_or_default(),
    ));
    out.insert("data".into(), data.chars().take(120).collect());
    out.insert("asn".into(), asn);
    out.insert(
        "appsec_action".into(),
        unwrap(&Value::String(
            meta.get("appsec_action").cloned().unwrap_or_default(),
        ))
        .to_lowercase(),
    );
    out
}

pub fn action_of(alert: &Map<String, Value>, http: Option<&HashMap<String, String>>) -> String {
    let http = match http {
        Some(h) => h,
        None => {
            let owned = http_of(alert);
            return action_of(alert, Some(&owned));
        }
    };
    if alert
        .get("decisions")
        .and_then(|d| d.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
    {
        return "Block".into();
    }
    let appsec = http.get("appsec_action").map(|s| s.as_str()).unwrap_or("");
    if matches!(appsec, "ban" | "block" | "deny") {
        return "Block".into();
    }
    let scenario = alert
        .get("scenario")
        .map(|v| unwrap(v).to_lowercase())
        .unwrap_or_default();
    if scenario.contains("outofband") || scenario.starts_with("anomaly score out-of-band") {
        return "Log".into();
    }
    if scenario.contains("manual/cso-ban") {
        return "Block".into();
    }
    "Alert".into()
}

pub fn enrich_alert(alert: &mut Map<String, Value>) {
    let http = http_of(alert);
    if let Some(h) = http.get("host") {
        if !h.is_empty() {
            alert.insert("host".into(), Value::String(h.clone()));
        }
    }
    if let Some(p) = http.get("path") {
        if !p.is_empty() {
            alert.insert("path".into(), Value::String(p.clone()));
        }
    }
    if let Some(m) = http.get("method") {
        if !m.is_empty() {
            alert.insert("method".into(), Value::String(m.clone()));
        }
    }
    let act = action_of(alert, Some(&http));
    alert.insert("action".into(), Value::String(act));
    let service = http
        .get("rule")
        .filter(|s| !s.is_empty())
        .or(http.get("service"))
        .cloned()
        .unwrap_or_else(|| alert.get("scenario").map(|v| unwrap(v)).unwrap_or_default());
    alert.insert("service".into(), Value::String(service));
}

fn parse_time(alert: &Map<String, Value>) -> Option<DateTime<Utc>> {
    let raw = alert
        .get("created_at")
        .or_else(|| alert.get("start_at"))
        .cloned()
        .unwrap_or(Value::String(String::new()));
    if let Some(n) = raw.as_f64().or_else(|| raw.as_i64().map(|i| i as f64)) {
        let mut ts = n;
        if ts > 1e12 {
            ts /= 1000.0;
        }
        let secs = ts.trunc() as i64;
        let nanos = ((ts - secs as f64) * 1e9) as u32;
        return Utc.timestamp_opt(secs, nanos).single();
    }
    if let Some(n) = raw.as_u64() {
        let mut ts = n as f64;
        if ts > 1e12 {
            ts /= 1000.0;
        }
        let secs = ts.trunc() as i64;
        return Utc.timestamp_opt(secs, 0).single();
    }
    let text = unwrap(&raw).replace('Z', "+00:00");
    if text.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(&text) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&text, "%Y-%m-%dT%H:%M:%S%.f%z") {
        return Some(dt.and_utc());
    }
    None
}

fn match_host(alert: &Map<String, Value>, host: &str) -> bool {
    if host.is_empty() {
        return true;
    }
    let want = clean_host(host);
    let raw_host = alert
        .get("host")
        .map(|v| unwrap(v))
        .unwrap_or_else(|| http_of(alert).get("host").cloned().unwrap_or_default());
    let got = clean_host(&raw_host);
    !got.is_empty()
        && (got == want || got.ends_with(&format!(".{want}")) || want.ends_with(&format!(".{got}")))
}

fn match_filters(row: &Map<String, Value>, filters: &HashMap<String, String>) -> bool {
    for key in FILTER_KEYS {
        let want = filters.get(*key).map(|s| s.trim()).unwrap_or("");
        if want.is_empty() {
            continue;
        }
        let got = row.get(*key).map(|v| unwrap(v)).unwrap_or_default();
        match *key {
            "path" | "ip" => {
                if !got.contains(want) {
                    return false;
                }
            }
            _ => {
                if got.to_lowercase() != want.to_lowercase() {
                    return false;
                }
            }
        }
    }
    true
}

fn bump(counter: &mut HashMap<String, i64>, key: &str) {
    if !key.is_empty() {
        *counter.entry(key.to_string()).or_insert(0) += 1;
    }
}

fn top(counter: &HashMap<String, i64>, n: usize) -> Vec<Value> {
    let mut items: Vec<(String, i64)> = counter.iter().map(|(k, v)| (k.clone(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let items: Vec<Value> = items
        .into_iter()
        .filter(|(k, _)| !k.is_empty())
        .take(n)
        .map(|(label, count)| json!({ "label": label, "count": count }))
        .collect();
    let total: i64 = items
        .iter()
        .filter_map(|v| v.get("count").and_then(|c| c.as_i64()))
        .sum();
    let total = if total == 0 { 1 } else { total };
    items
        .into_iter()
        .map(|mut item| {
            let count = item.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
            if let Some(obj) = item.as_object_mut() {
                let pct = (100.0 * count as f64 / total as f64 * 100.0).round() / 100.0;
                obj.insert("pct".into(), json!(pct));
            }
            item
        })
        .collect()
}

fn pack(counter: &HashMap<String, i64>, available: bool, n: usize) -> Value {
    json!({
        "available": available,
        "items": if available { top(counter, n) } else { Vec::<Value>::new() },
    })
}

pub fn classify_ua(ua: &str) -> (String, String, String) {
    let text = unwrap(&Value::String(ua.to_string()));
    let low = text.to_lowercase();
    if text.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    let browser = if let Some(hit) = BOT_RE.find(&text) {
        let mut b = hit.as_str().to_string();
        if let Some(c) = b.get_mut(0..1) {
            c.make_ascii_uppercase();
        }
        b
    } else if low.contains("edg/") {
        "Edge".into()
    } else if low.contains("chrome") && !low.contains("chromium") {
        if low.contains("mobile") {
            "ChromeMobile".into()
        } else {
            "Chrome".into()
        }
    } else if low.contains("firefox") {
        "Firefox".into()
    } else if low.contains("safari") && !low.contains("chrome") {
        "Safari".into()
    } else {
        "Unknown/Other".into()
    };
    let os_name = if low.contains("android") {
        "Android".into()
    } else if low.contains("iphone") || low.contains("ipad") || low.contains("ios") {
        "iOS".into()
    } else if low.contains("mac os") || low.contains("macintosh") {
        "MacOSX".into()
    } else if low.contains("windows") {
        "Windows".into()
    } else if low.contains("linux") {
        "Linux".into()
    } else {
        "Unknown/Other".into()
    };
    let device = if low.contains("ipad") || low.contains("tablet") {
        "Tablet".into()
    } else if low.contains("mobile") || low.contains("iphone") || low.contains("android") {
        "Mobile".into()
    } else {
        "Desktop".into()
    };
    (browser, os_name, device)
}

pub fn is_scanner_event(ua: &str, scenario: &str, path: &str) -> bool {
    if SCANNER_UA_RE.is_match(ua) {
        return true;
    }
    if SCANNER_SCENARIO_RE.is_match(scenario) {
        return true;
    }
    if SECRET_SCAN_PATH.is_match(path) {
        return true;
    }
    false
}

fn hour_bucket(dt: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<usize> {
    let dt = dt?;
    let local_now = now.with_timezone(&*GMT3);
    let local_dt = dt.with_timezone(&*GMT3);
    let hours = (local_now - local_dt).num_seconds() / 3600;
    if hours < 0 || hours > 23 {
        return None;
    }
    Some((23 - hours) as usize)
}

/// True when `dt` falls inside the last `hours` hours (inclusive). Missing timestamps are excluded.
pub fn within_window_hours(dt: Option<DateTime<Utc>>, now: DateTime<Utc>, hours: i64) -> bool {
    let Some(dt) = dt else {
        return false;
    };
    let age = (now - dt).num_seconds();
    age >= 0 && age <= hours.saturating_mul(3600)
}

fn hour_series(rows: &[Map<String, Value>], now: DateTime<Utc>) -> Value {
    let local = now.with_timezone(&*GMT3);
    let mut events = vec![0i64; 24];
    let mut blocked = vec![0i64; 24];
    let mut logged = vec![0i64; 24];
    for row in rows {
        let Some(idx) = hour_bucket(
            row.get("_dt")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
            now,
        ) else {
            continue;
        };
        events[idx] += 1;
        let action = row.get("action").and_then(|v| v.as_str()).unwrap_or("");
        if action == "Block" {
            blocked[idx] += 1;
        } else if action == "Log" {
            logged[idx] += 1;
        }
    }
    let mut labels = Vec::with_capacity(24);
    for i in 0..24 {
        let hour = (local.hour() as i64 - (23 - i as i64)).rem_euclid(24);
        labels.push(format!("{hour:02}:00"));
    }
    json!({
        "labels": labels,
        "events": events,
        "blocked": blocked,
        "logged": logged,
        "tz": "GMT-3",
    })
}

fn median(nums: &[i64]) -> f64 {
    if nums.is_empty() {
        return 0.0;
    }
    let mut ordered = nums.to_vec();
    ordered.sort_unstable();
    let n = ordered.len();
    let mid = n / 2;
    if n % 2 == 1 {
        ordered[mid] as f64
    } else {
        (ordered[mid - 1] + ordered[mid]) as f64 / 2.0
    }
}

fn scanner_pack(rows: &mut [Map<String, Value>], now: DateTime<Utc>, labels: &[String]) -> Value {
    let mut events = vec![0i64; 24];
    let mut blocked = vec![0i64; 24];
    let mut logged = vec![0i64; 24];
    let mut hour_ips: Vec<std::collections::HashSet<String>> =
        (0..24).map(|_| std::collections::HashSet::new()).collect();
    let mut all_ips = std::collections::HashSet::new();
    let mut total = 0i64;
    let mut blocked_total = 0i64;
    let mut logged_total = 0i64;
    let labels: Vec<String> = if labels.len() == 24 {
        labels.to_vec()
    } else {
        let empty = hour_series(&[], now);
        empty
            .get("labels")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .filter(|v: &Vec<String>| v.len() == 24)
            .unwrap_or_else(|| (0..24).map(|i| format!("{i:02}:00")).collect())
    };
    for row in rows.iter_mut() {
        let ua = row.get("ua").and_then(|v| v.as_str()).unwrap_or("");
        let scenario = row.get("scenario").and_then(|v| v.as_str()).unwrap_or("");
        let path = row.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if !is_scanner_event(ua, scenario, path) {
            row.insert("scanner".into(), Value::Bool(false));
            continue;
        }
        row.insert("scanner".into(), Value::Bool(true));
        total += 1;
        let ip = row
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !ip.is_empty() {
            all_ips.insert(ip.clone());
        }
        let action = row.get("action").and_then(|v| v.as_str()).unwrap_or("");
        if action == "Block" {
            blocked_total += 1;
        } else if action == "Log" {
            logged_total += 1;
        }
        let dt = row.get("_dt").and_then(|v| v.as_str()).and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        });
        let Some(idx) = hour_bucket(dt, now) else {
            continue;
        };
        events[idx] += 1;
        if !ip.is_empty() {
            hour_ips[idx].insert(ip);
        }
        if action == "Block" {
            blocked[idx] += 1;
        } else if action == "Log" {
            logged[idx] += 1;
        }
    }
    let sources_hourly: Vec<usize> = hour_ips.iter().map(|s| s.len()).collect();
    let mut peak_idx = 0usize;
    for (i, &count) in events.iter().enumerate() {
        if count >= events[peak_idx] {
            peak_idx = i;
        }
    }
    let hours: Vec<Value> = (0..24)
        .map(|i| {
            json!({
                "i": i,
                "label": labels[i],
                "events": events[i],
                "sources": sources_hourly[i],
                "blocked": blocked[i],
                "logged": logged[i],
            })
        })
        .collect();
    let last = hours.last().cloned().unwrap_or(json!({}));
    let peak = hours.get(peak_idx).cloned().unwrap_or(json!({}));
    let n_src = all_ips.len();
    json!({
        "ok": true,
        "source": SOURCE,
        "note": SCANNER_NOTE,
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
            "mean_events": ((events.iter().sum::<i64>() as f64 / 24.0) * 100.0).round() / 100.0,
            "median_events": median(&events),
            "max_events": events[peak_idx],
            "hours_active": events.iter().filter(|&&c| c > 0).count(),
            "events_per_source": if n_src > 0 { (total as f64 / n_src as f64 * 100.0).round() / 100.0 } else { 0.0 },
            "last_hour_events": last.get("events").cloned().unwrap_or(json!(0)),
            "last_hour_sources": last.get("sources").cloned().unwrap_or(json!(0)),
            "peak_idx": peak_idx,
            "peak_label": peak.get("label").cloned().unwrap_or(json!("")),
            "peak_events": peak.get("events").cloned().unwrap_or(json!(0)),
            "peak_sources": peak.get("sources").cloned().unwrap_or(json!(0)),
        },
    })
}

fn action_items(
    engine: &Map<String, Value>,
    rows: &[Map<String, Value>],
    origin: &[Value],
) -> Vec<Value> {
    let mut items = vec![
        json!({
            "id": "fail-closed-cso",
            "severity": "Low",
            "title": "Fail-closed is CSO-enforced (always ON; console cannot disable it)",
            "tags": ["Operator policy", "Edge"],
            "kind": "policy",
            "view": "engine",
        }),
        json!({
            "id": "bot-off",
            "severity": "Low",
            "title": "Bot detection/challenge stays OFF",
            "tags": ["Operator policy", "Bot traffic"],
            "kind": "policy",
            "view": "engine",
        }),
        json!({
            "id": "crs-oob",
            "severity": "Low",
            "title": "CRS stays out-of-band (detect/log, do not ban)",
            "tags": ["Operator policy", "Web app exploits"],
            "kind": "policy",
            "view": "engine",
        }),
    ];
    // Drift signal only: engine payload must keep fail_closed=true + cso_enforced metadata.
    let fail_closed_ok = engine
        .get("fail_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        && engine
            .get("fail_closed_mutable")
            .and_then(|v| v.as_bool())
            .map(|m| !m)
            .unwrap_or(true);
    if !fail_closed_ok {
        items.insert(
            0,
            json!({
                "id": "fail-open-drift",
                "severity": "High",
                "title": "Fail-closed policy metadata drifted — investigate edge bouncer config",
                "tags": ["Engine", "Policy"],
                "kind": "insight",
                "view": "engine",
            }),
        );
    }
    let mut env_ips = std::collections::HashSet::new();
    for r in rows {
        let path = r.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if path.contains("/.env") || path.contains("/.aws/") {
            if let Some(ip) = r.get("ip").and_then(|v| v.as_str()) {
                if !ip.is_empty() {
                    env_ips.insert(ip.to_string());
                }
            }
        }
    }
    if !env_ips.is_empty() {
        let n = env_ips.len();
        items.push(json!({
            "id": "env-probe",
            "severity": "Medium",
            "title": format!("Secret-file probes (/.env, /.aws) — {} source{}", n, if n == 1 { "" } else { "s" }),
            "tags": ["Security insight", "Active scanning"],
            "kind": "insight",
            "view": "alerts",
        }));
    }
    let down: Vec<String> = origin
        .iter()
        .filter_map(|p| p.as_object())
        .filter(|p| !probe_ok(p.get("status").unwrap_or(&Value::Null)))
        .filter_map(|p| p.get("host").and_then(|h| h.as_str()).map(String::from))
        .collect();
    if !down.is_empty() {
        items.push(json!({
            "id": "origin-down",
            "severity": "High",
            "title": format!("Origin probe failed: {}", down.iter().take(4).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
            "tags": ["Origin"],
            "kind": "insight",
            "view": "domains",
        }));
    }
    let mut ja4_counts: HashMap<String, i64> = HashMap::new();
    for r in rows {
        if let Some(j) = r.get("ja4h").and_then(|v| v.as_str()) {
            if !j.is_empty() {
                bump(&mut ja4_counts, j);
            }
        }
    }
    if !ja4_counts.is_empty() {
        let (label, count) = ja4_counts
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(k, v)| (k.clone(), *v))
            .unwrap();
        let sources: std::collections::HashSet<String> = rows
            .iter()
            .filter(|r| r.get("ja4h").and_then(|v| v.as_str()) == Some(label.as_str()))
            .filter_map(|r| r.get("ip").and_then(|v| v.as_str()))
            .filter(|ip| !ip.is_empty())
            .map(String::from)
            .collect();
        let count = count as i64;
        if count >= 8 && count >= std::cmp::max(4, (0.4 * rows.len() as f64) as i64) {
            let n = sources.len();
            items.push(json!({
                "id": "ja4-repeat",
                "severity": "Medium",
                "title": format!("Repeated JA4H fingerprint ({} events, {} source{})", count, n, if n == 1 { "" } else { "s" }),
                "tags": ["Security insight", "Client fingerprint"],
                "kind": "insight",
                "view": "alerts",
                "detail": label.chars().take(48).collect::<String>(),
            }));
        }
    }
    items
}

fn detection_tools(
    engine: &Map<String, Value>,
    rows: &[Map<String, Value>],
    hub: &[String],
) -> Vec<Value> {
    let hub_l = hub.join(" ").to_lowercase();
    let appsec = engine
        .get("appsec_listen")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let oob = engine
        .get("oob_log_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let blocked_ips: std::collections::HashSet<String> = rows
        .iter()
        .filter(|r| r.get("action").and_then(|v| v.as_str()) == Some("Block"))
        .filter_map(|r| r.get("ip").and_then(|v| v.as_str()))
        .filter(|ip| !ip.is_empty())
        .map(String::from)
        .collect();
    let exploits = blocked_ips.len();
    vec![
        json!({
            "id": "bot",
            "name": "Bot traffic",
            "status": "off",
            "running": false,
            "count": 0,
            "note": "CrowdSec 1.8 bot challenge remains OFF (operator policy).",
        }),
        json!({
            "id": "exploits",
            "name": "Web app exploits",
            "status": if appsec { "running" } else { "down" },
            "running": appsec,
            "count": exploits,
            "note": "Unique source IPs with a Block decision. OOB log-only matches are not counted as exploits.",
        }),
        json!({
            "id": "ddos",
            "name": "HTTP floods",
            "status": if hub_l.contains("http-dos") || hub_l.contains("ddos") { "running" } else { "limited" },
            "running": hub_l.contains("http-dos") || hub_l.contains("ddos"),
            "count": 0,
            "note": "No volumetric DDoS feed. Local HTTP scenarios only.",
        }),
        json!({
            "id": "api",
            "name": "API abuse",
            "status": if appsec { "running" } else { "down" },
            "running": appsec,
            "count": 0,
            "note": "Covered by AppSec on in-scope FQDNs.",
        }),
        json!({
            "id": "client",
            "name": "Client-side abuse",
            "status": "off",
            "running": false,
            "count": 0,
            "note": "Not in the CrowdSec band.",
        }),
        json!({
            "id": "fraud",
            "name": "Fraud protection",
            "status": "off",
            "running": false,
            "count": 0,
            "note": "Not in the CrowdSec band.",
        }),
        json!({
            "id": "crs",
            "name": "CRS out-of-band",
            "status": if oob { "running" } else { "check" },
            "running": oob,
            "count": rows.iter().filter(|r| r.get("action").and_then(|v| v.as_str()) == Some("Log")).count(),
            "note": "Detect/log only. UI cannot enable in-band CRS.",
        }),
    ]
}

fn appsec_perf(appsec: Option<&Map<String, Value>>) -> Value {
    let mx = appsec.cloned().unwrap_or_default();
    let in_sum = mx
        .get("cs_appsec_inband_parsing_time_seconds_sum")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let in_n = mx
        .get("cs_appsec_inband_parsing_time_seconds_count")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let out_sum = mx
        .get("cs_appsec_outband_parsing_time_seconds_sum")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let out_n = mx
        .get("cs_appsec_outband_parsing_time_seconds_count")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let inspected = mx
        .get("cs_appsec_reqs_total")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    json!({
        "available": !mx.is_empty(),
        "lifetime": true,
        "inspected": inspected,
        "blocks": mx.get("cs_appsec_block_total").or(mx.get("cs_appsec_blocks_total")).and_then(|v| v.as_i64()).unwrap_or(0),
        "rule_hits": mx.get("cs_appsec_rule_hits").and_then(|v| v.as_i64()).unwrap_or(0),
        "inband_ms": if in_n > 0.0 { ((1000.0 * in_sum / in_n) * 1000.0).round() / 1000.0 } else { 0.0 },
        "outband_ms": if out_n > 0.0 { ((1000.0 * out_sum / out_n) * 1000.0).round() / 1000.0 } else { 0.0 },
        "note": "CrowdSec AppSec process lifetime — not 24 h request volume.",
    })
}

pub struct BuildOptions<'a> {
    pub decisions: Option<&'a [Value]>,
    pub engine: Option<&'a Map<String, Value>>,
    pub hosts: Option<&'a [String]>,
    pub host: &'a str,
    pub origin_probes: Option<&'a [Value]>,
    pub public_probes: Option<&'a [Value]>,
    pub hub_rules: Option<&'a [String]>,
    pub now: Option<DateTime<Utc>>,
    pub filters: Option<&'a HashMap<String, String>>,
    pub appsec: Option<&'a Map<String, Value>>,
    pub edge: Option<&'a Map<String, Value>>,
    /// LAPI fetch limit used by the caller (for honest `sample.capped` reporting).
    pub alerts_fetch_limit: Option<usize>,
}

pub fn build(alerts: &[Value], opts: BuildOptions<'_>) -> Value {
    let engine = opts.engine.cloned().unwrap_or_default();
    let mut filters: HashMap<String, String> = FILTER_KEYS
        .iter()
        .map(|k| {
            (
                (*k).to_string(),
                opts.filters
                    .and_then(|f| f.get(*k))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default(),
            )
        })
        .collect();
    let hosts: Vec<String> = opts
        .hosts
        .unwrap_or(&[])
        .iter()
        .filter_map(|h| {
            let c = clean_host(h);
            if c.is_empty() {
                None
            } else {
                Some(c)
            }
        })
        .collect();
    let mut host = clean_host(opts.host);
    if !host.is_empty()
        && !hosts.is_empty()
        && !hosts.contains(&host)
        && !hosts
            .iter()
            .any(|h| host.ends_with(&format!(".{h}")) || h.ends_with(&format!(".{host}")))
    {
        host.clear();
    }
    let now = opts.now.unwrap_or_else(Utc::now);
    let decisions: Vec<&Map<String, Value>> = opts
        .decisions
        .unwrap_or(&[])
        .iter()
        .filter_map(|d| d.as_object())
        .collect();
    let origin: Vec<Value> = opts
        .origin_probes
        .unwrap_or(&[])
        .iter()
        .filter(|p| p.is_object())
        .cloned()
        .collect();
    let public: Vec<Value> = opts
        .public_probes
        .unwrap_or(&[])
        .iter()
        .filter(|p| p.is_object())
        .cloned()
        .collect();
    let hub_rules: Vec<String> = opts
        .hub_rules
        .unwrap_or(&[])
        .iter()
        .map(|x| x.to_string())
        .collect();

    let mut rows: Vec<Map<String, Value>> = Vec::new();
    let fetched = alerts.len();
    let fetch_limit = opts.alerts_fetch_limit.unwrap_or(500).max(1);
    let mut skipped_out_of_window = 0usize;
    for alert in alerts {
        let Some(alert_obj) = alert.as_object() else {
            continue;
        };
        let mut alert_map = alert_obj.clone();
        enrich_alert(&mut alert_map);
        if !match_host(&alert_map, &host) {
            continue;
        }
        let dt = parse_time(&alert_map);
        // KPIs claim a 24h window — drop events outside it (or without a parseable time).
        if !within_window_hours(dt, now, 24) {
            skipped_out_of_window += 1;
            continue;
        }
        let src = alert_map
            .get("source")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let ip = src
            .get("ip")
            .or_else(|| src.get("value"))
            .map(|v| unwrap(v))
            .unwrap_or_default();
        let cn = alert_map
            .get("cn")
            .map(|v| unwrap(v))
            .unwrap_or_else(|| {
                src.get("cn")
                    .or_else(|| src.get("country"))
                    .map(|v| unwrap(v))
                    .unwrap_or_default()
            })
            .to_uppercase();
        let http = http_of(&alert_map);
        let mut row = Map::new();
        row.insert(
            "when".into(),
            alert_map
                .get("created_at")
                .cloned()
                .unwrap_or(Value::String(String::new())),
        );
        row.insert("ip".into(), Value::String(ip));
        row.insert(
            "host".into(),
            Value::String(
                alert_map
                    .get("host")
                    .map(|v| unwrap(v))
                    .unwrap_or_else(|| http.get("host").cloned().unwrap_or_default()),
            ),
        );
        row.insert(
            "path".into(),
            Value::String(
                alert_map
                    .get("path")
                    .map(|v| unwrap(v))
                    .unwrap_or_else(|| http.get("path").cloned().unwrap_or_default()),
            ),
        );
        row.insert("country".into(), Value::String(cn));
        row.insert(
            "action".into(),
            Value::String(
                alert_map
                    .get("action")
                    .map(|v| unwrap(v))
                    .unwrap_or_else(|| "Alert".into()),
            ),
        );
        row.insert(
            "service".into(),
            Value::String(
                alert_map
                    .get("service")
                    .map(|v| unwrap(v))
                    .unwrap_or_else(|| http.get("service").cloned().unwrap_or_default()),
            ),
        );
        row.insert(
            "method".into(),
            Value::String(http.get("method").cloned().unwrap_or_default()),
        );
        row.insert(
            "ua".into(),
            Value::String(http.get("ua").cloned().unwrap_or_default()),
        );
        row.insert(
            "ja4h".into(),
            Value::String(http.get("ja4h").cloned().unwrap_or_default()),
        );
        row.insert(
            "http_version".into(),
            Value::String(http.get("http_version").cloned().unwrap_or_default()),
        );
        row.insert(
            "status".into(),
            Value::String(http.get("status").cloned().unwrap_or_default()),
        );
        row.insert(
            "asn".into(),
            Value::String(
                http.get("asn")
                    .cloned()
                    .unwrap_or_else(|| src.get("as_name").map(|v| unwrap(v)).unwrap_or_default()),
            ),
        );
        row.insert(
            "zones".into(),
            Value::String(http.get("zones").cloned().unwrap_or_default()),
        );
        row.insert(
            "data".into(),
            Value::String(http.get("data").cloned().unwrap_or_default()),
        );
        row.insert(
            "rule_ids".into(),
            Value::String(http.get("rule_ids").cloned().unwrap_or_default()),
        );
        row.insert(
            "scenario".into(),
            Value::String(
                alert_map
                    .get("scenario")
                    .map(|v| unwrap(v))
                    .unwrap_or_default(),
            ),
        );
        row.insert("scanner".into(), Value::String(String::new()));
        if let Some(dt) = dt {
            row.insert("_dt".into(), Value::String(dt.to_rfc3339()));
        }
        if !match_filters(&row, &filters) {
            continue;
        }
        rows.push(row);
    }

    let mut ips = HashMap::new();
    let mut paths = HashMap::new();
    let mut countries = HashMap::new();
    let mut host_counts = HashMap::new();
    let mut browsers = HashMap::new();
    let mut oses = HashMap::new();
    let mut devices = HashMap::new();
    let mut methods = HashMap::new();
    let mut versions = HashMap::new();
    let cache = HashMap::<String, i64>::new();
    let mut statuses = HashMap::new();
    let mut services = HashMap::new();
    let mut actions = HashMap::new();
    let mut uas = HashMap::new();
    let mut asns = HashMap::new();
    let mut ja4s = HashMap::new();
    let mut zones = HashMap::new();
    let mut ua_present = false;
    let mut method_present = false;
    let mut status_present = false;
    let mut version_present = false;
    let mut ja4_present = false;
    let mut asn_present = false;

    for row in &rows {
        if let Some(ip) = row.get("ip").and_then(|v| v.as_str()) {
            bump(&mut ips, ip);
        }
        if let Some(p) = row.get("path").and_then(|v| v.as_str()) {
            bump(&mut paths, p);
        }
        if let Some(c) = row.get("country").and_then(|v| v.as_str()) {
            bump(&mut countries, c);
        }
        if let Some(h) = row.get("host").and_then(|v| v.as_str()) {
            bump(&mut host_counts, h);
        }
        if let Some(s) = row.get("service").and_then(|v| v.as_str()) {
            bump(&mut services, s);
        }
        if let Some(a) = row.get("action").and_then(|v| v.as_str()) {
            bump(&mut actions, a);
        }
        if let Some(m) = row.get("method").and_then(|v| v.as_str()) {
            if !m.is_empty() {
                method_present = true;
                bump(&mut methods, m);
            }
        }
        if let Some(st) = row.get("status").and_then(|v| v.as_str()) {
            if !st.is_empty() {
                status_present = true;
                bump(&mut statuses, st);
            }
        }
        if let Some(v) = row.get("http_version").and_then(|v| v.as_str()) {
            if !v.is_empty() {
                version_present = true;
                bump(&mut versions, v);
            }
        }
        if let Some(j) = row.get("ja4h").and_then(|v| v.as_str()) {
            if !j.is_empty() {
                ja4_present = true;
                bump(&mut ja4s, &j.chars().take(40).collect::<String>());
            }
        }
        if let Some(a) = row.get("asn").and_then(|v| v.as_str()) {
            if !a.is_empty() {
                asn_present = true;
                bump(&mut asns, a);
            }
        }
        if let Some(z) = row.get("zones").and_then(|v| v.as_str()) {
            bump(&mut zones, z);
        }
        if let Some(ua) = row.get("ua").and_then(|v| v.as_str()) {
            if !ua.is_empty() {
                ua_present = true;
                bump(&mut uas, &ua.chars().take(72).collect::<String>());
                let (browser, os_name, device) = classify_ua(ua);
                if !browser.is_empty() {
                    bump(&mut browsers, &browser);
                }
                if !os_name.is_empty() {
                    bump(&mut oses, &os_name);
                }
                if !device.is_empty() {
                    bump(&mut devices, &device);
                }
            }
        }
    }

    let blocked = *actions.get("Block").unwrap_or(&0);
    let logged = *actions.get("Log").unwrap_or(&0);
    let total = rows.len() as i64;
    let origin_ok = origin
        .iter()
        .filter(|p| probe_ok(p.get("status").unwrap_or(&Value::Null)))
        .count();
    let origin_n = origin.len();
    let series = hour_series(&rows, now);
    let labels: Vec<String> = series
        .get("labels")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut rows_mut = rows;
    let scanners = scanner_pack(&mut rows_mut, now, &labels);
    let logs: Vec<Value> = rows_mut
        .iter()
        .take(100)
        .map(|row| {
            let mut m = Map::new();
            for (k, v) in row {
                if !k.starts_with('_') {
                    m.insert(k.clone(), v.clone());
                }
            }
            Value::Object(m)
        })
        .collect();

    let edge_pack = if let Some(edge) = opts.edge {
        if edge.get("label").is_some() {
            json!({
                "available": true,
                "items": [{"label": edge.get("label").cloned().unwrap_or(Value::String(String::new())), "count": total, "pct": 100.0}],
            })
        } else {
            pack(&HashMap::new(), false, 8)
        }
    } else {
        pack(&HashMap::new(), false, 8)
    };

    let filter_out: Map<String, Value> = filters
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k, Value::String(v)))
        .collect();

    let sample_capped = fetched >= fetch_limit;
    let window_label = if sample_capped {
        format!(
            "Last 24 hours · GMT-3 · sample of newest {fetch_limit} alerts (may be incomplete)"
        )
    } else {
        "Last 24 hours · GMT-3".to_string()
    };
    let note = if sample_capped {
        format!(
            "{NOTE} Alert sample hit the fetch limit ({fetch_limit}); raise WAF_ALERTS_LIMIT (max 500) or expect incomplete 24h KPIs under load."
        )
    } else {
        NOTE.to_string()
    };

    json!({
        "ok": true,
        "source": SOURCE,
        "note": note,
        "window": "24h",
        "window_label": window_label,
        "sample": {
            "fetched": fetched,
            "in_window": rows_mut.len(),
            "skipped_out_of_window": skipped_out_of_window,
            "fetch_limit": fetch_limit,
            "capped": sample_capped,
            "lapi_since": "24h",
        },
        "host": host,
        "hosts": hosts,
        "filters": Value::Object(filter_out),
        "generated_at": now.timestamp(),
        "kpis": {
            "events": total,
            "blocked": blocked,
            "logged": logged,
            "alerts": actions.get("Alert").copied().unwrap_or(0),
            "local_decisions": decisions.len(),
            "origin_ok": origin_ok,
            "origin_n": origin_n,
        },
        "traffic": {
            "total": total,
            "blocked": blocked,
            "logged": logged,
            "alerted": actions.get("Alert").copied().unwrap_or(0),
        },
        "series": series,
        "scanners": scanners,
        "top": {
            "ips": pack(&ips, true, 8),
            "paths": pack(&paths, true, 8),
            "countries": pack(&countries, true, 8),
            "hosts": pack(&host_counts, true, 8),
            "browsers": pack(&browsers, ua_present, 8),
            "os": pack(&oses, ua_present, 8),
            "devices": pack(&devices, ua_present, 8),
            "user_agents": pack(&uas, ua_present, 6),
            "methods": pack(&methods, method_present, 8),
            "http_versions": pack(&versions, version_present, 8),
            "cache": pack(&cache, false, 8),
            "status": pack(&statuses, status_present, 8),
            "asns": pack(&asns, asn_present, 8),
            "ja4h": pack(&ja4s, ja4_present, 8),
            "zones": pack(&zones, !zones.is_empty(), 8),
            "services": pack(&services, true, 8),
            "actions": pack(&actions, true, 8),
            "datacenters": if edge_pack.get("available").and_then(|v| v.as_bool()).unwrap_or(false) { edge_pack } else { pack(&HashMap::new(), false, 8) },
        },
        "logs": logs,
        "events": logs,
        "origin": origin,
        "public": public,
        "appsec": appsec_perf(opts.appsec),
        "action_items": action_items(&engine, &rows_mut, &origin),
        "detection_tools": detection_tools(&engine, &rows_mut, &hub_rules),
        "bot_challenge": false,
        "crs_inband": false,
    })
}
