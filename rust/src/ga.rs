//! CSO-safe GA4 snapshot for WAF finding precision (port of ga.py).

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

pub const DEFAULT_PROPERTY: &str = "G-EWYYWP65FN";
pub const SNAPSHOT_ENV: &str = "WAF_GA_SNAPSHOT_FILE";

static SECRET_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(token|key|password|secret|authorization|credential|api.?secret|measurement.?protocol)")
        .expect("SECRET_KEY_RE")
});

static PROPERTY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^G-[A-Z0-9]+$").expect("PROPERTY_RE"));

const HIGH_LAPI: i64 = 5;
const HIGH_GA: i64 = 20;

pub fn as_int(value: &Value, default: i64) -> i64 {
    let number = value
        .as_i64()
        .or_else(|| value.as_u64().map(|u| u as i64))
        .or_else(|| value.as_f64().map(|f| f as i64))
        .unwrap_or(default);
    if number >= 0 {
        number
    } else {
        default
    }
}

pub fn density(lapi_count: impl Into<i64>, ga_sessions: impl Into<i64>) -> f64 {
    let lapi = as_int(&Value::from(lapi_count.into()), 0);
    let sessions = as_int(&Value::from(ga_sessions.into()), 0);
    if sessions <= 0 {
        return lapi as f64;
    }
    ((lapi as f64 / sessions as f64) * 10000.0).round() / 10000.0
}

pub fn verdict(lapi_count: impl Into<i64>, ga_sessions: impl Into<i64>) -> String {
    let lapi = lapi_count.into();
    let sessions = ga_sessions.into();
    if lapi <= 0 {
        return "clean-traffic".into();
    }
    if sessions <= 0 {
        return "scanner-heavy".into();
    }
    if lapi >= HIGH_LAPI && sessions >= HIGH_GA {
        return "user-impact-risk".into();
    }
    "mixed".into()
}

fn empty_snapshot() -> Value {
    json!({
        "configured": false,
        "property": DEFAULT_PROPERTY,
        "window_days": 0,
        "hosts": [],
        "countries": [],
        "note": "Drop an aggregate GA4 snapshot at WAF_GA_SNAPSHOT_FILE. No Data API. No gtag on /waf.",
    })
}

pub fn scrub(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                if SECRET_KEY_RE.is_match(&key) {
                    continue;
                }
                out.insert(key, scrub(item));
            }
            Value::Object(out)
        }
        Value::Array(list) => Value::Array(list.into_iter().map(scrub).collect()),
        other => other,
    }
}

fn skip_host(host: &str) -> bool {
    host.trim().to_lowercase().starts_with("/waf")
}

fn normalize_hosts(raw: Option<&Value>) -> Vec<Value> {
    let mut hosts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let Some(list) = raw.and_then(|v| v.as_array()) else {
        return hosts;
    };
    for item in list {
        let (host, sessions) = if let Some(s) = item.as_str() {
            (s.trim().to_string(), 0i64)
        } else if let Some(obj) = item.as_object() {
            let host = obj
                .get("host")
                .or_else(|| obj.get("hostname"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let sessions = as_int(obj.get("sessions").unwrap_or(&Value::Null), 0);
            (host, sessions)
        } else {
            continue;
        };
        let key = host.to_lowercase();
        if host.is_empty() || skip_host(&host) || seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        hosts.push(json!({ "host": host, "sessions": sessions }));
    }
    hosts
}

fn normalize_countries(raw: Option<&Value>) -> Vec<Value> {
    let mut countries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let Some(list) = raw.and_then(|v| v.as_array()) else {
        return countries;
    };
    let cn_re = Regex::new(r"^[A-Z]{2}$").expect("cn");
    for item in list {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let cn = obj
            .get("cn")
            .or_else(|| obj.get("country"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_uppercase();
        if cn.is_empty() || seen.contains(&cn) || !cn_re.is_match(&cn) {
            continue;
        }
        seen.insert(cn.clone());
        countries.push(json!({
            "cn": cn,
            "sessions": as_int(obj.get("sessions").unwrap_or(&Value::Null), 0),
        }));
    }
    countries
}

pub fn load_snapshot(path: Option<&str>) -> Value {
    let raw_path = path
        .map(String::from)
        .or_else(|| std::env::var(SNAPSHOT_ENV).ok())
        .unwrap_or_default()
        .trim()
        .to_string();
    if raw_path.is_empty() {
        return empty_snapshot();
    }
    let file = Path::new(&raw_path);
    if !file.is_file() {
        return empty_snapshot();
    }
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(_) => return empty_snapshot(),
    };
    let data: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return empty_snapshot(),
    };
    let Some(data) = data.as_object() else {
        return empty_snapshot();
    };
    let data = scrub(Value::Object(data.clone()));
    let data = data.as_object().cloned().unwrap_or_default();
    let mut property_id = data
        .get("property")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_PROPERTY)
        .trim()
        .to_string();
    if property_id.is_empty() {
        property_id = DEFAULT_PROPERTY.to_string();
    }
    if !PROPERTY_RE.is_match(&property_id) {
        property_id = DEFAULT_PROPERTY.to_string();
    }
    let window_days = as_int(data.get("window_days").unwrap_or(&Value::Null), 7);
    let window_days = if window_days == 0 { 7 } else { window_days };
    json!({
        "configured": true,
        "property": property_id,
        "window_days": window_days,
        "hosts": normalize_hosts(data.get("hosts")),
        "countries": normalize_countries(data.get("countries")),
        "note": "Aggregate GA4 sessions (hostname + country). No client_id. LAPI geo unchanged.",
    })
}

fn country_sessions(snap: &Map<String, Value>) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    if let Some(list) = snap.get("countries").and_then(|v| v.as_array()) {
        for item in list {
            if let Some(obj) = item.as_object() {
                let cn = obj
                    .get("cn")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if !cn.is_empty() {
                    out.insert(cn, as_int(obj.get("sessions").unwrap_or(&Value::Null), 0));
                }
            }
        }
    }
    out
}

fn has_sessions(snap: &Map<String, Value>) -> bool {
    for key in ["hosts", "countries"] {
        if let Some(list) = snap.get(key).and_then(|v| v.as_array()) {
            for item in list {
                if let Some(obj) = item.as_object() {
                    if as_int(obj.get("sessions").unwrap_or(&Value::Null), 0) > 0 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn public(snap: Option<&Map<String, Value>>) -> Value {
    let loaded = load_snapshot(None);
    let snap = snap
        .cloned()
        .or_else(|| loaded.as_object().cloned())
        .unwrap_or_default();
    let configured = snap
        .get("configured")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    json!({
        "configured": configured,
        "contributes": configured && has_sessions(&snap),
        "property": snap.get("property").cloned().unwrap_or(json!(DEFAULT_PROPERTY)),
        "window_days": snap.get("window_days").cloned().unwrap_or(json!(0)),
        "hosts": snap.get("hosts").cloned().unwrap_or(json!([])),
        "note": snap.get("note").cloned().unwrap_or(json!("")),
    })
}

pub fn attach_map(payload: Option<&Map<String, Value>>) -> Map<String, Value> {
    let mut payload = payload.cloned().unwrap_or_default();
    let snap = load_snapshot(None);
    let snap_obj = snap.as_object().cloned().unwrap_or_default();
    let by_cn = country_sessions(&snap_obj);
    let mut countries = Vec::new();
    if let Some(rows) = payload.get("countries").and_then(|v| v.as_array()) {
        for row in rows {
            if let Some(obj) = row.as_object() {
                let mut item = obj.clone();
                if snap_obj
                    .get("configured")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    let cn = item
                        .get("cn")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_uppercase();
                    let sessions = *by_cn.get(&cn).unwrap_or(&0);
                    let count = item.get("count").cloned().unwrap_or(json!(0));
                    item.insert("ga_sessions".into(), json!(sessions));
                    let lapi_n = as_int(&count, 0);
                    item.insert("ga_density".into(), json!(density(lapi_n, sessions)));
                    item.insert("ga_verdict".into(), json!(verdict(lapi_n, sessions)));
                }
                countries.push(Value::Object(item));
            }
        }
    }
    payload.insert("countries".into(), Value::Array(countries));
    payload.insert("ga".into(), public(Some(&snap_obj)));
    if !payload.contains_key("geo_source") {
        payload.insert("geo_source".into(), json!("crowdsec-lapi"));
    }
    scrub(Value::Object(payload))
        .as_object()
        .cloned()
        .unwrap_or_default()
}

fn ga_connector(configured: bool) -> Value {
    json!({
        "type": "INTERNAL_IMPORT",
        "name": "Google Analytics 4",
        "scope": "aggregate-snapshot",
        "status": if configured { "configured" } else { "unconfigured" },
        "note": "Operator-exported hostname+country sessions. No Data API. No Measurement Protocol. No gtag on /waf.",
        "push": false,
    })
}

fn lapi_by_country(
    map_payload: Option<&Map<String, Value>>,
    payload: &Map<String, Value>,
) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    let mut sources: Vec<Vec<Value>> = Vec::new();
    if let Some(mp) = map_payload {
        if let Some(c) = mp.get("countries").and_then(|v| v.as_array()) {
            sources.push(c.clone());
        }
    }
    if let Some(map) = payload.get("map").and_then(|v| v.as_object()) {
        if let Some(c) = map.get("countries").and_then(|v| v.as_array()) {
            sources.push(c.clone());
        }
    }
    for rows in sources {
        for row in rows {
            if let Some(obj) = row.as_object() {
                let cn = obj
                    .get("cn")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if !cn.is_empty() {
                    out.insert(cn, as_int(obj.get("count").unwrap_or(&Value::Null), 0));
                }
            }
        }
    }
    out
}

pub fn attach_correlation(
    payload: Option<&Map<String, Value>>,
    map_payload: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    let mut payload = payload.cloned().unwrap_or_default();
    let snap = load_snapshot(None);
    let snap_obj = snap.as_object().cloned().unwrap_or_default();
    let by_cn = country_sessions(&snap_obj);
    let lapi = lapi_by_country(map_payload, &payload);
    let mut countries = Vec::new();
    if snap_obj
        .get("configured")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let mut seen = std::collections::HashSet::new();
        let mut keys: Vec<String> = by_cn.keys().chain(lapi.keys()).cloned().collect();
        keys.sort();
        keys.dedup();
        for cn in keys {
            if seen.contains(&cn) {
                continue;
            }
            seen.insert(cn.clone());
            let sessions = *by_cn.get(&cn).unwrap_or(&0);
            let count = *lapi.get(&cn).unwrap_or(&0);
            countries.push(json!({
                "cn": cn,
                "sessions": sessions,
                "lapi_count": count,
                "density": density(count, sessions),
                "verdict": verdict(count, sessions),
            }));
        }
    }
    let mut exposed = public(Some(&snap_obj));
    if let Some(obj) = exposed.as_object_mut() {
        obj.insert("countries".into(), Value::Array(countries));
    }
    payload.insert("ga".into(), exposed);
    payload.remove("map");
    let mut connectors: Vec<Value> = payload
        .get("connectors")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.is_object())
        .collect();
    let has_ga = connectors.iter().any(|c| {
        c.get("name").and_then(|v| v.as_str()) == Some("Google Analytics 4")
            && c.get("type").and_then(|v| v.as_str()) == Some("INTERNAL_IMPORT")
    });
    if !has_ga {
        connectors.push(ga_connector(
            snap_obj
                .get("configured")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        ));
    }
    payload.insert("connectors".into(), Value::Array(connectors));
    scrub(Value::Object(payload))
        .as_object()
        .cloned()
        .unwrap_or_default()
}
