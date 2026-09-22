//! Site catalog (port of catalog.py).

use std::path::PathBuf;

use serde_json::{json, Map, Value};

use crate::netguard;

fn control_dir() -> PathBuf {
    PathBuf::from(std::env::var("WAF_CONTROL").unwrap_or_else(|_| "/var/lib/waf-control".into()))
}

fn parse(raw: &str) -> Map<String, Value> {
    serde_json::from_str(raw)
        .ok()
        .and_then(|v: Value| v.as_object().cloned())
        .unwrap_or_default()
}

fn clean_host(value: &Value) -> Option<String> {
    netguard::sanitize_hostname(value.as_str().unwrap_or("")).ok()
}

pub fn load_catalog() -> Value {
    let data = if let Ok(env) = std::env::var("WAF_SITES_JSON") {
        if !env.trim().is_empty() {
            parse(&env)
        } else {
            Map::new()
        }
    } else {
        let path = std::env::var("WAF_SITES_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| control_dir().join("sites.json"));
        if path.is_file() {
            parse(&std::fs::read_to_string(path).unwrap_or_default())
        } else {
            Map::new()
        }
    };
    let sites_raw = data
        .get("sites")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let oos_raw = data
        .get("out_of_scope")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut sites = Map::new();
    for (host, meta) in sites_raw {
        if let (Some(clean), Some(obj)) =
            (clean_host(&Value::String(host.clone())), meta.as_object())
        {
            sites.insert(clean, Value::Object(obj.clone()));
        }
    }
    let mut oos = Map::new();
    for (host, why) in oos_raw {
        if let Some(clean) = clean_host(&Value::String(host)) {
            oos.insert(clean, why);
        }
    }
    let hosts = if let Some(list) = data.get("hosts").and_then(|v| v.as_array()) {
        list.iter()
            .filter_map(|h| clean_host(h))
            .collect::<Vec<_>>()
    } else {
        sites
            .iter()
            .filter(|(_, meta)| {
                meta.get("in_scope")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
            })
            .map(|(h, _)| h.clone())
            .collect()
    };
    json!({ "sites": sites, "out_of_scope": oos, "hosts": hosts })
}

pub fn in_scope_hosts() -> Vec<String> {
    if let Ok(env) = std::env::var("WAF_HOSTS") {
        if !env.trim().is_empty() {
            return env
                .split(',')
                .filter_map(|h| clean_host(&Value::String(h.to_string())))
                .collect();
        }
    }
    load_catalog()
        .get("hosts")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|h| h.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
