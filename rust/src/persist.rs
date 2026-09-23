//! Atomic file writes and audit log (port of persist.rs).

use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Map, Value};

fn control_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("WAF_CONTROL").unwrap_or_else(|_| "/var/lib/waf-control".into()),
    )
}

fn audit_log() -> std::path::PathBuf {
    control_dir().join("audit.jsonl")
}

pub fn utc_now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn atomic_write_text(path: &Path, text: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let _ = std::fs::write(&tmp, text);
    let _ = std::fs::rename(&tmp, path);
}

pub fn audit(event: &str, payload: &Map<String, Value>) {
    let _ = std::fs::create_dir_all(control_dir());
    let mut line = Map::new();
    line.insert("ts".into(), json!(utc_now()));
    line.insert("event".into(), json!(event));
    for (k, v) in payload {
        line.insert(k.clone(), v.clone());
    }
    if let Ok(text) = serde_json::to_string(&Value::Object(line)) {
        use std::io::Write;
        if let Ok(mut fh) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit_log())
        {
            let _ = writeln!(fh, "{text}");
        }
    }
}

/// Tail the local operator audit JSONL (read-only). Never tails docker/container logs.
pub fn audit_tail(lines: usize) -> Value {
    let lines = lines.clamp(1, 500);
    let path = audit_log();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let all: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = all.len().saturating_sub(lines);
    let items: Vec<Value> = all[start..]
        .iter()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| json!({"raw": l})))
        .collect();
    json!({
        "ok": true,
        "source": "audit.jsonl",
        "path": path.display().to_string(),
        "lines": items.len(),
        "items": items,
        "note": "Read-only local operator audit. Not a CrowdSec or Docker log stream.",
    })
}

fn redact_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                let lk = k.to_lowercase();
                if lk.contains("password")
                    || lk.contains("secret")
                    || lk.contains("token")
                    || lk.contains("api_key")
                    || lk.contains("apikey")
                    || lk.ends_with("_key")
                    || lk.contains("credential")
                {
                    out.insert(k.clone(), json!("[redacted]"));
                } else {
                    out.insert(k.clone(), redact_value(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(redact_value).collect()),
        other => other.clone(),
    }
}

fn read_json_file(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Downloadable WAF_CONTROL snapshot without secrets (sites, filters, routes metadata).
pub fn control_export() -> Value {
    let dir = control_dir();
    let sites_path = std::env::var("WAF_SITES_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir.join("sites.json"));
    let filters_path = dir.join("site-filters.json");
    let routes_path = dir.join("routes.json");
    let sites = read_json_file(&sites_path).map(|v| redact_value(&v));
    let filters = read_json_file(&filters_path).map(|v| redact_value(&v));
    let routes = read_json_file(&routes_path).map(|v| redact_value(&v));
    json!({
        "ok": true,
        "exported_at": utc_now(),
        "control_dir": dir.display().to_string(),
        "files": {
            "sites": { "path": sites_path.display().to_string(), "present": sites.is_some(), "data": sites },
            "site_filters": { "path": filters_path.display().to_string(), "present": filters.is_some(), "data": filters },
            "routes": { "path": routes_path.display().to_string(), "present": routes.is_some(), "data": routes },
        },
        "note": "Operator control-plane export. Secrets redacted. Does not include CrowdSec LAPI credentials, Traefik dynamic.yaml, or docker state.",
    })
}
