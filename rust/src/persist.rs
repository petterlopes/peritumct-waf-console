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
