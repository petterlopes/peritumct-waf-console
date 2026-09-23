//! Shared HTTP status semantics (port of status.py).

use serde_json::Value;

pub fn app_version() -> String {
    std::env::var("WAF_APP_VERSION").unwrap_or_else(|_| "2.0.2".into())
}

pub fn app_product() -> String {
    std::env::var("WAF_APP_PRODUCT").unwrap_or_else(|_| "waf-console".into())
}

pub fn app_name() -> String {
    format!("{}/{}", app_product(), app_version())
}

pub fn http_status_ok(code: &Value) -> bool {
    let c = code
        .as_i64()
        .or_else(|| code.as_u64().map(|u| u as i64))
        .or_else(|| code.as_str().and_then(|s| s.parse().ok()));
    match c {
        Some(c) if (200..400).contains(&c) => true,
        _ => false,
    }
}
