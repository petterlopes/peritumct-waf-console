//! Shared HTTP status semantics (port of status.py).

use serde_json::Value;

pub fn app_version() -> String {
    std::env::var("WAF_APP_VERSION").unwrap_or_else(|_| "2.0.10".into())
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
        .or_else(|| code.as_u64().and_then(|u| i64::try_from(u).ok()))
        .or_else(|| {
            code.as_f64().and_then(|f| {
                if f.is_finite() && f.fract() == 0.0 {
                    Some(f as i64)
                } else {
                    None
                }
            })
        })
        .or_else(|| {
            code.as_str().and_then(|s| {
                let s = s.trim();
                s.parse::<i64>()
                    .ok()
                    .or_else(|| {
                        s.parse::<f64>().ok().and_then(|f| {
                            if f.is_finite() && f.fract() == 0.0 {
                                Some(f as i64)
                            } else {
                                None
                            }
                        })
                    })
            })
        });
    match c {
        Some(c) if (200..400).contains(&c) => true,
        _ => false,
    }
}
