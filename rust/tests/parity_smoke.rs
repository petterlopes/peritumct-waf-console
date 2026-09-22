//! Parity smoke tests mirroring Python `tests/test_*.py` (no CrowdSec).

use serde_json::{json, Map, Value};
use tempfile::TempDir;
use waf_console::{control, correlate, ga, routes};

fn classify_code(name: &str) -> String {
    correlate::classify(Some(name), None)
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn classify_attack(name: &str) -> Vec<String> {
    correlate::classify(Some(name), None)
        .get("attack")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn correlate_classify_sqli_xss_ssrf() {
    assert_eq!(classify_code("crowdsecurity/http-generic-sqli"), "A03");
    assert_eq!(classify_code("crs/941110-xss"), "A03");
    assert_eq!(classify_code("ssrf-probe"), "A10");
    assert_eq!(
        classify_attack("crowdsecurity/http-generic-sqli"),
        vec!["T1190"]
    );
    assert_eq!(classify_attack("crs/941110-xss"), vec!["T1190"]);
}

#[test]
fn correlate_classify_probing_and_empty() {
    assert_eq!(classify_code("http-probing"), "A05");
    assert_eq!(classify_code(""), "none");
}

#[test]
fn correlate_scrub_drops_secret_keys() {
    let mut map = Map::new();
    map.insert("api_secret".into(), json!("leak"));
    map.insert("note".into(), json!("ok"));
    let scrubbed = correlate::scrub(Value::Object(map));
    let blob = scrubbed.to_string();
    assert!(!blob.contains("leak"));
    assert!(!blob.contains("api_secret"));
    assert!(blob.contains("ok"));
}

#[test]
fn correlate_stix_bundle_shape() {
    let payload = json!({
        "findings": [{"id": "f1", "name": "test", "severity": "medium"}],
        "generated_at": 1,
    });
    let bundle = correlate::stix_bundle(&payload);
    assert_eq!(bundle.get("type").and_then(|v| v.as_str()), Some("bundle"));
    assert!(bundle.get("objects").and_then(|v| v.as_array()).is_some());
}

#[test]
fn control_validate_duration_and_cidr() {
    assert_eq!(control::validate_duration("4h").unwrap(), "4h");
    assert!(control::validate_duration("999h").is_err());
    assert!(control::validate_cidr("10.0.0.1").unwrap().ends_with("/32"));
    assert!(control::validate_cidr("10.0.0.0/8").is_err());
}

#[test]
fn routes_validate_name_reserved() {
    let dir = TempDir::new().expect("tempdir");
    std::env::set_var("WAF_CONTROL", dir.path());
    let err = routes::upsert_route(Map::from_iter([
        ("name".into(), json!("waf-console")),
        ("host".into(), json!("example.com")),
        ("service_url".into(), json!("http://127.0.0.1:8081")),
    ]))
    .unwrap_err()
    .to_string();
    assert!(err.contains("reserved"));
}

#[test]
fn ga_load_snapshot_unconfigured_without_file() {
    std::env::set_var(ga::SNAPSHOT_ENV, "");
    let snap = ga::load_snapshot(None);
    assert_eq!(
        snap.get("configured").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        snap.get("property").and_then(|v| v.as_str()),
        Some(ga::DEFAULT_PROPERTY)
    );
}
