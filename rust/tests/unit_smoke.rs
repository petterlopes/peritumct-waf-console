//! Offline smoke tests (no CrowdSec / network).

use serde_json::json;
use tempfile::TempDir;
use waf_console::{ga, netguard, persist, status};

#[test]
fn sanitize_hostname_accepts_fqdn() {
    let host = netguard::sanitize_hostname("Example.COM").expect("valid host");
    assert_eq!(host, "example.com");
}

#[test]
fn sanitize_hostname_rejects_injection() {
    assert!(netguard::sanitize_hostname("evil\rhost").is_err());
    assert!(netguard::sanitize_hostname("").is_err());
}

#[test]
fn http_status_ok_2xx_and_3xx() {
    assert!(status::http_status_ok(&json!(200)));
    assert!(status::http_status_ok(&json!(302)));
    assert!(status::http_status_ok(&json!("301")));
    assert!(!status::http_status_ok(&json!(404)));
    assert!(!status::http_status_ok(&json!("nope")));
}

#[test]
fn persist_atomic_write_roundtrip() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("nested").join("state.json");
    persist::atomic_write_text(&path, "{\"ok\":true}\n");
    let text = std::fs::read_to_string(&path).expect("read back");
    assert!(text.contains("\"ok\": true") || text.contains("\"ok\":true"));
}

#[test]
fn ga_density_and_verdict() {
    assert!((ga::density(5, 100) - 0.05).abs() < 0.0001);
    assert_eq!(ga::verdict(0, 10), "clean-traffic");
    assert_eq!(ga::verdict(3, 0), "scanner-heavy");
    assert_eq!(ga::verdict(5, 20), "user-impact-risk");
    assert_eq!(ga::verdict(2, 100), "mixed");
}
