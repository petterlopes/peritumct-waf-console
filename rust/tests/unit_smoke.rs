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
fn parse_simple_yaml_login_password() {
    use std::io::Write;
    use waf_console::lapi::parse_simple_yaml;
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("creds.yaml");
    let password = "a".repeat(64);
    let mut f = std::fs::File::create(&path).expect("create");
    write!(
        f,
        "url: http://127.0.0.1:18080\r\nlogin: localhost\r\npassword: {password}\r\n"
    )
    .expect("write");
    let data = parse_simple_yaml(&path);
    assert_eq!(data.get("url").map(String::as_str), Some("http://127.0.0.1:18080"));
    assert_eq!(data.get("login").map(String::as_str), Some("localhost"));
    assert_eq!(data.get("password").cloned(), Some(password));
}

#[test]
fn within_window_hours_filters_age() {
    use chrono::{Duration, Utc};
    use waf_console::dashboard::within_window_hours;

    let now = Utc::now();
    assert!(within_window_hours(Some(now - Duration::hours(1)), now, 24));
    assert!(within_window_hours(Some(now - Duration::hours(23)), now, 24));
    assert!(!within_window_hours(Some(now - Duration::hours(25)), now, 24));
    assert!(!within_window_hours(Some(now + Duration::hours(1)), now, 24));
    assert!(!within_window_hours(None, now, 24));
}

#[test]
fn dashboard_build_marks_sample_and_window() {
    use chrono::{Duration, Utc};
    use serde_json::json;
    use waf_console::dashboard::{self, BuildOptions};

    let now = Utc::now();
    let inside = (now - Duration::hours(2)).to_rfc3339();
    let outside = (now - Duration::hours(30)).to_rfc3339();
    let alerts = vec![
        json!({
            "created_at": inside,
            "scenario": "http-probing",
            "source": {"ip": "1.2.3.4", "cn": "BR"},
            "meta": [{"key": "http_path", "value": "/"}]
        }),
        json!({
            "created_at": outside,
            "scenario": "http-probing",
            "source": {"ip": "5.6.7.8", "cn": "US"},
            "meta": [{"key": "http_path", "value": "/old"}]
        }),
    ];
    let engine = serde_json::Map::from_iter([
        ("fail_closed".into(), json!(true)),
        ("fail_closed_mutable".into(), json!(false)),
        ("oob_log_only".into(), json!(true)),
        ("appsec_listen".into(), json!(true)),
    ]);
    let opts = BuildOptions {
        decisions: None,
        engine: Some(&engine),
        hosts: None,
        host: "",
        origin_probes: None,
        public_probes: None,
        hub_rules: None,
        now: Some(now),
        filters: None,
        appsec: None,
        edge: None,
        alerts_fetch_limit: Some(2),
    };
    let out = dashboard::build(&alerts, opts);
    assert_eq!(out["window"], "24h");
    assert_eq!(out["sample"]["fetched"], 2);
    assert_eq!(out["sample"]["in_window"], 1);
    assert_eq!(out["sample"]["skipped_out_of_window"], 1);
    assert_eq!(out["sample"]["capped"], true);
    assert!(out["window_label"]
        .as_str()
        .unwrap_or("")
        .contains("sample of newest"));
    let actions = out["action_items"].as_array().cloned().unwrap_or_default();
    assert!(actions.iter().any(|a| a["id"] == "fail-closed-cso"));
}

#[test]
fn repeated_offenders_ranks_sources() {
    use waf_console::lapi::repeated_offenders;
    let alerts = vec![
        json!({"scenario": "http-probing", "source": {"ip": "198.51.100.10"}}),
        json!({"scenario": "http-probing", "source": {"ip": "198.51.100.10"}}),
        json!({"scenario": "ssh-bf", "source": {"ip": "198.51.100.10"}}),
        json!({"scenario": "http-probing", "source": {"value": "203.0.113.5"}}),
    ];
    let out = repeated_offenders(&alerts, 8);
    assert_eq!(out["ok"], true);
    assert_eq!(out["sample_size"], 4);
    let items = out["items"].as_array().expect("items");
    assert_eq!(items[0]["ip"], "198.51.100.10");
    assert_eq!(items[0]["events"], 3);
    assert_eq!(items[1]["ip"], "203.0.113.5");
    assert_eq!(items[1]["events"], 1);
}

#[test]
fn ip_dossier_rejects_invalid_ip() {
    use waf_console::lapi::ip_dossier;
    assert!(ip_dossier("not-an-ip").is_err());
    assert!(ip_dossier("").is_err());
}

