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
fn validate_since_allowlist() {
    use waf_console::lapi::validate_since;
    assert_eq!(validate_since("24h").unwrap(), "24h");
    assert_eq!(validate_since("7D").unwrap(), "7d");
    assert!(validate_since("99h").is_err());
    assert!(validate_since("now").is_err());
    assert!(validate_since("").is_err());
}

#[test]
fn control_export_and_audit_tail_offline() {
    use waf_console::persist::{audit, audit_tail, control_export};

    let dir = TempDir::new().expect("tempdir");
    std::env::set_var("WAF_CONTROL", dir.path());
    let sites = dir.path().join("sites.json");
    std::fs::write(&sites, r#"{"hosts":{"example.com":{"kind":"web"}},"secret_token":"abc"}"#).unwrap();
    let mut map = serde_json::Map::new();
    map.insert("ip".into(), json!("203.0.113.10"));
    audit("test.event", &map);
    let export = control_export();
    assert_eq!(export["ok"], true);
    assert_eq!(export["files"]["sites"]["present"], true);
    let sites_data = &export["files"]["sites"]["data"];
    assert_eq!(sites_data["secret_token"], "[redacted]");
    let tail = audit_tail(10);
    assert_eq!(tail["ok"], true);
    assert!(tail["items"].as_array().unwrap().len() >= 1);
    std::env::remove_var("WAF_CONTROL");
}

#[test]
fn http_status_ok_accepts_whole_floats() {
    assert!(status::http_status_ok(&json!(200.0)));
    assert!(status::http_status_ok(&json!("302.0")));
    assert!(!status::http_status_ok(&json!(404.5)));
}

#[test]
fn canonical_ip_collapses_ipv6_forms() {
    use waf_console::netguard::{canonical_ip, same_ip};
    assert_eq!(canonical_ip("2001:db8:0:0:0:0:0:1"), "2001:db8::1");
    assert!(same_ip("2001:db8::1", "2001:db8:0:0:0:0:0:1"));
    assert!(!same_ip("203.0.113", "203.0.113.1"));
    assert_eq!(canonical_ip("not-an-ip"), "not-an-ip");
}

#[test]
fn repeated_offenders_merge_ipv6_spellings() {
    use waf_console::lapi::repeated_offenders;
    let alerts = vec![
        json!({"scenario": "http-probing", "source": {"ip": "2001:db8::1"}}),
        json!({"scenario": "http-probing", "source": {"ip": "2001:db8:0:0:0:0:0:1"}}),
    ];
    let out = repeated_offenders(&alerts, 8);
    let items = out["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["ip"], "2001:db8::1");
    assert_eq!(items[0]["events"], 2);
}

#[test]
fn hour_label_is_bucket_start_not_clock_hour() {
    use chrono::{TimeZone, Utc};
    use waf_console::dashboard::{self, BuildOptions};

    // 17:30 UTC is 14:30 GMT-3. An event at 16:45 UTC is 13:45 GMT-3,
    // 45 minutes ago, so it belongs in the bucket that starts at 13:30.
    let now = Utc.with_ymd_and_hms(2026, 6, 15, 17, 30, 0).unwrap();
    let event = Utc
        .with_ymd_and_hms(2026, 6, 15, 16, 45, 0)
        .unwrap()
        .to_rfc3339();
    let alerts = vec![json!({
        "created_at": event,
        "scenario": "http-probing",
        "source": {"ip": "203.0.113.10", "cn": "BR"},
        "meta": [{"key": "http_path", "value": "/"}]
    })];
    let opts = BuildOptions {
        decisions: None,
        engine: None,
        hosts: None,
        host: "",
        origin_probes: None,
        public_probes: None,
        hub_rules: None,
        now: Some(now),
        filters: None,
        appsec: None,
        edge: None,
        alerts_fetch_limit: Some(10),
    };
    let out = dashboard::build(&alerts, opts);
    let labels = out["series"]["labels"].as_array().expect("labels");
    assert_eq!(labels.len(), 24);
    assert_eq!(labels[23], "13:30");
    let events = out["series"]["events"].as_array().expect("events");
    assert_eq!(events[23], 1);
    assert_eq!(out["scanners"]["stats"]["last_hour_events"], 1);
    assert_eq!(out["scanners"]["last_hour"]["label"], "13:30");
}

#[test]
fn top_pct_is_share_of_all_events_not_the_slice() {
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use waf_console::dashboard::{self, BuildOptions};

    let now = Utc::now();
    let mut alerts = Vec::new();
    for _ in 0..6 {
        alerts.push(json!({
            "created_at": (now - Duration::minutes(5)).to_rfc3339(),
            "scenario": "http-probing",
            "source": {"ip": "203.0.113.10", "cn": "BR"}
        }));
    }
    for _ in 0..3 {
        alerts.push(json!({
            "created_at": (now - Duration::minutes(5)).to_rfc3339(),
            "scenario": "http-probing",
            "source": {"ip": "203.0.113.11", "cn": "US"}
        }));
    }
    alerts.push(json!({
        "created_at": (now - Duration::minutes(5)).to_rfc3339(),
        "scenario": "http-probing",
        "source": {"ip": "203.0.113.12", "cn": "DE"}
    }));
    let mut filters = HashMap::new();
    filters.insert("country".into(), "BR".into());
    let opts = BuildOptions {
        decisions: None,
        engine: None,
        hosts: None,
        host: "",
        origin_probes: None,
        public_probes: None,
        hub_rules: None,
        now: Some(now),
        filters: Some(&filters),
        appsec: None,
        edge: None,
        alerts_fetch_limit: Some(50),
    };
    let filtered = dashboard::build(&alerts, opts);
    assert_eq!(filtered["sample"]["in_window"], 10);
    assert_eq!(filtered["kpis"]["events"], 6);

    let opts_all = BuildOptions {
        decisions: None,
        engine: None,
        hosts: None,
        host: "",
        origin_probes: None,
        public_probes: None,
        hub_rules: None,
        now: Some(now),
        filters: None,
        appsec: None,
        edge: None,
        alerts_fetch_limit: Some(50),
    };
    let all = dashboard::build(&alerts, opts_all);
    let ips = all["top"]["ips"]["items"].as_array().expect("ips");
    assert_eq!(ips[0]["count"], 6);
    assert_eq!(ips[0]["pct"].as_f64(), Some(60.0));
    assert_eq!(ips[1]["pct"].as_f64(), Some(30.0));
    assert_eq!(ips[2]["pct"].as_f64(), Some(10.0));
}

#[test]
fn naive_timestamp_counts_as_utc() {
    use chrono::{TimeZone, Utc};
    use waf_console::dashboard::{self, BuildOptions};

    let now = Utc.with_ymd_and_hms(2026, 6, 15, 12, 0, 0).unwrap();
    let alerts = vec![json!({
        "created_at": "2026-06-15T11:00:00",
        "scenario": "http-probing",
        "source": {"ip": "198.51.100.9"}
    })];
    let opts = BuildOptions {
        decisions: None,
        engine: None,
        hosts: None,
        host: "",
        origin_probes: None,
        public_probes: None,
        hub_rules: None,
        now: Some(now),
        filters: None,
        appsec: None,
        edge: None,
        alerts_fetch_limit: Some(10),
    };
    let out = dashboard::build(&alerts, opts);
    assert_eq!(out["sample"]["in_window"], 1);
    assert_eq!(out["sample"]["skipped_out_of_window"], 0);
    assert_eq!(out["kpis"]["events"], 1);
}

#[test]
fn correlate_order_and_stix_ip_family() {
    use waf_console::correlate;

    let alerts = vec![
        json!({
            "scenario": "anomaly score out-of-band: lfi: 5, anomaly: 5",
            "source": {"ip": "2001:db8:0:0:0:0:0:1"},
            "created_at": "2026-01-01T00:00:00Z"
        }),
        json!({
            "scenario": "crowdsecurity/vpatch-env-access",
            "source": {"ip": "2001:db8::1"},
            "created_at": "2026-01-01T01:00:00Z"
        }),
    ];
    let data = correlate::correlate(&alerts, None);
    let owasp = data["owasp"].as_array().expect("owasp");
    let codes: Vec<&str> = owasp
        .iter()
        .filter_map(|v| v.get("code").and_then(|c| c.as_str()))
        .collect();
    assert_eq!(
        codes,
        vec!["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
    );
    assert_eq!(owasp[0]["id"], "A01:2025");
    assert_eq!(owasp[2]["name"], "Software Supply Chain Failures");
    assert_eq!(owasp[4]["name"], "Injection");
    assert_eq!(owasp[9]["name"], "Mishandling of Exceptional Conditions");
    assert!(owasp[4]["url"]
        .as_str()
        .unwrap_or("")
        .starts_with("https://top10.owasp.org/2025/"));
    let findings = data["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["ip"], "2001:db8::1");
    assert_eq!(findings[0]["events"], 2);
    let attack = findings[0]["attack"].as_array().expect("attack");
    assert_eq!(attack[0], "T1190");
    assert_eq!(attack[1], "T1595");
    let techniques = data["mitre"]["techniques"].as_array().expect("techniques");
    assert_eq!(techniques[0]["id"], "T1190");
    assert_eq!(techniques[1]["id"], "T1595");

    let bundle = correlate::stix_bundle(&data);
    let objects = bundle["objects"].as_array().expect("objects");
    let patterns: Vec<&str> = objects
        .iter()
        .filter_map(|o| o.get("pattern").and_then(|p| p.as_str()))
        .collect();
    assert!(patterns.iter().any(|p| p.contains("ipv6-addr:value = '2001:db8::1'")));
    assert!(patterns.iter().all(|p| !p.contains("ipv4-addr:value = '2001:")));
}

#[test]
fn secret_insight_ignores_environment_suffix() {
    use chrono::{Duration, Utc};
    use waf_console::dashboard::{self, BuildOptions};

    let now = Utc::now();
    let stamp = (now - Duration::minutes(2)).to_rfc3339();
    let alerts = vec![
        json!({
            "created_at": stamp,
            "scenario": "http-probing",
            "source": {"ip": "203.0.113.10"},
            "meta": [{"key": "http_path", "value": "/.environment"}]
        }),
        json!({
            "created_at": stamp,
            "scenario": "http-probing",
            "source": {"ip": "203.0.113.11"},
            "meta": [{"key": "http_path", "value": "/.aws"}]
        }),
    ];
    let opts = BuildOptions {
        decisions: None,
        engine: None,
        hosts: None,
        host: "",
        origin_probes: None,
        public_probes: None,
        hub_rules: None,
        now: Some(now),
        filters: None,
        appsec: None,
        edge: None,
        alerts_fetch_limit: Some(10),
    };
    let out = dashboard::build(&alerts, opts);
    let items = out["action_items"].as_array().expect("items");
    let env = items.iter().find(|a| a["id"] == "env-probe").expect("insight");
    let title = env["title"].as_str().unwrap_or("");
    assert!(title.contains("1 source"), "{title}");
    assert!(!title.contains("2 source"));
}

#[test]
fn machines_status_soft_fails_offline() {
    use waf_console::lapi::machines_status;
    // Without cscli/NOMAD this returns ok:false and empty items — never panics.
    let out = machines_status();
    assert!(out.get("items").is_some());
    assert!(out.get("source").is_some());
    assert_eq!(out["source"], "cscli");
}

