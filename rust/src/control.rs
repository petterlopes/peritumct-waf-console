//! Operator WAF control plane (port of control.py).

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use regex::Regex;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::catalog;
use crate::netguard;
use crate::persist;

static HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9.-]{0,80}$").expect("HOST_RE"));
static PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/[A-Za-z0-9._~/=-]{0,127}$").expect("PATH_RE"));
static RULE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(crowdsecurity|peritumct)/[A-Za-z0-9._-]+$").expect("RULE_RE"));
static NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,47}$").expect("NAME_RE"));
static DURATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d+)([hm])$").expect("DURATION_RE"));
static CRS_INBAND_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*-\s*crowdsecurity/crs-inband\b").expect("CRS_INBAND"));

pub const ACTIONS: &[&str] = &["allow_match", "skip_rule", "bypass_host"];

const FORBIDDEN: &[&str] = &[
    "disablebodyinspection",
    "include_large_uploads",
    "crs-inband",
    "droprequest",
    "default_remediation",
    "nomad job run",
    "fail_closed",
];

fn config_root() -> PathBuf {
    PathBuf::from(std::env::var("CROWDSEC_CONFIG").unwrap_or_else(|_| "/etc/crowdsec".into()))
}

fn control_dir() -> PathBuf {
    PathBuf::from(std::env::var("WAF_CONTROL").unwrap_or_else(|_| "/var/lib/waf-control".into()))
}

fn filters_json() -> PathBuf {
    control_dir().join("site-filters.json")
}

fn appsec_file() -> String {
    std::env::var("WAF_APPSEC_FILE").unwrap_or_else(|_| "peritumct-site-filters.yaml".into())
}

fn appsec_name() -> String {
    std::env::var("WAF_APPSEC_NAME").unwrap_or_else(|_| "peritumct/site-filters".into())
}

fn filters_yaml() -> PathBuf {
    config_root().join("appsec-configs").join(appsec_file())
}

fn acquis_path() -> PathBuf {
    config_root().join("acquis.d").join("appsec.yaml")
}

fn appsec_port() -> u16 {
    std::env::var("CROWDSEC_APPSEC_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7422)
}

fn allowlist_name() -> String {
    std::env::var("WAF_ALLOWLIST").unwrap_or_else(|_| "cso-operators".into())
}

pub fn load_catalog() -> Value {
    catalog::load_catalog()
}

pub fn sites() -> Map<String, Value> {
    load_catalog()
        .get("sites")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

pub fn out_of_scope() -> Map<String, Value> {
    load_catalog()
        .get("out_of_scope")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

fn utc() -> String {
    persist::utc_now()
}

pub fn audit(event: &str, payload: &Map<String, Value>) {
    persist::audit(event, payload);
}

pub fn load_filters() -> Value {
    let path = filters_json();
    if !path.is_file() {
        return json!({ "version": 1, "items": [] });
    }
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let data: Value = serde_json::from_str(&text).unwrap_or(json!({ "version": 1, "items": [] }));
    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    json!({ "version": 1, "items": items })
}

pub fn save_filters(store: &Value) {
    let text = serde_json::to_string_pretty(store).unwrap_or_default() + "\n";
    persist::atomic_write_text(&filters_json(), &text);
}

fn reject_forbidden(parts: &[&str]) -> Result<()> {
    let blob = parts.join(" ").to_lowercase();
    for token in FORBIDDEN {
        if blob.contains(token) {
            return Err(anyhow!("forbidden operation: {token}"));
        }
    }
    Ok(())
}

pub fn validate_host(host: &str) -> Result<String> {
    let host = host.trim().to_lowercase();
    let oos = out_of_scope();
    let sites = sites();
    if oos.contains_key(&host) {
        return Err(anyhow!("host out of WAF scope: {host}"));
    }
    if !sites.contains_key(&host) {
        return Err(anyhow!("host not in catalog"));
    }
    if !HOST_RE.is_match(&host) {
        return Err(anyhow!("invalid host"));
    }
    Ok(host)
}

pub fn validate_path(path: &str) -> Result<String> {
    let path = path.trim();
    if !PATH_RE.is_match(path) || path == "/" {
        return Err(anyhow!(
            "invalid path_prefix (must start with / and must not be only /)"
        ));
    }
    if path.contains("//") || path.contains("..") {
        return Err(anyhow!("invalid path_prefix"));
    }
    reject_forbidden(&[path])?;
    Ok(path.to_string())
}

pub fn validate_rule(name: &str) -> Result<String> {
    let name = name.trim();
    if !RULE_RE.is_match(name) {
        return Err(anyhow!("invalid AppSec rule"));
    }
    reject_forbidden(&[name])?;
    Ok(name.to_string())
}

pub fn validate_cidr(value: &str) -> Result<String> {
    let mut raw = value.trim().to_string();
    if !raw.contains('/') {
        raw.push_str("/32");
    }
    let net: IpNet = raw.parse().map_err(|_| anyhow!("invalid CIDR"))?;
    if net.addr().is_ipv6() {
        return Err(anyhow!("IPv4 only"));
    }
    if net.prefix_len() < 16 {
        return Err(anyhow!("prefix too broad (minimum /16)"));
    }
    Ok(net.to_string())
}

pub fn validate_duration(value: &str) -> Result<String> {
    let caps = DURATION_RE
        .captures(value.trim())
        .ok_or_else(|| anyhow!("invalid duration (e.g. 4h, 30m)"))?;
    let amount: i64 = caps[1].parse()?;
    let unit = &caps[2];
    let hours = if unit == "m" {
        amount as f64 / 60.0
    } else {
        amount as f64
    };
    if hours <= 0.0 || hours > 168.0 {
        return Err(anyhow!("maximum duration is 168h"));
    }
    Ok(format!("{amount}{unit}"))
}

pub fn render_yaml(items: &[Value]) -> Result<String> {
    let mut pre_eval = Vec::new();
    let mut on_match = Vec::new();
    for item in items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        if !obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) {
            continue;
        }
        let host = validate_host(obj.get("host").and_then(|v| v.as_str()).unwrap_or(""))?;
        let action = obj.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let reason = obj
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("cso")
            .chars()
            .take(120)
            .collect::<String>()
            .replace('"', "");
        let pname = obj
            .get("name")
            .or_else(|| obj.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("policy")
            .chars()
            .take(48)
            .collect::<String>();
        match action {
            "skip_rule" => {
                let rule = validate_rule(obj.get("rule").and_then(|v| v.as_str()).unwrap_or(""))?;
                let mut filt = format!(r#"IsInBand == true && req.Host == "{host}""#);
                if let Some(path) = obj.get("path_prefix").and_then(|v| v.as_str()) {
                    if !path.is_empty() {
                        let path = validate_path(path)?;
                        filt.push_str(&format!(r#" && req.URL.Path startsWith "{path}""#));
                    }
                }
                pre_eval.push((filt, rule, format!("{pname}: {reason}")));
            }
            "allow_match" => {
                let path = validate_path(
                    obj.get("path_prefix")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                )?;
                let filt = format!(r#"req.Host == "{host}" && req.URL.Path startsWith "{path}""#);
                on_match.push((filt, format!("{pname}: {reason}")));
            }
            "bypass_host" => {
                let filt = format!(r#"req.Host == "{host}""#);
                on_match.push((
                    filt,
                    format!(
                        "{pname}: {}",
                        if reason.is_empty() {
                            "bypass host".into()
                        } else {
                            reason
                        }
                    ),
                ));
            }
            _ => return Err(anyhow!("unknown action")),
        }
    }
    let mut lines = vec![
        "# Generated by peritumct-waf-console. Hooks only: allow path, skip named rule, host bypass.".into(),
        format!("name: {}", appsec_name()),
    ];
    if !pre_eval.is_empty() {
        lines.push("pre_eval:".into());
        for (filt, rule, reason) in pre_eval {
            lines.push(format!("  # {reason}"));
            lines.push("  - filter: |".into());
            lines.push(format!("      {filt}"));
            lines.push("    apply:".into());
            lines.push(format!(r#"      - RemoveInBandRuleByName("{rule}")"#));
        }
    }
    if !on_match.is_empty() {
        lines.push("on_match:".into());
        for (filt, reason) in on_match {
            lines.push(format!("  # {reason}"));
            lines.push("  - filter: |".into());
            lines.push(format!("      {filt}"));
            lines.push("    apply:".into());
            lines.push(r#"      - SetRemediation("allow")"#.into());
            lines.push("      - CancelAlert()".into());
            lines.push("      - CancelEvent()".into());
        }
    }
    lines.push(String::new());
    let text = lines.join("\n");
    reject_forbidden(&[&text])?;
    Ok(text)
}

pub fn ensure_acquis() -> Result<bool> {
    let path = acquis_path();
    let text = if path.is_file() {
        std::fs::read_to_string(&path)?
    } else {
        String::new()
    };
    if CRS_INBAND_RE.is_match(&text) {
        return Err(anyhow!("acquis lists crs-inband — refused"));
    }
    let name = appsec_name();
    if text.contains(&name) {
        return Ok(false);
    }
    if !text.contains("crowdsecurity/crs") {
        return Err(anyhow!("unexpected AppSec acquis"));
    }
    let backup = path.with_extension("yaml.bak");
    std::fs::write(&backup, &text)?;
    let needle = "  - crowdsecurity/crs\n";
    let updated = if let Some(_) = text.find(needle) {
        text.replacen(needle, &format!("{needle}  - {name}\n"), 1)
    } else {
        format!("{}\n  - {name}\n", text.trim_end())
    };
    persist::atomic_write_text(&path, &updated);
    Ok(true)
}

pub fn crowdsec_pids() -> Vec<i32> {
    #[cfg(target_os = "linux")]
    {
        let proc = PathBuf::from("/proc");
        if !proc.is_dir() {
            return Vec::new();
        }
        let mut found = Vec::new();
        if let Ok(entries) = std::fs::read_dir(proc) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                let cmdline = entry.path().join("cmdline");
                if let Ok(bytes) = std::fs::read(cmdline) {
                    let cmd = String::from_utf8_lossy(&bytes).replace('\0', " ");
                    if cmd.starts_with("crowdsec ") || cmd.starts_with("crowdsec\t") {
                        if let Ok(pid) = name.parse::<i32>() {
                            found.push(pid);
                        }
                    }
                }
            }
        }
        found
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

pub fn sighup_crowdsec() -> Result<Vec<i32>> {
    #[cfg(target_os = "linux")]
    {
        let pids = crowdsec_pids();
        if pids.is_empty() {
            return Err(anyhow!("CrowdSec PID missing (pid: host required)"));
        }
        for pid in &pids {
            let status = Command::new("kill")
                .args(["-HUP", &pid.to_string()])
                .status()
                .map_err(|e| anyhow!("sighup failed for {pid}: {e}"))?;
            if !status.success() {
                return Err(anyhow!("sighup failed for {pid}"));
            }
        }
        Ok(pids)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = crowdsec_pids();
        Err(anyhow!("CrowdSec SIGHUP is only supported on Linux"))
    }
}

pub fn wait_appsec(timeout: f64) -> bool {
    let deadline = Instant::now() + Duration::from_secs_f64(timeout);
    let port = appsec_port();
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}")
                .parse::<SocketAddr>()
                .unwrap_or_else(|_| "127.0.0.1:7422".parse().unwrap()),
            Duration::from_millis(1200),
        )
        .is_ok()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(400));
    }
    false
}

pub fn apply_filters(store: &Value) -> Result<Value> {
    let items = store
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let yaml_text = render_yaml(&items)?;
    let yaml_path = filters_yaml();
    if let Some(parent) = yaml_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let previous = if yaml_path.is_file() {
        std::fs::read_to_string(&yaml_path)?
    } else {
        String::new()
    };
    persist::atomic_write_text(&yaml_path, &yaml_text);
    let acquis_changed = ensure_acquis()?;
    match (|| -> Result<Vec<i32>> {
        let pids = sighup_crowdsec()?;
        if !wait_appsec(12.0) {
            return Err(anyhow!("AppSec did not come back after HUP"));
        }
        Ok(pids)
    })() {
        Ok(pids) => {
            let mut audit_payload = Map::new();
            audit_payload.insert("count".into(), json!(items.len()));
            audit_payload.insert("acquis_changed".into(), json!(acquis_changed));
            audit("filters.apply", &audit_payload);
            Ok(json!({
                "ok": true,
                "pids": pids,
                "acquis_changed": acquis_changed,
                "yaml": yaml_path.to_string_lossy(),
            }))
        }
        Err(e) => {
            if !previous.is_empty() {
                persist::atomic_write_text(&yaml_path, &previous);
                let _ = sighup_crowdsec();
            }
            Err(e)
        }
    }
}

pub fn validate_name(name: &str) -> Result<String> {
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        return Ok(String::new());
    }
    if !NAME_RE.is_match(&name) {
        return Err(anyhow!("invalid policy name (a-z, 0-9, ._-; max 48)"));
    }
    reject_forbidden(&[&name])?;
    Ok(name)
}

pub fn compose_policy(
    payload: &Map<String, Value>,
    existing: Option<&Map<String, Value>>,
) -> Result<Map<String, Value>> {
    let action = payload
        .get("action")
        .or_else(|| existing.and_then(|e| e.get("action")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !ACTIONS.contains(&action.as_str()) {
        return Err(anyhow!(
            "action must be allow_match, skip_rule or bypass_host"
        ));
    }
    let host = validate_host(
        payload
            .get("host")
            .or_else(|| existing.and_then(|e| e.get("host")))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    let reason = payload
        .get("reason")
        .or_else(|| existing.and_then(|e| e.get("reason")))
        .and_then(|v| v.as_str())
        .unwrap_or("cso-console")
        .chars()
        .take(120)
        .collect::<String>();
    reject_forbidden(&[&reason])?;
    let name = validate_name(
        payload
            .get("name")
            .or_else(|| existing.and_then(|e| e.get("name")))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    let id = existing
        .and_then(|e| e.get("id"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string()[..12].to_string());
    let host_prefix = host.split('.').next().unwrap_or("site");
    let mut item = Map::new();
    item.insert("id".into(), json!(id));
    item.insert(
        "name".into(),
        json!(if name.is_empty() {
            format!("{action}-{host_prefix}")
        } else {
            name
        }),
    );
    item.insert(
        "enabled".into(),
        json!(if payload.contains_key("enabled") {
            payload
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
        } else {
            existing
                .and_then(|e| e.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
        }),
    );
    item.insert("action".into(), json!(action));
    item.insert("host".into(), json!(host));
    item.insert("reason".into(), json!(reason));
    item.insert(
        "created_at".into(),
        json!(existing
            .and_then(|e| e.get("created_at"))
            .cloned()
            .unwrap_or_else(|| json!(utc()))),
    );
    item.insert("updated_at".into(), json!(utc()));
    match item.get("action").and_then(|v| v.as_str()).unwrap_or("") {
        "allow_match" => {
            item.insert(
                "path_prefix".into(),
                json!(validate_path(
                    payload
                        .get("path_prefix")
                        .or_else(|| existing.and_then(|e| e.get("path_prefix")))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                )?),
            );
        }
        "skip_rule" => {
            item.insert(
                "rule".into(),
                json!(validate_rule(
                    payload
                        .get("rule")
                        .or_else(|| existing.and_then(|e| e.get("rule")))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                )?),
            );
            let path = if payload.contains_key("path_prefix") {
                payload
                    .get("path_prefix")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            } else {
                existing
                    .and_then(|e| e.get("path_prefix"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            };
            if !path.is_empty() {
                item.insert("path_prefix".into(), json!(validate_path(path)?));
            }
        }
        "bypass_host" => {
            let confirmed = payload
                .get("confirm")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                || existing
                    .and_then(|e| e.get("confirm"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            if !confirmed {
                return Err(anyhow!("bypass_host requires confirm=true"));
            }
            item.insert("confirm".into(), json!(true));
        }
        _ => {}
    }
    Ok(item)
}

fn assert_unique_name(store: &Value, name: &str, exclude_id: Option<&str>) -> Result<()> {
    let items = store
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for item in items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        if obj.get("name").and_then(|v| v.as_str()) != Some(name) {
            continue;
        }
        if exclude_id
            .map(|id| obj.get("id").and_then(|v| v.as_str()) == Some(id))
            .unwrap_or(false)
        {
            continue;
        }
        return Err(anyhow!("a policy with this name already exists"));
    }
    Ok(())
}

pub fn add_filter(payload: Map<String, Value>) -> Result<Value> {
    let mut item = compose_policy(&payload, None)?;
    let mut store = load_filters();
    let given = validate_name(payload.get("name").and_then(|v| v.as_str()).unwrap_or(""))?;
    if let Err(e) = assert_unique_name(
        &store,
        item.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        None,
    ) {
        if !given.is_empty() {
            return Err(e);
        }
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let new_name = format!(
            "{}-{}",
            item.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("policy"),
            &id[..6.min(id.len())]
        );
        item.insert("name".into(), json!(new_name));
        assert_unique_name(
            &store,
            item.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            None,
        )?;
    }
    store
        .get_mut("items")
        .and_then(|v| v.as_array_mut())
        .context("items")?
        .push(Value::Object(item.clone()));
    apply_filters(&store)?;
    save_filters(&store);
    audit("policy.create", &item);
    Ok(Value::Object(item))
}

pub fn update_filter(payload: Map<String, Value>) -> Result<Value> {
    let fid = payload
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if fid.is_empty() {
        return Err(anyhow!("id required to edit"));
    }
    let mut store = load_filters();
    let idx = store
        .get("items")
        .and_then(|v| v.as_array())
        .context("items")?
        .iter()
        .position(|x| x.get("id").and_then(|v| v.as_str()) == Some(fid.as_str()));
    let idx = idx.ok_or_else(|| anyhow!("policy not found"))?;
    let existing = store
        .get("items")
        .and_then(|v| v.as_array())
        .and_then(|a| a.get(idx))
        .and_then(|v| v.as_object())
        .cloned();
    let item = compose_policy(&payload, existing.as_ref())?;
    assert_unique_name(
        &store,
        item.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        Some(&fid),
    )?;
    let items = store
        .get_mut("items")
        .and_then(|v| v.as_array_mut())
        .context("items")?;
    items[idx] = Value::Object(item.clone());
    apply_filters(&store)?;
    save_filters(&store);
    audit("policy.update", &item);
    Ok(Value::Object(item))
}

pub fn delete_filter(fid: &str) -> Result<Value> {
    let fid = fid.trim();
    let mut store = load_filters();
    let items = store
        .get_mut("items")
        .and_then(|v| v.as_array_mut())
        .context("items")?;
    let before = items.len();
    items.retain(|i| i.get("id").and_then(|v| v.as_str()) != Some(fid));
    if items.len() == before {
        return Err(anyhow!("policy not found"));
    }
    apply_filters(&store)?;
    save_filters(&store);
    let mut audit_payload = Map::new();
    audit_payload.insert("id".into(), json!(fid));
    audit("policy.delete", &audit_payload);
    Ok(json!({ "ok": true, "id": fid }))
}

pub fn toggle_filter(fid: &str, enabled: bool) -> Result<Value> {
    let mut store = load_filters();
    let items = store
        .get_mut("items")
        .and_then(|v| v.as_array_mut())
        .context("items")?;
    let mut found = None;
    for item in items.iter_mut() {
        if item.get("id").and_then(|v| v.as_str()) == Some(fid) {
            if let Some(obj) = item.as_object_mut() {
                obj.insert("enabled".into(), json!(enabled));
                found = Some(obj.clone());
            }
            break;
        }
    }
    let found = found.ok_or_else(|| anyhow!("policy not found"))?;
    apply_filters(&store)?;
    save_filters(&store);
    let mut audit_payload = Map::new();
    audit_payload.insert("id".into(), json!(fid));
    audit_payload.insert("enabled".into(), json!(enabled));
    audit("policy.toggle", &audit_payload);
    Ok(Value::Object(found))
}

fn nomad_bin() -> Option<String> {
    std::env::var("NOMAD_BIN").ok().filter(|s| !s.is_empty())
}

fn cscli_bin() -> Option<String> {
    std::env::var("CROWDSEC_CSCLI")
        .ok()
        .filter(|s| !s.is_empty())
}

fn nomad_addr() -> String {
    std::env::var("NOMAD_ADDR").unwrap_or_else(|_| "http://127.0.0.1:4646".into())
}

fn nomad_job() -> String {
    std::env::var("WAF_CROWDSEC_JOB").unwrap_or_else(|_| "crowdsec".into())
}

pub fn nomad_alloc() -> Result<String> {
    let nomad =
        nomad_bin().ok_or_else(|| anyhow!("set CROWDSEC_CSCLI or NOMAD_BIN to run cscli"))?;
    let output = Command::new(&nomad)
        .args(["job", "allocs", "-json", &nomad_job()])
        .env("NOMAD_ADDR", nomad_addr())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("nomad allocs")?;
    if !output.status.success() {
        return Err(anyhow!(
            "{}",
            String::from_utf8_lossy(&output.stdout)
                .chars()
                .chain(String::from_utf8_lossy(&output.stderr).chars())
                .take(800)
                .collect::<String>()
        ));
    }
    let data: Value = serde_json::from_slice(&output.stdout)?;
    let empty: Vec<Value> = Vec::new();
    let mut running: Vec<&Map<String, Value>> = data
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|a| a.as_object())
        .filter(|a| a.get("ClientStatus").and_then(|v| v.as_str()) == Some("running"))
        .collect();
    if running.is_empty() {
        return Err(anyhow!("no running CrowdSec Nomad alloc"));
    }
    running.sort_by_key(|a| {
        std::cmp::Reverse(a.get("ModifyIndex").and_then(|v| v.as_i64()).unwrap_or(0))
    });
    Ok(running[0]
        .get("ID")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string())
}

pub fn cscli(args: &[&str]) -> Result<String> {
    let output = if let Some(bin) = cscli_bin() {
        Command::new(&bin)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    } else if let Some(nomad) = nomad_bin() {
        let alloc = nomad_alloc()?;
        let mut cmd = Command::new(&nomad);
        cmd.args(["alloc", "exec", "-task", &nomad_job(), &alloc, "cscli"]);
        cmd.args(args);
        cmd.env("NOMAD_ADDR", nomad_addr());
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()
    } else {
        return Err(anyhow!(
            "set CROWDSEC_CSCLI to the cscli binary, or NOMAD_BIN for alloc exec"
        ));
    }?;
    if !output.status.success() {
        let msg = String::from_utf8_lossy(&output.stderr);
        let msg = if msg.is_empty() {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            msg.to_string()
        };
        return Err(anyhow!("{}", msg.chars().take(800).collect::<String>()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn allowlist_add(cidr: &str, reason: &str) -> Result<Value> {
    let cidr = validate_cidr(cidr)?;
    let reason = reason.chars().take(80).collect::<String>();
    let reason = if reason.is_empty() {
        "cso-console".to_string()
    } else {
        reason
    };
    reject_forbidden(&[&reason])?;
    let _ = cscli(&[
        "allowlists",
        "create",
        &allowlist_name(),
        "-d",
        "operator allowlist",
    ]);
    let out = cscli(&["allowlists", "add", &allowlist_name(), &cidr, "-d", &reason])?;
    let mut audit_payload = Map::new();
    audit_payload.insert("cidr".into(), json!(cidr));
    audit_payload.insert("reason".into(), json!(reason));
    audit("allowlist.add", &audit_payload);
    Ok(json!({ "ok": true, "cidr": cidr, "out": out }))
}

pub fn allowlist_remove(cidr: &str) -> Result<Value> {
    let cidr = validate_cidr(cidr)?;
    let out = cscli(&["allowlists", "remove", &allowlist_name(), &cidr])?;
    let mut audit_payload = Map::new();
    audit_payload.insert("cidr".into(), json!(cidr));
    audit("allowlist.remove", &audit_payload);
    Ok(json!({ "ok": true, "cidr": cidr, "out": out }))
}

pub fn hub_appsec_rules() -> Vec<String> {
    let root = config_root().join("hub").join("appsec-rules");
    let mut names = Vec::new();
    if root.is_dir() {
        walk_yaml(&root, &root, &mut names, 250);
    }
    names
}

fn walk_yaml(root: &PathBuf, dir: &PathBuf, names: &mut Vec<String>, limit: usize) {
    if names.len() >= limit {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if names.len() >= limit {
            break;
        }
        let path = entry.path();
        if path.is_dir() {
            walk_yaml(root, &path, names, limit);
        } else if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let rel = rel.strip_suffix(".yaml").unwrap_or(&rel);
            names.push(if rel.contains('/') {
                rel.to_string()
            } else {
                format!("crowdsecurity/{rel}")
            });
        }
    }
}

fn traefik_api() -> Result<String> {
    netguard::assert_loopback_http_url(
        &std::env::var("TRAEFIK_API")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/api/http/routers".into()),
        "TRAEFIK_API",
    )
}

fn fetch_traefik_routers() -> Vec<Value> {
    let url = traefik_api().unwrap_or_default();
    if url.is_empty() {
        return Vec::new();
    }
    // Reuse routes-style fetch via simple HTTP GET
    crate::routes::live_http()
}

pub fn traefik_site_map() -> HashMap<String, Value> {
    let routers = fetch_traefik_routers();
    let sites = sites();
    let mut by_host: HashMap<String, Value> = HashMap::new();
    for host in sites.keys() {
        for router in &routers {
            let rule = router.get("rule").and_then(|v| v.as_str()).unwrap_or("");
            if rule.contains(&format!("Host(`{host}`)")) {
                let entry = by_host
                    .entry(host.clone())
                    .or_insert_with(|| json!({ "routers": [], "middlewares": [] }));
                if let Some(obj) = entry.as_object_mut() {
                    if let Some(arr) = obj.get_mut("routers").and_then(|v| v.as_array_mut()) {
                        if let Some(name) = router.get("name") {
                            arr.push(name.clone());
                        }
                    }
                    if let Some(mws) = router.get("middlewares").and_then(|v| v.as_array()) {
                        let mut set: HashSet<String> = obj
                            .get("middlewares")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        for mw in mws {
                            if let Some(s) = mw.as_str() {
                                set.insert(s.to_string());
                            }
                        }
                        let mut sorted: Vec<String> = set.into_iter().collect();
                        sorted.sort();
                        obj.insert(
                            "middlewares".into(),
                            Value::Array(sorted.into_iter().map(Value::String).collect()),
                        );
                    }
                }
            }
        }
    }
    by_host
        .into_iter()
        .map(|(host, mut info)| {
            let mws = info
                .get("middlewares")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let bouncer = mws.iter().any(|m| {
                m.as_str()
                    .map(|s| s.contains("crowdsec") || s.contains("security-chain"))
                    .unwrap_or(false)
            });
            if let Some(obj) = info.as_object_mut() {
                obj.insert("bouncer".into(), json!(bouncer));
            }
            (host, info)
        })
        .collect()
}

pub fn sites_payload() -> Value {
    let store = load_filters();
    let traefik = traefik_site_map();
    let site_map = sites();
    let mut rows = Vec::new();
    for (host, meta) in &site_map {
        let mut row = if meta.is_object() {
            meta.as_object().cloned().unwrap_or_default()
        } else {
            Map::from_iter([
                ("kind".into(), json!("web")),
                ("in_scope".into(), json!(true)),
            ])
        };
        row.insert("host".into(), json!(host));
        row.insert(
            "traefik".into(),
            traefik.get(host).cloned().unwrap_or(json!({})),
        );
        let filters: Vec<Value> = store
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| i.get("host").and_then(|v| v.as_str()) == Some(host.as_str()))
            .collect();
        row.insert("filters".into(), Value::Array(filters));
        rows.push(Value::Object(row));
    }
    json!({
        "ok": true,
        "sites": rows,
        "out_of_scope": out_of_scope(),
        "actions": ACTIONS,
        "policy": {
            "crs_inband": false,
            "fail_closed": true,
            "include_large_uploads": false,
            "mutations": [
                "unban-ip",
                "ban-ip",
                "allowlist-add",
                "allowlist-remove",
                "policy-create",
                "policy-update",
                "policy-delete",
                "site-filter-allow_match",
                "site-filter-skip_rule",
                "site-filter-bypass_host",
            ],
        },
    })
}

/// Read-only integrity hashes for CrowdSec operator configs (never Traefik paths).
pub fn config_integrity() -> Value {
    let root = config_root();
    let candidates = [
        ("profiles", root.join("profiles.yaml")),
        ("acquis_appsec", root.join("acquis.d").join("appsec.yaml")),
        ("site_filters_yaml", filters_yaml()),
        (
            "operators_parser",
            root.join("parsers")
                .join("s02-enrich")
                .join("cso-operators.yaml"),
        ),
    ];
    let mut files = Vec::new();
    for (name, path) in candidates {
        if path.is_file() {
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let sha1 = crate::sha1_digest::hex(&bytes);
                    files.push(json!({
                        "name": name,
                        "path": path.display().to_string(),
                        "present": true,
                        "bytes": bytes.len(),
                        "sha1": sha1,
                    }));
                }
                Err(e) => {
                    files.push(json!({
                        "name": name,
                        "path": path.display().to_string(),
                        "present": true,
                        "error": e.to_string().chars().take(200).collect::<String>(),
                    }));
                }
            }
        } else {
            files.push(json!({
                "name": name,
                "path": path.display().to_string(),
                "present": false,
            }));
        }
    }
    json!({
        "ok": true,
        "config_root": root.display().to_string(),
        "files": files,
        "note": "CrowdSec-only config hashes. Traefik static/dynamic paths are never inspected or restored from this console.",
    })
}
