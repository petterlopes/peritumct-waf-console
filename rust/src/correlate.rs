//! OWASP Top 10:2021 correlation + local CTI export (port of correlate.py).

#[path = "sha1_digest.rs"]
mod sha1_digest;

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use chrono::Utc;
use regex::Regex;
use serde_json::{json, Map, Value};

pub const OWASP_SOURCE: &str = "https://owasp.org/Top10/2021/";

pub fn owasp_2021() -> &'static [Value] {
    static OWASP: LazyLock<Vec<Value>> = LazyLock::new(|| {
        vec![
            json!({"code":"A01","id":"A01:2021","name":"Broken Access Control","url":"https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control.html"}),
            json!({"code":"A02","id":"A02:2021","name":"Cryptographic Failures","url":"https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures.html"}),
            json!({"code":"A03","id":"A03:2021","name":"Injection","url":"https://owasp.org/Top10/2021/A03_2021-Injection.html"}),
            json!({"code":"A04","id":"A04:2021","name":"Insecure Design","url":"https://owasp.org/Top10/2021/A04_2021-Insecure_Design.html"}),
            json!({"code":"A05","id":"A05:2021","name":"Security Misconfiguration","url":"https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration.html"}),
            json!({"code":"A06","id":"A06:2021","name":"Vulnerable and Outdated Components","url":"https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components.html"}),
            json!({"code":"A07","id":"A07:2021","name":"Identification and Authentication Failures","url":"https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures.html"}),
            json!({"code":"A08","id":"A08:2021","name":"Software and Data Integrity Failures","url":"https://owasp.org/Top10/2021/A08_2021-Software_and_Data_Integrity_Failures.html"}),
            json!({"code":"A09","id":"A09:2021","name":"Security Logging and Monitoring Failures","url":"https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures.html"}),
            json!({"code":"A10","id":"A10:2021","name":"Server-Side Request Forgery (SSRF)","url":"https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29.html"}),
        ]
    });
    OWASP.as_slice()
}

pub fn attack_catalog() -> &'static HashMap<&'static str, Value> {
    static ATTACK: LazyLock<HashMap<&str, Value>> = LazyLock::new(|| {
        let entries = [
            (
                "T1190",
                "Exploit Public-Facing Application",
                "Initial Access",
                "https://attack.mitre.org/techniques/T1190/",
            ),
            (
                "T1595",
                "Active Scanning",
                "Reconnaissance",
                "https://attack.mitre.org/techniques/T1595/",
            ),
            (
                "T1110",
                "Brute Force",
                "Credential Access",
                "https://attack.mitre.org/techniques/T1110/",
            ),
            (
                "T1059",
                "Command and Scripting Interpreter",
                "Execution",
                "https://attack.mitre.org/techniques/T1059/",
            ),
            (
                "T1083",
                "File and Directory Discovery",
                "Discovery",
                "https://attack.mitre.org/techniques/T1083/",
            ),
            (
                "T1046",
                "Network Service Discovery",
                "Discovery",
                "https://attack.mitre.org/techniques/T1046/",
            ),
            (
                "T1189",
                "Drive-by Compromise",
                "Initial Access",
                "https://attack.mitre.org/techniques/T1189/",
            ),
            (
                "T1505",
                "Server Software Component",
                "Persistence",
                "https://attack.mitre.org/techniques/T1505/",
            ),
            (
                "T1090",
                "Proxy",
                "Command and Control",
                "https://attack.mitre.org/techniques/T1090/",
            ),
            (
                "T1562",
                "Impair Defenses",
                "Defense Evasion",
                "https://attack.mitre.org/techniques/T1562/",
            ),
            (
                "T1600",
                "Weaken Encryption",
                "Defense Evasion",
                "https://attack.mitre.org/techniques/T1600/",
            ),
            (
                "T1068",
                "Exploitation for Privilege Escalation",
                "Privilege Escalation",
                "https://attack.mitre.org/techniques/T1068/",
            ),
            (
                "T1505.003",
                "Web Shell",
                "Persistence",
                "https://attack.mitre.org/techniques/T1505/003/",
            ),
        ];
        entries
            .into_iter()
            .map(|(id, name, tactic, url)| {
                (
                    id,
                    json!({"id": id, "name": name, "tactic": tactic, "url": url}),
                )
            })
            .collect()
    });
    &ATTACK
}

static TACTIC_ORDER: &[&str] = &[
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Command and Control",
];

static NOISE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)^\s*(?:enabling body inspection|disabl(?:e|ing) body inspection|update\s*:\s*[+-]\d+|(?:capi|community).{0,48}(?:blocklist|ips)|synced \d+|loading (?:parsers|scenarios|collections)|crowdsec (?:started|version)|capacity overflow|bucket overflow)",
    )
    .expect("NOISE_RE")
});

static CRS_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<gid>913|920|921|930|931|932|933|934|941|942|943|944)\d{3}\b")
        .expect("CRS_ID_RE")
});

static MITRE_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bT\d{4}(?:\.\d{3})?\b").expect("MITRE_ID_RE"));

static OOB_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)out-of-band|outofband|\boob\b|log-only").expect("OOB_RE"));

static SECRET_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(token|key|password|secret|authorization|credential)").expect("SECRET_KEY_RE")
});

static NONE_HIT: LazyLock<Value> = LazyLock::new(|| {
    json!({
        "code": "none",
        "id": "",
        "name": "",
        "url": "",
        "attack": [],
        "confidence": "none",
    })
});

struct ClassRule {
    re: Regex,
    code: &'static str,
    attack: &'static [&'static str],
    confidence: &'static str,
}

static CLASSIFY_RULES: LazyLock<Vec<ClassRule>> = LazyLock::new(|| {
    vec![
        rule(r"(?i)ssrf", "A10", &["T1190"], "high"),
        rule(r"(?i)sqli|sql.?inject", "A03", &["T1190"], "high"),
        rule(r"(?i)xss|cross.?site.?script", "A03", &["T1190"], "high"),
        rule(
            r"(?i)rce|remote.?code|command.?inject|php.?inject|log4j|jndi",
            "A03",
            &["T1190", "T1059", "T1068"],
            "high",
        ),
        rule(
            r"(?i)lfi|path.?traversal|directory.?traversal|local.?file.?inclusion",
            "A01",
            &["T1190"],
            "high",
        ),
        rule(
            r"(?i)rfi|remote.?file.?inclusion",
            "A03",
            &["T1190"],
            "high",
        ),
        rule(
            r"(?i)webshell|backdoor",
            "A01",
            &["T1505", "T1505.003"],
            "high",
        ),
        rule(r"(?i)wordpress-uploads-listing", "A01", &["T1190"], "high"),
        rule(
            r"(?i)env-access|sensitive.?files|admin.?interface|git-config",
            "A01",
            &["T1190"],
            "high",
        ),
        rule(r"(?i)wordpress.?login", "A07", &["T1110"], "high"),
        rule(
            r"(?i)brute(?:[-_ ]?force)?|\bbf\b|[-_/]bf(?:[-_/]|$)|ssh-slow-bf|ssh-bf",
            "A07",
            &["T1110"],
            "high",
        ),
        rule(r"(?i)xmlrpc", "A05", &["T1595"], "medium"),
        rule(
            r"(?i)waf.?bypass|disable.?security|impair.?defense",
            "A05",
            &["T1562"],
            "medium",
        ),
        rule(
            r"(?i)weak.?crypto|insecure.?tls",
            "A02",
            &["T1600"],
            "medium",
        ),
        rule(r"(?i)vpatch|cve-\d{4}", "A06", &["T1190"], "medium"),
        rule(
            r"(?i)wordpress.?scan|http-wordpress",
            "A05",
            &["T1595"],
            "medium",
        ),
        rule(r"(?i)wordpress", "A06", &["T1190"], "medium"),
        rule(
            r"(?i)probing|scanner|http-crawl|bad-user-agent|open-proxy|http-scan",
            "A05",
            &["T1595"],
            "medium",
        ),
    ]
});

fn rule(
    pat: &str,
    code: &'static str,
    attack: &'static [&'static str],
    confidence: &'static str,
) -> ClassRule {
    ClassRule {
        re: Regex::new(pat).expect("class rule"),
        code,
        attack,
        confidence,
    }
}

fn crs_class(gid: &str) -> Option<(&'static str, &'static [&'static str], &'static str)> {
    match gid {
        "913" | "920" | "921" => Some(("A05", &["T1595"], "medium")),
        "930" => Some(("A01", &["T1190"], "high")),
        "931" | "941" | "942" | "944" => Some(("A03", &["T1190"], "high")),
        "932" => Some(("A03", &["T1190", "T1059", "T1068"], "high")),
        "933" => Some(("A03", &["T1190", "T1059"], "high")),
        "934" => Some(("A10", &["T1190"], "high")),
        "943" => Some(("A07", &["T1110"], "medium")),
        _ => None,
    }
}

fn owasp_by_code() -> HashMap<String, Value> {
    owasp_2021()
        .iter()
        .filter_map(|v| {
            let code = v.get("code")?.as_str()?.to_string();
            Some((code, v.clone()))
        })
        .collect()
}

fn owasp_meta(code: &str) -> Map<String, Value> {
    let by = owasp_by_code();
    by.get(code)
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_else(|| {
            let mut m = Map::new();
            m.insert("code".into(), json!(code));
            m.insert("id".into(), json!(""));
            m.insert("name".into(), json!(""));
            m.insert("url".into(), json!(""));
            m
        })
}

fn hit(code: &str, attack: &[&str], confidence: &str) -> Value {
    let meta = owasp_meta(code);
    let catalog = attack_catalog();
    let mut seen = HashSet::new();
    let mut techniques = Vec::new();
    for tid in attack {
        if catalog.contains_key(*tid) && seen.insert(*tid) {
            techniques.push(json!(*tid));
        }
    }
    json!({
        "code": code,
        "id": meta.get("id").cloned().unwrap_or(json!("")),
        "name": meta.get("name").cloned().unwrap_or(json!("")),
        "url": meta.get("url").cloned().unwrap_or(json!("")),
        "attack": techniques,
        "confidence": confidence,
    })
}

pub fn is_noise_event(name: Option<&str>) -> bool {
    let text = name.unwrap_or("").trim();
    if text.is_empty() {
        return true;
    }
    NOISE_RE.is_match(text)
}

fn mitre_from_alert(alert: Option<&Map<String, Value>>) -> Vec<String> {
    let Some(alert) = alert else {
        return Vec::new();
    };
    let mut chunks = Vec::new();
    for key in ["labels", "tags"] {
        if let Some(val) = alert.get(key) {
            if let Some(arr) = val.as_array() {
                for item in arr {
                    chunks.push(item.to_string().trim_matches('"').to_string());
                }
            } else {
                chunks.push(val.to_string().trim_matches('"').to_string());
            }
        }
    }
    if let Some(meta) = alert.get("meta") {
        if let Some(list) = meta.as_array() {
            for item in list {
                if let Some(obj) = item.as_object() {
                    if let Some(k) = obj.get("key") {
                        chunks.push(k.to_string());
                    }
                    if let Some(v) = obj.get("value") {
                        chunks.push(v.to_string());
                    }
                }
            }
        } else if let Some(obj) = meta.as_object() {
            for (k, v) in obj {
                chunks.push(k.clone());
                chunks.push(v.to_string());
            }
        }
    }
    let catalog = attack_catalog();
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let tid_re = Regex::new(r"(?i)^t(\d{4}(?:\.\d{3})?)$").expect("tid");
    for chunk in chunks {
        for m in MITRE_ID_RE.find_iter(&chunk) {
            if let Some(caps) = tid_re.captures(m.as_str()) {
                let tid = format!("T{}", caps.get(1).unwrap().as_str());
                if catalog.contains_key(tid.as_str()) && seen.insert(tid.clone()) {
                    found.push(tid);
                }
            }
        }
    }
    found
}

pub fn classify(name: Option<&str>, alert: Option<&Map<String, Value>>) -> Value {
    let text = name.unwrap_or("").trim();
    if text.is_empty() || is_noise_event(Some(text)) {
        return NONE_HIT.clone();
    }
    let mut result: Value = NONE_HIT.clone();
    if let Some(caps) = CRS_ID_RE.captures(text) {
        if let Some(mapped) = crs_class(caps.name("gid").unwrap().as_str()) {
            result = hit(mapped.0, mapped.1, mapped.2);
        }
    }
    if result.get("code").and_then(|v| v.as_str()) == Some("none") {
        for rule in CLASSIFY_RULES.iter() {
            if rule.re.is_match(text) {
                result = hit(rule.code, rule.attack, rule.confidence);
                break;
            }
        }
    }
    let hub = mitre_from_alert(alert);
    if !hub.is_empty() {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("attack".into(), json!(hub));
            if obj.get("confidence").and_then(|v| v.as_str()) == Some("none") {
                obj.insert("confidence".into(), json!("medium"));
            }
        }
    }
    if result.get("code").and_then(|v| v.as_str()) != Some("none") && OOB_RE.is_match(text) {
        if let Some(obj) = result.as_object_mut() {
            if obj.get("confidence").and_then(|v| v.as_str()) == Some("high") {
                obj.insert("confidence".into(), json!("medium"));
            }
            if hub.is_empty() {
                if obj
                    .get("attack")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
                {
                    obj.insert("attack".into(), json!(["T1595"]));
                }
            }
        }
    }
    result
}

fn alert_ip(alert: &Map<String, Value>) -> String {
    let src = alert
        .get("source")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let ip = src
        .get("ip")
        .or_else(|| src.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !ip.is_empty() {
        return ip.to_string();
    }
    if let Some(events) = alert.get("events").and_then(|v| v.as_array()) {
        if let Some(ev) = events.first().and_then(|v| v.as_object()) {
            let ev_src = ev
                .get("source")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            return ev_src
                .get("ip")
                .or_else(|| ev_src.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
        }
    }
    String::new()
}

fn alert_geo(alert: &Map<String, Value>) -> (String, String) {
    let mut src = alert
        .get("source")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut cn = src
        .get("cn")
        .or_else(|| src.get("country"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut city = src
        .get("city")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if cn.is_empty() || city.is_empty() {
        if let Some(events) = alert.get("events").and_then(|v| v.as_array()) {
            if let Some(ev) = events.first().and_then(|v| v.as_object()) {
                let ev_src = ev
                    .get("source")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();
                if cn.is_empty() {
                    cn = ev_src
                        .get("cn")
                        .or_else(|| ev_src.get("country"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                }
                if city.is_empty() {
                    city = ev_src
                        .get("city")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                }
            }
        }
    }
    (cn.trim().to_uppercase(), city.trim().to_string())
}

fn alert_name(alert: &Map<String, Value>) -> String {
    if let Some(name) = alert.get("scenario").or_else(|| alert.get("reason")) {
        let s = name.as_str().unwrap_or("").to_string();
        if !s.is_empty() {
            return s;
        }
    }
    if let Some(decisions) = alert.get("decisions").and_then(|v| v.as_array()) {
        if let Some(d) = decisions.first().and_then(|v| v.as_object()) {
            return d
                .get("scenario")
                .or_else(|| d.get("reason"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
        }
    }
    String::new()
}

fn env_url(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_string()
}

fn connector(ctype: &str, name: &str, scope: &str, status: &str, note: &str) -> Value {
    json!({
        "type": ctype,
        "name": name,
        "scope": scope,
        "status": status,
        "note": note,
        "push": false,
    })
}

pub fn connectors() -> Vec<Value> {
    let misp = if !env_url("WAF_MISP_URL").is_empty() {
        "configured"
    } else {
        "unconfigured"
    };
    let hive = if !env_url("WAF_THEHIVE_URL").is_empty() {
        "configured"
    } else {
        "unconfigured"
    };
    let opencti = if !env_url("WAF_OPENCTI_URL").is_empty() {
        "configured"
    } else {
        "unconfigured"
    };
    let _ = env_url("WAF_MISP_KEY");
    let _ = env_url("WAF_THEHIVE_KEY");
    let _ = env_url("WAF_OPENCTI_TOKEN");
    vec![
        connector(
            "INTERNAL_ENRICHMENT",
            "MITRE ATT&CK",
            "local-catalog",
            "configured",
            "Local ATT&CK Enterprise subset. Tactics match attack.mitre.org. No GitHub download.",
        ),
        connector(
            "INTERNAL_ENRICHMENT",
            "OWASP Top 10:2021",
            "local-catalog",
            "configured",
            &format!("CrowdSec scenario/AppSec/CRS IDs mapped to A01–A10. {OWASP_SOURCE}"),
        ),
        connector(
            "INTERNAL_EXPORT_FILE",
            "MISP",
            "file-export",
            misp,
            "Download MISP event JSON. No outbound push of findings.",
        ),
        connector(
            "INTERNAL_EXPORT_FILE",
            "TheHive",
            "file-export",
            hive,
            "Download TheHive alert JSON. No outbound push of findings.",
        ),
        connector(
            "INTERNAL_EXPORT_FILE",
            "OpenCTI",
            "file-export",
            opencti,
            "Download STIX 2.1 bundle. No outbound push of findings.",
        ),
        connector(
            "EXTERNAL_IMPORT",
            "OpenCTI import",
            "disabled",
            "unconfigured",
            "Inbound connector import is not enabled.",
        ),
        connector(
            "STREAM",
            "OpenCTI stream",
            "disabled",
            "unconfigured",
            "Live stream push is not enabled.",
        ),
    ]
}

pub fn scrub(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                if SECRET_KEY_RE.is_match(&key) {
                    continue;
                }
                out.insert(key, scrub(item));
            }
            Value::Object(out)
        }
        Value::Array(list) => Value::Array(list.into_iter().map(scrub).collect()),
        other => other,
    }
}

fn collapse_findings(findings: Vec<Value>) -> Vec<Value> {
    let catalog = attack_catalog();
    let attack_order: Vec<&str> = catalog.keys().copied().collect();
    let mut merged: HashMap<(String, String), Value> = HashMap::new();
    let mut order: Vec<(String, String)> = Vec::new();
    let rank = |c: &str| match c {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    for item in findings {
        let ip = item
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let owasp = item
            .get("owasp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let key = (ip.clone(), owasp.clone());
        if !merged.contains_key(&key) {
            let mut row = item.as_object().cloned().unwrap_or_default();
            row.insert(
                "events".into(),
                json!(item.get("events").and_then(|v| v.as_i64()).unwrap_or(1)),
            );
            let atk: HashSet<String> = item
                .get("attack")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let ordered: Vec<Value> = attack_order
                .iter()
                .filter(|tid| atk.contains(**tid))
                .map(|tid| json!(*tid))
                .collect();
            row.insert("attack".into(), Value::Array(ordered));
            merged.insert(key.clone(), Value::Object(row));
            order.push(key);
            continue;
        }
        let row = merged.get_mut(&key).unwrap().as_object_mut().unwrap();
        let ev = row.get("events").and_then(|v| v.as_i64()).unwrap_or(1)
            + item.get("events").and_then(|v| v.as_i64()).unwrap_or(1);
        row.insert("events".into(), json!(ev));
        let mut seen: HashSet<String> = row
            .get("attack")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(atk) = item.get("attack").and_then(|v| v.as_array()) {
            for tid in atk {
                if let Some(s) = tid.as_str() {
                    seen.insert(s.to_string());
                }
            }
        }
        let ordered: Vec<Value> = attack_order
            .iter()
            .filter(|tid| seen.contains(**tid))
            .map(|tid| json!(*tid))
            .collect();
        row.insert("attack".into(), Value::Array(ordered));
        let incoming = item.get("when").and_then(|v| v.as_str()).unwrap_or("");
        let current = row.get("when").and_then(|v| v.as_str()).unwrap_or("");
        if incoming > current {
            row.insert("when".into(), json!(incoming));
        }
        let inc_conf = item
            .get("confidence")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cur_conf = row.get("confidence").and_then(|v| v.as_str()).unwrap_or("");
        if rank(inc_conf) > rank(cur_conf) {
            row.insert("confidence".into(), json!(inc_conf));
        }
        let incoming_name = item.get("scenario").and_then(|v| v.as_str()).unwrap_or("");
        let current_name = row.get("scenario").and_then(|v| v.as_str()).unwrap_or("");
        if OOB_RE.is_match(current_name)
            && !incoming_name.is_empty()
            && !OOB_RE.is_match(incoming_name)
        {
            row.insert("scenario".into(), json!(incoming_name));
        }
    }
    order
        .into_iter()
        .filter_map(|k| merged.remove(&k))
        .collect()
}

fn recount(catalog: &mut HashMap<String, Value>, findings: &[Value]) -> HashMap<String, i64> {
    for item in catalog.values_mut() {
        if let Some(obj) = item.as_object_mut() {
            obj.insert("count".into(), json!(0));
        }
    }
    let codes: Vec<String> = catalog.keys().cloned().collect();
    let mut owasp_ips: HashMap<String, HashSet<String>> =
        codes.iter().map(|c| (c.clone(), HashSet::new())).collect();
    let attack_keys: Vec<&str> = attack_catalog().keys().copied().collect();
    let mut attack_ips: HashMap<&str, HashSet<String>> = attack_keys
        .iter()
        .map(|tid| (*tid, HashSet::new()))
        .collect();
    for finding in findings {
        let ip = finding
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let token = if ip.is_empty() {
            format!(
                "finding:{}|{}",
                finding
                    .get("scenario")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                finding.get("when").and_then(|v| v.as_str()).unwrap_or("")
            )
        } else {
            ip.to_string()
        };
        let code = finding.get("owasp").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(set) = owasp_ips.get_mut(code) {
            set.insert(token.clone());
        }
        if let Some(atk) = finding.get("attack").and_then(|v| v.as_array()) {
            for tid in atk {
                if let Some(t) = tid.as_str() {
                    if let Some(set) = attack_ips.get_mut(t) {
                        set.insert(if ip.is_empty() {
                            token.clone()
                        } else {
                            ip.to_string()
                        });
                    }
                }
            }
        }
    }
    for (code, seen) in &owasp_ips {
        if let Some(item) = catalog.get_mut(code) {
            if let Some(obj) = item.as_object_mut() {
                obj.insert("count".into(), json!(seen.len()));
            }
        }
    }
    attack_keys
        .into_iter()
        .map(|tid| {
            (
                tid.to_string(),
                attack_ips.get(tid).map(|s| s.len() as i64).unwrap_or(0),
            )
        })
        .collect()
}

pub fn correlate(alerts: &[Value], hub_rules: Option<&[String]>) -> Value {
    let mut catalog: HashMap<String, Value> = HashMap::new();
    for item in owasp_2021() {
        let code = item
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        catalog.insert(
            code.clone(),
            json!({
                "code": code,
                "id": item.get("id"),
                "name": item.get("name"),
                "url": item.get("url"),
                "count": 0,
                "hub_rules": [],
            }),
        );
    }
    if let Some(rules) = hub_rules {
        for rule in rules {
            let hit = classify(Some(rule), None);
            if let Some(code) = hit.get("code").and_then(|v| v.as_str()) {
                if let Some(entry) = catalog.get_mut(code) {
                    if let Some(arr) = entry.get_mut("hub_rules").and_then(|v| v.as_array_mut()) {
                        arr.push(json!(rule));
                    }
                }
            }
        }
    }
    let mut findings = Vec::new();
    for alert in alerts {
        let Some(alert_obj) = alert.as_object() else {
            continue;
        };
        let name = alert_name(alert_obj);
        if is_noise_event(Some(&name)) {
            continue;
        }
        let hit = classify(Some(&name), Some(alert_obj));
        if hit.get("code").and_then(|v| v.as_str()) == Some("none")
            && hit
                .get("attack")
                .and_then(|v| v.as_array())
                .map(|a| a.is_empty())
                .unwrap_or(true)
        {
            continue;
        }
        let (cn, city) = alert_geo(alert_obj);
        findings.push(json!({
            "when": alert_obj.get("created_at").or_else(|| alert_obj.get("start_at")).cloned().unwrap_or(json!("")),
            "ip": alert_ip(alert_obj),
            "cn": cn,
            "city": city,
            "scenario": name,
            "owasp": hit.get("code"),
            "attack": hit.get("attack").cloned().unwrap_or(json!([])),
            "confidence": hit.get("confidence").cloned().unwrap_or(json!("none")),
        }));
    }
    let findings = collapse_findings(findings);
    let attack_counts = recount(&mut catalog, &findings);
    let owasp_list: Vec<Value> = catalog.values().cloned().collect();
    let attack_list: Vec<Value> = attack_catalog()
        .iter()
        .map(|(tid, meta)| {
            json!({
                "id": tid,
                "name": meta.get("name"),
                "url": meta.get("url"),
                "count": attack_counts.get(*tid).copied().unwrap_or(0),
            })
        })
        .collect();
    let payload = json!({
        "ok": true,
        "source": OWASP_SOURCE,
        "push": false,
        "owasp": owasp_list,
        "findings": findings,
        "attack": attack_list,
        "mitre": mitre_block(&findings, &attack_counts),
        "connectors": connectors(),
    });
    scrub(payload)
}

fn mitre_block(findings: &[Value], attack_counts: &HashMap<String, i64>) -> Value {
    let catalog = attack_catalog();
    let mut tech_owasp: HashMap<&str, HashSet<String>> =
        catalog.keys().map(|tid| (*tid, HashSet::new())).collect();
    for finding in findings {
        let code = finding.get("owasp").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(atk) = finding.get("attack").and_then(|v| v.as_array()) {
            for tid in atk {
                if let Some(t) = tid.as_str() {
                    if !code.is_empty() && code != "none" {
                        if let Some(set) = tech_owasp.get_mut(t) {
                            set.insert(code.to_string());
                        }
                    }
                }
            }
        }
    }
    let mut techniques = Vec::new();
    for (tid, meta) in catalog.iter() {
        let owasp: Vec<String> = tech_owasp
            .get(tid)
            .map(|s| {
                let mut v: Vec<_> = s.iter().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default();
        techniques.push(json!({
            "id": tid,
            "name": meta.get("name"),
            "tactic": meta.get("tactic"),
            "url": meta.get("url"),
            "count": attack_counts.get(*tid).copied().unwrap_or(0),
            "owasp": owasp,
        }));
    }
    let mut tactic_map: HashMap<String, Value> = HashMap::new();
    for tech in &techniques {
        let name = tech
            .get("tactic")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let entry = tactic_map
            .entry(name.clone())
            .or_insert_with(|| json!({"name": name, "count": 0, "techniques": []}));
        if let Some(obj) = entry.as_object_mut() {
            let c = obj.get("count").and_then(|v| v.as_i64()).unwrap_or(0)
                + tech.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            obj.insert("count".into(), json!(c));
            if let Some(arr) = obj.get_mut("techniques").and_then(|v| v.as_array_mut()) {
                arr.push(tech.get("id").cloned().unwrap_or(json!("")));
            }
        }
    }
    let tactics: Vec<Value> = TACTIC_ORDER
        .iter()
        .filter_map(|name| tactic_map.get(*name).cloned())
        .collect();
    let uncovered: Vec<Value> = techniques
        .iter()
        .filter(|t| t.get("count").and_then(|v| v.as_i64()).unwrap_or(0) == 0)
        .filter_map(|t| t.get("id").cloned())
        .collect();
    json!({
        "techniques": techniques,
        "tactics": tactics,
        "findings": findings,
        "uncovered": uncovered,
    })
}

fn stix_id(kind: &str, seed: &str) -> String {
    let digest = sha1_digest::hex(seed.as_bytes());
    let packed = &digest[..32];
    let uuid_str = format!(
        "{}-{}-{}-{}-{}",
        &packed[0..8],
        &packed[8..12],
        &packed[12..16],
        &packed[16..20],
        &packed[20..32]
    );
    format!("{kind}--{uuid_str}")
}

fn now_stix() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string()
}

pub fn stix_bundle(payload: &Value) -> Value {
    let payload = if payload.is_object() {
        payload
    } else {
        &Value::Null
    };
    let now = now_stix();
    let identity_id = stix_id("identity", "waf-console");
    let mut objects: Vec<Value> = vec![json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "WAF Console",
        "identity_class": "system",
        "description": "Local CrowdSec WAF console. File export only; push=False.",
    })];
    let mut seen_attack = HashSet::new();
    let mut seen_owasp = HashSet::new();
    if let Some(list) = payload.get("owasp").and_then(|v| v.as_array()) {
        for cat in list {
            let code = cat.get("code").and_then(|v| v.as_str()).unwrap_or("");
            if code.is_empty() || code == "none" {
                continue;
            }
            seen_owasp.insert(code.to_string());
            let ap_id = stix_id("attack-pattern", &format!("owasp-{code}"));
            objects.push(json!({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": format!("{code}:2021 {}", cat.get("name").and_then(|v| v.as_str()).unwrap_or("")).trim(),
                "description": cat.get("url").unwrap_or(&json!(OWASP_SOURCE)),
                "external_references": [{
                    "source_name": "owasp",
                    "external_id": cat.get("id").unwrap_or(&json!(format!("{code}:2021"))),
                    "url": cat.get("url").unwrap_or(&json!(OWASP_SOURCE)),
                }],
            }));
        }
    }
    if let Some(list) = payload.get("attack").and_then(|v| v.as_array()) {
        for tech in list {
            let tid = tech.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if tid.is_empty() || seen_attack.contains(tid) {
                continue;
            }
            seen_attack.insert(tid.to_string());
            let url = tech
                .get("url")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    attack_catalog()
                        .get(tid)
                        .and_then(|m| m.get("url"))
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("");
            objects.push(json!({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": stix_id("attack-pattern", &format!("mitre-{tid}")),
                "created": now,
                "modified": now,
                "name": tech.get("name").unwrap_or(&json!(tid)),
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tid,
                    "url": url,
                }],
            }));
        }
    }
    if let Some(list) = payload.get("findings").and_then(|v| v.as_array()) {
        for finding in list {
            let ip = finding
                .get("ip")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let scenario = finding
                .get("scenario")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let seed = [
                finding.get("when").and_then(|v| v.as_str()).unwrap_or(""),
                ip,
                scenario,
            ]
            .join("|");
            let indicator_id = stix_id("indicator", if seed.is_empty() { scenario } else { &seed });
            let pattern = if !ip.is_empty() {
                format!("[ipv4-addr:value = '{ip}']")
            } else {
                format!(
                    "[x-waf-scenario:value = '{}']",
                    if scenario.is_empty() {
                        "unknown"
                    } else {
                        scenario
                    }
                )
            };
            objects.push(json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": if scenario.is_empty() { if ip.is_empty() { "waf-finding" } else { ip } } else { scenario },
                "description": format!(
                    "OWASP {} · ATT&CK {} · confidence {}",
                    finding.get("owasp").and_then(|v| v.as_str()).unwrap_or("none"),
                    finding.get("attack").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_else(|| "none".into()),
                    finding.get("confidence").and_then(|v| v.as_str()).unwrap_or("none"),
                ),
                "indicator_types": ["malicious-activity"],
                "pattern_type": "stix",
                "pattern": pattern,
                "valid_from": now,
            }));
            let owasp_code = finding.get("owasp").and_then(|v| v.as_str()).unwrap_or("");
            if !owasp_code.is_empty() && owasp_code != "none" {
                objects.push(json!({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": stix_id("relationship", &(indicator_id.clone() + owasp_code)),
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": stix_id("attack-pattern", &format!("owasp-{owasp_code}")),
                }));
            }
        }
    }
    let findings_json =
        serde_json::to_string(payload.get("findings").unwrap_or(&json!([]))).unwrap_or_default();
    let bundle_seed = if findings_json.len() > 800 {
        &findings_json[..800]
    } else {
        &findings_json
    };
    scrub(json!({
        "type": "bundle",
        "id": stix_id("bundle", bundle_seed),
        "objects": objects,
    }))
}

pub fn misp_event(payload: &Value) -> Value {
    let payload = if payload.is_object() {
        payload
    } else {
        &Value::Null
    };
    let now = Utc::now().format("%Y-%m-%d").to_string();
    let mut attributes = Vec::new();
    let tags = vec![
        json!({"name": "owasp:top10:2021"}),
        json!({"name": "tlp:amber"}),
    ];
    let catalog = attack_catalog();
    if let Some(list) = payload.get("findings").and_then(|v| v.as_array()) {
        for finding in list {
            let ip = finding
                .get("ip")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let scenario = finding
                .get("scenario")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let owasp = finding
                .get("owasp")
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            let comment = format!(
                "{} · {} · {}",
                scenario,
                owasp,
                finding
                    .get("confidence")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            );
            if !ip.is_empty() {
                attributes.push(json!({
                    "type": "ip-src",
                    "category": "Network activity",
                    "value": ip,
                    "comment": comment,
                    "to_ids": true,
                }));
            }
            if !scenario.is_empty() {
                attributes.push(json!({
                    "type": "text",
                    "category": "Other",
                    "value": scenario,
                    "comment": comment,
                    "to_ids": false,
                }));
            }
            if let Some(atk) = finding.get("attack").and_then(|v| v.as_array()) {
                for tid in atk {
                    let t = tid.as_str().unwrap_or("");
                    let name = catalog
                        .get(t)
                        .and_then(|m| m.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("ATT&CK");
                    attributes.push(json!({
                        "type": "text",
                        "category": "External analysis",
                        "value": t,
                        "comment": name,
                        "to_ids": false,
                    }));
                }
            }
        }
    }
    scrub(json!({
        "Event": {
            "info": "WAF console CrowdSec findings (OWASP Top 10:2021)",
            "date": now,
            "threat_level_id": "2",
            "analysis": "1",
            "distribution": "0",
            "published": false,
            "Attribute": attributes,
            "Tag": tags,
            "Galaxy": [],
        },
        "push": false,
    }))
}

pub fn thehive_alert(payload: &Value) -> Value {
    let payload = if payload.is_object() {
        payload
    } else {
        &Value::Null
    };
    let findings = payload
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut artifacts = Vec::new();
    let mut tags = vec![
        "waf-console".to_string(),
        "crowdsec".to_string(),
        "owasp-top10-2021".to_string(),
    ];
    for finding in &findings {
        let ip = finding
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let scenario = finding
            .get("scenario")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !ip.is_empty() {
            artifacts.push(json!({
                "dataType": "ip",
                "data": ip,
                "message": if scenario.is_empty() { "crowdsec-alert" } else { scenario },
                "tags": [finding.get("owasp").and_then(|v| v.as_str()).unwrap_or("none")],
            }));
        }
        let owasp = finding.get("owasp").and_then(|v| v.as_str()).unwrap_or("");
        if !owasp.is_empty() && owasp != "none" {
            let tag = format!("owasp:{owasp}");
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        if let Some(atk) = finding.get("attack").and_then(|v| v.as_array()) {
            for tid in atk {
                if let Some(t) = tid.as_str() {
                    let tag = format!("attack:{t}");
                    if !tags.contains(&tag) {
                        tags.push(tag);
                    }
                }
            }
        }
    }
    scrub(json!({
        "type": "waf-console",
        "source": "crowdsec-lapi",
        "sourceRef": format!("waf-findings-{}", Utc::now().format("%Y%m%dT%H%M%SZ")),
        "title": "WAF console CrowdSec findings",
        "description": "Local export of CrowdSec LAPI/AppSec findings correlated with OWASP Top 10:2021. push=False.",
        "severity": 2,
        "status": "New",
        "follow": false,
        "tags": tags,
        "artifacts": artifacts,
        "push": false,
    }))
}

pub fn owasp_list() -> &'static [Value] {
    owasp_2021()
}
