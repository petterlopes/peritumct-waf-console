//! Network hardening helpers (port of netguard.py).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::Value;

static HOST_RE: OnceLock<Regex> = OnceLock::new();

fn host_re() -> &'static Regex {
    HOST_RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$").expect("HOST_RE")
    })
}

pub fn sanitize_hostname(host: &str) -> Result<String> {
    let value = host.trim().to_lowercase();
    if value.is_empty() || value.len() > 253 {
        return Err(anyhow!("invalid host"));
    }
    if value.contains(['\r', '\n', '\0', '/', '\\', ' ', ':', '@']) {
        return Err(anyhow!("invalid host"));
    }
    if !host_re().is_match(&value) {
        return Err(anyhow!("invalid host"));
    }
    Ok(value)
}

pub fn assert_probe_server(value: &str, name: &str) -> Result<String> {
    let raw = value.trim();
    if raw.is_empty() {
        return Ok(String::new());
    }
    raw.parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|e| anyhow!("{name} must be a literal IP address: {e}"))
}

pub fn assert_loopback_http_url(url: &str, name: &str) -> Result<String> {
    let raw = url.trim();
    if raw.is_empty() {
        return Err(anyhow!("{name} is empty"));
    }
    let parsed =
        url::Url::parse(raw).map_err(|_| anyhow!("{name} scheme must be http or https"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(anyhow!("{name} scheme must be http or https"));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(anyhow!("{name} must not embed credentials"));
    }
    let host = parsed.host_str().unwrap_or("").to_lowercase();
    if host.is_empty() {
        return Err(anyhow!("{name} missing host"));
    }
    if matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
        return Ok(raw.trim_end_matches('/').to_string());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            return Ok(raw.trim_end_matches('/').to_string());
        }
    }
    Err(anyhow!("{name} must target loopback (got {host})"))
}

pub fn env_int(name: &str, default: i64, minimum: i64, maximum: i64) -> i64 {
    let raw = std::env::var(name).unwrap_or_default();
    if raw.trim().is_empty() {
        return default;
    }
    match raw.parse::<i64>() {
        Ok(v) => v.clamp(minimum, maximum),
        Err(_) => default,
    }
}

pub struct TtlCache {
    inner: Mutex<HashMap<String, (Value, Instant)>>,
}

impl TtlCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, key: &str) -> Option<Value> {
        let now = Instant::now();
        let mut guard = self.inner.lock().ok()?;
        if let Some((value, exp)) = guard.get(key) {
            if now < *exp {
                return Some(value.clone());
            }
            guard.remove(key);
        }
        None
    }

    pub fn set(&self, key: &str, value: Value, ttl: f64) {
        if ttl <= 0.0 {
            return;
        }
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(
                key.to_string(),
                (value, Instant::now() + Duration::from_secs_f64(ttl)),
            );
        }
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.clear();
        }
    }
}

impl Default for TtlCache {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RateLimiter {
    limit: usize,
    window: Duration,
    hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new(limit: usize, window_sec: f64) -> Self {
        Self {
            limit: limit.max(1),
            window: Duration::from_secs_f64(window_sec.max(0.5)),
            hits: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;
        let Ok(mut guard) = self.hits.lock() else {
            return true;
        };
        let bucket = guard.entry(key.to_string()).or_default();
        bucket.retain(|t| *t > cutoff);
        if bucket.len() >= self.limit {
            return false;
        }
        bucket.push(now);
        if guard.len() > 4096 {
            let stale: Vec<String> = guard
                .iter()
                .filter(|(_, v)| v.is_empty() || v.last().is_some_and(|t| *t < cutoff))
                .map(|(k, _)| k.clone())
                .take(512)
                .collect();
            for k in stale {
                guard.remove(&k);
            }
        }
        true
    }
}
