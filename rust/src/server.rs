//! Axum HTTP server — API parity with Python app.py Handler.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, Method, Request, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::catalog;
use crate::control;
use crate::correlate;
use crate::dashboard;
use crate::lapi;
use crate::netguard::{self, RateLimiter};
use crate::routes;
use crate::status;

const HTML_CSP: &str = concat!(
    "default-src 'self'; ",
    "base-uri 'self'; ",
    "form-action 'self'; ",
    "frame-ancestors 'self'; ",
    "img-src 'self' data:; ",
    "style-src 'self' 'unsafe-inline'; ",
    "script-src 'self'; ",
    "connect-src 'self'; ",
    "object-src 'none'"
);

static HEAVY_GET: &[&str] = &[
    "/api/dashboard",
    "/api/coverage",
    "/api/correlation",
    "/api/correlation/stix",
    "/api/correlation/misp",
    "/api/correlation/thehive",
    "/api/overview",
];

#[derive(Clone)]
pub struct AppState {
    pub static_dir: PathBuf,
    pub post_limiter: Arc<RateLimiter>,
    pub heavy_limiter: Arc<RateLimiter>,
}

fn json_err(code: StatusCode, message: impl Into<String>) -> Response {
    (code, Json(json!({"ok": false, "error": message.into()}))).into_response()
}

fn json_ok(body: Value) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

fn download_json(body: Value, filename: &str) -> Response {
    let raw = serde_json::to_vec(&body).unwrap_or_default();
    let safe: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{safe}\""),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(raw))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn client_key(headers: &HeaderMap, addr: Option<SocketAddr>) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| addr.map(|a| a.ip().to_string()))
        .unwrap_or_else(|| "unknown".into())
}

fn mutation_guard(headers: &HeaderMap) -> Option<&'static str> {
    let host_hdr = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let host_only = host_hdr.split(':').next().unwrap_or(&host_hdr);
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if origin.is_empty() {
        return None;
    }
    let Ok(parsed) = url::Url::parse(origin) else {
        return Some("invalid origin");
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Some("invalid origin");
    }
    let origin_host = parsed.host_str().unwrap_or("").to_lowercase();
    if origin_host.is_empty() {
        return Some("invalid origin");
    }
    let allowed: HashSet<&str> = [host_only, "127.0.0.1", "localhost", "::1"]
        .into_iter()
        .collect();
    if !allowed.contains(origin_host.as_str()) {
        return Some("origin mismatch");
    }
    None
}

fn parse_query(query: Option<&str>) -> HashMap<String, String> {
    let mut qs = HashMap::new();
    let Some(raw) = query else {
        return qs;
    };
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        qs.insert(k.into_owned(), v.into_owned());
    }
    qs
}

const MAX_POST_BODY: usize = 2 * 1024 * 1024;

async fn post_json_payload(
    headers: &HeaderMap,
    body: Body,
) -> Result<Map<String, Value>, &'static str> {
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
    {
        return Ok(Map::new());
    }
    let bytes = axum::body::to_bytes(body, MAX_POST_BODY)
        .await
        .map_err(|_| "invalid body")?;
    if bytes.is_empty() {
        return Ok(Map::new());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid json")?;
    Ok(value.as_object().cloned().unwrap_or_default())
}

fn route_path(uri: &Uri) -> String {
    let path = uri.path();
    if path == "/waf" || path == "/waf/" {
        return "/".into();
    }
    if let Some(rest) = path.strip_prefix("/waf/") {
        return if rest.is_empty() {
            "/".into()
        } else {
            format!("/{rest}")
        };
    }
    path.to_string()
}

fn content_type_for(name: &str) -> &'static str {
    if name.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if name.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if name.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if name.ends_with(".svg") {
        "image/svg+xml"
    } else if name.ends_with(".png") {
        "image/png"
    } else if name.ends_with(".json") {
        "application/json; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn serve_static(static_dir: &Path, name: &str, cacheable: bool) -> Response {
    let target = match (static_dir.join(name)).canonicalize() {
        Ok(p) => p,
        Err(_) => return json_err(StatusCode::NOT_FOUND, "asset missing"),
    };
    let root = match static_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return json_err(StatusCode::NOT_FOUND, "asset missing"),
    };
    if !target.starts_with(&root) {
        return json_err(StatusCode::FORBIDDEN, "forbidden");
    }
    if !target.is_file() {
        return json_err(StatusCode::NOT_FOUND, "asset missing");
    }
    let Ok(bytes) = std::fs::read(&target) else {
        return json_err(StatusCode::NOT_FOUND, "asset missing");
    };
    let ctype = content_type_for(name);
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ctype)
        .header(
            header::CACHE_CONTROL,
            if cacheable {
                "public, max-age=120"
            } else {
                "no-store"
            },
        );
    if ctype.starts_with("text/html") {
        builder = builder.header(header::CONTENT_SECURITY_POLICY, HTML_CSP);
    }
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn security_middleware(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert_with(|| header::HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        header::HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        header::HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    headers.insert(
        header::HeaderName::from_static("x-robots-tag"),
        header::HeaderValue::from_static("noindex, nofollow"),
    );
    resp
}

async fn dispatch(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let qs = parse_query(uri.query());
    let (parts, body) = req.into_parts();
    let _ = parts;

    // /waf bare → redirect
    if method == Method::GET && uri.path() == "/waf" {
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/waf/")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let path = route_path(&uri);
    let key = client_key(&headers, Some(addr));

    if method == Method::GET && HEAVY_GET.contains(&path.as_str()) {
        if !state.heavy_limiter.allow(&key) {
            return json_err(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded (heavy-get)",
            );
        }
    }

    if method == Method::POST {
        if !state.post_limiter.allow(&key) {
            return json_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded (post)");
        }
        if let Some(msg) = mutation_guard(&headers) {
            return json_err(StatusCode::FORBIDDEN, msg);
        }
        let ctype = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if !ctype.is_empty() && ctype != "application/json" && ctype != "text/json" {
            return json_err(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported media type");
        }
    }

    let post_payload = if method == Method::POST {
        match post_json_payload(&headers, body).await {
            Ok(map) => Some(map),
            Err(msg) => return json_err(StatusCode::BAD_REQUEST, msg),
        }
    } else {
        None
    };

    let static_dir = state.static_dir.clone();

    // Offload blocking CrowdSec / TLS / fs work.
    let result = tokio::task::spawn_blocking(move || {
        handle_sync(method, path, qs, post_payload, static_dir)
    })
    .await;

    match result {
        Ok(resp) => resp,
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

fn handle_sync(
    method: Method,
    path: String,
    qs: HashMap<String, String>,
    post_payload: Option<Map<String, Value>>,
    static_dir: PathBuf,
) -> Response {
    if method == Method::GET {
        return handle_get(&path, &qs, &static_dir);
    }
    if method == Method::POST {
        let payload = post_payload.unwrap_or_default();
        return handle_post(&path, &payload);
    }
    json_err(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

fn handle_get(path: &str, qs: &HashMap<String, String>, static_dir: &Path) -> Response {
    match path {
        "/" | "/index.html" => return serve_static(static_dir, "index.html", false),
        p if p.starts_with("/static/") => {
            let name = p.rsplit('/').next().unwrap_or("");
            return serve_static(static_dir, name, true);
        }
        "/app.css" | "/app.js" | "/i18n.js" | "/world.js" | "/map.js" => {
            return serve_static(static_dir, path.trim_start_matches('/'), true);
        }
        "/logo.svg" | "/logo.png" => {
            return serve_static(static_dir, path.trim_start_matches('/'), true);
        }
        p if p.starts_with("/locales/") => {
            let name = p.rsplit('/').next().unwrap_or("");
            if name != "en.json" && name != "pt-BR.json" {
                return json_err(StatusCode::NOT_FOUND, "not found");
            }
            return serve_static(static_dir, &format!("locales/{name}"), true);
        }
        _ => {}
    }

    match path {
        "/api/health" => {
            let eng = lapi::engine_status();
            let mut out = eng.as_object().cloned().unwrap_or_default();
            out.insert("ok".into(), json!(true));
            json_ok(Value::Object(out))
        }
        "/api/overview" => json_ok(lapi::overview()),
        "/api/dashboard" => {
            let host = qs.get("host").cloned().unwrap_or_default();
            let mut filters = HashMap::new();
            for k in ["ip", "path", "country", "action", "method"] {
                filters.insert(k.to_string(), qs.get(k).cloned().unwrap_or_default());
            }
            match lapi::dashboard_payload(&host, filters) {
                Ok(v) => json_ok(v),
                Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
            }
        }
        "/api/decisions" => {
            let (data, err) = lapi::fetch_local_decisions();
            if err.is_some() && data.is_empty() {
                return json_err(StatusCode::BAD_GATEWAY, err.unwrap());
            }
            json_ok(json!({
                "ok": true,
                "total": data.len(),
                "community_omitted": true,
                "items": lapi::prefer_local_decisions(&data, 120),
            }))
        }
        "/api/alerts" => match lapi::fetch_alerts(lapi::alerts_fetch_limit(200)) {
            Ok(data) => {
                let mut items = Vec::new();
                for mut alert in data {
                    if let Some(obj) = alert.as_object_mut() {
                        let src = lapi::source_of(obj);
                        if let Some(cn) = src.get("cn").and_then(|v| v.as_str()) {
                            if !cn.is_empty() {
                                obj.insert("cn".into(), json!(cn));
                            }
                        }
                        dashboard::enrich_alert(obj);
                    }
                    items.push(alert);
                }
                json_ok(json!({"ok": true, "items": items}))
            }
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
        },
        "/api/domains" => {
            let hosts = catalog::in_scope_hosts();
            let origin = lapi::probe_hosts(&hosts, "127.0.0.1");
            let public = match lapi::public_ip() {
                Ok(ip) if !ip.is_empty() => lapi::probe_hosts(&hosts, &ip),
                _ => vec![],
            };
            json_ok(json!({"ok": true, "origin": origin, "public": public}))
        }
        "/api/engine" => {
            let rules = lapi::build_rules();
            let mut eng = lapi::engine_status()
                .as_object()
                .cloned()
                .unwrap_or_default();
            eng.insert("ok".into(), json!(true));
            eng.insert(
                "profiles".into(),
                rules
                    .pointer("/profiles/names")
                    .cloned()
                    .unwrap_or(json!([])),
            );
            eng.insert(
                "policy".into(),
                rules.get("policy").cloned().unwrap_or(json!({})),
            );
            eng.insert(
                "appsec".into(),
                rules.get("appsec").cloned().unwrap_or(json!({})),
            );
            json_ok(Value::Object(eng))
        }
        "/api/map" => match lapi::fetch_alerts(lapi::alerts_fetch_limit(200)) {
            Ok(alerts) => {
                let map = lapi::build_map(&alerts);
                let mut out = map.as_object().cloned().unwrap_or_default();
                out.insert("ok".into(), json!(true));
                json_ok(Value::Object(out))
            }
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
        },
        "/api/rules" => {
            let mut rules = lapi::build_rules().as_object().cloned().unwrap_or_default();
            rules.insert("ok".into(), json!(true));
            json_ok(Value::Object(rules))
        }
        "/api/allowlists" => {
            let mut al = lapi::build_allowlists()
                .as_object()
                .cloned()
                .unwrap_or_default();
            al.insert("ok".into(), json!(true));
            json_ok(Value::Object(al))
        }
        "/api/metrics" => json_ok(lapi::scrape_metrics()),
        "/api/coverage" => {
            let alerts = lapi::fetch_alerts(lapi::alerts_fetch_limit(200)).unwrap_or_default();
            let hub = control::hub_appsec_rules();
            let corr = correlate::correlate(&alerts, Some(&hub));
            let map = lapi::build_map(&alerts);
            let correlation = Value::Object(crate::ga::attach_correlation(
                corr.as_object(),
                map.as_object(),
            ));
            json_ok(json!({
                "ok": true,
                "map": map,
                "rules": lapi::build_rules(),
                "allowlists": lapi::build_allowlists(),
                "metrics": lapi::scrape_metrics(),
                "engine": lapi::engine_status(),
                "sites": control::sites_payload(),
                "filters": control::load_filters(),
                "correlation": correlation,
            }))
        }
        "/api/correlation" => match lapi::correlation_payload() {
            Ok(v) => json_ok(v),
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
        },
        "/api/correlation/stix" => match lapi::correlation_payload() {
            Ok(p) => download_json(correlate::stix_bundle(&p), "waf-findings.stix.json"),
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
        },
        "/api/correlation/misp" => match lapi::correlation_payload() {
            Ok(p) => download_json(correlate::misp_event(&p), "waf-findings.misp.json"),
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
        },
        "/api/correlation/thehive" => match lapi::correlation_payload() {
            Ok(p) => download_json(correlate::thehive_alert(&p), "waf-findings.thehive.json"),
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
        },
        "/api/sites" => json_ok(control::sites_payload()),
        "/api/filters" | "/api/policies" => {
            let mut f = control::load_filters()
                .as_object()
                .cloned()
                .unwrap_or_default();
            f.insert("ok".into(), json!(true));
            json_ok(Value::Object(f))
        }
        "/api/hub/appsec-rules" => {
            json_ok(json!({"ok": true, "items": control::hub_appsec_rules()}))
        }
        "/api/admin" => match routes::admin_payload() {
            Ok(v) => json_ok(v),
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
        },
        "/api/routes" | "/api/tunnels" => match routes::payload() {
            Ok(v) => json_ok(v),
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
        },
        _ => json_err(StatusCode::NOT_FOUND, "not found"),
    }
}

fn is_client_err(msg: &str) -> bool {
    [
        "invalid",
        "required",
        "not found",
        "forbidden",
        "out of",
        "must",
        "maximum",
        "already exists",
    ]
    .iter()
    .any(|t| msg.contains(t))
}

fn map_err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    if is_client_err(&msg) {
        json_err(StatusCode::BAD_REQUEST, msg)
    } else {
        json_err(StatusCode::BAD_GATEWAY, msg)
    }
}

fn handle_post(path: &str, payload: &Map<String, Value>) -> Response {
    match path {
        "/api/decisions/delete" => {
            let ip = payload
                .get("ip")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if ip.is_empty() {
                return json_err(StatusCode::BAD_REQUEST, "ip required");
            }
            if ip.parse::<std::net::IpAddr>().is_err() {
                return json_err(StatusCode::BAD_REQUEST, "invalid ip");
            }
            match lapi::lapi("DELETE", "/v1/decisions", &[("ip", ip.clone())], None) {
                Ok(result) => json_ok(json!({"ok": true, "ip": ip, "result": result})),
                Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
            }
        }
        "/api/allowlists/check" => {
            let ip = payload
                .get("ip")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if ip.parse::<std::net::IpAddr>().is_err() {
                return json_err(StatusCode::BAD_REQUEST, "invalid ip");
            }
            match lapi::check_allowlist_ip(ip) {
                Ok(v) => json_ok(v),
                Err(e) => map_err(e),
            }
        }
        "/api/filters" | "/api/policies" => {
            let result = if payload
                .get("id")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
            {
                control::update_filter(payload.clone())
                    .map(|item| json!({"ok": true, "item": item, "op": "update"}))
            } else {
                control::add_filter(payload.clone())
                    .map(|item| json!({"ok": true, "item": item, "op": "create"}))
            };
            match result {
                Ok(v) => json_ok(v),
                Err(e) => map_err(e),
            }
        }
        "/api/filters/update" | "/api/policies/update" => {
            match control::update_filter(payload.clone()) {
                Ok(item) => json_ok(json!({"ok": true, "item": item, "op": "update"})),
                Err(e) => map_err(e),
            }
        }
        "/api/filters/delete" | "/api/policies/delete" => {
            let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
            match control::delete_filter(id) {
                Ok(v) => json_ok(v),
                Err(e) => map_err(e),
            }
        }
        "/api/filters/toggle" => {
            let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let enabled = payload
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            match control::toggle_filter(id, enabled) {
                Ok(item) => json_ok(json!({"ok": true, "item": item})),
                Err(e) => map_err(e),
            }
        }
        "/api/allowlists/items" => {
            let cidr = payload
                .get("cidr")
                .or_else(|| payload.get("ip"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let reason = payload
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("cso-console");
            match control::allowlist_add(cidr, reason) {
                Ok(v) => json_ok(v),
                Err(e) => map_err(e),
            }
        }
        "/api/allowlists/items/delete" => {
            let cidr = payload
                .get("cidr")
                .or_else(|| payload.get("ip"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match control::allowlist_remove(cidr) {
                Ok(v) => json_ok(v),
                Err(e) => map_err(e),
            }
        }
        "/api/decisions" => match lapi::add_ban(payload) {
            Ok(v) => json_ok(v),
            Err(e) => map_err(e),
        },
        "/api/routes" | "/api/routes/update" => match routes::upsert_route(payload.clone()) {
            Ok(v) => json_ok(v),
            Err(e) => map_err(e),
        },
        "/api/routes/delete" => {
            let id = payload
                .get("id")
                .or_else(|| payload.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match routes::delete_route(id) {
                Ok(v) => json_ok(v),
                Err(e) => map_err(e),
            }
        }
        "/api/tunnels" | "/api/tunnels/update" => match routes::upsert_tunnel(payload.clone()) {
            Ok(v) => json_ok(v),
            Err(e) => map_err(e),
        },
        "/api/tunnels/delete" => {
            let id = payload
                .get("id")
                .or_else(|| payload.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match routes::delete_tunnel(id) {
                Ok(v) => json_ok(v),
                Err(e) => map_err(e),
            }
        }
        _ => json_err(StatusCode::NOT_FOUND, "not found"),
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .fallback(dispatch)
        .layer(middleware::from_fn(security_middleware))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::SERVER,
            header::HeaderValue::from_str(&status::app_name())
                .unwrap_or_else(|_| header::HeaderValue::from_static("waf-console")),
        ))
        .with_state(state)
}

pub async fn serve() -> anyhow::Result<()> {
    let bind = std::env::var("WAF_BIND").unwrap_or_else(|_| "127.0.0.1".into());
    if bind != "127.0.0.1" && bind != "::1" {
        anyhow::bail!("WAF_BIND must be loopback");
    }
    let port: u16 = std::env::var("WAF_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(18990);

    // Fail closed on misconfigured outbound URLs before accepting traffic.
    let _ = lapi::metrics_url()?;
    let _ = lapi::public_ip()?;

    let static_dir = std::env::var("WAF_STATIC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Prefer ../static relative to binary cwd, then ./static
            let candidates = [
                PathBuf::from("static"),
                PathBuf::from("../static"),
                PathBuf::from("/app/static"),
            ];
            candidates
                .into_iter()
                .find(|p| p.is_dir())
                .unwrap_or_else(|| PathBuf::from("static"))
        });

    let post_rate = netguard::env_int("WAF_POST_RATE", 60, 5, 600) as usize;
    let heavy_rate = netguard::env_int("WAF_HEAVY_GET_RATE", 40, 5, 600) as usize;

    let state = AppState {
        static_dir,
        post_limiter: Arc::new(RateLimiter::new(post_rate, 60.0)),
        heavy_limiter: Arc::new(RateLimiter::new(heavy_rate, 60.0)),
    };

    let app = router(state);
    let addr: SocketAddr = format!("{bind}:{port}").parse()?;
    tracing::info!("{} listening http://{bind}:{port}", status::app_name());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

// silence unused import warning for get/post if only fallback used
#[allow(dead_code)]
fn _routes_marker() {
    let _: (
        axum::routing::MethodRouter<()>,
        axum::routing::MethodRouter<()>,
    ) = (get(|| async {}), post(|| async {}));
}
