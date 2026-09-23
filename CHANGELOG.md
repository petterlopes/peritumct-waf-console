# Changelog

## 2.0.3 — 2026-09-22

- Toolchain: pin **rustc 1.98.1** (stable 2026-09-03 — vtable miscompilation fix); MSRV `1.98.1`; Docker `rust:1.98.1-bookworm`
- License: **GPL-3.0-or-later** (Linux-like copyleft; replaces MIT) — see `LICENSE` / `NOTICE`
- Production performance: Cargo `[profile.release]` LTO + `codegen-units=1` + `panic=abort` (LTO via Cargo profile only — not global `RUSTFLAGS`, which breaks dep builds with `embed-bitcode=no`); default `TOKIO_WORKER_THREADS=4` in image

## 2.0.2 — 2026-09-22

- Fix: LAPI machine login — normalize YAML CRLF/BOM, explicit JSON body, User-Agent, accept legacy `code` JWT field
- Fix: AppSec config listing ignores `#` comments (no false `crs-inband` from “do not enable” notes)
- Observability: `/api/health` includes `lapi_creds` lengths/url only (never secrets)

## 2.0.1 — 2026-09-22

- Fix: Docker builder pin `rust:1.88-bookworm` (lockfile needs rustc ≥1.88; 1.85 broke production builds)
- Tuning: probe workers 12, longer TTLs, POST/heavy rates 90/60, `RUST_LOG=warn`, `TOKIO_WORKER_THREADS=4`
- Hardening: non-root default image user, `.dockerignore`, sparse crates index, release strip
- Deploy: auto-update health wait extended for first Rust compile; prefer `runtime: rust` in health gate

## 2.0.0 — 2026-09-22

- **Runtime: Rust** (`rust/` crate `waf-console`) replaces the stdlib Python server as the primary binary
- API + static UI parity: same routes, loopback SSRF posture, rate limits, Origin guard, Domains palette, control/routes/correlate/dashboard
- Multi-stage Dockerfile (Rust builder → slim runtime); `WAF_APP_VERSION` default `2.0.0`
- Engine health reports `runtime: "rust"`
- Python sources moved to `legacy/python/` (rollback only)
- CI: `cargo test` smoke + container build/Trivy; legacy Python tests on workflow_dispatch

## 1.0.18 — 2026-09-22

- Design: shared `persist.py` (atomic writes + audit); catalog host sanitization via `netguard`
- Hardening: sliding-window rate limits (POST + heavy GET); bounded LAPI/Traefik/metrics reads; XSS escapes across Domains/Alerts/Decisions/Map/Policies UI
- Hardening: static asset Cache-Control separate from API `no-store`; request timeouts; Content-Type on mutating fetch
- Tuning: alert/engine status TTL caches (`WAF_ALERTS_CACHE_TTL`, `WAF_ENGINE_CACHE_TTL`); rate knobs `WAF_POST_RATE`, `WAF_HEAVY_GET_RATE`
- Branding: `WAF_APP_PRODUCT` / `WAF_APP_VERSION` env (default `waf-console/1.0.18`) for multi-site packs
- Docs: homologation matrix for **Docker**, **Podman**, **Cilium**, and **Kubernetes** (`docs/HOMOLOGATION.md`)

## 1.0.17 — 2026-09-22

- Design: shared `status.py` (version + HTTP healthy) and `netguard.py` (loopback URL / probe IP / TTL cache)
- Hardening: LAPI/metrics/Traefik URLs must be loopback; `PUBLIC_IP` must be a literal IP; Host/SNI sanitized
- Hardening: security headers (Referrer-Policy, Permissions-Policy, CSP on HTML); Origin check on POST; JSON-only mutations
- Tuning: parallel domain probes (`WAF_PROBE_WORKERS`) with TTL cache (`WAF_PROBE_CACHE_TTL`, `WAF_METRICS_CACHE_TTL`)
- Thread-safe LAPI token cache; Bandit coverage expanded to routes/dashboard/status/netguard

## 1.0.16 — 2026-09-22

- Domains health cards: HTTP status colors by class (2xx green, 3xx cyan, 4xx orange, 5xx/error red)
- Fix false “all red” when `PUBLIC_IP` is unset (no longer require public 200 for tile color)
- Origin/public tables and overview edge map use the same status palette
- Probe “healthy” counts treat 2xx and 3xx (redirect) as up

## 1.0.15 — 2026-09-18

- Scanner card layout: large single-scale bar chart, equal KPI tiles, plot and 24h strip share the same inset. Sources stay orange dots on the event axis (no dual Y). Still does not name the tool.

## 1.0.14 — 2026-09-18

- Interactive scanner graph: hourly axes, dual scale (events / unique sources), peak callout, hover/click quantities, last-hour / mean / active-hour stats. Still does not name the tool.

## 1.0.13 — 2026-09-18

- Dashboard real-time scanner graph (events + unique sources). Does not name the tool. Ordinary browser traffic is not counted.

## 1.0.12 — 2026-09-18

- One OWASP finding per source IP (in-band Hub name wins over CrowdSec OOB “lfi” on /.env)
- Dashboard secret-file and JA4H insights count unique sources; “Web app exploits” counts Block IPs only

## 1.0.11 — 2026-09-18

- OWASP/ATT&CK tiles count unique source IPs; repeated LAPI rows collapse with an event tally
- AppSec out-of-band anomaly scores map to T1595 (scanning), not T1190 (exploit), unless Hub labels say otherwise
- Unclassified CrowdSec names never become findings
- `vpatch-git-config` is A01 (exposed Git metadata), not A06

## 1.0.10 — 2026-09-18

- Administration menu with WAF shortcuts and the local Teleport forward to `http://127.0.0.1:18990/waf/`
- Console never writes Traefik `dynamic.yaml` or a sidecar (no directory provider)
- Local tunnel only: `tsh ssh -N -L 18990:127.0.0.1:18990 root@localhost` / `waf-admin.ps1 tunnel`
- OWASP/MITRE correlation drops CrowdSec engine chatter (body inspection, CAPI updates, OOB scores without a technique)
- CRS IDs must be six digits; T1046 is Discovery; scanners stay T1595; SQLi/XSS/SSRF stay T1190

## 1.0.9 — 2026-09-17

- Use the official PERITUM shield PNG (transparent background) in the rail, credits, footer, and favicon

## 1.0.8 — 2026-09-17

- PERITUM shield logo in the rail, favicon, credits page, and footer
- Credits, privacy, and terms stay pinned in the sidebar and a page footer (not buried in the nav scroll)

## 1.0.7 — 2026-09-17

- Credits, privacy policy and terms of use (EN default, pt-BR secondary)
- Author links: periciacomputacional.com/sobre, LinkedIn, Instagram @peritopetterlopes
- Deep links `#credits` `#privacy` `#terms`

## 1.0.5 — 2026-09-17

- Dedicated MITRE ATT&CK tab (local Enterprise catalog, tactic/technique tiles, no GitHub download)
- Map country selection is a console-wide filter (alerts, decisions, OWASP, MITRE)
- GA honesty: snapshot inactive unless `WAF_GA_SNAPSHOT_FILE` has aggregate sessions (`contributes` only then)

## 1.0.4 — 2026-09-17

- Optional GA4 aggregate snapshot (`WAF_GA_SNAPSHOT_FILE`) for WAF finding precision (LAPI/GA threat density)
- No Google Data API, no Measurement Protocol, no gtag on the console

## 1.0.3 — 2026-09-17

- OWASP Top 10:2021 correlation tab for CrowdSec LAPI/AppSec findings
- OpenCTI-inspired local connectors (MISP / TheHive / ATT&CK / OpenCTI STIX file export; no outbound push)

## 1.0.2 — 2026-09-17

- Robinson country map (Natural Earth 110m, public domain) with LAPI choropleth, hover, pan/zoom, and optional edge routes

## 1.0.1 — 2026-09-17

- Equirectangular world map: continent rings share the same projection as LAPI geo dots
- English remains the default UI locale; pt-BR is opt-in via the EN/PT switcher (no browser auto-switch)
- Cache-bust static assets at `?v=1.6`; serve `/waf/world.js`
- Map and allowlist notes follow the selected locale instead of overwriting it with API copy

## 1.0.0 — 2026-09-17

- First public MIT release of the PeritumCT CrowdSec WAF console
- English UI default, pt-BR secondary
- Policy CRUD, local decisions, LAPI geo map, loopback bind
- Integration docs for new environments
- SAST (Ruff, Bandit) and SCA (pip-audit, Trivy) in GitHub Actions
