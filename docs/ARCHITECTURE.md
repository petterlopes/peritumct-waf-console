# Architecture

Operator-facing HTTP console for a **local** CrowdSec Security Engine (LAPI + AppSec).
**Primary runtime: Rust** (`rust/` → binary `waf-console`). English UI default; `pt-BR` secondary.
Python 1.x sources remain under `legacy/python/` for rollback only.

## System context

```
Operator browser (EN / pt-BR)
        │  PathPrefix /waf  (admin overlay — NO CrowdSec bouncer)
        ▼
waf-console 127.0.0.1:18990   Axum (Tokio) — Rust 2.x
        │
        ├─ LAPI 127.0.0.1:18080     machine JWT + bouncer X-Api-Key
        ├─ AppSec 127.0.0.1:7422    policy YAML + SIGHUP to CrowdSec PIDs
        ├─ optional metrics :6060   Prometheus text (loopback URL only)
        └─ optional Traefik API     loopback routers map (read-only)
```

Homologated beside **Docker**, **Podman**, **Kubernetes**, and **Cilium** edges —
see [HOMOLOGATION.md](HOMOLOGATION.md).

## Process model

| Concern | Implementation (Rust) | Legacy Python |
|---------|----------------------|---------------|
| HTTP API + static UI | `rust/src/server.rs` + `lapi.rs` | `legacy/python/app.py` |
| Version / HTTP healthy (2xx/3xx) | `status.rs` | `status.py` |
| SSRF / TTL / rate limit | `netguard.rs` | `netguard.py` |
| Atomic writes + audit JSONL | `persist.rs` | `persist.py` |
| Policy CRUD, allowlists, SIGHUP | `control.rs` | `control.py` |
| Site catalog | `catalog.rs` | `catalog.py` |
| Dashboard aggregates | `dashboard.rs` | `dashboard.py` |
| OWASP / ATT&CK correlation | `correlate.rs` | `correlate.py` |
| Optional GA snapshot | `ga.rs` | `ga.py` |
| Traefik route/tunnel store | `routes.rs` | `routes.py` |
| Locales | `static/locales/*.json` | same |

## Security boundaries

Unchanged from 1.x: loopback bind; loopback-only LAPI/metrics/Traefik URLs; literal
`PUBLIC_IP`; no CRS in-band / bot challenge; `/waf` off bouncer chain; CTI exports
`push: false` with secret scrubbing; Traefik fragment preview only (`applied: false`).
