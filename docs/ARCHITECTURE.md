# Architecture

Operator-facing HTTP console for a **local** CrowdSec Security Engine (LAPI + AppSec).
Stdlib Python only at runtime. English UI default; `pt-BR` secondary.

## System context

```
Operator browser (EN / pt-BR)
        │  PathPrefix /waf  (admin overlay — NO CrowdSec bouncer)
        ▼
waf-console 127.0.0.1:18990   ThreadingHTTPServer (stdlib)
        │
        ├─ LAPI 127.0.0.1:18080     machine JWT + bouncer X-Api-Key
        ├─ AppSec 127.0.0.1:7422    policy YAML + SIGHUP to CrowdSec PIDs
        ├─ optional metrics :6060   Prometheus text (loopback URL only)
        └─ optional Traefik API     loopback routers map (read-only)
```

Homologated beside **Docker**, **Podman**, **Kubernetes**, and **Cilium** edges —
see [HOMOLOGATION.md](HOMOLOGATION.md).

## Process model

| Concern | Implementation |
|---------|----------------|
| HTTP API + static UI | `app.py` (`Handler`) |
| Version / HTTP healthy (2xx/3xx) | `status.py` |
| SSRF / TTL / rate limit / bounded reads | `netguard.py` |
| Atomic writes + audit JSONL | `persist.py` |
| Policy CRUD, allowlists, SIGHUP | `control.py` |
| Site catalog (no prod hosts in Git) | `catalog.py` |
| Dashboard aggregates | `dashboard.py` |
| OWASP / ATT&CK correlation | `correlate.py` |
| Optional GA snapshot attach | `ga.py` |
| Traefik route/tunnel operator store | `routes.py` (never empty sidecar maps) |
| Locales | `static/locales/en.json`, `pt-BR.json` |

## Security boundaries

1. **Bind:** `WAF_BIND` must be `127.0.0.1` or `::1` or the process exits.
2. **Outbound URLs:** LAPI, metrics, Traefik API must target loopback (`netguard.assert_loopback_http_url`).
3. **PUBLIC_IP probes:** literal IP only (no DNS) when set.
4. **Mutations:** JSON body, size cap, Origin check when present, sliding-window rate limits.
5. **CSO forbid list:** CRS in-band, `INCLUDE_LARGE_UPLOADS`, fail-closed flips, bot challenge — rejected in `control.py`.
6. **Anti-lockout:** reverse-proxy `/waf` must not attach the CrowdSec bouncer.

## Data flow

```
CrowdSec engine
   │ alerts / decisions / allowlists
   ▼
LAPI (loopback) ──► console API ──► browser (EN/pt-BR)
   ▲
AppSec configs ◄── control.apply_filters (YAML + SIGHUP)
```

Domains health: parallel TLS probes to catalog hosts via `127.0.0.1:443` (SNI=Host),
cached briefly; UI colours by HTTP class (`http-2xx` green, etc.).

## Deployment shapes

| Shape | Console | CrowdSec | Edge |
|-------|---------|----------|------|
| Compose lab | Docker / Podman host network | Same host loopback | Optional local Traefik |
| Rocky / bare metal | Podman compose + systemd timer | Podman host network | Traefik on host or K8s |
| K8s + Cilium | Host loopback + socat/Endpoints | Host engine | Traefik Deployment + Cilium LB |

## Versioning

Health and `Server` header use `WAF_APP_PRODUCT` / `WAF_APP_VERSION`
(default `waf-console/1.0.18`). Site packs may brand as `waf-admin` without forking logic.
