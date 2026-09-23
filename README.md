# PeritumCT WAF Console

Open-source operator console for a local [CrowdSec](https://github.com/crowdsecurity/crowdsec) engine
(LAPI + AppSec). It is **not** the CrowdSec cloud dashboard.

**Default language: English.** Brazilian Portuguese (`pt-BR`) is the secondary UI locale.

- License (this console): [GPL-3.0-or-later](LICENSE) · Copyright (c) 2026 PeritumCT — Linux-like copyleft (not MIT); see [NOTICE](NOTICE)
- CrowdSec engine: [MIT](https://github.com/crowdsecurity/crowdsec?tab=MIT-1-ov-file) — separate process; see [NOTICE](NOTICE)
- Pin tested with CrowdSec **v1.8.1**: https://github.com/crowdsecurity/crowdsec/releases#release-v1.8.1
- **Current console:** 2.0.3 (Rust **1.98.1**) · legacy Python under `legacy/python/`

Portuguese README: [README.pt-BR.md](README.pt-BR.md) · Docs index: [docs/README.md](docs/README.md)

## Homologated platforms

Validated in production-like environments with:

| Platform | Status |
|----------|--------|
| **Docker Compose** | Homologated |
| **Podman Compose** | Homologated |
| **Kubernetes** (Traefik CRDs) | Homologated |
| **Cilium** (CNI / LB to Traefik) | Homologated |

Full matrix, topologies, and acceptance checklist:
**[docs/HOMOLOGATION.md](docs/HOMOLOGATION.md)** · [docs/HOMOLOGATION.pt-BR.md](docs/HOMOLOGATION.pt-BR.md)

## Runtime (Rust)

Primary binary: `rust/` → container `CMD ["/app/waf-console"]`.

```bash
cd rust && cargo test --test unit_smoke --test parity_smoke
docker compose -f docker-compose.example.yml build
```

Python 1.x lives in `legacy/python/` for emergency rollback only.

- Dark operator UI (dashboard, overview, map, decisions, alerts, OWASP / ATT&CK correlation, hub rules, metrics, Domains)
- **Policy CRUD** per FQDN: allow a path, skip a named in-band rule, or bypass AppSec for a host
- Local LAPI ban / unban (max 168h) and allowlist CIDR add/remove via `cscli`
- Loopback-only bind (`127.0.0.1`) so LAPI/AppSec stay off the public network
- HTTP status palette on Domains (2xx green, 3xx cyan, 4xx orange, 5xx red)
- Hardening: SSRF loopback checks, rate limits, atomic policy writes, CSP / security headers

## What it never does

- Enable CRS in-band, `INCLUDE_LARGE_UPLOADS` / `DisableBodyInspection`, or fail-closed changes
- Enable CrowdSec 1.8 bot detection / challenge
- Put this UI behind the CrowdSec bouncer (lockout risk)
- Call a third-party GeoIP API (map uses LAPI coordinates; land polygons are public-domain Natural Earth 110m)

## Quick start (Docker)

```bash
cp examples/sites.json /var/lib/waf-control/sites.json   # edit FQDNs
cp docker-compose.example.yml docker-compose.yml         # edit volumes
docker compose up -d --build
curl -sS http://127.0.0.1:18990/api/health
# UI: http://127.0.0.1:18990/waf/   (EN default; PT toggle in the header)
```

### Podman

```bash
podman compose -f docker-compose.yml up -d --build
# or: podman-compose -f docker-compose.yml up -d --build
curl -sf http://127.0.0.1:18990/api/health
```

### Kubernetes + Cilium

Run the console on the **node** (loopback) and expose `/waf` through Traefik **without**
the CrowdSec bouncer. Point AppSec/LAPI middlewares at the node InternalIP.
See [docs/HOMOLOGATION.md](docs/HOMOLOGATION.md) § Kubernetes + Cilium and
[docs/INTEGRATION.md](docs/INTEGRATION.md) § reverse proxy.

## Documentation

| Doc | Topic |
|-----|--------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules and boundaries |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | Traefik, acquis, env, verify |
| [docs/HOMOLOGATION.md](docs/HOMOLOGATION.md) | Docker / Podman / Cilium / K8s |
| [docs/SECURITY.md](docs/SECURITY.md) | SAST / SCA |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## Security scans

CI runs SAST (Ruff + Bandit) and SCA (pip-audit + Trivy filesystem). See
[docs/SECURITY.md](docs/SECURITY.md) and `.github/workflows/security.yml`.

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -q
ruff check .
bandit -q -r app.py control.py catalog.py routes.py dashboard.py status.py netguard.py persist.py
pip-audit -r requirements-dev.txt
```

## Privacy

The console stores operator audit events locally (`WAF_CONTROL/audit.jsonl`).
It does not send telemetry. IP addresses in CrowdSec alerts are security events.

- Credits: [docs/CREDITS.md](docs/CREDITS.md)
- Privacy: [docs/PRIVACY.md](docs/PRIVACY.md)
- Terms of use: [docs/TERMS.md](docs/TERMS.md)

UI tabs: Credits · Privacy · Terms (`#credits`, `#privacy`, `#terms`).
