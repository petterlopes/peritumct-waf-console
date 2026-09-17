# PeritumCT WAF Console

Open-source operator console for a local [CrowdSec](https://github.com/crowdsecurity/crowdsec) engine
(LAPI + AppSec). It is **not** the CrowdSec cloud dashboard.

**Default language: English.** Brazilian Portuguese (`pt-BR`) is the secondary UI locale.

- License (this console): [MIT](LICENSE) · Copyright (c) 2026 PeritumCT
- CrowdSec engine: [MIT](https://github.com/crowdsecurity/crowdsec?tab=MIT-1-ov-file) — see [NOTICE](NOTICE)
- Pin tested with CrowdSec **v1.8.1**: https://github.com/crowdsecurity/crowdsec/releases#release-v1.8.1

Portuguese README: [README.pt-BR.md](README.pt-BR.md)

## What it does

- Dark operator UI (overview, map, decisions, alerts, hub rules, metrics)
- **Policy CRUD** per FQDN: allow a path, skip a named in-band rule, or bypass AppSec for a host
- Local LAPI ban / unban (max 168h) and allowlist CIDR add/remove via `cscli`
- Loopback-only bind (`127.0.0.1`) so LAPI/AppSec stay off the public network

## What it never does

- Enable CRS in-band, `INCLUDE_LARGE_UPLOADS` / `DisableBodyInspection`, or fail-closed changes
- Enable CrowdSec 1.8 bot detection / challenge
- Put this UI behind the CrowdSec bouncer (lockout risk)
- Call a third-party GeoIP API (map uses LAPI `source.latitude` / `longitude` only)

## Quick start

```bash
cp examples/sites.json /var/lib/waf-control/sites.json   # edit FQDNs
cp docker-compose.example.yml docker-compose.yml         # edit volumes
docker compose up -d --build
curl -sS http://127.0.0.1:18990/api/health
# UI: http://127.0.0.1:18990/waf/   (EN default; PT toggle in the header)
```

Full integration (Traefik, reverse-proxy anti-lockout, systemd, verification):
[docs/INTEGRATION.md](docs/INTEGRATION.md) · [docs/INTEGRATION.pt-BR.md](docs/INTEGRATION.pt-BR.md)

## Security scans

CI runs SAST (Ruff + Bandit) and SCA (pip-audit + Trivy filesystem). See
[docs/SECURITY.md](docs/SECURITY.md) and `.github/workflows/security.yml`.

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
ruff check .
bandit -q -r app.py control.py catalog.py
pip-audit -r requirements-dev.txt
```

## Privacy

The console stores operator audit events locally (`WAF_CONTROL/audit.jsonl`).
It does not send telemetry. IP addresses in CrowdSec alerts are security events.
Details: [docs/PRIVACY.md](docs/PRIVACY.md).
