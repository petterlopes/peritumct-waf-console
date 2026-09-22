# Security scanning (SAST / SCA)

## SAST (static application security testing)

| Tool | Scope |
|------|--------|
| Ruff | Python lint + common bug patterns (`app.py`, `control.py`, `catalog.py`) |
| Bandit | Python security rules (`app.py`, `control.py`, `catalog.py`, `routes.py`, `dashboard.py`, `status.py`, `netguard.py`, `persist.py`) |
| unittest | Validators, catalog load, forbidden tokens |

Runtime has **no PyPI dependencies**. SAST therefore focuses on first-party code.

## SCA (software composition analysis)

| Tool | Scope |
|------|--------|
| pip-audit | `requirements-dev.txt` (CI/dev tools only) |
| Trivy fs | Repository filesystem + Docker base image in CI |
| Secret scan | High-confidence credential patterns on the working tree |

The CrowdSec engine image (`crowdsecurity/crowdsec`) is operated **beside** this console, not vendored. Track its CVE stream separately when you pin `v1.8.1`.

## GitHub Actions

`.github/workflows/security.yml` runs on push/PR:

1. `python -m unittest`
2. `ruff check .`
3. `bandit -r app.py control.py catalog.py routes.py dashboard.py status.py netguard.py persist.py`
4. `pip-audit -r requirements-dev.txt`
5. Trivy filesystem
6. `scripts/verify-no-committed-secrets.sh`

Dependabot updates GitHub Actions weekly (`.github/dependabot.yml`).

## Operator threats this console does **not** accept

- SSRF via `PUBLIC_IP` / Traefik API / metrics / LAPI: must be loopback URLs or literal IP (validated at startup/use)
- Binding off loopback
- Enabling CRS in-band or bot challenge from the UI
- Putting `/waf` behind the bouncer
