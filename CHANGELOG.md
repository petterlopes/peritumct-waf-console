# Changelog

## 1.0.1 — 2026-09-17

- Equirectangular world map: continent rings share the same projection as LAPI geo dots
- English remains the default UI locale; pt-BR is opt-in via the EN/PT switcher (no browser auto-switch)
- Cache-bust static assets at `?v=1.5`; serve `/waf/world.js`

## 1.0.0 — 2026-09-17

- First public MIT release of the PeritumCT CrowdSec WAF console
- English UI default, pt-BR secondary
- Policy CRUD, local decisions, LAPI geo map, loopback bind
- Integration docs for new environments
- SAST (Ruff, Bandit) and SCA (pip-audit, Trivy) in GitHub Actions
