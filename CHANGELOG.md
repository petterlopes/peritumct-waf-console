# Changelog

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
