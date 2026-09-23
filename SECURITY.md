# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.x (Rust) | yes |
| 1.0.x (legacy Python) | security fixes only / rollback |

## Reporting a vulnerability

Email security reports to the PeritumCT security contact listed on the GitHub
repository Security tab. Do not open a public issue for exploitable flaws.

Please include:

- affected commit / tag
- reproduction against **your** CrowdSec/LAPI (no third-party targets)
- impact (auth bypass, RCE, SSRF, data exposure)

We aim to acknowledge within 5 business days.

## Hardening defaults

- `WAF_BIND` must be loopback (`127.0.0.1` or `::1`); the process exits otherwise
- LAPI, metrics, and Traefik API URLs must target loopback; `PUBLIC_IP` must be a literal IP
- Prefer env `CROWDSEC_LAPI=http://127.0.0.1:18080` when the credentials file still says `:8080` (Traefik dashboard collision)
- HTML responses send CSP + `Referrer-Policy` / `Permissions-Policy`; POST requires matching Origin when present
- POST and heavy GET endpoints are rate-limited per client IP
- Put the UI on an admin-only reverse-proxy path **without** the CrowdSec bouncer
- Do not publish `:18080`, `:7422`, `:6060`, or `:18990` on the public Internet
- CrowdSec 1.8 bot detection / challenge stays off
- CRS in-band and `DisableBodyInspection` stay off
- Machine JWT login uses HTTP/1.0 loopback to LAPI (parity with urllib); bouncer key remains separate
