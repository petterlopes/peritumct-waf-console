# Privacy (DPO)

Effective 17 September 2026. UI: Privacy tab · `#privacy` · Portuguese:
[PRIVACY.pt-BR.md](PRIVACY.pt-BR.md)

This console is an **operator tool**. It is not a public website and must stay on
loopback + admin VPN. It is **not** the privacy notice of
[periciacomputacional.com](https://periciacomputacional.com/sobre/) or other origin sites.

**Controller:** Petter Anderson Lopes, operating as PERITUM / Perícia Computacional.

- About: https://periciacomputacional.com/sobre/
- LinkedIn: https://www.linkedin.com/in/petter-anderson-lopes/
- Instagram: [@peritopetterlopes](https://www.instagram.com/peritopetterlopes/)

## Data processed

| Data | Where | Purpose | Lawful basis (GDPR/LGPD) |
|------|--------|---------|---------------------------|
| Client IPs in CrowdSec alerts/decisions | CrowdSec LAPI (read) | Security monitoring | Legitimate interest / legal obligation (network security) |
| Operator CIDRs on allowlists | CrowdSec allowlists | Prevent lockout | Legitimate interest |
| Policy documents (host, path, rule name, reason) | `WAF_CONTROL/site-filters.json` + AppSec YAML | WAF exceptions | Legitimate interest |
| Audit JSONL (who did what) | `WAF_CONTROL/audit.jsonl` | Accountability | Legitimate interest |

No advertising IDs, no third-party analytics **in this console**, no third-party GeoIP service.

An optional `WAF_GA_SNAPSHOT_FILE` is an operator-exported **aggregate** of public-site
GA4 sessions by hostname and country (no `client_id`, no user IDs). Analytics **does
not contribute** until that file is a valid aggregate export with at least one host
or country session count greater than zero. Dest production default is inactive
(`WAF_GA_SNAPSHOT_FILE` commented). The console never loads gtag on `/waf`, never
calls the Google Data API, and never sends CrowdSec IPs to Google.

## Retention

CrowdSec decisions follow engine TTL (console cap 168h for manual bans).
Rotate `audit.jsonl` with your host log policy (example: 90 days).

## Data subject requests

This UI is not a consumer app. End-user IPs appear only as security telemetry
inside CrowdSec. Handle access/erasure through your CrowdSec/LAPI retention
process, not through this console.

## Internationalization

UI default is English; `pt-BR` is optional and stored in `localStorage` (`waf-locale`)
in the operator browser only.
