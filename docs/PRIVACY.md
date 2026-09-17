# Privacy (DPO)

This console is an **operator tool**. It is not a public website and must stay on
loopback + admin VPN.

## Data processed

| Data | Where | Purpose | Lawful basis (GDPR/LGPD) |
|------|--------|---------|---------------------------|
| Client IPs in CrowdSec alerts/decisions | CrowdSec LAPI (read) | Security monitoring | Legitimate interest / legal obligation (network security) |
| Operator CIDRs on allowlists | CrowdSec allowlists | Prevent lockout | Legitimate interest |
| Policy documents (host, path, rule name, reason) | `WAF_CONTROL/site-filters.json` + AppSec YAML | WAF exceptions | Legitimate interest |
| Audit JSONL (who did what) | `WAF_CONTROL/audit.jsonl` | Accountability | Legitimate interest |

No advertising IDs, no third-party analytics, no third-party GeoIP service.

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
