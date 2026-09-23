# Product positioning

**PeritumCT WAF Console** is an open source, self-hosted operations interface for **local** [CrowdSec](https://github.com/crowdsecurity/crowdsec) installations.

**One-liner:** Console open source self-hosted for CrowdSec, with a Rust backend, local LAPI/AppSec operations, and OWASP / MITRE ATT&CK context for alerts.

## Executive summary

The console brings security data and actions closer to the operator: reviewing alerts, managing blocking decisions, creating per-domain AppSec exceptions, checking services, and interpreting events with a **local** MITRE ATT&CK catalog and OWASP Top 10:2021 mappings.

Distributed under **GPL-3.0-or-later**, it is designed for restricted administrative access: loopback listener, local LAPI, and remote access through the organization’s network and identity controls. Core functions do **not** depend on the CrowdSec Console SaaS. CrowdSec remains responsible for detection and, with remediation components, traffic protection.

**Distinguishing combination:** local operation · Rust backend · per-FQDN AppSec controls · contextualized alerts.

## What it is / is not

| Is | Is not |
|----|--------|
| Operator UI next to your engine | CrowdSec cloud console replacement for fleet SaaS |
| Management + observability path | Path that receives every business HTTP request |
| Heuristic OWASP / ATT&CK context | Compliance certification or full ATT&CK matrix |
| CTI **file** exports (operator download) | Automatic push to MISP / TheHive / OpenCTI |
| Declares CSO fail-closed policy metadata | End-to-end verifier of Traefik/bouncer fail-closed |

## Architecture (two paths)

1. **Application traffic:** client → reverse proxy + remediation → CrowdSec/AppSec → application.
2. **Administrative operations:** operator browser → restricted admin access → console → LAPI / metrics / local config.

If the console UI is unavailable, that alone does **not** redefine the protection policy configured in the proxy and engine.

## Honest limits (operators)

- Applying policies needs writable AppSec volumes, `pid: host`, and privilege to SIGHUP CrowdSec (see Compose admin example).
- Allowlists need host `cscli` (`CROWDSEC_CSCLI`) or Nomad alloc exec (`NOMAD_BIN`).
- Dashboard **24h** uses LAPI `since=24h` plus a client window filter; when `WAF_ALERTS_LIMIT` caps the sample, `sample.capped` / `window_label` disclose incomplete coverage (2.0.4+).
- `fail_closed` in the console is **CSO-enforced metadata** (always ON, not mutable). Validate real fail-closed on the remediation component.
- No built-in operator login / MFA / RBAC — protect `/waf` with overlay VPN, Teleport, or IdP-aware admin middleware; keep `/waf` **off** the CrowdSec bouncer.
- **2.0.5 complements** (inspired by [CrowdSec Manager](https://github.com/hhftechnology/crowdsec_manager), CSO-filtered): IP dossier, read-only bouncers, repeated-offender sample — see [COMPARISON.md](COMPARISON.md).
- **2.0.6:** Alerts filters/inspect/CSV and Decisions hide-expired/CSV — still no docker.sock, container shell, Traefik writes, or captcha.
- **2.0.7:** Hub inventory read-only + IP management (check blocked / public IP).
- **2.0.8:** Control-plane export (secrets redacted), audit.jsonl tail RO, alerts `since=` allowlist, CrowdSec-only config integrity hashes.
- **2.0.9:** Alert inspect ban/unban/dossier, decisions filters/stats, machines RO, since-aligned offenders/map, allowlists CSV.

## Editorial article

Full English narrative (baseline documented in the article; repo may be newer):

- https://periciacomputacional.com/peritumct-waf-console-local-control-of-crowdsec-powered-by-a-rust-backend

Author: Petter Anderson Lopes · PeritumCT.

## Positioning language (do / don’t)

**Do:** open source · self-hosted · Rust backend · local LAPI/AppSec · per-FQDN policies · OWASP/MITRE context.

**Don’t:** “first CrowdSec self-hosted console”, “first in the world in Rust”, or exclusivity claims — adjacent community UIs and WAF proxies exist; differentiate by the **proven combination** above.
