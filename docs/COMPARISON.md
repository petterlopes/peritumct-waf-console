# CrowdSec Manager vs PeritumCT WAF Console

CSO review of [hhftechnology/crowdsec_manager](https://github.com/hhftechnology/crowdsec_manager) (Go + React, MIT) as a **feature complement** source — not a stack merge.

**Console pin:** PeritumCT **2.0.6** · CrowdSec engine **v1.8.1** · loopback LAPI/AppSec · `/waf` off bouncer · GPL-3.0-or-later.

## Scope of this review

| Pass | Focus |
|------|--------|
| R1 | Map Manager capabilities (dashboard, decisions, hub, Traefik/Pangolin, docker, mobile) |
| R2 | Classify **integrate / adapt / reject** under PeritumCT CSO constraints |
| R3 | Document honest gaps and deferred work |
| R4 | Ship safe P0 complements (2.0.5) |
| R5 | Align README / PRODUCT / overlays |
| R6 | Screenshot-grounded Alerts/Decisions analytics UX (2.0.6) |

## Posture difference (non-negotiable)

| Topic | CrowdSec Manager | PeritumCT WAF Console |
|-------|------------------|------------------------|
| Privilege model | Often mounts **docker.sock**, Traefik dynamic paths, compose control | **No** docker.sock; **never** writes Traefik `dynamic.yaml` |
| Network | Independent image can publish `:8080` | **`WAF_BIND` loopback only** (process exits otherwise) |
| Remediation UI | Captcha / challenge flows in product surface | CrowdSec **bot-challenge / CRS in-band forbidden** |
| Shell | Container terminal in UI | **Rejected** (no interactive shell into engine/stack) |
| Geo | Optional MaxMind GeoLite MMDB | Map uses **LAPI geo only** (no third-party GeoIP API) |
| License / runtime | MIT · Go/React | **GPL-3.0-or-later** · Rust Axum + static UI |
| Role | Full stack manager (Pangolin/Traefik/multi-proxy) | Operator console **beside** an existing CrowdSec + Traefik |

Manager is excellent for homelab/Pangolin fleets that accept host Docker control. PeritumCT targets **restricted admin** overlays (NetBird / Teleport / IdP) next to production CrowdSec.

## Screenshot evidence (Manager UI)

Operator screenshots of Manager v1.x informed the 2.0.6 adapt/reject list:

| Manager screen | Observed | CSO decision |
|----------------|----------|--------------|
| Alerts filters | ID, since/until, IP, CIDR, scope, type, scenario, origin, country, **Include CAPI** | **Adapt** filters on local LAPI sample; **reject** CAPI-include default |
| Alert inspect modal | Scenario, geo, ASN, narrative, decisions, events | **Adapt** inspect dialog (sample JSON + summary); no GeoLite dependency |
| Alerts charts / table | Top scenarios, frequency, AS column, Export CSV, Cards/Table, **delete** alert | **Adapt** top scenarios/countries + CSV + AS; **reject** alert delete + card dual-view for now |
| Decisions analysis | Charts, since/until, type filter, **captcha** type dominant | **Adapt** hide-expired + CSV; **reject** creating captcha decisions |
| Allowlists vs Whitelists | LAPI allowlists + Traefik whitelist shortcut | Keep LAPI allowlists; **reject** Traefik whitelist path |
| Bouncers | Add / delete / status | Keep **read-only** list (2.0.5); **reject** add/delete |
| Health | LAPI, metrics, bouncers, **Console SaaS enroll**, **container via Docker** | Keep LAPI/metrics/bouncers RO; **reject** SaaS enroll + docker health |
| Captcha wizard | Turnstile + Traefik `dynamic_config` + captcha.html | **Reject** entirely |
| Config Validation | Snapshots of `/etc/traefik/*` + CrowdSec YAML + restore | **Reject** Traefik FIM/restore from UI |
| Settings | Traefik dynamic config path for whitelist writes | **Reject** |
| Backups / Terminal / Cron / Updates | Host/stack control plane | **Reject** in-console |
| Dashboard | Top countries/AS/scenarios, blocked IPs, container status | Partial overlap with our dashboard/map; **reject** container status |

## Feature matrix

| Capability | Manager | PeritumCT | CSO decision |
|------------|---------|-----------|--------------|
| Decisions list / ban / unban | Yes | Yes (local origins; CAPI omitted) | Keep ours |
| Alerts filters + inspect + CSV | Yes | **2.0.6** sample filters, inspect, CSV, top scenarios/countries | **Integrated (adapt)** |
| Decisions hide-expired + CSV | Yes | **2.0.6** | **Integrated (adapt)** |
| Allowlists / whitelists | Yes | LAPI allowlists only | Keep ours; no Traefik whitelist UI |
| Hub browse / install | Yes (install mode) | Hub AppSec rules **read-only** | **Adapt later** — list OK; install stays out of UI |
| IP dossier | Yes | **`GET /api/ip`** (2.0.5) | Integrated |
| Bouncers inventory | Yes (+ add/delete) | **`GET /api/bouncers`** RO (2.0.5) | Integrated RO |
| Repeated offenders | Dashboard-style | Overview + `/api/offenders` (2.0.5) | Integrated |
| Captcha / bot challenge | First-class wizard | Forbidden | **Reject** |
| Traefik dynamic writes / whitelist | First-class | Never | **Reject** |
| docker.sock / container status | Yes | No | **Reject** |
| Backups / Terminal / Cron / Updates | Yes | No | **Reject** |
| Config drift + Traefik snapshots | Yes | No | **Reject** |
| CrowdSec Console SaaS enroll | Health card | Out of scope | **Reject** |
| OWASP / MITRE / CTI file export | No | Yes | Keep ours |
| Per-FQDN AppSec policies | Limited/other model | First-class | Keep ours |

## Integrated in 2.0.5 (P0)

1. **IP dossier** — `GET /api/ip?ip=`
2. **Bouncers (read-only)** — `cscli bouncers list`
3. **Repeated offenders** — capped 24h sample rollup

## Integrated in 2.0.6 (screenshot pass)

1. **Alerts analysis** — IP/scenario/country/origin filters on the loaded LAPI sample; top scenarios/countries; AS + origin columns; Export CSV; inspect dialog (no delete, no captcha create).
2. **Decisions hygiene** — Hide expired toggle + Export CSV; ban UI remains **ban-only** (never captcha).

## Explicitly rejected

- Mounting `/var/run/docker.sock` into the console
- Interactive terminal / arbitrary `exec` into CrowdSec or Traefik containers
- Writing Traefik static/dynamic config or Traefik whitelists from the UI
- Captcha / Turnstile / bot-challenge wizards or decision types from the UI
- Publishing the console on a public interface by default
- Enabling CRS in-band, `INCLUDE_LARGE_UPLOADS`, or fail-open toggles
- In-console backups, cron, host updates, config restore of Traefik paths
- Treating Manager’s Pangolin compose as a drop-in for homologated Docker/Podman/Cilium/K8s pins

## Deferred (still CSO-safe)

| Item | Notes |
|------|--------|
| Control-plane export | Downloadable snapshot of `WAF_CONTROL` JSON (no secrets) |
| Read-only log tail | Bounded tail of operator-configured paths under allowlist |
| Hub catalog UX | Richer browse **without** install/upgrade buttons |
| Server-side since/until on alerts | Today filters are client-side on the 24h capped sample |
| CrowdSec-only config hash RO | Optional FIM of AppSec/profiles — never Traefik paths |

## Operator takeaway

Use **CrowdSec Manager** when you want a Docker-centric full stack UI (especially Pangolin + Traefik writes + captcha). Use **PeritumCT WAF Console** when CrowdSec/Traefik already run under a hardened IaC pin and the console must stay **loopback, non-bouncer, non-docker.sock**, with per-FQDN AppSec and local OWASP/MITRE context.

Upstream Manager: [crowdsec-manager.hhf.technology](https://crowdsec-manager.hhf.technology) · [github.com/hhftechnology/crowdsec_manager](https://github.com/hhftechnology/crowdsec_manager).
