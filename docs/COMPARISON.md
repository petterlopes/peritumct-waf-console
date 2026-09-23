# CrowdSec Manager vs PeritumCT WAF Console

CSO review of [hhftechnology/crowdsec_manager](https://github.com/hhftechnology/crowdsec_manager) (Go + React, MIT) as a **feature complement** source — not a stack merge.

**Console pin:** PeritumCT **2.0.7** · CrowdSec engine **v1.8.1** · loopback LAPI/AppSec · `/waf` off bouncer · GPL-3.0-or-later.

## Scope of this review

| Pass | Focus |
|------|--------|
| R1 | Map Manager capabilities (dashboard, decisions, hub, Traefik/Pangolin, docker, mobile) |
| R2 | Classify **integrate / adapt / reject** under PeritumCT CSO constraints |
| R3 | Document honest gaps and deferred work |
| R4 | Ship safe P0 complements (2.0.5) |
| R5 | Align README / PRODUCT / overlays |
| R6 | Screenshot-grounded Alerts/Decisions analytics UX (2.0.6) |
| R7 | Hub browse RO + IP management + reject Health/Logs/Notifications privilege (2.0.7) |
| R8 | System plane screenshots: Services / Updates / Terminal / Traefik Whitelist — **all reject**; review closed |

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

Operator screenshots of Manager v1.x informed the 2.0.5–2.0.7 adapt/reject list (R6–R8):

| Manager screen | Observed | CSO decision |
|----------------|----------|--------------|
| Hub Home / parsers / scenarios / AppSec / postoverflows | Install Mode, Remove, path helpers | **Adapt** RO inventory (2.0.7); **reject** install/remove |
| Health Containers / Traefik Integration | docker.sock inventory | **Reject** |
| IP Management | Check blocked / Security check / Unban / public IP | **Adapt** (2.0.7) on Decisions |
| Logs stream | Docker service logs + Start Stream | **Reject** docker stream; optional path-tail still deferred |
| Notifications Discord wizard | Detect compose + webhook/CTI/Geoapify secrets | **Reject** (no secret harvesting UI) |
| **Services Management** | Start/Stop/Restart for pangolin, traefik, crowdsec, gerbil; **Enroll CrowdSec**; **Graceful Shutdown** | **Reject** — host/orchestrator control plane |
| **System Update** | Edit Docker image tags (CrowdSec/Gerbil/Pangolin/Traefik) | **Reject** — image lifecycle belongs to IaC, not the WAF console |
| **Terminal / Container Shell** | Interactive shell into crowdsec/traefik/pangolin/gerbil | **Reject** |
| **Whitelist Management** | Whitelist current IP / comprehensive CrowdSec **+ Traefik** | Keep LAPI allowlists; **reject** Traefik whitelist writes and “all locations” push |
| Alert inspect modal | Scenario, geo, ASN, narrative, decisions, events | **Adapt** inspect dialog (sample JSON + summary); no GeoLite dependency |
| Alerts charts / table | Top scenarios, frequency, AS column, Export CSV, Cards/Table, **delete** alert | **Adapt** top scenarios/countries + CSV + AS; **reject** alert delete + card dual-view for now |
| Decisions analysis | Charts, since/until, type filter, **captcha** type dominant | **Adapt** hide-expired + CSV; **reject** creating captcha decisions |
| Allowlists vs Whitelists | LAPI allowlists + Traefik whitelist shortcut | Keep LAPI allowlists; **reject** Traefik whitelist path |
| Bouncers | Add / delete / status | Keep **read-only** list (2.0.5); **reject** add/delete |
| Health | LAPI, metrics, bouncers, **Console SaaS enroll**, **container via Docker** | Keep LAPI/metrics/bouncers RO; **reject** SaaS enroll + docker health |
| Captcha wizard | Turnstile + Traefik `dynamic_config` + captcha.html | **Reject** entirely |
| Config Validation | Snapshots of `/etc/traefik/*` + CrowdSec YAML + restore | **Reject** Traefik FIM/restore from UI |
| Settings | Traefik dynamic config path for whitelist writes | **Reject** |
| Backups / Cron | Host/stack control plane | **Reject** in-console |
| Dashboard | Top countries/AS/scenarios, blocked IPs, container status | Partial overlap with our dashboard/map; **reject** container status |

## Feature matrix

| Capability | Manager | PeritumCT | CSO decision |
|------------|---------|-----------|--------------|
| Decisions list / ban / unban | Yes | Yes (local origins; CAPI omitted) | Keep ours |
| Alerts filters + inspect + CSV | Yes | **2.0.6** sample filters, inspect, CSV, top scenarios/countries | **Integrated (adapt)** |
| Decisions hide-expired + CSV | Yes | **2.0.6** | **Integrated (adapt)** |
| Allowlists / whitelists | Yes | LAPI allowlists only | Keep ours; no Traefik whitelist UI |
| Hub browse / install | Yes (install mode) | **2.0.7** RO inventory (collections/scenarios/parsers/postoverflows/AppSec) | **Integrated RO** — install/remove rejected |
| IP management | Check / Security / Unban | **2.0.7** on Decisions (+ dossier 2.0.5) | **Integrated (adapt)** |
| Notifications / Discord wizard | Yes | No | **Reject** |
| Docker log stream | Yes | No | **Reject** |
| Bouncers inventory | Yes (+ add/delete) | **`GET /api/bouncers`** RO (2.0.5) | Integrated RO |
| Repeated offenders | Dashboard-style | Overview + `/api/offenders` (2.0.5) | Integrated |
| Captcha / bot challenge | First-class wizard | Forbidden | **Reject** |
| Traefik dynamic writes / whitelist | First-class | Never | **Reject** |
| docker.sock / container status | Yes | No | **Reject** |
| Services start/stop/restart / Graceful Shutdown | Yes (Pangolin stack) | No | **Reject** |
| Docker image tag updates (System Update) | Yes | No | **Reject** — IaC owns pins |
| Enroll CrowdSec Console SaaS | Button on Services | No | **Reject** |
| Container shell (Terminal) | Yes | No | **Reject** |
| Whitelist → Traefik + CrowdSec | Yes | LAPI allowlists only | **Reject** Traefik half |
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

## Integrated in 2.0.7 (Hub / IP / Health screenshot pass)

1. **Hub inventory (read-only)** — Rules view browses collections, scenarios, parsers, postoverflows, AppSec configs/rules from local CrowdSec Hub YAML paths. **No** Install / Remove / Direct cscli / Captcha management.
2. **IP management** — Decisions view: public IP label, Check blocked (dossier summary), dossier + ban/unban already present.
3. Screenshot rejects confirmed: Docker container health tab, Traefik Integration tab, Hub install mode, Discord notification wizard (webhook/CTI/Geoapify keys), live docker log stream, scenario Remove.

## R8 — System plane (no code; rejects only)

Final Manager screenshots confirm the privilege boundary. **Nothing from this plane is integrated:**

| Screen | Why rejected |
|--------|----------------|
| Services Management | Start/Stop/Restart of pangolin/traefik/crowdsec/gerbil + Graceful Shutdown requires docker.sock / host privilege |
| Enroll CrowdSec | SaaS Console enrollment is out of PeritumCT posture |
| System Update | Changing Docker image tags from a WAF console bypasses homologated IaC pins |
| Terminal | Interactive container shell is RCE-adjacent for operators and attackers who reach `/waf` |
| Whitelist Management (CrowdSec + Traefik) | Traefik dynamic whitelist writes remain forbidden; use Allowlists (LAPI/cscli) only |

**Review status:** CrowdSec Manager feature surface reviewed for safe complements. Ship line is **2.0.7**. Remaining deferred items are optional polish (control export, path-tail logs, server-side alert windows) — not Manager privilege features.

## Explicitly rejected

- Mounting `/var/run/docker.sock` into the console
- Interactive terminal / arbitrary `exec` into CrowdSec or Traefik containers
- Writing Traefik static/dynamic config or Traefik whitelists from the UI
- Captcha / Turnstile / bot-challenge wizards or decision types from the UI
- Publishing the console on a public interface by default
- Enabling CRS in-band, `INCLUDE_LARGE_UPLOADS`, or fail-open toggles
- In-console backups, cron, host updates, Docker image tag edits, config restore of Traefik paths
- Service start/stop/restart, graceful shutdown, or CrowdSec Console SaaS enroll from the UI
- Treating Manager’s Pangolin/Gerbil compose as a drop-in for homologated Docker/Podman/Cilium/K8s pins

## Deferred (still CSO-safe)

| Item | Notes |
|------|--------|
| Control-plane export | Downloadable snapshot of `WAF_CONTROL` JSON (no secrets) |
| Read-only log tail | Bounded tail of operator-configured paths under allowlist — **not** docker log stream |
| Server-side since/until on alerts | Today filters are client-side on the 24h capped sample |
| CrowdSec-only config hash RO | Optional FIM of AppSec/profiles — never Traefik paths |

## Operator takeaway

Use **CrowdSec Manager** when you want a Docker-centric full stack UI (especially Pangolin + Traefik writes + captcha). Use **PeritumCT WAF Console** when CrowdSec/Traefik already run under a hardened IaC pin and the console must stay **loopback, non-bouncer, non-docker.sock**, with per-FQDN AppSec and local OWASP/MITRE context.

Upstream Manager: [crowdsec-manager.hhf.technology](https://crowdsec-manager.hhf.technology) · [github.com/hhftechnology/crowdsec_manager](https://github.com/hhftechnology/crowdsec_manager).
