# CrowdSec Manager vs PeritumCT WAF Console

CSO review of [hhftechnology/crowdsec_manager](https://github.com/hhftechnology/crowdsec_manager) (Go + React, MIT, v2.4.0) as a **feature complement** source — not a stack merge.

**Console pin:** PeritumCT **2.0.5** · CrowdSec engine **v1.8.1** · loopback LAPI/AppSec · `/waf` off bouncer · GPL-3.0-or-later.

## Scope of this review

| Pass | Focus |
|------|--------|
| R1 | Map Manager capabilities (dashboard, decisions, hub, Traefik/Pangolin, docker, mobile) |
| R2 | Classify **integrate / adapt / reject** under PeritumCT CSO constraints |
| R3 | Document honest gaps and deferred work |
| R4 | Ship safe P0 complements in-tree (this release) |
| R5 | Align README / PRODUCT / overlays |

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

## Feature matrix

| Capability | Manager | PeritumCT | CSO decision |
|------------|---------|-----------|--------------|
| Decisions list / ban / unban | Yes | Yes (local origins; CAPI omitted) | Keep ours |
| Alerts / metrics / health | Yes | Yes | Keep ours |
| Allowlists / whitelists | Yes | Yes (`cscli` / Nomad exec) | Keep ours |
| Hub browse / install | Yes (install mode) | Hub AppSec rules **read-only** | **Adapt later** — list OK; install stays out of UI |
| Scenarios management | Yes | Via engine/cscli, not full UI | Defer |
| IP security check / dossier | Yes | **`GET /api/ip`** + Decisions UI (2.0.5) | **Integrated (adapt)** |
| Bouncers inventory | Yes | **`GET /api/bouncers`** + Engine UI (2.0.5) | **Integrated (RO)** |
| Repeated offenders rollup | Dashboard-style | **`offenders` on overview** + `/api/offenders` | **Integrated (sample-honest)** |
| Logs viewer | Yes | Not in UI | **P1** optional RO tail of known paths only |
| Backups | Yes | Operator host backups | Reject in-console |
| Traefik / Caddy / NPM writes | Yes | Never | **Reject** |
| Captcha / bot challenge | Detect/manage | Forbidden by policy | **Reject** |
| docker.sock / container start-stop | Yes | No | **Reject** |
| Container shell | Yes | No | **Reject** |
| Pangolin / Gerbil bundle | First-class | Out of scope | **Reject** (deploy alongside if desired) |
| Mobile app | Yes | No | Out of scope |
| GeoLite enrichment | Optional volume | Not required | Reject as dependency |
| OWASP / MITRE / CTI file export | No (Manager focus) | Yes (local catalogs + STIX/MISP/TheHive files) | Keep ours |
| Per-FQDN AppSec policies | Limited/other model | First-class | Keep ours |
| Fail-closed honesty | Stack-dependent | CSO metadata + docs (2.0.4+) | Keep ours |

## Integrated in 2.0.5 (P0)

Safe complements inspired by Manager UX, implemented with PeritumCT constraints:

1. **IP dossier** — `GET /api/ip?ip=` aggregates local decisions, recent LAPI alerts, allowlist check. No Traefik whitelist mutation.
2. **Bouncers (read-only)** — `cscli bouncers list -o json` via existing control path; soft-fail when binary missing.
3. **Repeated offenders** — rollup from the **current alert sample** (`since=24h`, `WAF_ALERTS_LIMIT`); UI discloses sample nature.

## Explicitly rejected

- Mounting `/var/run/docker.sock` into the console
- Interactive terminal / arbitrary `exec` into CrowdSec or Traefik containers
- Writing Traefik static/dynamic config from the UI
- Publishing the console on a public interface by default
- Enabling captcha, bot-challenge, CRS in-band, `INCLUDE_LARGE_UPLOADS`, or fail-open toggles
- Treating Manager’s Pangolin compose as a drop-in replacement for homologated Docker/Podman/Cilium/K8s pins

## Deferred (P1 — still CSO-safe)

| Item | Notes |
|------|--------|
| Control-plane export | Downloadable snapshot of `WAF_CONTROL` JSON (no secrets) |
| Read-only log tail | Bounded tail of operator-configured paths under allowlist |
| Hub catalog UX | Richer browse of installed collections **without** install/upgrade buttons |
| Decision analytics filters | Deeper filtering already partially in dashboard — extend without new privilege |

## Operator takeaway

Use **CrowdSec Manager** when you want a Docker-centric full stack UI (especially Pangolin). Use **PeritumCT WAF Console** when CrowdSec/Traefik already run under a hardened IaC pin and the console must stay **loopback, non-bouncer, non-docker.sock**, with per-FQDN AppSec and local OWASP/MITRE context.

Upstream Manager docs: [crowdsec-manager.hhf.technology](https://crowdsec-manager.hhf.technology) · repo [github.com/hhftechnology/crowdsec_manager](https://github.com/hhftechnology/crowdsec_manager).
