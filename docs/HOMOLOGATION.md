# Homologation matrix

This console was **homologated** (operator-validated) against the following stacks.
Homologation means: install, health, Domains probes, decisions/alerts, policy CRUD path,
and reverse-proxy anti-lockout (`/waf` **without** CrowdSec bouncer) were exercised on
real infrastructure — not only unit tests.

| Runtime / platform | Role | Homologated | Notes |
|--------------------|------|-------------|-------|
| **Docker Compose** | Console container (`network_mode: host`) | Yes | `docker-compose.example.yml`; `USER nobody` overridden with `user: "0:0"` when SIGHUP/`cscli` need host privileges |
| **Podman Compose** | Console + CrowdSec engine on Rocky Linux | Yes | rocky-212 host network; systemd oneshot + timer auto-update |
| **Kubernetes** | Traefik IngressRoute / Middleware CRDs | Yes | `/waf` → host Endpoints; middlewares `crowdsec-bouncer` (AppSec) vs `admin-netbird-only` (console) |
| **Cilium** | Cluster networking / LB to Traefik | Yes | NetBird → host :443 → Cilium LB → Traefik; LAPI/AppSec reached via node InternalIP |
| **Traefik** | Edge + CrowdSec bouncer plugin v1.5.0 | Yes | Fail-closed AppSec; console never on bouncer chain |
| **CrowdSec** | LAPI + AppSec CRS **OOB** | Yes | Pin **v1.8.1**; CRS in-band and bot-challenge **off** |
| **systemd** | Units + 15‑minute GitHub auto-update | Yes | `waf-console.service`, proxy socat, `waf-console-update.timer` |
| **Nomad** (optional pack) | Site pack branding `waf-admin` | Yes | Same codebase via `WAF_APP_PRODUCT`; `cscli` via `NOMAD_BIN` alloc exec when needed |

## Reference topologies

### A — Docker Compose (lab / single host)

```
Operator → http://127.0.0.1:18990/waf/
                ↓
         docker compose (host network)
                ↓
         CrowdSec LAPI :18080 / AppSec :7422 (loopback)
```

```bash
cp examples/sites.json /var/lib/waf-control/sites.json
cp docker-compose.example.yml docker-compose.yml
docker compose up -d --build
curl -sf http://127.0.0.1:18990/api/health
```

### B — Podman on bare metal / VM (rocky-style)

```
NetBird / admin overlay
        ↓
Traefik (or host proxy) PathPrefix(/waf) ──no bouncer──► socat NODE_IP:18990
                                                              ↓
                                                    127.0.0.1:18990 console
CrowdSec engine: podman host network (LAPI/AppSec)
Console: podman compose + systemd auto-update from GitHub main
```

Verified with:

- Podman + `podman compose` / `podman-compose`
- `WAF_BIND=127.0.0.1` (process exits if bind is not loopback)
- Health: `version` prefix `waf-console/`
- Domains tiles: HTTP status palette (2xx green, 3xx cyan, 4xx orange, 5xx red)

### C — Kubernetes + Cilium + Traefik

```
Clients (NetBird) → Cilium LoadBalancer :443 → Traefik Deployment
   ├─ Host(`app…`) + crowdsec-bouncer → AppSec (NODE_IP:7422) + LAPI (NODE_IP:18080)
   └─ PathPrefix(`/waf`) + admin-only middleware → Endpoints(NODE_IP:18990)
                                                      ↓ socat → 127.0.0.1:18990
```

Homologated pieces:

| Piece | Evidence |
|-------|----------|
| Cilium | Cluster CNI / LB path to Traefik service |
| Kubernetes CRDs | Traefik `Middleware`, `IngressRoute`, Ingress annotations |
| Host CrowdSec | Engine not in-cluster; LAPI/AppSec listen on node IP for Traefik pods |
| Console | Host loopback only; never published as NodePort publicly |

IaC companion (not vendored here): operators maintain Traefik values, middlewares, and
reconcile scripts next to their cluster SoT (example: PeritumCT `cilium-devsecops-peritumct`).

## Acceptance checklist (any homologated stack)

1. `GET /api/health` → `ok: true`, `oob_log_only: true`, `crs_inband_present: false`
2. `WAF_BIND` is loopback; `:18080` / `:7422` / `:18990` not on the public Internet
3. `/waf` reverse-proxy path has **no** CrowdSec bouncer middleware
4. Domains / dashboard origin probes colour by HTTP class (2xx green)
5. Policy mutations refuse CRS in-band / `INCLUDE_LARGE_UPLOADS` / fail-closed flips
6. Unit tests: `python -m unittest discover -s tests -q`
7. Optional CI: Ruff, Bandit, pip-audit, Trivy (see [SECURITY.md](SECURITY.md))

## Auto-update (homologated on Podman/systemd)

When deployed with the PeritumCT rocky host pack:

1. Timer every **15 minutes** fetches `origin/main` of this repository
2. On SHA change → `podman compose up -d --build`, preserve host compose overlay
3. Gate: health must report `waf-console/*` before marking success

Operators can force: `FORCE=1 /usr/local/bin/update-waf-console.sh`

## Version branding

| Env | Default | Use |
|-----|---------|-----|
| `WAF_APP_PRODUCT` | `waf-console` | Product name in `Server` / health `version` |
| `WAF_APP_VERSION` | `1.0.18` | Semver string |

Site packs (e.g. Nomad `waf-admin`) set `WAF_APP_PRODUCT=waf-admin` while tracking this repo.

## Out of scope for homologation claims

- CrowdSec SaaS / cloud console
- Enabling CRS in-band or bot challenge
- Public exposure of LAPI/AppSec/console
- Third-party GeoIP APIs (map uses LAPI coordinates + Natural Earth only)
