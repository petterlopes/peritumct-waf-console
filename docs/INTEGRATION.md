# Integration guide (new environments)

Default language of this document: **English**. Portuguese: [INTEGRATION.pt-BR.md](INTEGRATION.pt-BR.md).

This console operates a **local** CrowdSec Security Engine. It does not replace Traefik, Nomad, or the CrowdSec cloud console.

Tested with CrowdSec **v1.8.1** (`crowdsecurity/crowdsec:v1.8.1`, commit `909b515`).
Release: https://github.com/crowdsecurity/crowdsec/releases#release-v1.8.1  
License: https://github.com/crowdsecurity/crowdsec?tab=MIT-1-ov-file

## 1. Architecture

```
 Internet → reverse proxy (Traefik / nginx)
              ├─ site Hosts  → crowdsec-bouncer → AppSec :7422 + LAPI :18080
              └─ /waf        → WAF console :18990   **no bouncer**
 CrowdSec engine (host network, loopback only)
 WAF console (loopback :18990, optional pid:host for SIGHUP)
```

| Port | Bind | Role |
|------|------|------|
| 18080 | `127.0.0.1` | CrowdSec LAPI |
| 7422 | `127.0.0.1` | CrowdSec AppSec |
| 6060 | `127.0.0.1` | Prometheus metrics (optional UI) |
| 18990 | `127.0.0.1` | This console |

Never publish LAPI/AppSec/metrics/console on a public address.

## 2. Prerequisites

1. CrowdSec 1.8.x with AppSec collections:
   - `crowdsecurity/appsec-virtual-patching`
   - `crowdsecurity/appsec-generic-rules`
   - `crowdsecurity/appsec-crs` (**out-of-band**, not `crs-inband`)
2. A reverse-proxy bouncer (example: Traefik `crowdsec-bouncer-traefik-plugin`) in **fail-closed** for AppSec.
3. Machine credentials: `/etc/crowdsec/local_api_credentials.yaml`
4. Bouncer API key file (example path `/run/lapi_key`)
5. Admin overlay/VPN (or SSH tunnel) to reach the console. Do not expose `:18990` to the Internet.

**Keep off (CISO defaults):**

- CrowdSec 1.8 bot detection / challenge (opt-in; do not add challenge collections)
- `crowdsecurity/crs-inband`
- `DisableBodyInspection` / `INCLUDE_LARGE_UPLOADS` until you prove it on that engine version

## 3. Site catalog

Copy [examples/sites.json](../examples/sites.json) to `WAF_SITES_FILE` (default `/var/lib/waf-control/sites.json`).

```json
{
  "sites": {
    "www.example.com": { "kind": "web", "chain": "security-chain", "bouncer": true, "appsec": true, "in_scope": true }
  },
  "out_of_scope": {
    "grpc.example.com": "gRPC — AppSec must stay off"
  }
}
```

Alternatively set `WAF_SITES_JSON` (inline JSON) or `WAF_HOSTS=www.example.com,shop.example.com`.

Hosts in `out_of_scope` are rejected by policy create/update (HTTP 400).

## 4. Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `WAF_BIND` | `127.0.0.1` | Must stay loopback |
| `WAF_PORT` | `18990` | Console port |
| `CROWDSEC_CREDS` | `/etc/crowdsec/local_api_credentials.yaml` | Machine login |
| `CROWDSEC_CONFIG` | `/etc/crowdsec` | Config + hub |
| `CROWDSEC_PROFILES` | `/etc/crowdsec/profiles.yaml` | OOB log-only detection |
| `CROWDSEC_BOUNCER_KEY` | `/run/lapi_key` | `X-Api-Key` for decision stream |
| `CROWDSEC_LAPI` | from creds `url` | `http://127.0.0.1:18080` |
| `CROWDSEC_METRICS` | `http://127.0.0.1:6060/metrics` | Optional |
| `CROWDSEC_CSCLI` | empty | Host `cscli` binary (preferred) |
| `NOMAD_BIN` | empty | Optional: `nomad alloc exec` fallback |
| `WAF_CROWDSEC_JOB` | `crowdsec` | Nomad job name if using Nomad |
| `WAF_CONTROL` | `/var/lib/waf-control` | Policies JSON + audit log |
| `WAF_SITES_FILE` | `$WAF_CONTROL/sites.json` | Catalog |
| `WAF_ALLOWLIST` | `cso-operators` | cscli allowlist name |
| `WAF_APPSEC_NAME` | `peritumct/site-filters` | AppSec config name written by the console |
| `WAF_APPSEC_FILE` | `peritumct-site-filters.yaml` | File under `appsec-configs/` |
| `PUBLIC_IP` | empty | Origin vs public HTTP probes (optional) |
| `TRAEFIK_API` | `http://127.0.0.1:8080/api/http/routers` | Optional bouncer map |

## 5. Reverse proxy (anti-lockout)

The console **must not** use the CrowdSec bouncer middleware. Operators need unban while banned.

Traefik example:

```yaml
http:
  routers:
    waf-console:
      rule: "PathPrefix(`/waf`)"
      priority: 200
      entryPoints: ["websecure"]
      service: waf-console
      middlewares:
        - admin-only          # SourceRange: VPN/overlay + 127.0.0.1
        - waf-strip
      # do NOT attach crowdsec-bouncer here
  middlewares:
    waf-strip:
      stripPrefix:
        prefixes: ["/waf"]
  services:
    waf-console:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:18990"
```

Assets and API are served under `/waf/` (the process also accepts `/` on loopback).

## 6. CrowdSec AppSec acquis

Keep CRS **out of band**. Example `acquis.d/appsec.yaml`:

```yaml
appsec_configs:
  - crowdsecurity/appsec-default
  - crowdsecurity/crs
  - peritumct/site-filters
labels:
  type: appsec
listen_addr: 127.0.0.1:7422
source: appsec
```

The console appends `peritumct/site-filters` if missing. It refuses to start a write if a list item `crowdsecurity/crs-inband` is present.

Put a **log-only** profile for `crowdsecurity/crowdsec-appsec-outofband` above remediation profiles so OOB CRS does not ban publishers / operators.

## 7. Policy apply (SIGHUP)

Creating/editing/deleting policies writes YAML and sends **SIGHUP** to processes whose `/proc/*/cmdline` starts with `crowdsec`.

That requires:

- `pid: host` (or running the console on the host network namespace of CrowdSec)
- permission to signal the CrowdSec PID (often uid 0)
- writable `appsec-configs/` and `acquis.d/`

If you only need read-only health/map/decisions, omit `pid: host` and do not mount AppSec config read-write. Ban/unban still work via LAPI; allowlist writes need `CROWDSEC_CSCLI`.

## 8. Docker

```bash
cp docker-compose.example.yml docker-compose.yml
# point volumes at your CrowdSec config/data
docker compose up -d --build
```

Override `user: "0:0"` and `pid: host` when this replica must SIGHUP CrowdSec. The image defaults to `nobody` for a read-mostly replica.

## 9. systemd

Install [systemd/waf-console.service](../systemd/waf-console.service) after the compose file lives in `/opt/peritumct-waf-console`.

`systemctl restart waf-console` rebuilds the container. It must **not** restart Nomad or Traefik.

## 10. Verification

```bash
curl -sf http://127.0.0.1:18990/api/health
curl -sf http://127.0.0.1:18990/waf/locales/en.json | head
python3 - <<'PY'
import json, urllib.request
h = json.load(urllib.request.urlopen("http://127.0.0.1:18990/api/health", timeout=8))
assert h.get("lapi_listen") and h.get("appsec_listen")
assert str(h.get("version", "")).startswith("waf-console/")
assert h.get("locale", {}).get("default") == "en"
print("ok", h["version"])
PY
```

Then hit each in-scope Host from the **public** address of the reverse proxy and expect HTTP 200 (fail-closed will 403 if AppSec is down).

## 11. Language

| Surface | Default | Secondary |
|---------|---------|-----------|
| UI | English (`en`) | `pt-BR` (header EN/PT; `localStorage waf-locale`) |
| API errors | English | — |
| Docs | English | `*.pt-BR.md` |

Browsers with `Accept-Language: pt*` open in Portuguese until the operator picks EN.

## 12. SCA / SAST

See [SECURITY.md](SECURITY.md). GitHub Actions workflow: `.github/workflows/security.yml`.
