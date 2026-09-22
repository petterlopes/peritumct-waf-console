# Architecture

```
Operator browser (EN default / pt-BR)
        │  PathPrefix /waf  (no CrowdSec bouncer)
        ▼
waf-console 127.0.0.1:18990   stdlib HTTP
        │
        ├─ LAPI 127.0.0.1:18080  (machine token + bouncer key)
        ├─ AppSec 127.0.0.1:7422 (policy YAML + SIGHUP)
        └─ optional Traefik API / Prometheus :6060
```

Modules:

- `app.py` — HTTP API and static UI
- `status.py` — version + HTTP probe health semantics
- `netguard.py` — loopback URL / probe IP validation, TTL cache, rate limiter, bounded reads
- `persist.py` — atomic file writes + shared audit log
- `control.py` — policy CRUD, allowlists, SIGHUP
- `catalog.py` — site inventory from JSON/env (no hardcoded production hosts)
- `static/locales/en.json` — default strings
- `static/locales/pt-BR.json` — secondary locale
