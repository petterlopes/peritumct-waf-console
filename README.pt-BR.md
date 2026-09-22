# PeritumCT WAF Console

Console open-source para um engine [CrowdSec](https://github.com/crowdsecurity/crowdsec) local
(LAPI + AppSec). **Não** é o dashboard cloud da CrowdSec.

**Idioma padrão: inglês.** Português do Brasil (`pt-BR`) é o idioma secundário da UI (seletor EN/PT).

Documentação principal em inglês: [README.md](README.md) · índice: [docs/README.md](docs/README.md).

**Runtime 2.x: Rust** (`rust/`). Python 1.x em `legacy/python/` (rollback).

## Plataformas homologadas

| Plataforma | Estado |
|------------|--------|
| **Docker Compose** | Homologado |
| **Podman Compose** | Homologado |
| **Kubernetes** (CRDs Traefik) | Homologado |
| **Cilium** (CNI / LB → Traefik) | Homologado |

Detalhes, topologias e checklist: **[docs/HOMOLOGATION.pt-BR.md](docs/HOMOLOGATION.pt-BR.md)** ·
[docs/HOMOLOGATION.md](docs/HOMOLOGATION.md) (EN).

## Arranque rápido

```bash
cp examples/sites.json /var/lib/waf-control/sites.json
cp docker-compose.example.yml docker-compose.yml
docker compose up -d --build   # ou: podman compose …
curl -sf http://127.0.0.1:18990/api/health
# UI: http://127.0.0.1:18990/waf/
```

Integração (Traefik anti-lockout, acquis OOB, variáveis): [docs/INTEGRATION.pt-BR.md](docs/INTEGRATION.pt-BR.md).

Créditos, privacidade e termos: [docs/CREDITS.pt-BR.md](docs/CREDITS.pt-BR.md) ·
[docs/PRIVACY.pt-BR.md](docs/PRIVACY.pt-BR.md) · [docs/TERMS.pt-BR.md](docs/TERMS.pt-BR.md).
Na UI: Créditos, Privacidade, Termos (`#credits`, `#privacy`, `#terms`).

## O que nunca faz

- Activar CRS in-band, bot-challenge ou `INCLUDE_LARGE_UPLOADS` pela UI
- Colocar `/waf` atrás do bouncer CrowdSec (risco de lockout)
- Expor LAPI/AppSec/console na Internet pública
