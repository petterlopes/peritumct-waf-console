<p align="center">
  <img src="docs/media/social/social-linkedin-en.jpg" alt="PeritumCT WAF Console" width="920">
</p>

# PeritumCT WAF Console

**Console open source e self-hosted que reúne operação de WAF, decisões, políticas por domínio e contexto MITRE ATT&CK e OWASP na infraestrutura do operador.**

Interface de operações para instalações **locais** do [CrowdSec](https://github.com/crowdsecurity/crowdsec) — backend em Rust, UI estática servida pela aplicação. **Não** é o dashboard cloud da CrowdSec.

**Idioma padrão da UI: inglês.** Português do Brasil (`pt-BR`) no seletor EN/PT.

| | |
|--|--|
| **Console** | **2.0.6** · GPL-3.0-or-later · [NOTICE](NOTICE) |
| **Engine** | CrowdSec **v1.8.1** (MIT, processo separado) |
| **Artigo (EN)** | [Local control of CrowdSec…](https://periciacomputacional.com/peritumct-waf-console-local-control-of-crowdsec-powered-by-a-rust-backend) |
| **Docs EN** | [PRODUCT](docs/PRODUCT.md) · [COMPARISON](docs/COMPARISON.md) · [MARKETING](docs/MARKETING.md) · [README.md](README.md) |

## Porque existe

Proteger aplicações exige mais do que instalar o engine: ver domínio em falha, entender decisões, ajustar excepções e distinguir detecção de bloqueio — sem depender de um dashboard externo para o dia a dia.

O PeritumCT WAF Console mantém esse fluxo **junto ao engine**: alertas/decisões LAPI, políticas AppSec por FQDN, allowlists, sondagens Domains, métricas, mapa com geo da LAPI e correlação local OWASP Top 10:2021 / MITRE ATT&CK.

## Capturas

<p align="center">
  <img src="docs/media/screenshots/01-dashboard.png" alt="Dashboard" width="900">
</p>

Galeria: [docs/media/README.md](docs/media/README.md).

## Plataformas homologadas

Docker Compose · Podman · Kubernetes (Traefik) · Cilium — [docs/HOMOLOGATION.pt-BR.md](docs/HOMOLOGATION.pt-BR.md).

## Arranque rápido

```bash
cp examples/sites.json /var/lib/waf-control/sites.json
cp docker-compose.example.yml docker-compose.yml
docker compose up -d --build
curl -sf http://127.0.0.1:18990/api/health
# UI: http://127.0.0.1:18990/waf/
```

Para **políticas e allowlists**, use o Compose de admin (`pid: host`, `user: "0:0"`, mounts CrowdSec/`cscli`) — ver comentários no example.

## O que nunca faz

- Activar CRS in-band, bot-challenge ou `INCLUDE_LARGE_UPLOADS` pela UI
- Colocar `/waf` atrás do bouncer (anti-lockout)
- Expor LAPI/AppSec/console na Internet pública
- Alegar exclusividade “primeiro do mundo” — o diferencial é a **combinação** local + Rust + FQDN + OWASP/MITRE

## Honestidade operacional (2.0.6+)

- **Fail-closed:** metadado CSO na consola; validar no bouncer/remediação
- **Dashboard 24h:** `since=24h` + filtro; amostra limitada divulga `sample.capped`
- **AuthN:** sem login embutido — overlay/IdP/Teleport
- **Políticas:** volumes AppSec graváveis + SIGHUP

## Documentação e MKT

Integração: [docs/INTEGRATION.pt-BR.md](docs/INTEGRATION.pt-BR.md) ·  
Posicionamento / LinkedIn / GitHub About: [docs/MARKETING.md](docs/MARKETING.md) ·  
Legal: [CREDITS](docs/CREDITS.pt-BR.md) · [PRIVACY](docs/PRIVACY.pt-BR.md) · [TERMS](docs/TERMS.pt-BR.md)

## Contribuir

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · issues e PRs bem-vindos.
