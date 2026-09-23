# Guia de integração (novos ambientes)

Documento secundário em **pt-BR**. A referência canônica é [INTEGRATION.md](INTEGRATION.md) (inglês).

O console opera um CrowdSec **local** (LAPI + AppSec). Idioma da UI: inglês por padrão, pt-BR no seletor EN/PT.

**Runtime do console:** Rust **2.0.9** (MSRV / builder Docker **1.98.1**, **GPL-3.0-or-later**) — ver [TOOLCHAIN.md](TOOLCHAIN.md) e [NOTICE](../NOTICE).
Python 1.x em `legacy/python/` só para rollback.

**Homologado** com Docker Compose, Podman Compose, Kubernetes (CRDs Traefik) e Cilium —
ver [HOMOLOGATION.pt-BR.md](HOMOLOGATION.pt-BR.md).

Quando o Traefik ocupa `:8080`, o LAPI fica tipicamente em `:18080`. Preferir
`CROWDSEC_LAPI=http://127.0.0.1:18080` mesmo que o YAML de credenciais ainda cite `:8080`.

## Passos mínimos

1. CrowdSec v1.8.1, AppSec em `127.0.0.1:7422`, LAPI em `127.0.0.1:18080`. CRS **out-of-band**. Bot-challenge desligado.
2. Copiar `examples/sites.json` para `WAF_SITES_FILE` e editar os FQDN.
3. Reverse proxy: `PathPrefix /waf` **sem** bouncer CrowdSec (anti-lockout).
4. `docker compose` ou `podman compose` a partir de `docker-compose.example.yml`. Bind só loopback.
5. Em K8s+Cilium: Traefik no cluster; console no nó (loopback); AppSec/LAPI no InternalIP do nó.
6. Verificar `GET /api/health` e cores Domains por classe HTTP (2xx verde).

Políticas (criar/editar/excluir) fazem SIGHUP no engine — precisa `pid: host` e volume AppSec gravável. Não reiniciar Nomad/Traefik para aplicar um filtro.

A aba **OWASP** correlaciona achados CrowdSec com o Top 10:2021 e exporta arquivos STIX/MISP/TheHive (conectores estilo OpenCTI: só enriquecimento local e download). Não há push outbound; tokens nunca saem no JSON. O mapa continua a usar só geo do LAPI.

Snapshot GA4 opcional (`WAF_GA_SNAPSHOT_FILE`): exportar à mão sessões por hostname e país. O console **não** chama a Data API, **não** carrega gtag em `/waf` e **não** envia IPs CrowdSec pelo Measurement Protocol.

Licença do **console**: GPL-3.0-or-later (`LICENSE` / `NOTICE`).
Licença CrowdSec (engine, processo separado) MIT: https://github.com/crowdsecurity/crowdsec?tab=MIT-1-ov-file
