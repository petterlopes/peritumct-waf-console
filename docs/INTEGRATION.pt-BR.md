# Guia de integração (novos ambientes)

Documento secundário em **pt-BR**. A referência canônica é [INTEGRATION.md](INTEGRATION.md) (inglês).

O console opera um CrowdSec **local** (LAPI + AppSec). Idioma da UI: inglês por padrão, pt-BR no seletor EN/PT.

## Passos mínimos

1. CrowdSec v1.8.1, AppSec em `127.0.0.1:7422`, LAPI em `127.0.0.1:18080`. CRS **out-of-band**. Bot-challenge desligado.
2. Copiar `examples/sites.json` para `WAF_SITES_FILE` e editar os FQDN.
3. Reverse proxy: `PathPrefix /waf` **sem** bouncer CrowdSec (anti-lockout).
4. `docker compose` a partir de `docker-compose.example.yml`. Bind só loopback.
5. Verificar `GET /api/health` e HTTP 200 nos Hosts públicos.

Políticas (criar/editar/excluir) fazem SIGHUP no engine — precisa `pid: host` e volume AppSec gravável. Não reiniciar Nomad/Traefik para aplicar um filtro.

A aba **OWASP** correlaciona achados CrowdSec com o Top 10:2021 e exporta arquivos STIX/MISP/TheHive (conectores estilo OpenCTI: só enriquecimento local e download). Não há push outbound; tokens nunca saem no JSON. O mapa continua a usar só geo do LAPI.

Snapshot GA4 opcional (`WAF_GA_SNAPSHOT_FILE`): exportar à mão sessões por hostname e país (Explore ou Relatórios → Usuário → Tech/Geo, 7 dias) para o JSON de exemplo. O console **não** chama a Data API, **não** carrega gtag em `/waf` e **não** envia IPs CrowdSec pelo Measurement Protocol. Densidade LAPI/GA distingue scanner-heavy de risco para usuários.

Licença CrowdSec MIT: https://github.com/crowdsecurity/crowdsec?tab=MIT-1-ov-file
