# Guia de integração (novos ambientes)

Documento secundário em **pt-BR**. A referência canónica é [INTEGRATION.md](INTEGRATION.md) (inglês).

A consola opera um CrowdSec **local** (LAPI + AppSec). Idioma da UI: inglês por omissão, pt-BR no selector EN/PT.

## Passos mínimos

1. CrowdSec v1.8.1, AppSec em `127.0.0.1:7422`, LAPI em `127.0.0.1:18080`. CRS **out-of-band**. Bot-challenge desligado.
2. Copiar `examples/sites.json` para `WAF_SITES_FILE` e editar os FQDN.
3. Reverse proxy: `PathPrefix /waf` **sem** bouncer CrowdSec (anti-lockout).
4. `docker compose` a partir de `docker-compose.example.yml`. Bind só loopback.
5. Verificar `GET /api/health` e HTTP 200 nos Hosts públicos.

Políticas (criar/editar/apagar) fazem SIGHUP no engine — precisa `pid: host` e volume AppSec gravável. Não reiniciar Nomad/Traefik para aplicar um filtro.

Licença CrowdSec MIT: https://github.com/crowdsecurity/crowdsec?tab=MIT-1-ov-file
