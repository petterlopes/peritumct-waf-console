# Privacidade (DPO)

Vigente a 17 de setembro de 2026. UI: separador Privacidade · `#privacy` ·
English: [PRIVACY.md](PRIVACY.md)

Esta consola é uma **ferramenta de operador**. Não é um sítio público e deve
ficar em loopback + VPN admin. **Não** substitui o aviso de privacidade de
[periciacomputacional.com](https://periciacomputacional.com/sobre/) nem de outros origins.

**Controlador:** Petter Anderson Lopes, na qualidade de PERITUM / Perícia Computacional.

- Sobre: https://periciacomputacional.com/sobre/
- LinkedIn: https://www.linkedin.com/in/petter-anderson-lopes/
- Instagram: [@peritopetterlopes](https://www.instagram.com/peritopetterlopes/)

## Dados tratados

| Dado | Onde | Finalidade | Base legal (GDPR/LGPD) |
|------|------|------------|-------------------------|
| IPs de cliente em alertas/decisões CrowdSec | LAPI CrowdSec (leitura) | Monitorização de segurança | Interesse legítimo / obrigação legal (segurança de rede) |
| CIDRs de operador em allowlists | Allowlists CrowdSec | Evitar lockout | Interesse legítimo |
| Documentos de política (host, path, regra, motivo) | `WAF_CONTROL/site-filters.json` + YAML AppSec | Excepções WAF | Interesse legítimo |
| Auditoria JSONL | `WAF_CONTROL/audit.jsonl` | Prestação de contas | Interesse legítimo |

Sem IDs de publicidade, sem analítica de terceiros **nesta consola**, sem GeoIP de terceiros.

Um `WAF_GA_SNAPSHOT_FILE` opcional é um **agregado** exportado pelo operador de
sessões GA4 do sítio público por hostname e país (sem `client_id`). A analítica
**não contribui** até esse ficheiro ser um export agregado válido com pelo menos
uma contagem de sessões maior que zero. O dest está inactivo por omissão.
A consola nunca carrega gtag em `/waf`, nunca chama a Google Data API e nunca
envia IPs CrowdSec para a Google.

## Conservação

As decisões CrowdSec seguem o TTL do engine (teto da consola 168h para bans
manuais). Rode `audit.jsonl` com a política de logs do host (exemplo: 90 dias).

## Pedidos de titular

Esta UI não é uma aplicação de consumidor. IPs de utilizador final aparecem só
como telemetria de segurança no CrowdSec. Acesso/apagamento seguem o processo
de retenção CrowdSec/LAPI, não esta consola.

## Internacionalização

O idioma padrão da UI é inglês; `pt-BR` é opcional e fica em `localStorage`
(`waf-locale-v2`) só no browser do operador.
