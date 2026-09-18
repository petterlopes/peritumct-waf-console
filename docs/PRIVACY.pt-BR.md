# Privacidade (DPO)

Vigente em 17 de setembro de 2026. UI: aba Privacidade · `#privacy` ·
English: [PRIVACY.md](PRIVACY.md)

Este console é uma **ferramenta de operador**. Não é um site público e deve
ficar em loopback + VPN admin. **Não** substitui o aviso de privacidade de
[periciacomputacional.com](https://periciacomputacional.com/sobre/) nem de outros origins.

**Controlador:** Petter Anderson Lopes, na qualidade de PERITUM / Perícia Computacional.

- Sobre: https://periciacomputacional.com/sobre/
- LinkedIn: https://www.linkedin.com/in/petter-anderson-lopes/
- Instagram: [@peritopetterlopes](https://www.instagram.com/peritopetterlopes/)

## Dados tratados

| Dado | Onde | Finalidade | Base legal (GDPR/LGPD) |
|------|------|------------|-------------------------|
| IPs de cliente em alertas/decisões CrowdSec | LAPI CrowdSec (leitura) | Monitoramento de segurança | Interesse legítimo / obrigação legal (segurança de rede) |
| CIDRs de operador em allowlists | Allowlists CrowdSec | Evitar lockout | Interesse legítimo |
| Documentos de política (host, path, regra, motivo) | `WAF_CONTROL/site-filters.json` + YAML AppSec | Exceções WAF | Interesse legítimo |
| Auditoria JSONL | `WAF_CONTROL/audit.jsonl` | Prestação de contas | Interesse legítimo |

Sem IDs de publicidade, sem analítica de terceiros **neste console**, sem GeoIP de terceiros.

Um `WAF_GA_SNAPSHOT_FILE` opcional é um **agregado** exportado pelo operador de
sessões GA4 do site público por hostname e país (sem `client_id`). A analítica
**não contribui** até esse arquivo ser um export agregado válido com pelo menos
uma contagem de sessões maior que zero. O dest está inativo por padrão.
O console nunca carrega gtag em `/waf`, nunca chama a Google Data API e nunca
envia IPs CrowdSec para a Google.

## Retenção

As decisões CrowdSec seguem o TTL do engine (teto do console 168h para bans
manuais). Rotacione `audit.jsonl` com a política de logs do host (exemplo: 90 dias).

## Pedidos de titular

Esta UI não é um aplicativo de consumidor. IPs de usuário final aparecem só
como telemetria de segurança no CrowdSec. Acesso/exclusão seguem o processo
de retenção CrowdSec/LAPI, não este console.

## Internacionalização

O idioma padrão da UI é inglês; `pt-BR` é opcional e fica em `localStorage`
(`waf-locale-v2`) só no navegador do operador.
