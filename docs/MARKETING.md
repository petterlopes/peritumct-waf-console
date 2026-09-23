# Marketing & GitHub publication

Kit for GitHub About, social posts, and README assets. Screenshots and creatives live under [media/](media/README.md).

## GitHub repository settings (manual)

In **Settings → General**:

| Field | Suggested value |
|-------|-----------------|
| **Description** | Open source self-hosted CrowdSec console — Rust backend, local LAPI/AppSec, per-FQDN policies, OWASP & MITRE ATT&CK context |
| **Website** | https://periciacomputacional.com/peritumct-waf-console-local-control-of-crowdsec-powered-by-a-rust-backend |
| **Topics** | `crowdsec` `waf` `rust` `appsec` `open-source` `self-hosted` `owasp` `mitre-attack` `gpl` `security` `traefik` `devops` |

**Social preview image:** upload [media/social/social-linkedin-en.jpg](media/social/social-linkedin-en.jpg) (or set automatically via README hero).

## Short GitHub blurb

**PeritumCT WAF Console** is an open source self-hosted console for local CrowdSec installs, with a Rust backend and a static UI served by the app.

It gathers alerts, decisions, per-FQDN AppSec policies, allowlists, metrics, HTTP probes, and a LAPI-based map. Heuristic OWASP Top 10:2021 and MITRE ATT&CK correlation plus local CTI file exports support investigation — without depending on CrowdSec Console SaaS for core ops.

Designed for loopback and org-managed admin access. Control actions need local credentials and permissions. The console does not replace CrowdSec detection or remediation components.

License: **GPL-3.0-or-later**.

## LinkedIn (EN)

Sharing **PeritumCT WAF Console**, an open source project for local CrowdSec operations.

Self-hosted UI for day-to-day AppSec work:

- Local alerts and decisions (ban / unban)
- Per-domain AppSec policies and allowlists
- Map, metrics, and HTTPS service checks
- Heuristic OWASP Top 10:2021 and MITRE ATT&CK correlation
- Local CTI file exports for investigation workflows

The 2.x line is **Rust**. Core functions do not require CrowdSec Console SaaS. Protect operator access with your admin network/IdP; policy apply needs engine permissions (`pid: host`, writable AppSec, `cscli`).

**GPL-3.0-or-later** · [github.com/petterlopes/peritumct-waf-console](https://github.com/petterlopes/peritumct-waf-console)

Article: https://periciacomputacional.com/peritumct-waf-console-local-control-of-crowdsec-powered-by-a-rust-backend

#Rust #CrowdSec #OpenSource #AppSec #SelfHosted #DevSecOps

## LinkedIn (pt-BR)

Estou compartilhando o **PeritumCT WAF Console**, projeto open source para facilitar a operação local do CrowdSec.

Interface self-hosted para a rotina de quem protege aplicações: alertas e decisões, políticas AppSec por domínio, allowlists, mapa, métricas, sondagens HTTP, correlação OWASP Top 10:2021 / MITRE ATT&CK e exportações CTI locais.

Backend **Rust** (2.x). Funções principais sem depender do CrowdSec Console SaaS. Acesso administrativo via infraestrutura da organização; aplicar políticas exige permissões no engine.

**GPL-3.0-or-later** · [repositório](https://github.com/petterlopes/peritumct-waf-console)

#Rust #CrowdSec #OpenSource #AppSec #SelfHosted #DevSecOps

## Title / subtitle (editorial)

**Title:** PeritumCT WAF Console: local control of CrowdSec, powered by a Rust backend  

**Subtitle:** An open source, self-hosted console that brings WAF operations, decisions, per-domain policies, and MITRE ATT&CK and OWASP context to the operator’s own infrastructure.

## Checklist before a campaign push

- [ ] README hero + screenshots render on github.com
- [ ] About description / website / topics set
- [ ] Social preview image uploaded
- [ ] Article URL live
- [ ] Version pin in README matches release (`2.0.7+`)
- [ ] No “first in the world” claims
- [ ] LICENSE / NOTICE / SECURITY.md linked
