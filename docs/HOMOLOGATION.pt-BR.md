# Matriz de homologação

Este console foi **homologado** (validado por operadores) nas stacks abaixo.
Homologação significa: instalação, health, probes Domains, decisions/alerts, caminho de
CRUD de políticas e anti-lockout no reverse-proxy (`/waf` **sem** bouncer CrowdSec)
exercitados em infraestrutura real — não só testes unitários.

**Pin actual:** console **2.0.9** (Rust **1.98.1**, GPL-3.0-or-later) · CrowdSec **v1.8.1** (MIT).
Ver [TOOLCHAIN.md](TOOLCHAIN.md).

| Runtime / plataforma | Papel | Homologado | Notas |
|----------------------|-------|------------|-------|
| **Docker Compose** | Contentor do console (`network_mode: host`) | Sim | `docker-compose.example.yml`; `user: "0:0"` quando SIGHUP/`cscli` precisam de privilégios no host |
| **Podman Compose** | Console + engine CrowdSec em Rocky Linux | Sim | rocky-212 host network; systemd + timer de auto-update |
| **Kubernetes** | Traefik IngressRoute / Middleware CRDs | Sim | `/waf` → Endpoints no nó; middlewares AppSec vs admin-only |
| **Cilium** | Rede do cluster / LB até Traefik | Sim | NetBird → :443 → Cilium LB → Traefik; LAPI/AppSec via InternalIP do nó |
| **Traefik** | Borda + plugin bouncer v1.5.0 | Sim | AppSec fail-closed; console nunca na cadeia do bouncer |
| **CrowdSec** | LAPI + AppSec CRS **OOB** | Sim | Pin **v1.8.1**; CRS in-band e bot-challenge **desligados** |
| **systemd** | Units + auto-update GitHub 15 min | Sim | console, proxy socat, timer |
| **Nomad** (pack opcional) | Branding `waf-admin` | Sim | Mesmo código via `WAF_APP_PRODUCT` |

Documentação principal em inglês: [HOMOLOGATION.md](HOMOLOGATION.md).

## Topologias de referência

### Docker Compose

```bash
cp examples/sites.json /var/lib/waf-control/sites.json
cp docker-compose.example.yml docker-compose.yml
docker compose up -d --build
curl -sf http://127.0.0.1:18990/api/health
```

### Podman (host)

Engine CrowdSec + console em host network; `/waf` via proxy no IP do nó → loopback.
Timer systemd actualiza a partir de `github.com/petterlopes/peritumct-waf-console` `main`.

### Kubernetes + Cilium + Traefik

Clientes (NetBird) → Cilium LB → Traefik:

- Hosts de aplicação + `crowdsec-bouncer` → AppSec/LAPI no nó
- `PathPrefix(/waf)` + middleware admin-only → console no nó (**sem** bouncer)

## Checklist de aceitação

1. `GET /api/health` → `ok`, `oob_log_only`, sem CRS in-band
2. Bind loopback; portas sensíveis fora da Internet pública
3. `/waf` sem middleware bouncer
4. Cores Domains por classe HTTP (2xx verde)
5. Mutações recusam operações CSO proibidas
6. Smoke Rust: `cd rust && cargo test --test unit_smoke --test parity_smoke`
7. Toolchain: Rust **1.98.1**, licença console **GPL-3.0-or-later** (ver [TOOLCHAIN.md](TOOLCHAIN.md) / [NOTICE](../NOTICE))
