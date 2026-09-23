# Security scanning (SAST / SCA)

## SAST (static application security testing)

| Tool | Scope |
|------|--------|
| `cargo test` | Rust unit / parity smoke (`rust/tests/`) |
| `cargo clippy` | Correctness-oriented lints (CI) |
| `cargo fmt` | Format check (CI, non-blocking) |
| unittest (legacy) | `legacy/python/tests` on `workflow_dispatch` only |

## SCA (software composition analysis)

| Tool | Scope |
|------|--------|
| `cargo audit` | Rust crate advisories (CI optional / best-effort) |
| Trivy image | Multi-stage Docker image in CI — binary pin **v0.74.0** via `trivy-action` `version:` |
| Secret scan | `scripts/verify-no-committed-secrets.sh` |

The CrowdSec engine image (`crowdsecurity/crowdsec`) is operated **beside** this console, not vendored. Track its CVE stream separately when you pin `v1.8.1`.

## GitHub Actions

`.github/workflows/security.yml` runs on push/PR:

1. Rust toolchain **1.98.1** — `cargo test` (unit_smoke + parity_smoke)
2. `cargo clippy` / `cargo fmt` (warnings allowed)
3. Optional `cargo audit`
4. `docker build` + Trivy image (CRITICAL/HIGH) with scanner **[v0.74.0](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0)** (`aquasecurity/trivy-action@v0.36.0`)
5. `scripts/verify-no-committed-secrets.sh`

Dependabot updates GitHub Actions weekly (`.github/dependabot.yml`).

## Operator threats this console does **not** accept

- SSRF via `PUBLIC_IP` / Traefik API / metrics / LAPI: must be loopback URLs or literal IP (validated at startup/use)
- Binding off loopback
- Enabling CRS in-band or bot challenge from the UI
- Putting `/waf` behind the bouncer
- Committing LAPI machine passwords or bouncer keys
