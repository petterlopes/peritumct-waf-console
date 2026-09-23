# Contributing

Default language for issues, PRs, and code comments is **English**.
`pt-BR` is welcome in `docs/*.pt-BR.md` and `static/locales/pt-BR.json`.

## License

This project is **GPL-3.0-or-later**. Contributions are accepted under the same
license. Do not add MIT-only dual-license requirements for first-party code.

## Development (Rust — primary)

Requires **rustc ≥ 1.98.1** (see [docs/TOOLCHAIN.md](docs/TOOLCHAIN.md)).

```bash
cd rust
cargo test --test unit_smoke --test parity_smoke
cargo clippy --all-targets -- -W clippy::correctness
```

Container:

```bash
docker compose -f docker-compose.example.yml build
# or Podman on rocky-style hosts
```

Homologation expectations (Docker / Podman / Cilium / K8s): [docs/HOMOLOGATION.md](docs/HOMOLOGATION.md).

## Legacy Python (rollback only)

`legacy/python/` is not the production path. Optional local checks:

```bash
cd legacy/python
PYTHONPATH=. python -m unittest discover -s tests -v
```

## Pull requests

- Keep the UI behind loopback; do not weaken `WAF_BIND`
- Prefer `CROWDSEC_LAPI=http://127.0.0.1:18080` when host LAPI is remapped from `:8080`
- Do not enable CRS in-band, bot challenge, or `INCLUDE_LARGE_UPLOADS` from the UI
- Update `static/locales/en.json` first, then `pt-BR.json`
- Add or extend Rust smoke tests under `rust/tests/`
- Keep Docker builder on `rust:1.98.1-bookworm` (or newer **patch** on the same minor after CSO review)
