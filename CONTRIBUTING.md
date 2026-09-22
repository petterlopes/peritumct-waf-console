# Contributing

Default language for issues, PRs, and code comments is **English**.
`pt-BR` is welcome in `docs/*.pt-BR.md` and `static/locales/pt-BR.json`.

## Development

Runtime is Python 3.12 **stdlib only** (`app.py`, `control.py`, `catalog.py`).
Do not add production PyPI dependencies without a CSO review.

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
ruff check .
bandit -q -r app.py control.py catalog.py routes.py dashboard.py status.py netguard.py persist.py
```

Homologation expectations (Docker / Podman / Cilium / K8s): [docs/HOMOLOGATION.md](docs/HOMOLOGATION.md).

## Pull requests

- Keep the UI behind loopback; do not weaken `WAF_BIND`
- Do not enable CRS in-band, bot challenge, or `INCLUDE_LARGE_UPLOADS` from the UI
- Update `static/locales/en.json` first, then `pt-BR.json`
- Add or extend tests for validators and catalog loading
