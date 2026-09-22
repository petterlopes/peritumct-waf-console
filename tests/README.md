# Python unit tests (legacy)

These tests target `legacy/python/`. From repo root:

```bash
cd legacy/python
PYTHONPATH=. python -m unittest discover -s tests -v
```

Rust smoke tests (primary):

```bash
cd rust && cargo test --test unit_smoke --test parity_smoke
```
