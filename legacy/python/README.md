# Legacy Python runtime (stdlib-only)

This directory holds the pre-2.0.0 Python console. The production path is the
Rust binary under `../../rust/` (image `CMD` is `/app/waf-console`).

Use only for emergency rollback or parity comparison. Do not deploy Python as
the primary runtime after 2.0.0.

```bash
# Emergency rollback (host network, loopback bind):
cd legacy/python
WAF_BIND=127.0.0.1 WAF_PORT=18990 python3 -u app.py
```

Invariants (unchanged in Rust):

- Loopback bind only
- No CRS in-band / bot challenge
- `/waf` never on CrowdSec bouncer chain
- No secrets in JSON responses
