#!/usr/bin/env bash
# CSO deploy pin bump + FORCE update for rocky-212 waf-console → 2.0.9
set -euo pipefail
PIN="2.0.10"
python3 - <<'PY'
from pathlib import Path
import re
pin = "2.0.10"
for p in [
    Path("/etc/peritumct/crowdsec/docker-compose.yml"),
    Path("/opt/peritumct-waf-console/docker-compose.yml"),
]:
    if not p.is_file():
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    n = re.sub(r'WAF_APP_VERSION:\s*"[^"]+"', f'WAF_APP_VERSION: "{pin}"', t)
    n = re.sub(r'peritumct-waf-console:2\.\d+\.\d+', f'peritumct-waf-console:{pin}', n)
    if n != t:
        p.write_text(n, encoding="utf-8")
        print(f"pinned {p}")
    else:
        print(f"unchanged {p}")
PY
echo "=== pre health ==="
curl -sf --max-time 8 http://127.0.0.1:18990/api/health || echo "health_pre_fail"
echo
echo "=== FORCE update ==="
FORCE=1 /usr/local/bin/update-waf-console.sh
echo "=== post ==="
curl -sf --max-time 15 http://127.0.0.1:18990/api/health
echo
systemctl is-active crowdsec waf-console waf-console-proxy || true
