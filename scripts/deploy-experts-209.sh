#!/usr/bin/env bash
# CSO deploy pin bump + FORCE update for expertsforensic waf-admin → 2.0.9
set -euo pipefail
PIN="2.0.9"
python3 - <<'PY'
from pathlib import Path
import re
pin = "2.0.9"
for p in [
    Path("/root/waf-admin/docker-compose.yml"),
    Path("/srv/waf-admin/docker-compose.yml"),
]:
    if not p.is_file():
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    n = re.sub(r'WAF_APP_VERSION:\s*"[^"]+"', f'WAF_APP_VERSION: "{pin}"', t)
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
if [ -x /usr/local/bin/update-waf-admin.sh ]; then
  FORCE=1 /usr/local/bin/update-waf-admin.sh
elif [ -x /root/waf-admin/update-waf-admin.sh ]; then
  FORCE=1 bash /root/waf-admin/update-waf-admin.sh
else
  bash /root/waf-admin.sh install
fi
echo "=== post ==="
curl -sf --max-time 15 http://127.0.0.1:18990/api/health
echo
