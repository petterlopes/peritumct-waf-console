#!/usr/bin/env python3
import json
import urllib.request
from collections import Counter

def get(path):
    return json.loads(urllib.request.urlopen("http://127.0.0.1:18990" + path, timeout=30).read().decode())

alerts = get("/api/alerts").get("items") or []
keys = Counter()
sample = {}
for a in alerts:
    for ev in a.get("events") or []:
        for row in ev.get("meta") or []:
            if not isinstance(row, dict):
                continue
            k = str(row.get("key") or "")
            v = str(row.get("value") or "")
            keys[k] += 1
            if k not in sample and v:
                sample[k] = v[:120]
    for row in a.get("meta") or []:
        if isinstance(row, dict):
            k = str(row.get("key") or "")
            keys["alert." + k] += 1
print("n_alerts", len(alerts))
print("keys", keys.most_common(50))
print("sample", json.dumps(sample, indent=2)[:4000])
mx = get("/api/metrics")
print("metrics_ok", mx.get("ok"), "appsec", mx.get("appsec"), "top", (mx.get("top_alerts") or [])[:6])
dash = get("/api/dashboard")
print("dash_kpis", dash.get("kpis"))
print("top_available", {k: v.get("available") for k, v in (dash.get("top") or {}).items()})
