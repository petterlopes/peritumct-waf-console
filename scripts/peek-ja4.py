#!/usr/bin/env python3
import json, urllib.request
from collections import Counter
alerts = json.loads(urllib.request.urlopen("http://127.0.0.1:18990/api/alerts", timeout=30).read().decode()).get("items") or []
ja4 = Counter(); methods = Counter(); uas = Counter(); asns = Counter()
for a in alerts:
    mm = {}
    for row in a.get("meta") or []:
        if isinstance(row, dict):
            mm[str(row.get("key") or "")] = str(row.get("value") or "")
    if mm.get("ja4h"):
        ja4[mm["ja4h"][:24]] += 1
    if mm.get("method"):
        methods[mm["method"]] += 1
    if mm.get("user_agent"):
        uas[mm["user_agent"][:80]] += 1
    src = a.get("source") or {}
    if src.get("as_name") or src.get("as_number"):
        asns[str(src.get("as_name") or src.get("as_number"))] += 1
print("methods", methods)
print("ja4", ja4.most_common(8))
print("uas", uas.most_common(6))
print("asns", asns.most_common(6))
print("n", len(alerts))
