#!/usr/bin/env python3
"""Build a compact public-domain country ring set for the WAF console map.

Source: Natural Earth 110m admin-0 (public domain).
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

EPS = 0.55
MIN_AREA = 0.12


def dist(p, a, b):
    if a == b:
        return math.hypot(p[0] - a[0], p[1] - a[1])
    denom = (b[0] - a[0]) ** 2 + (b[1] - a[1]) ** 2
    t = ((p[0] - a[0]) * (b[0] - a[0]) + (p[1] - a[1]) * (b[1] - a[1])) / denom
    t = max(0.0, min(1.0, t))
    x = a[0] + t * (b[0] - a[0])
    y = a[1] + t * (b[1] - a[1])
    return math.hypot(p[0] - x, p[1] - y)


def simplify(ring, eps):
    if len(ring) < 4:
        return ring
    stack = [(0, len(ring) - 1)]
    keep = [False] * len(ring)
    keep[0] = keep[-1] = True
    while stack:
        i, j = stack.pop()
        maxd = -1.0
        idx = None
        a, b = ring[i], ring[j]
        for k in range(i + 1, j):
            d = dist(ring[k], a, b)
            if d > maxd:
                maxd = d
                idx = k
        if idx is not None and maxd > eps:
            keep[idx] = True
            stack.append((i, idx))
            stack.append((idx, j))
    out = [ring[i] for i, flag in enumerate(keep) if flag]
    if out[0] != out[-1]:
        out.append(out[0])
    return out if len(out) >= 4 else ring[:3] + [ring[0]]


def area(ring):
    total = 0.0
    for i in range(len(ring) - 1):
        total += ring[i][0] * ring[i + 1][1] - ring[i + 1][0] * ring[i][1]
    return abs(total) / 2.0


def round_ring(ring):
    out = []
    prev = None
    for lon, lat in ring:
        pt = [round(float(lon), 1), round(float(lat), 1)]
        if prev == pt:
            continue
        out.append(pt)
        prev = pt
    if len(out) >= 2 and out[0] != out[-1]:
        out.append(out[0])
    return out


def box(lon, lat, d=0.45):
    return [
        [round(lon - d, 2), round(lat - d, 2)],
        [round(lon + d, 2), round(lat - d, 2)],
        [round(lon + d, 2), round(lat + d, 2)],
        [round(lon - d, 2), round(lat + d, 2)],
        [round(lon - d, 2), round(lat - d, 2)],
    ]


def main():
    src = Path(sys.argv[1])
    dests = [Path(p) for p in sys.argv[2:]]
    geo = json.loads(src.read_text(encoding="utf-8"))
    countries = []
    for feat in geo["features"]:
        props = feat["properties"]
        iso = props.get("ISO_A2") or ""
        if iso in ("-99", "", None):
            iso = props.get("ISO_A2_EH") or ""
        if iso in ("-99", "", None):
            continue
        if iso == "CN-TW":
            iso = "TW"
        name = props.get("NAME") or props.get("ADMIN") or iso
        geom = feat["geometry"]
        polys = []
        if geom["type"] == "Polygon":
            polys = [geom["coordinates"]]
        elif geom["type"] == "MultiPolygon":
            polys = geom["coordinates"]
        rings = []
        for poly in polys:
            if not poly:
                continue
            outer = [(float(x), float(y)) for x, y in poly[0]]
            outer = simplify(outer, EPS)
            outer = round_ring(outer)
            if len(outer) < 4:
                continue
            if area(outer) < MIN_AREA and len(polys) > 1:
                continue
            rings.append(outer)
        if not rings:
            continue
        rings.sort(key=area, reverse=True)
        countries.append({"id": iso, "name": name, "rings": rings[:8]})

    extras = [
        ("SG", "Singapore", box(103.82, 1.35, 0.55)),
        ("HK", "Hong Kong", box(114.17, 22.32, 0.4)),
        ("BH", "Bahrain", box(50.55, 26.07, 0.35)),
        ("MT", "Malta", box(14.4, 35.9, 0.35)),
        ("MV", "Maldives", box(73.51, 4.17, 0.4)),
        ("QA", None, None),
    ]
    have = {c["id"] for c in countries}
    for iso, name, ring in extras:
        if ring is None or iso in have:
            continue
        countries.append({"id": iso, "name": name, "rings": [ring]})
    countries.sort(key=lambda c: c["id"])

    header = (
        "/* Natural Earth 110m admin-0 countries, public domain.\n"
        " * Simplified lon/lat rings for the WAF console Robinson map.\n"
        " */\n"
        "const WORLD_COUNTRIES = "
    )
    body = json.dumps(countries, separators=(",", ":"), ensure_ascii=True)
    text = header + body + "\n"
    for dest in dests:
        dest.write_text(text, encoding="utf-8")
        print(dest, dest.stat().st_size, "countries", len(countries))


if __name__ == "__main__":
    main()
