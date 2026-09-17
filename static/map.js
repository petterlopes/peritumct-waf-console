/* Robinson world map: Natural Earth countries, LAPI choropleth, edge arcs, pan/zoom. */
const MAP_W = 960
const MAP_H = 500
const ROBINSON_X = [1, 0.9986, 0.9954, 0.99, 0.9822, 0.973, 0.96, 0.9427, 0.9216, 0.8962, 0.8679, 0.835, 0.7986, 0.7597, 0.7186, 0.6732, 0.6213, 0.5722, 0.5322]
const ROBINSON_Y = [0, 0.062, 0.124, 0.186, 0.248, 0.31, 0.372, 0.434, 0.4958, 0.5571, 0.6176, 0.6769, 0.7346, 0.7903, 0.8435, 0.8936, 0.9394, 0.9761, 1]
const mapUi = { scale: 1, tx: 0, ty: 0, selected: "", arcs: true, drag: null, moved: 0, payload: null }

function mapEl(id) { return document.getElementById(id) }

function lerp(a, b, t) { return a + (b - a) * t }

function project(lat, lon) {
  lat = Number(lat)
  lon = Number(lon)
  const absLat = Math.min(90, Math.abs(lat))
  const idx = absLat / 5
  const i = Math.min(17, Math.floor(idx))
  const t = idx - i
  const X = lerp(ROBINSON_X[i], ROBINSON_X[i + 1], t)
  const Y = lerp(ROBINSON_Y[i], ROBINSON_Y[i + 1], t)
  const x = 0.8487 * X * (lon * Math.PI / 180)
  const y = 1.3523 * Y * (lat >= 0 ? 1 : -1)
  const xMax = 0.8487 * Math.PI
  const yMax = 1.3523
  const pad = 18
  const s = Math.min((MAP_W - 2 * pad) / (2 * xMax), (MAP_H - 2 * pad) / (2 * yMax))
  return [MAP_W / 2 + x * s, MAP_H / 2 - y * s]
}

function ringPath(ring) {
  if (!ring || ring.length < 3) return ""
  const pts = ring.map(([lon, lat]) => project(lat, lon))
  return "M " + pts.map((p) => p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" L ") + " Z"
}

function hexMix(a, b, t) {
  const pa = parseInt(a.slice(1), 16)
  const pb = parseInt(b.slice(1), 16)
  const ch = (shift) => Math.round((((pa >> shift) & 255) * (1 - t)) + (((pb >> shift) & 255) * t))
  return "#" + [ch(16), ch(8), ch(0)].map((n) => n.toString(16).padStart(2, "0")).join("")
}

function countryFill(count, max) {
  if (!count) return "#123048"
  const t = Math.max(0.18, Math.min(1, Math.log10(1 + count) / Math.log10(1 + Math.max(max, 2))))
  return hexMix("#1a4d6e", "#3ee0ff", t)
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")
}

function worldList() {
  return (typeof WORLD_COUNTRIES === "undefined" ? [] : WORLD_COUNTRIES) || []
}

function countryMeta(iso) {
  const hit = worldList().find((c) => c.id === iso)
  if (!hit) return { id: iso, name: iso, short: iso }
  const short = hit.name
    .replace("United States of America", "United States")
    .replace("United Kingdom", "UK")
    .replace("Dem. Rep. Congo", "DR Congo")
    .replace("Central African Rep.", "CAR")
    .replace("Fr. S. Antarctic Lands", "TAAF")
  return { id: iso, name: hit.name, short: short.length > 18 ? iso : short }
}

function greatCircle(lat1, lon1, lat2, lon2, steps) {
  const toR = Math.PI / 180
  const p1 = [Math.cos(lat1 * toR) * Math.cos(lon1 * toR), Math.cos(lat1 * toR) * Math.sin(lon1 * toR), Math.sin(lat1 * toR)]
  const p2 = [Math.cos(lat2 * toR) * Math.cos(lon2 * toR), Math.cos(lat2 * toR) * Math.sin(lon2 * toR), Math.sin(lat2 * toR)]
  const dot = Math.max(-1, Math.min(1, p1[0] * p2[0] + p1[1] * p2[1] + p1[2] * p2[2]))
  const omega = Math.acos(dot)
  const out = []
  if (!(omega > 1e-6)) return [[lon1, lat1], [lon2, lat2]]
  for (let i = 0; i <= steps; i++) {
    const t = i / steps
    const a = Math.sin((1 - t) * omega) / Math.sin(omega)
    const b = Math.sin(t * omega) / Math.sin(omega)
    const x = a * p1[0] + b * p2[0]
    const y = a * p1[1] + b * p2[1]
    const z = a * p1[2] + b * p2[2]
    out.push([Math.atan2(y, x) / toR, Math.atan2(z, Math.hypot(x, y)) / toR])
  }
  return out
}

function arcPath(lat1, lon1, lat2, lon2) {
  const pts = greatCircle(lat1, lon1, lat2, lon2, 28).map(([lon, lat]) => project(lat, lon))
  return "M " + pts.map((p) => p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" L ")
}

function graticule() {
  const lines = []
  for (let lon = -180; lon <= 180; lon += 30) {
    const pts = []
    for (let lat = -80; lat <= 80; lat += 5) pts.push(project(lat, lon))
    lines.push(`<polyline class="graticule${lon === 0 ? " meridian0" : ""}" points="${pts.map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ")}"/>`)
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const pts = []
    for (let lon = -180; lon <= 180; lon += 5) pts.push(project(lat, lon))
    lines.push(`<polyline class="graticule${lat === 0 ? " equator" : ""}" points="${pts.map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ")}"/>`)
  }
  return lines.join("")
}

function applyMapTransform(svg) {
  const g = svg && svg.querySelector(".map-scene")
  if (!g) return
  g.setAttribute("transform", `translate(${mapUi.tx} ${mapUi.ty}) scale(${mapUi.scale})`)
}

function zoomMap(factor, cx, cy) {
  const svg = mapEl("mapFull")
  const next = Math.max(1, Math.min(8, mapUi.scale * factor))
  const originX = cx == null ? MAP_W / 2 : cx
  const originY = cy == null ? MAP_H / 2 : cy
  if (next <= 1.001) {
    mapUi.scale = 1
    mapUi.tx = 0
    mapUi.ty = 0
  } else {
    mapUi.tx = originX - ((originX - mapUi.tx) * next) / mapUi.scale
    mapUi.ty = originY - ((originY - mapUi.ty) * next) / mapUi.scale
    mapUi.scale = next
  }
  applyMapTransform(svg)
}

function showMapTip(html, ev) {
  const tip = mapEl("mapTip")
  if (!tip) return
  if (!html) {
    tip.classList.add("hidden")
    tip.innerHTML = ""
    return
  }
  tip.innerHTML = html
  tip.classList.remove("hidden")
  const x = Math.min(window.innerWidth - 240, (ev.clientX || 0) + 14)
  const y = Math.min(window.innerHeight - 90, (ev.clientY || 0) + 14)
  tip.style.left = x + "px"
  tip.style.top = y + "px"
}

function selectCountry(iso) {
  iso = (iso || "").toUpperCase()
  if (mapUi.selected && mapUi.selected === iso) iso = ""
  mapUi.selected = iso
  const box = mapEl("filterBox")
  if (box) box.value = iso
  if (typeof applyFilter === "function") {
    applyFilter()
    return
  }
  if (typeof renderMapView === "function" && mapUi.payload) renderMapView(mapUi.payload)
  if (typeof renderMap === "function" && mapEl("mapMini") && mapUi.payload) renderMap(mapEl("mapMini"), mapUi.payload, { interactive: false })
}

function bindMapSvg(svg, interactive) {
  if (!svg || svg.dataset.bound === "1") return
  svg.dataset.bound = "1"
  svg.addEventListener("pointerdown", (ev) => {
    if (!interactive || ev.button !== 0) return
    mapUi.moved = 0
    mapUi.drag = { x: ev.clientX, y: ev.clientY, tx: mapUi.tx, ty: mapUi.ty }
    svg.setPointerCapture(ev.pointerId)
  })
  svg.addEventListener("pointermove", (ev) => {
    if (!mapUi.drag) return
    mapUi.moved += Math.hypot(ev.clientX - mapUi.drag.x, ev.clientY - mapUi.drag.y)
    mapUi.tx = mapUi.drag.tx + (ev.clientX - mapUi.drag.x)
    mapUi.ty = mapUi.drag.ty + (ev.clientY - mapUi.drag.y)
    applyMapTransform(svg)
  })
  const endDrag = () => { mapUi.drag = null }
  svg.addEventListener("pointerup", endDrag)
  svg.addEventListener("pointercancel", endDrag)
  svg.addEventListener("wheel", (ev) => {
    if (!interactive) return
    ev.preventDefault()
    const rect = svg.getBoundingClientRect()
    const px = ((ev.clientX - rect.left) / rect.width) * MAP_W
    const py = ((ev.clientY - rect.top) / rect.height) * MAP_H
    zoomMap(ev.deltaY < 0 ? 1.18 : 0.85, px, py)
  }, { passive: false })
}

function layoutLabels(countries) {
  const placed = []
  countries.slice().sort((a, b) => (b.count || 0) - (a.count || 0)).slice(0, 10).forEach((c) => {
    if (!Number.isFinite(Number(c.lat)) || !Number.isFinite(Number(c.lon))) return
    let [x, y] = project(Number(c.lat), Number(c.lon))
    let dy = 0
    for (let n = 0; n < 8 && placed.some((p) => Math.hypot(p.x - x, p.y - (y + dy)) < 28); n++) {
      dy = dy <= 0 ? Math.abs(dy) + 13 : -dy
    }
    y += dy
    placed.push({ cn: c.cn, count: c.count, x, y, city: c.city, meta: countryMeta(c.cn) })
  })
  return placed
}

function renderMap(svg, payload, opts) {
  if (!svg) return
  mapUi.payload = payload || mapUi.payload
  const interactive = !!(opts && opts.interactive)
  const points = (payload && payload.points) || []
  const countries = (payload && payload.countries) || []
  const edge = payload && payload.edge
  const max = countries.reduce((n, c) => Math.max(n, Number(c.count) || 0), 0)
  const byIso = {}
  countries.forEach((c) => { byIso[(c.cn || "").toUpperCase()] = c })
  const land = worldList().map((c) => {
    const hit = byIso[c.id] || {}
    const count = Number(hit.count) || 0
    const sel = mapUi.selected && mapUi.selected === c.id
    const d = (c.rings || []).map(ringPath).join(" ")
    const meta = countryMeta(c.id)
    return `<path class="country${count ? " hot" : ""}${sel ? " selected" : ""}" data-iso="${c.id}" data-name="${escapeHtml(meta.name)}" data-count="${count}" fill="${countryFill(count, max)}" d="${d}"/>`
  }).join("")
  let arcs = ""
  if (mapUi.arcs && edge && Number.isFinite(Number(edge.lat)) && Number.isFinite(Number(edge.lon))) {
    const seen = {}
    points.slice(0, 18).forEach((p) => {
      const key = (p.cn || p.ip || "") + ":" + Math.round(Number(p.lat)) + "," + Math.round(Number(p.lon))
      if (seen[key]) return
      seen[key] = 1
      const d = arcPath(Number(edge.lat), Number(edge.lon), Number(p.lat), Number(p.lon))
      arcs += `<path class="map-arc-glow" d="${d}"/><path class="map-arc" d="${d}"/>`
    })
  }
  const dots = points.map((p) => {
    const lat = Number(p.lat)
    const lon = Number(p.lon)
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return ""
    const [x, y] = project(lat, lon)
    const r = Math.min(7.5, 2.4 + Math.log10(1 + Number(p.capacity || 1)) * 2)
    const cls = p.approx ? "geo-dot approx" : "geo-dot"
    return `<circle class="${cls}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(1)}" data-ip="${escapeHtml(p.ip)}" data-cn="${escapeHtml(p.cn)}" data-city="${escapeHtml(p.city)}" data-as="${escapeHtml(p.as_name)}" data-sc="${escapeHtml(p.scenario)}" data-geo="${p.approx ? "centroid" : "LAPI"}"/>`
  }).join("")
  let edgeMark = ""
  if (edge && Number.isFinite(Number(edge.lat))) {
    const [x, y] = project(Number(edge.lat), Number(edge.lon))
    edgeMark = `<circle class="edge-dot" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="5"/><text class="map-label edge" x="${(x + 8).toFixed(1)}" y="${(y - 8).toFixed(1)}">${escapeHtml(edge.label || t("map.edge", "Edge"))}</text>`
  }
  const labels = interactive
    ? layoutLabels(countries).map((c) => {
      const text = c.city || c.meta.short
      return `<text class="map-label" x="${c.x.toFixed(1)}" y="${c.y.toFixed(1)}">${escapeHtml(text)}</text>`
    }).join("")
    : ""
  svg.setAttribute("viewBox", "0 0 " + MAP_W + " " + MAP_H)
  svg.setAttribute("preserveAspectRatio", "xMidYMid meet")
  svg.innerHTML = `<defs>
    <radialGradient id="oceanGrad" cx="50%" cy="46%" r="68%">
      <stop offset="0%" stop-color="#0e2a44"/>
      <stop offset="100%" stop-color="#061018"/>
    </radialGradient>
  </defs>
  <g class="map-scene">
    <rect class="ocean" width="${MAP_W}" height="${MAP_H}" fill="url(#oceanGrad)"/>
    ${graticule()}${land}${arcs}${dots}${edgeMark}${labels}
  </g>`
  applyMapTransform(svg)
  bindMapSvg(svg, interactive)
  svg.onmousemove = (ev) => {
    const country = ev.target.closest && ev.target.closest(".country")
    const dot = ev.target.closest && ev.target.closest(".geo-dot")
    if (dot) {
      const city = dot.getAttribute("data-city")
      const place = [dot.getAttribute("data-cn"), city].filter(Boolean).join(" · ")
      showMapTip(`<b>${escapeHtml(dot.getAttribute("data-ip"))}</b><span>${escapeHtml(place)} · ${escapeHtml(dot.getAttribute("data-geo"))}</span><span>${escapeHtml(dot.getAttribute("data-as"))}</span><span>${escapeHtml(dot.getAttribute("data-sc"))}</span>`, ev)
      return
    }
    if (country) {
      const n = country.getAttribute("data-count") || "0"
      showMapTip(`<b>${escapeHtml(country.getAttribute("data-name"))}</b><span>${escapeHtml(country.getAttribute("data-iso"))} · ${n} ${t("map.alerts", "alerts")}</span>`, ev)
      return
    }
    showMapTip("", ev)
  }
  svg.onmouseleave = () => showMapTip("", {})
  svg.onclick = (ev) => {
    if (mapUi.moved > 8) return
    const country = ev.target.closest && ev.target.closest(".country")
    if (country) selectCountry(country.getAttribute("data-iso"))
  }
  const legend = mapEl("mapLegend")
  if (legend && interactive) {
    legend.innerHTML = `<span>${t("map.legend_none", "No alerts")}</span><i></i><i></i><i></i><i></i><span>${t("map.legend_high", "High")}</span>`
  }
}

function bindMapChrome() {
  if (mapEl("mapZoomIn")) mapEl("mapZoomIn").onclick = () => zoomMap(1.35)
  if (mapEl("mapZoomOut")) mapEl("mapZoomOut").onclick = () => zoomMap(0.74)
  if (mapEl("mapReset")) mapEl("mapReset").onclick = () => {
    mapUi.scale = 1
    mapUi.tx = 0
    mapUi.ty = 0
    mapUi.selected = ""
    if (mapEl("filterBox")) mapEl("filterBox").value = ""
    if (typeof applyFilter === "function") applyFilter()
    else if (mapUi.payload && typeof renderMapView === "function") renderMapView(mapUi.payload)
  }
  if (mapEl("mapArcs")) mapEl("mapArcs").onclick = () => {
    mapUi.arcs = !mapUi.arcs
    mapEl("mapArcs").classList.toggle("active", mapUi.arcs)
    if (mapUi.payload) {
      if (mapEl("mapFull")) renderMap(mapEl("mapFull"), mapUi.payload, { interactive: true })
      if (mapEl("mapMini")) renderMap(mapEl("mapMini"), mapUi.payload, { interactive: false })
    }
  }
}
