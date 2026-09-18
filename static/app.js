const $ = (id) => document.getElementById(id)
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]))
}
const views = ["dashboard", "overview", "sites", "map", "decisions", "alerts", "owasp", "mitre", "rules", "allowlists", "metrics", "admin", "domains", "engine", "credits", "privacy", "terms"]
function viewTitles() {
  return {
    dashboard: t("nav.dashboard", "Dashboard"),
    overview: t("nav.overview", "Overview"),
    sites: t("nav.sites", "Policies"),
    map: t("nav.map", "Map"),
    decisions: t("nav.decisions", "Decisions"),
    alerts: t("nav.alerts", "Alerts"),
    owasp: t("nav.owasp", "OWASP"),
    mitre: t("nav.mitre", "MITRE"),
    rules: t("nav.rules", "Rules"),
    allowlists: t("nav.allowlists", "Allowlists"),
    metrics: t("nav.metrics", "Metrics"),
    admin: t("nav.admin", "Admin"),
    domains: t("nav.domains", "Domains"),
    engine: t("nav.engine", "Engine"),
    credits: t("nav.credits", "Credits"),
    privacy: t("nav.privacy", "Privacy"),
    terms: t("nav.terms", "Terms")
  }
}

let cache = { decisions: [], alerts: [], domains: { origin: [], public: [] }, overview: null, coverage: null, correlation: null, dashboard: null }
let owaspSelected = ""
let mitreSelected = ""
let mitreTactic = ""
let dashTab = "security"
let dashPage = { events: 0, logs: 0 }
let dashFilters = { ip: "", path: "", country: "", action: "", method: "" }
let dashGroupBy = ""
let dashOpenRow = ""

function fmtTime(ts) {
  if (!ts) return "—"
  const d = new Date(typeof ts === "number" ? (ts > 1e12 ? ts : ts * 1000) : ts)
  if (Number.isNaN(d.getTime())) return String(ts)
  return d.toLocaleString(localeTag(), { hour12: false })
}

async function api(path, opts) {
  const res = await fetch(BASE + path, Object.assign({ headers: { Accept: "application/json" } }, opts))
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || res.statusText)
  return data
}

function setLive(ok, label) {
  $("liveDot").className = "dot " + (ok ? "ok" : "bad")
  $("liveLabel").textContent = label
}

function showView(name) {
  if (views.indexOf(name) < 0) name = "dashboard"
  views.forEach((v) => {
    const node = $("view-" + v)
    if (node) node.classList.toggle("hidden", v !== name)
  })
  document.querySelectorAll("[data-view]").forEach((btn) => {
    if (btn.classList.contains("brand")) return
    btn.classList.toggle("active", btn.dataset.view === name)
  })
  $("viewTitle").textContent = viewTitles()[name]
  if (location.hash.replace(/^#/, "") !== name) history.replaceState(null, "", "#" + name)
}

function hourBuckets(alerts) {
  const buckets = Array(24).fill(0)
  const now = Date.now()
  ;(alerts || []).forEach((a) => {
    const t = Date.parse(a.created_at || a.timestamp || "") || 0
    if (!t) return
    const h = Math.floor((now - t) / 3600000)
    if (h >= 0 && h < 24) buckets[23 - h] += 1
  })
  return buckets
}

function areaChart(svg, buckets, stroke, fill) {
  const max = Math.max(1, ...buckets)
  const w = 320
  const hgt = 110
  const step = w / Math.max(1, buckets.length - 1)
  const pts = buckets.map((v, i) => {
    const x = i * step
    const y = hgt - 10 - (v / max) * (hgt - 22)
    return [x, y]
  })
  const d = "M " + pts.map((p) => p.join(" ")).join(" L ")
  const area = d + ` L ${w} ${hgt} L 0 ${hgt} Z`
  const id = "g-" + stroke.replace("#", "")
  svg.innerHTML =
    `<defs><linearGradient id="${id}" x1="0" x2="0" y1="0" y2="1">` +
    `<stop offset="0%" stop-color="${fill}" stop-opacity="0.4"/>` +
    `<stop offset="100%" stop-color="${fill}" stop-opacity="0"/></linearGradient></defs>` +
    `<path d="${area}" fill="url(#${id})"></path>` +
    `<path d="${d}" fill="none" stroke="${stroke}" stroke-width="2.4"></path>`
}

function barChart(svg, buckets) {
  const max = Math.max(1, ...buckets)
  const w = 180
  const hgt = 110
  const n = buckets.length
  const gap = 2
  const bw = (w - gap * (n - 1)) / n
  svg.innerHTML = buckets.map((v, i) => {
    const h = Math.max(3, (v / max) * (hgt - 12))
    const x = i * (bw + gap)
    const y = hgt - h
    return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="2" fill="#3ee0ff" opacity="${0.35 + 0.65 * (v / max)}"></rect>`
  }).join("")
}

function setRing(id, pct) {
  const el = $(id)
  if (el) el.setAttribute("stroke-dasharray", Math.max(0, Math.min(100, pct)) + ",100")
}

function scenarioOf(item) {
  return item.scenario || (item.decisions && item.decisions[0] && item.decisions[0].scenario) || item.reason || "—"
}

function ipOf(item) {
  if (item.value) return item.value
  if (item.ip) return item.ip
  if (item.source && item.source.ip) return item.source.ip
  if (item.events && item.events[0] && item.events[0].source && item.events[0].source.ip) return item.events[0].source.ip
  return "—"
}

function selectedIso() {
  return (typeof mapUi !== "undefined" && mapUi && mapUi.selected) || ""
}

function selectedHost() {
  const el = $("domainFilter")
  return el ? (el.value || "").trim().toLowerCase() : ""
}

function hostOf(item) {
  return String((item && (item.host || item.target_fqdn)) || "").toLowerCase()
}

function hostMatch(item) {
  const host = selectedHost()
  if (!host) return true
  const got = hostOf(item)
  return got === host || got.endsWith("." + host)
}

function geoMatch(cn) {
  const iso = selectedIso()
  if (!iso) return true
  return String(cn || "").toUpperCase() === iso.toUpperCase()
}

function countryOf(alert) {
  const src = (alert && alert.source) || {}
  let cn = src.cn || src.country || ""
  if (!cn && alert && alert.events && alert.events[0] && alert.events[0].source) {
    const evSrc = alert.events[0].source
    cn = evSrc.cn || evSrc.country || ""
  }
  if (!cn && alert) cn = alert.cn || ""
  if (!cn) cn = cnOfIp(ipOf(alert))
  return String(cn || "").toUpperCase()
}

function mapPoints() {
  const map = (cache.coverage && cache.coverage.map) || (cache.overview && cache.overview.map) || (typeof mapUi !== "undefined" && mapUi && mapUi.payload) || {}
  return map.points || []
}

function cnOfIp(ip) {
  if (!ip || ip === "—") return ""
  const needle = String(ip).toLowerCase()
  const hit = mapPoints().find((p) => p && String(p.ip || "").toLowerCase() === needle)
  if (hit) return String(hit.cn || "").toUpperCase()
  const findings = (cache.correlation && cache.correlation.findings) || []
  const f = findings.find((x) => x && String(x.ip || "").toLowerCase() === needle)
  return f ? String(f.cn || "").toUpperCase() : ""
}

function matchesFilter(text) {
  const q = ($("filterBox").value || "").trim().toLowerCase()
  if (!q) return true
  return String(text).toLowerCase().includes(q)
}

function attackLink(tid) {
  const mitre = (cache.correlation && cache.correlation.mitre) || {}
  const catalog = mitre.techniques || (cache.correlation && cache.correlation.attack) || []
  const tech = catalog.find((x) => x.id === tid)
  const url = (tech && tech.url) || ("https://attack.mitre.org/techniques/" + String(tid).replace(".", "/") + "/")
  return `<a href="${url}" target="_blank" rel="noopener">${tid}</a>`
}

function renderFilterChip() {
  const chip = $("mapFilterChip")
  const label = $("mapFilterLabel")
  if (!chip) return
  const iso = selectedIso()
  if (!iso) {
    chip.classList.add("hidden")
    return
  }
  const meta = (typeof countryMeta === "function") ? countryMeta(iso) : { name: iso }
  chip.classList.remove("hidden")
  if (label) label.textContent = t("map.filter_chip", "Map: ") + (meta.name || iso)
}

function stack(items) {
  if (!items.length) return "<p class='hint'>" + t("empty", "no data") + "</p>"
  return items.map((it) => `<div class="stack-row"><span>${it.l}</span><b>${it.r}</b></div>`).join("")
}

function renderOverview(data) {
  const c = data.counts || {}
  $("kpiDecisions").textContent = c.decisions_local ?? c.decisions ?? "—"
  $("kpiDomains").textContent = (c.domains_ok ?? 0) + "/" + (c.domains ?? 0)
  const pct = c.domains ? Math.round((100 * c.domains_ok) / c.domains) : 0
  setRing("domRing", pct)
  setRing("localRing", c.decisions_local ? Math.min(100, 12 + c.decisions_local * 8) : 8)
  const alerts = (data.alerts || []).filter((a) => geoMatch(countryOf(a)) && hostMatch(a))
  const buckets = hourBuckets(alerts)
  areaChart($("sparkCyan"), buckets, "#3ee0ff", "#3ee0ff")
  areaChart($("sparkGreen"), buckets, "#3dff9c", "#3dff9c")
  barChart($("bars"), buckets.slice(-12))
  const eng = data.engine || {}
  const rows = [
    ["LAPI", eng.lapi_listen],
    ["AppSec", eng.appsec_listen],
    ["OOB log-only", eng.oob_log_only],
    ["Fail-closed", eng.fail_closed]
  ]
  $("engineProgress").innerHTML = rows.map(([n, ok]) =>
    `<li>${n}<div class="bar"><span style="width:${ok ? 100 : 18}%"></span></div></li>`
  ).join("")
  $("edgeMap").innerHTML = (data.domains || []).map((d) => {
    const ok = d.status === 200
    return `<div class="edge-node"><b>${d.host}</b><span class="${ok ? "ok" : "bad"}">${ok ? "200 origin" : (d.status || d.error || "fail")}</span></div>`
  }).join("")
  $("rtaRings").innerHTML = [
    ["LAPI", eng.lapi_listen],
    ["AppSec", eng.appsec_listen],
    ["Key", eng.bouncer_key_present],
    ["OOB", eng.oob_log_only]
  ].map(([n, ok]) => `
    <div class="rta-item">
      <div class="mini-ring">
        <svg viewBox="0 0 36 36" class="ring">
          <path class="ring-bg" d="M18 2.5a15.5 15.5 0 1 1 0 31 15.5 15.5 0 1 1 0-31"/>
          <path class="ring-fg ${ok ? "green" : "cyan"}" stroke-dasharray="${ok ? 100 : 18},100" d="M18 2.5a15.5 15.5 0 1 1 0 31 15.5 15.5 0 1 1 0-31"/>
        </svg>
        <div class="ring-label">${ok ? "OK" : "NO"}</div>
      </div>
      ${n}
    </div>`).join("")
  const ips = []
  alerts.forEach((a) => {
    const ip = ipOf(a)
    if (ip !== "—" && !ips.includes(ip)) ips.push(ip)
  })
  const pad = ips.slice(0, 9)
  while (pad.length < 9) pad.push("—")
  $("ipPad").innerHTML = pad.map((ip) => `<div class="ip-chip">${ip}</div>`).join("")
  const map = data.map || (cache.coverage && cache.coverage.map) || { points: [] }
  renderMap($("mapMini"), map, { interactive: false })
  if ($("mapMiniNote")) $("mapMiniNote").textContent = t("map.note")
  setLive(!data.error && eng.lapi_listen, data.error ? "LAPI: " + data.error : t("live.lapi_up"))
  renderGaPrecision(cache.correlation, "gaOverview")
  if (cache.correlation) paintMitreOverview(cache.correlation)
}

function renderMapView(payload) {
  const map = payload || { points: [], countries: [] }
  mapUi.payload = map
  renderMap($("mapFull"), map, { interactive: true })
  const selected = mapUi.selected
  $("mapCountries").innerHTML = (map.countries || []).map((c) => {
    const active = selected && geoMatch(c.cn) ? " active" : ""
    const name = (typeof countryMeta === "function" ? countryMeta(c.cn).name : c.cn)
    const gaBit = (c.ga_sessions != null) ? (" · " + t("map.ga", "GA") + " " + c.ga_sessions) : ""
    const vclass = c.ga_verdict ? " ga-" + c.ga_verdict : ""
    return `<button type="button" class="stack-row country-row${active}${vclass}" data-iso="${c.cn}"><span>${name}</span><b>${c.count}${gaBit}</b></button>`
  }).join("") || `<p class="hint">${t("empty", "no data")}</p>`
  $("mapCountries").onclick = (ev) => {
    const btn = ev.target.closest("[data-iso]")
    if (btn) selectCountry(btn.getAttribute("data-iso"))
  }
  const points = (map.points || []).filter((p) => geoMatch(p.cn))
  $("mapPoints").innerHTML = points.map((p) =>
    `<tr><td><code>${p.ip || ""}</code></td><td>${p.cn || ""}</td><td>${p.as_name || ""}</td><td>${p.scenario || ""}</td><td>${p.approx ? t("centroide") : "LAPI"}</td></tr>`
  ).join("") || `<tr><td colspan="5">${t("no_geo")}</td></tr>`
}

function renderRules(rules) {
  rules = rules || {}
  const profiles = rules.profiles || {}
  $("rulesProfiles").innerHTML = stack((profiles.names || []).map((n) => ({ l: n, r: (profiles.on_success || []).join(" / ") || "profile" })))
  $("rulesAppsec").textContent = (rules.appsec && rules.appsec.raw) || JSON.stringify(rules.appsec || {}, null, 2)
  const policy = rules.policy || {}
  $("rulesPolicy").innerHTML = Object.entries(policy)
    .filter(([k]) => k !== "note")
    .map(([k, v]) => `<span class="pill ${v ? "on" : "off"}">${k}: ${Array.isArray(v) ? v.join(", ") : v}</span>`)
    .join("")
  const hub = rules.hub || {}
  $("hubPanels").innerHTML = Object.entries(hub).map(([name, info]) => {
    const items = (info.items || []).slice(0, 8).map((i) => `<div class="stack-row"><span>${i}</span></div>`).join("")
    return `<article class="card host-tile"><div class="card-head"><h2>${name}</h2><span class="tag">${info.count || 0}</span></div>${items || "<p class='hint'>" + t("empty") + "</p>"}</article>`
  }).join("")
}

function renderAllowlists(data) {
  data = data || {}
  $("allowNote").textContent = t("allow.note")
  const lapi = data.lapi || []
  const items = []
  lapi.forEach((x) => {
    (x.items || []).forEach((it) => items.push({ l: (x.name || "allowlist") + " · " + (it.value || it), r: it.description || x.description || "allowlist" }))
    if (!(x.items && x.items.length)) items.push({ l: x.name || JSON.stringify(x).slice(0, 80), r: x.description || "allowlist" })
  })
  $("allowLapi").innerHTML = items.length ? stack(items) : `<p class="hint">LAPI HTTP ${data.lapi_status || "—"}</p>`
  $("allowParser").innerHTML = stack((data.parser_cidrs || []).map((c) => ({ l: c, r: data.parser_file || "parser" })))
}

function renderSites(payload) {
  payload = payload || cache.sites || {}
  const sites = payload.sites || []
  $("sitesBody").innerHTML = sites.map((s) => {
    const n = (s.filters || []).length
    const b = (s.traefik && s.traefik.bouncer) || s.bouncer
    return `<tr><td>${s.host}</td><td>${s.kind}</td><td>${s.chain}</td><td class="${b ? "ok" : "bad"}">${b ? "on" : "off"}</td><td>${n}</td></tr>`
  }).join("")
  const oos = payload.out_of_scope || {}
  $("sitesOut").textContent = t("sites.out") + Object.entries(oos).map(([h, why]) => h + " (" + why + ")").join(" · ")
  const sel = $("filterHost")
  if (sel && !sel.dataset.ready) {
    sel.innerHTML = sites.map((s) => `<option value="${s.host}">${s.host}</option>`).join("")
    sel.dataset.ready = "1"
  }
  const all = []
  sites.forEach((s) => (s.filters || []).forEach((f) => all.push(f)))
  window.__policies = {}
  $("filtersBody").innerHTML = all.map((f) => {
    window.__policies[f.id] = f
    const extra = f.path_prefix || f.rule || (f.action === "bypass_host" ? "*" : "")
    const on = f.enabled === false ? "off" : "on"
    const name = f.name || f.id
    return `<tr><td>${name}</td><td>${f.host}</td><td>${f.action} <span class="tag">${on}</span></td><td><code>${extra}</code></td><td>${f.reason || ""}</td><td>
      <button data-fedit="${f.id}">${t("policy.edit_btn")}</button>
      <button data-ftoggle="${f.id}" data-fen="${f.enabled === false}">${f.enabled === false ? "On" : "Off"}</button>
      <button data-fdel="${f.id}">${t("policy.delete_btn")}</button>
    </td></tr>`
  }).join("") || `<tr><td colspan="6">${t("policy.empty")}</td></tr>`
}

function resetPolicyForm() {
  const form = $("filterForm")
  if (!form) return
  form.reset()
  $("policyId").value = ""
  $("policyFormTitle").textContent = t("policy.new")
  $("filterSubmit").textContent = t("policy.create")
  $("filterCancel").classList.add("hidden")
}

function fillPolicyForm(item) {
  const form = $("filterForm")
  if (!form || !item) return
  form.elements.id.value = item.id || ""
  form.elements.name.value = item.name || ""
  form.elements.host.value = item.host || ""
  form.elements.action.value = item.action || "allow_match"
  form.elements.path_prefix.value = item.path_prefix || ""
  form.elements.rule.value = item.rule || ""
  form.elements.reason.value = item.reason || ""
  form.elements.confirm.checked = item.action === "bypass_host"
  $("policyFormTitle").textContent = t("policy.edit")
  $("filterSubmit").textContent = t("policy.save")
  $("filterCancel").classList.remove("hidden")
  form.scrollIntoView({ behavior: "smooth", block: "center" })
}

function applyCoverage(coverage) {
  cache.coverage = coverage
  renderRules(coverage.rules)
  renderAllowlists(coverage.allowlists)
  renderMetrics(coverage.metrics)
  if (coverage.sites) {
    cache.sites = coverage.sites
    renderSites(coverage.sites)
  }
  if (coverage.correlation) cache.correlation = coverage.correlation
  if (coverage.map) {
    if (typeof mapUi !== "undefined") mapUi.payload = coverage.map
    if (cache.overview) cache.overview.map = coverage.map
  }
  applyFilter()
}

function renderMetrics(mx) {
  mx = mx || {}
  if (!mx.ok) {
    $("mxLocal").textContent = "—"
    $("mxCapi").textContent = "—"
    $("mxBlock").textContent = "—"
    $("mxOrigins").innerHTML = `<p class="hint">${mx.error || t("mx.down")}</p>`
    $("metricsBody").innerHTML = ""
    return
  }
  $("mxLocal").textContent = Math.round(mx.local_decisions || 0)
  $("mxCapi").textContent = Math.round(mx.capi_decisions || 0)
  const blocks = (mx.appsec && (mx.appsec.cs_appsec_block_total || mx.appsec.cs_appsec_blocks_total)) || 0
  $("mxBlock").textContent = Math.round(blocks)
  $("mxOrigins").innerHTML = stack(Object.entries(mx.decisions_by_origin || {}).map(([k, v]) => ({ l: k, r: Math.round(v) })))
  $("mxAlerts").innerHTML = stack((mx.top_alerts || []).map((a) => ({ l: a.reason, r: Math.round(a.count) })))
  $("metricsBody").innerHTML = Object.entries(mx.gauges || {}).map(([k, v]) =>
    `<tr><td>${k}</td><td>${Math.round(v)}</td></tr>`
  ).join("") || `<tr><td colspan="2">${t("mx.empty")}</td></tr>`
}

function renderDecisions(items) {
  const iso = selectedIso()
  const filtered = (items || []).filter((d) => {
    if (!matchesFilter([d.value, d.origin, d.scenario, d.reason].join(" "))) return false
    if (!iso) return true
    return geoMatch(cnOfIp(d.value || d.ip || ""))
  })
  $("decisionsBody").innerHTML = filtered.map((d) => {
    const ip = d.value || d.ip || "—"
    return `<tr>
      <td><code>${ip}</code></td>
      <td>${d.origin || "—"}</td>
      <td>${d.type || d.action || "ban"}</td>
      <td>${d.scenario || d.reason || "—"}</td>
      <td>${d.until || d.duration || "—"}</td>
      <td>${ip !== "—" ? `<button data-unban="${ip}">Unban</button>` : ""}</td>
    </tr>`
  }).join("") || `<tr><td colspan="6">${t("decisions.empty")}</td></tr>`
}

function renderAlerts(items) {
  const filtered = (items || []).filter((a) => matchesFilter([ipOf(a), scenarioOf(a), countryOf(a), hostOf(a)].join(" ")) && geoMatch(countryOf(a)) && hostMatch(a))
  $("alertsBody").innerHTML = filtered.map((a) => `<tr>
    <td>${fmtTime(a.created_at)}</td>
    <td><code>${ipOf(a)}</code></td>
    <td>${countryOf(a) || "—"}</td>
    <td>${scenarioOf(a)}</td>
    <td>${a.capacity || (a.decisions ? a.decisions.length : "—")}</td>
  </tr>`).join("") || `<tr><td colspan="5">${t("alerts.empty")}</td></tr>`
}

function renderOwasp(data) {
  data = data || cache.correlation || {}
  const cats = data.owasp || []
  const max = Math.max(1, ...cats.map((c) => c.count || 0))
  const tiles = $("owaspTiles")
  if (tiles) {
    tiles.innerHTML = cats.map((c) => {
      const hot = (c.count || 0) > 0
      const pct = Math.round((100 * (c.count || 0)) / max)
      const rules = (c.hub_rules || []).slice(0, 3).join(", ")
      const active = owaspSelected === c.code ? " active" : ""
      return `<button type="button" class="owasp-tile${hot ? " hot" : ""}${active}" data-owasp="${c.code}">
        <b>${c.code}</b>
        <span>${c.name || ""}</span>
        <strong>${c.count || 0}</strong>
        <div class="owasp-bar"><span style="width:${pct}%"></span></div>
        <small>${rules || t("owasp.no_rules", "no hub rules")}</small>
      </button>`
    }).join("")
    tiles.onclick = (ev) => {
      const tile = ev.target.closest("[data-owasp]")
      if (!tile) return
      const code = tile.getAttribute("data-owasp")
      owaspSelected = owaspSelected === code ? "" : code
      renderOwasp(cache.correlation)
    }
  }
  const findings = (data.findings || []).filter((f) => {
    if (owaspSelected && f.owasp !== owaspSelected) return false
    if (!geoMatch(f.cn)) return false
    if (!hostMatch(f)) return false
    return matchesFilter([f.when, f.ip, f.cn, f.scenario, f.owasp, (f.attack || []).join(" "), f.confidence].join(" "))
  })
  const body = $("owaspFindings")
  if (body) {
    body.innerHTML = findings.map((f) => `<tr>
      <td>${fmtTime(f.when)}</td>
      <td><code>${f.ip || "—"}</code></td>
      <td>${f.scenario || "—"}${Number(f.events) > 1 ? " ×" + f.events : ""}</td>
      <td>${f.owasp || "none"}</td>
      <td>${(f.attack || []).map(attackLink).join(" ") || "—"}</td>
      <td>${f.confidence || "—"}</td>
    </tr>`).join("") || `<tr><td colspan="6">${t("owasp.empty", "No correlated findings")}</td></tr>`
  }
  const attack = $("owaspAttack")
  if (attack) {
    attack.innerHTML = stack((data.attack || []).map((a) => ({
      l: a.id + " " + (a.name || ""),
      r: a.count || 0
    }))) || `<p class="hint">${t("empty")}</p>`
  }
  const conn = $("owaspConnectors")
  if (conn) {
    conn.innerHTML = (data.connectors || []).map((c) => `<tr>
      <td class="connector-type">${c.type || ""}</td>
      <td>${c.name || ""}</td>
      <td>${c.scope || ""}</td>
      <td>${c.status || ""}</td>
      <td>${c.note || ""}</td>
    </tr>`).join("") || `<tr><td colspan="5">${t("empty")}</td></tr>`
  }
  renderGaPrecision(data, "gaPrecision")
}

function renderGaPrecision(data, mountId) {
  const mount = $(mountId)
  if (!mount) return
  const gaData = (data && data.ga) || {}
  if (!gaData.configured) {
    mount.className = "hint muted ga-inactive-line"
    mount.innerHTML = t("ga.inactive", "GA snapshot not loaded — LAPI only. Console never sends traffic to Google.")
    return
  }
  const iso = selectedIso()
  const hosts = (gaData.hosts || []).map((h) => {
    const name = h.host || h
    const sessions = (h.sessions != null) ? h.sessions : ""
    return `<div class="stack-row"><span>${name}</span><b>${sessions} ${t("ga.sessions", "sessions")}</b></div>`
  }).join("") || `<p class="hint">${t("empty")}</p>`
  const countries = (gaData.countries || []).map((c) => {
    const lapi = (c.lapi_count != null) ? c.lapi_count : "—"
    const vclass = c.verdict ? " ga-" + c.verdict : ""
    const highlight = iso && String(c.cn || "").toUpperCase() === iso.toUpperCase() ? " selected" : ""
    return `<div class="stack-row${vclass}${highlight}"><span>${c.cn} · LAPI ${lapi}</span><b>${c.sessions} ${t("ga.sessions", "sessions")} · ${t("ga.density", "density")} ${c.density} · ${c.verdict || ""}</b></div>`
  }).join("") || `<p class="hint">${t("empty")}</p>`
  mount.className = "card"
  mount.innerHTML =
    `<div class="card-head"><h2 data-i18n="ga.title">${t("ga.title", "GA4 precision")}</h2><span class="tag">${t("map.ga", "GA")}</span></div>` +
    `<p class="hint">${gaData.note || t("ga.note")}</p>` +
    `<div class="grid-2"><div><h2>${t("th.host", "Host")}</h2>${hosts}</div><div><h2>${t("map.countries", "Countries")}</h2>${countries}</div></div>`
}

function paintMitreOverview(data) {
  const mount = $("mitreOverview")
  if (!mount) return
  data = data || cache.correlation || {}
  const techniques = ((data.mitre || {}).techniques || []).slice()
  techniques.sort((a, b) => (b.count || 0) - (a.count || 0))
  const top = techniques.slice(0, 8)
  const max = Math.max(1, ...top.map((c) => c.count || 0))
  mount.innerHTML = top.map((c) => {
    const hot = (c.count || 0) > 0
    const pct = Math.round((100 * (c.count || 0)) / max)
    return `<button type="button" class="mitre-tile${hot ? " hot" : ""}" data-mitre-jump="${c.id}">
      <b>${c.id}</b>
      <span>${c.name || ""}</span>
      <small>${c.tactic || ""}</small>
      <strong>${c.count || 0}</strong>
      <div class="owasp-bar"><span style="width:${pct}%"></span></div>
    </button>`
  }).join("") || `<p class="hint">${t("mitre.empty", "No ATT&CK findings")}</p>`
}

function renderMitre(data) {
  data = data || cache.correlation || {}
  paintMitreOverview(data)
  const mitre = data.mitre || {}
  const techniques = mitre.techniques || []
  const tactics = mitre.tactics || []
  const max = Math.max(1, ...techniques.map((c) => c.count || 0))
  const chips = $("mitreTactics")
  if (chips) {
    chips.innerHTML = `<span class="hint">${t("mitre.tactics", "Tactics")}</span>` + tactics.map((tac) => {
      const active = mitreTactic === tac.name ? " active" : ""
      return `<button type="button" class="tactic-chip${active}" data-tactic="${tac.name}">${tac.name}<b>${tac.count || 0}</b></button>`
    }).join("")
    chips.onclick = (ev) => {
      const btn = ev.target.closest("[data-tactic]")
      if (!btn) return
      const name = btn.getAttribute("data-tactic")
      mitreTactic = mitreTactic === name ? "" : name
      renderMitre(cache.correlation)
    }
  }
  const tiles = $("mitreTiles")
  if (tiles) {
    const visible = techniques.filter((c) => !mitreTactic || c.tactic === mitreTactic)
    tiles.innerHTML = visible.map((c) => {
      const hot = (c.count || 0) > 0
      const pct = Math.round((100 * (c.count || 0)) / max)
      const active = mitreSelected === c.id ? " active" : ""
      return `<button type="button" class="mitre-tile${hot ? " hot" : ""}${active}" data-mitre="${c.id}">
        <b>${c.id}</b>
        <span>${c.name || ""}</span>
        <small>${c.tactic || ""}</small>
        <strong>${c.count || 0}</strong>
        <div class="owasp-bar"><span style="width:${pct}%"></span></div>
        <small>${(c.owasp || []).join(" ") || "—"}</small>
      </button>`
    }).join("") || `<p class="hint">${t("mitre.empty", "No ATT&CK findings")}</p>`
    tiles.onclick = (ev) => {
      const tile = ev.target.closest("[data-mitre]")
      if (!tile) return
      const id = tile.getAttribute("data-mitre")
      mitreSelected = mitreSelected === id ? "" : id
      renderMitre(cache.correlation)
    }
  }
  const tacticIds = mitreTactic ? techniques.filter((x) => x.tactic === mitreTactic).map((x) => x.id) : []
  const findings = (mitre.findings || data.findings || []).filter((f) => {
    if (mitreSelected && !(f.attack || []).includes(mitreSelected)) return false
    if (mitreTactic && !(f.attack || []).some((id) => tacticIds.includes(id))) return false
    if (!geoMatch(f.cn)) return false
    if (!hostMatch(f)) return false
    return matchesFilter([f.when, f.ip, f.cn, f.scenario, f.owasp, (f.attack || []).join(" "), f.confidence].join(" "))
  })
  const body = $("mitreFindings")
  if (body) {
    body.innerHTML = findings.map((f) => `<tr>
      <td>${fmtTime(f.when)}</td>
      <td><code>${f.ip || "—"}</code></td>
      <td>${f.cn || "—"}</td>
      <td>${f.scenario || "—"}${Number(f.events) > 1 ? " ×" + f.events : ""}</td>
      <td>${(f.attack || []).map(attackLink).join(" ") || "—"}</td>
      <td>${f.owasp || "none"}</td>
      <td>${f.confidence || "—"}</td>
    </tr>`).join("") || `<tr><td colspan="7">${t("mitre.empty", "No ATT&CK findings")}</td></tr>`
  }
  const uncovered = $("mitreUncovered")
  if (uncovered) {
    const ids = mitre.uncovered || []
    uncovered.innerHTML = ids.length
      ? ids.map((id) => `<span class="pill">${attackLink(id)}</span>`).join("")
      : `<p class="hint">${t("empty")}</p>`
  }
  renderGaPrecision(data, "gaMitre")
}

function renderDomains(data) {
  const pub = {}
  ;(data.public || []).forEach((d) => { pub[d.host] = d })
  $("domainsBody").innerHTML = (data.origin || []).map((d) => {
    const p = pub[d.host] || {}
    const oc = d.status === 200 ? "ok" : "bad"
    const pc = p.status === 200 ? "ok" : "bad"
    return `<tr><td>${d.host}</td><td class="${oc}">${d.status || d.error}</td><td class="${pc}">${p.status || p.error || "—"}</td></tr>`
  }).join("")
  $("hostTiles").innerHTML = (data.origin || []).map((d) => {
    const p = pub[d.host] || {}
    const ok = d.status === 200 && p.status === 200
    return `<article class="card host-tile ${ok ? "glow-green" : ""}">
      <div class="card-head"><h2>${d.host.replace(".neurofocus.com.br", "").replace(".com", "")}</h2><span class="tag ${ok ? "tracking" : ""}">${ok ? "Active" : "Check"}</span></div>
      <div class="kpi ${ok ? "ok" : "bad"}">${d.status || "—"}</div>
      <p>${t("public")} ${p.status || "—"}</p>
    </article>`
  }).join("")
}

function fillDomainFilter(hosts) {
  const sel = $("domainFilter")
  if (!sel) return
  const current = sel.value
  const opts = ["<option value=\"\">" + t("dash.all_domains", "All domains") + "</option>"]
  ;(hosts || []).forEach((h) => {
    opts.push("<option value=\"" + esc(h) + "\">" + esc(h) + "</option>")
  })
  sel.innerHTML = opts.join("")
  const saved = localStorage.getItem("waf-domain-v1") || current || ""
  if (saved && (hosts || []).indexOf(saved) >= 0) sel.value = saved
}

function dashQuery() {
  const q = new URLSearchParams()
  const host = selectedHost()
  if (host) q.set("host", host)
  Object.keys(dashFilters).forEach((k) => {
    if (dashFilters[k]) q.set(k, dashFilters[k])
  })
  const s = q.toString()
  return s ? ("?" + s) : ""
}

function renderDashChips() {
  const el = $("dashFilterChips")
  if (!el) return
  const chips = []
  Object.keys(dashFilters).forEach((k) => {
    if (!dashFilters[k]) return
    chips.push("<span class=\"filter-chip\">" + esc(k) + "=" + esc(dashFilters[k]) + " <button type=\"button\" data-chip=\"" + esc(k) + "\">×</button></span>")
  })
  el.innerHTML = chips.join("")
  el.classList.toggle("hidden", chips.length === 0)
}

function dashLines(svg, series) {
  if (!svg || !series) return
  const ev = series.events || []
  const bl = series.blocked || []
  const lg = series.logged || []
  const max = Math.max(1, ...ev, ...bl, ...lg)
  const w = 720
  const hgt = 160
  const n = Math.max(ev.length, 2)
  const step = w / (n - 1)
  const path = (arr, color) => {
    const pts = arr.map((v, i) => (i * step).toFixed(1) + " " + (hgt - 12 - (v / max) * (hgt - 24)).toFixed(1))
    return "<path d=\"M " + pts.join(" L ") + "\" fill=\"none\" stroke=\"" + color + "\" stroke-width=\"2.2\"></path>"
  }
  svg.innerHTML = path(ev, "#8ea0c0") + path(lg, "#3ee0ff") + path(bl, "#ffb020")
}

function scannerChart(svg, pack) {
  if (!svg || !pack) return
  const ev = pack.events || []
  const src = pack.sources_hourly || []
  const max = Math.max(1, ...ev, ...src)
  const w = 720
  const hgt = 180
  const n = Math.max(ev.length, 2)
  const step = w / (n - 1)
  const path = (arr, color, fill) => {
    const pts = arr.map((v, i) => (i * step).toFixed(1) + " " + (hgt - 14 - (v / max) * (hgt - 28)).toFixed(1))
    const line = "<path d=\"M " + pts.join(" L ") + "\" fill=\"none\" stroke=\"" + color + "\" stroke-width=\"2.2\"></path>"
    if (!fill) return line
    const area = "M 0 " + (hgt - 8) + " L " + pts.join(" L ") + " L " + ((n - 1) * step).toFixed(1) + " " + (hgt - 8) + " Z"
    return "<path d=\"" + area + "\" fill=\"" + fill + "\" opacity=\"0.18\"></path>" + line
  }
  svg.innerHTML = path(ev, "#3ee0ff", "#3ee0ff") + path(src, "#ffb020", "")
}

function topCard(title, pack, key) {
  if (!pack || !pack.available) {
    return "<article class=\"top-card\"><h3>" + title + "</h3><p class=\"na\">" + t("dash.na", "Not in LAPI event meta") + "</p></article>"
  }
  const items = pack.items || []
  const max = Math.max(1, ...items.map((i) => i.count || 0))
  const rows = items.map((i) => {
    const w = Math.round(100 * (i.count || 0) / max)
    const click = key ? " data-filter-key=\"" + esc(key) + "\" data-filter-val=\"" + esc(i.label) + "\"" : ""
    return "<div class=\"bar-row" + (key ? " clickable" : "") + "\"" + click + "><div><div>" + esc(i.label) + "</div><div class=\"track\"><span style=\"width:" + w + "%\"></span></div></div><b>" + i.count + "</b></div>"
  }).join("") || "<p class=\"na\">" + t("empty", "no data") + "</p>"
  return "<article class=\"top-card\"><h3>" + title + "</h3>" + rows + "</article>"
}

function pageSlice(items, key) {
  const size = 10
  const page = dashPage[key] || 0
  const start = page * size
  return { rows: (items || []).slice(start, start + size), page, pages: Math.max(1, Math.ceil((items || []).length / size)), total: (items || []).length }
}

function renderPager(id, key, total) {
  const el = $(id)
  if (!el) return
  const size = 10
  const pages = Math.max(1, Math.ceil(total / size))
  if (dashPage[key] >= pages) dashPage[key] = 0
  el.innerHTML = "<span>" + (dashPage[key] * size + 1) + "–" + Math.min(total, (dashPage[key] + 1) * size) + " / " + total + "</span>" +
    "<button type=\"button\" data-pg=\"" + key + "\" data-d=\"-1\">‹</button>" +
    "<button type=\"button\" data-pg=\"" + key + "\" data-d=\"1\">›</button>"
}

function exportCsv(name, rows, cols) {
  const lines = [cols.join(",")]
  rows.forEach((r) => {
    lines.push(cols.map((c) => "\"" + String(r[c] == null ? "" : r[c]).replace(/\"/g, "\"\"") + "\"").join(","))
  })
  const blob = new Blob([lines.join("\n")], { type: "text/csv" })
  const a = document.createElement("a")
  a.href = URL.createObjectURL(blob)
  a.download = name
  a.click()
  URL.revokeObjectURL(a.href)
}

function groupedEvents(items) {
  if (!dashGroupBy) return items || []
  const groups = {}
  ;(items || []).forEach((r) => {
    const g = r[dashGroupBy] || "—"
    groups[g] = (groups[g] || 0) + 1
  })
  return Object.keys(groups).sort((a, b) => groups[b] - groups[a]).map((label) => ({
    _group: true,
    label,
    count: groups[label]
  }))
}

function detailRow(r, cols) {
  const bits = ["method", "ua", "ja4h", "asn", "zones", "data", "http_version", "rule_ids", "scenario", "scanner"]
    .filter((k) => r[k])
    .map((k) => "<div><span>" + esc(k) + "</span><code>" + esc(r[k]) + "</code></div>")
    .join("")
  return "<tr class=\"dash-detail\"><td colspan=\"" + cols + "\"><div class=\"dash-detail-grid\">" + (bits || "<span class=\"na\">" + t("dash.na", "Not in LAPI event meta") + "</span>") + "</div></td></tr>"
}

function rowKey(r, i) {
  return [r.when, r.ip, r.path, i].join("|")
}

function renderDashboard(data) {
  data = data || cache.dashboard || {}
  if ($("dashNote")) $("dashNote").textContent = data.note || t("dash.note", "LAPI/AppSec events in this window.")
  if ($("dashWindow")) $("dashWindow").textContent = data.window_label || t("dash.window", "Last 24 hours · GMT-3")
  fillDomainFilter(data.hosts || [])
  renderDashChips()
  const k = data.kpis || {}
  if ($("dashKpis")) {
    $("dashKpis").innerHTML =
      "<div class=\"kpi-tile\"><span>" + t("dash.kpi.events", "Events") + "</span><b>" + (k.events ?? 0) + "</b></div>" +
      "<div class=\"kpi-tile orange\"><span>" + t("dash.kpi.blocked", "Blocked") + "</span><b>" + (k.blocked ?? 0) + "</b></div>" +
      "<div class=\"kpi-tile cyan\"><span>" + t("dash.kpi.logged", "Logged (OOB)") + "</span><b>" + (k.logged ?? 0) + "</b></div>" +
      "<div class=\"kpi-tile green\"><span>" + t("dash.kpi.origin", "Origin 200") + "</span><b>" + (k.origin_ok ?? 0) + "/" + (k.origin_n ?? 0) + "</b></div>"
  }
  const tr = data.traffic || {}
  const tot = Math.max(1, tr.total || 0)
  if ($("dashStack")) {
    $("dashStack").innerHTML =
      "<i class=\"blocked\" style=\"width:" + (100 * (tr.blocked || 0) / tot) + "%\"></i>" +
      "<i class=\"logged\" style=\"width:" + (100 * (tr.logged || 0) / tot) + "%\"></i>" +
      "<i class=\"alert\" style=\"width:" + (100 * (tr.alerted || 0) / tot) + "%\"></i>"
  }
  if ($("dashStackLegend")) {
    $("dashStackLegend").innerHTML =
      "<span class=\"leg-blocked\">" + t("dash.kpi.blocked", "Blocked") + " " + (tr.blocked || 0) + "</span>" +
      "<span class=\"leg-logged\">" + t("dash.kpi.logged", "Logged") + " " + (tr.logged || 0) + "</span>" +
      "<span>" + t("dash.kpi.alerts", "Alerts") + " " + (tr.alerted || 0) + "</span>"
  }
  const actions = (data.action_items || []).map((it) =>
    "<div class=\"action-row\"><div><span class=\"sev " + String(it.severity || "").toLowerCase() + "\">" + esc(it.severity || "") + "</span><h3>" + esc(it.title || "") + "</h3><small>" + esc((it.tags || []).join(" · ")) + "</small></div><button type=\"button\" data-viewjump=\"" + esc(it.view || "engine") + "\">" + t("dash.review", "Review") + "</button></div>"
  ).join("") || "<p class=\"hint\">" + t("empty", "no data") + "</p>"
  if ($("dashActions")) $("dashActions").innerHTML = actions
  const tools = (data.detection_tools || []).map((it) =>
    "<div class=\"tool-row\"><div><h3>" + esc(it.name || "") + "</h3><small>" + esc(it.note || "") + "</small></div><span class=\"status " + (it.running ? "on" : "off") + "\">" + (it.running ? t("dash.running", "Running") : t("dash.off", "Off")) + " · " + (it.count || 0) + "</span></div>"
  ).join("")
  if ($("dashTools")) $("dashTools").innerHTML = tools
  dashLines($("dashSeries"), data.series)
  const scanners = data.scanners || {}
  scannerChart($("dashScanners"), scanners)
  if ($("dashScannerPoll")) $("dashScannerPoll").textContent = (scanners.poll_s || 15) + "s"
  if ($("dashScannerKpis")) {
    $("dashScannerKpis").innerHTML =
      "<div class=\"kpi-tile cyan\"><span>" + t("dash.kpi.events", "Events") + "</span><b>" + (scanners.events_total || 0) + "</b></div>" +
      "<div class=\"kpi-tile orange\"><span>" + t("dash.scanners.sources", "Sources") + "</span><b>" + (scanners.sources || 0) + "</b></div>"
  }
  if ($("dashScannerLegend")) {
    $("dashScannerLegend").innerHTML =
      "<span class=\"leg-logged\">" + t("dash.kpi.events", "Events") + "</span>" +
      "<span class=\"leg-blocked\">" + t("dash.scanners.sources", "Sources") + "</span>" +
      "<span>" + esc(scanners.tz || "GMT-3") + "</span>"
  }
  if ($("dashLegend")) {
    $("dashLegend").innerHTML =
      "<span>" + t("dash.kpi.events", "Events") + "</span><span>" + t("dash.kpi.logged", "Logged") + "</span><span>" + t("dash.kpi.blocked", "Blocked") + "</span>" +
      "<span>" + esc((data.series && data.series.tz) || "GMT-3") + "</span>"
  }
  const top = data.top || {}
  if ($("dashTop")) {
    $("dashTop").innerHTML = [
      topCard(t("dash.top.ips", "Source IPs"), top.ips, "ip"),
      topCard(t("dash.top.paths", "Top paths"), top.paths, "path"),
      topCard(t("dash.top.countries", "Countries"), top.countries, "country"),
      topCard(t("dash.top.hosts", "Top hosts"), top.hosts, "host"),
      topCard(t("dash.top.asns", "ASNs"), top.asns, ""),
      topCard(t("dash.top.browsers", "Browsers"), top.browsers, ""),
      topCard(t("dash.top.os", "Operating systems"), top.os, ""),
      topCard(t("dash.top.devices", "Device types"), top.devices, ""),
      topCard(t("dash.top.ua", "User agents"), top.user_agents, ""),
      topCard(t("dash.top.methods", "HTTP methods"), top.methods, "method"),
      topCard(t("dash.top.http", "HTTP versions"), top.http_versions, ""),
      topCard(t("dash.top.ja4h", "JA4H fingerprints"), top.ja4h, ""),
      topCard(t("dash.top.cache", "Cache statuses"), top.cache, ""),
      topCard(t("dash.top.status", "Status codes"), top.status, ""),
      topCard(t("dash.top.zones", "Matched zones"), top.zones, ""),
      topCard(t("dash.top.edge", "WAF edge"), top.datacenters, ""),
      topCard(t("dash.top.services", "Security services"), top.services, ""),
      topCard(t("dash.top.actions", "Security actions"), top.actions, "action")
    ].join("")
  }
  const origin = data.origin || (cache.domains && cache.domains.origin) || []
  const pubMap = {}
  ;((cache.domains && cache.domains.public) || data.public || []).forEach((p) => { pubMap[p.host] = p })
  if ($("dashOriginBody")) {
    $("dashOriginBody").innerHTML = origin.map((d) => {
      const p = pubMap[d.host] || {}
      const oc = d.status === 200 ? "ok" : "bad"
      const pc = p.status === 200 ? "ok" : "bad"
      return "<tr><td>" + esc(d.host) + "</td><td class=\"" + oc + "\">" + esc(d.status || d.error || "—") + "</td><td class=\"" + pc + "\">" + esc(p.status || p.error || "—") + "</td></tr>"
    }).join("") || "<tr><td colspan=\"3\">" + t("empty") + "</td></tr>"
  }
  const perf = data.appsec || {}
  if ($("dashPerfNote") && perf.note) $("dashPerfNote").textContent = perf.note
  if ($("dashPerf")) {
    $("dashPerf").innerHTML = perf.available
      ? ("<div class=\"kpi-tile\"><span>" + t("dash.kpi.inspected", "AppSec inspected") + "</span><b>" + (perf.inspected ?? 0) + "</b></div>" +
         "<div class=\"kpi-tile orange\"><span>" + t("dash.kpi.appsec_blocks", "AppSec blocks") + "</span><b>" + (perf.blocks ?? 0) + "</b></div>" +
         "<div class=\"kpi-tile\"><span>" + t("dash.kpi.rule_hits", "Rule hits") + "</span><b>" + (perf.rule_hits ?? 0) + "</b></div>" +
         "<div class=\"kpi-tile cyan\"><span>" + t("dash.kpi.inband_ms", "In-band ms") + "</span><b>" + (perf.inband_ms ?? 0) + "</b></div>" +
         "<div class=\"kpi-tile\"><span>" + t("dash.kpi.outband_ms", "Out-of-band ms") + "</span><b>" + (perf.outband_ms ?? 0) + "</b></div>")
      : "<p class=\"na\">" + t("dash.na", "Not in LAPI event meta") + "</p>"
  }
  const eventsSrc = groupedEvents(data.events || [])
  const ev = pageSlice(eventsSrc, "events")
  if ($("dashEventsBody")) {
    if (dashGroupBy) {
      $("dashEventsBody").innerHTML = ev.rows.map((r) => "<tr><td colspan=\"6\"><b>" + esc(r.label) + "</b> · " + r.count + "</td></tr>").join("") || "<tr><td colspan=\"6\">" + t("empty") + "</td></tr>"
    } else {
      $("dashEventsBody").innerHTML = ev.rows.map((r, i) => {
        const key = rowKey(r, i)
        const open = dashOpenRow === key ? detailRow(r, 6) : ""
        return "<tr class=\"dash-row\" data-rk=\"" + esc(key) + "\"><td>" + esc(fmtTime(r.when)) + "</td><td>" + esc(r.action || "") + "</td><td>" + esc(r.country || "—") + "</td><td><code>" + esc(r.ip || "") + "</code></td><td>" + esc(r.host || "") + "</td><td>" + esc(r.service || "") + "</td></tr>" + open
      }).join("") || "<tr><td colspan=\"6\">" + t("empty") + "</td></tr>"
    }
  }
  renderPager("dashEventsPager", "events", ev.total)
  const lg = pageSlice(data.logs || [], "logs")
  if ($("dashLogsBody")) {
    $("dashLogsBody").innerHTML = lg.rows.map((r, i) => {
      const key = "log|" + rowKey(r, i)
      const open = dashOpenRow === key ? detailRow(r, 4) : ""
      return "<tr class=\"dash-row\" data-rk=\"" + esc(key) + "\"><td>" + esc(fmtTime(r.when)) + "</td><td><code>" + esc(r.ip || "") + "</code></td><td>" + esc(r.host || "") + "</td><td><code>" + esc(r.path || "") + "</code></td></tr>" + open
    }).join("") || "<tr><td colspan=\"4\">" + t("empty") + "</td></tr>"
  }
  renderPager("dashLogsPager", "logs", lg.total)
}

function showDashTab(name) {
  dashTab = name || "security"
  document.querySelectorAll(".dash-tab").forEach((btn) => btn.classList.toggle("active", btn.dataset.dash === dashTab))
  ;["security", "traffic", "origin", "performance", "events", "logs"].forEach((id) => {
    const node = $("dash-" + id)
    if (node) node.classList.toggle("hidden", id !== dashTab)
  })
}

async function setDashFilter(key, value) {
  if (key === "host") {
    const sel = $("domainFilter")
    if (sel) sel.value = value || ""
    localStorage.setItem("waf-domain-v1", selectedHost())
  } else if (Object.prototype.hasOwnProperty.call(dashFilters, key)) {
    dashFilters[key] = value || ""
  }
  dashPage = { events: 0, logs: 0 }
  try { await loadDashboard() } catch (err) { setLive(false, String(err.message || err)) }
}

async function loadDashboard() {
  cache.dashboard = await api("/api/dashboard" + dashQuery())
  renderDashboard(cache.dashboard)
}

function applyFilter() {
  renderDecisions(cache.decisions)
  renderAlerts(cache.alerts)
  renderOwasp(cache.correlation)
  renderMitre(cache.correlation)
  if (cache.overview) renderOverview(cache.overview)
  if (cache.dashboard) renderDashboard(cache.dashboard)
  const map = (cache.coverage && cache.coverage.map) || (typeof mapUi !== "undefined" && mapUi && mapUi.payload)
  if (map && typeof renderMapView === "function") renderMapView(map)
  renderFilterChip()
  renderGaPrecision(cache.correlation, "gaOverview")
}

function renderAdmin(data) {
  if (!data) return
  const tun = data.local_tunnel || {}
  if ($("adminTunnelCmd") && tun.command) $("adminTunnelCmd").textContent = tun.command
  if ($("adminActions")) {
    $("adminActions").innerHTML = (data.actions || []).map((it) =>
      "<div class=\"action-row\"><div><h3>" + esc(it.title || "") + "</h3><small>" + esc(it.detail || "") + "</small></div><button type=\"button\" data-viewjump=\"" + esc(it.view || "admin") + "\">" + t("admin.open", "Open") + "</button></div>"
    ).join("")
  }
}

async function loadAdmin() {
  const admin = await api("/api/admin")
  cache = { ...cache, admin }
  renderAdmin(admin)
}

async function loadCore() {
  const [overview, decisions, alerts, domains, engine, correlation] = await Promise.all([
    api("/api/overview"),
    api("/api/decisions"),
    api("/api/alerts"),
    api("/api/domains"),
    api("/api/engine"),
    api("/api/correlation")
  ])
  cache = { ...cache, overview, decisions: decisions.items || [], alerts: alerts.items || [], domains, engine, correlation }
  renderOverview(overview)
  renderDomains(domains)
  applyFilter()
  $("enginePre").textContent = JSON.stringify(engine, null, 2)
  await loadDashboard()
}

async function loadCoverage() {
  const coverage = await api("/api/coverage")
  applyCoverage(coverage)
}

async function loadAll() {
  try {
    await loadCore()
    await loadCoverage()
    await loadAdmin()
  } catch (err) {
    setLive(false, String(err.message || err))
  }
}

async function unban(ip) {
  if (!ip) return
  if (!window.confirm(t("decisions.unban_confirm") + ip + "?")) return
  await api("/api/decisions/delete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip })
  })
  await loadAll()
}

document.querySelectorAll("[data-view]").forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.view))
})
window.addEventListener("hashchange", () => {
  const name = location.hash.replace(/^#/, "")
  if (views.indexOf(name) >= 0) showView(name)
})
const mitreOverviewCard = $("mitreOverviewCard")
if (mitreOverviewCard) {
  const openMitre = () => showView("mitre")
  mitreOverviewCard.addEventListener("click", openMitre)
  mitreOverviewCard.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault()
      openMitre()
    }
  })
}
$("refreshBtn").addEventListener("click", loadAll)
$("filterBox").addEventListener("input", applyFilter)
if ($("domainFilter")) $("domainFilter").addEventListener("change", async () => {
  localStorage.setItem("waf-domain-v1", selectedHost())
  dashPage = { events: 0, logs: 0 }
  try { await loadDashboard() } catch (err) { setLive(false, String(err.message || err)) }
  applyFilter()
})
document.querySelectorAll(".dash-tab").forEach((btn) => {
  btn.addEventListener("click", () => showDashTab(btn.dataset.dash))
})
if ($("dashFilterAdd")) $("dashFilterAdd").addEventListener("click", () => {
  const key = ($("dashFilterField") && $("dashFilterField").value) || "ip"
  const val = (($("dashFilterValue") && $("dashFilterValue").value) || "").trim()
  if (!val) return
  setDashFilter(key, val)
})
if ($("dashFilterValue")) $("dashFilterValue").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") {
    ev.preventDefault()
    if ($("dashFilterAdd")) $("dashFilterAdd").click()
  }
})
if ($("dashFilterClear")) $("dashFilterClear").addEventListener("click", async () => {
  dashFilters = { ip: "", path: "", country: "", action: "", method: "" }
  dashPage = { events: 0, logs: 0 }
  try { await loadDashboard() } catch (err) { setLive(false, String(err.message || err)) }
})
if ($("dashFilterChips")) $("dashFilterChips").addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-chip]")
  if (!btn) return
  setDashFilter(btn.getAttribute("data-chip"), "")
})
if ($("dashGroupBy")) $("dashGroupBy").addEventListener("change", () => {
  dashGroupBy = $("dashGroupBy").value || ""
  dashPage = { events: 0, logs: 0 }
  renderDashboard(cache.dashboard)
})
if ($("dashTop")) $("dashTop").addEventListener("click", (ev) => {
  const row = ev.target.closest("[data-filter-key]")
  if (!row) return
  setDashFilter(row.getAttribute("data-filter-key"), row.getAttribute("data-filter-val") || "")
})
if ($("dashCustomRule")) $("dashCustomRule").addEventListener("click", () => showView("sites"))
;["dashEventsBody", "dashLogsBody"].forEach((id) => {
  if (!$(id)) return
  $(id).addEventListener("click", (ev) => {
    const row = ev.target.closest("[data-rk]")
    if (!row) return
    const key = row.getAttribute("data-rk")
    dashOpenRow = dashOpenRow === key ? "" : key
    renderDashboard(cache.dashboard)
  })
})
if ($("dashActions")) $("dashActions").addEventListener("click", (ev) => {
  const jump = ev.target.closest("[data-viewjump]")
  if (jump) showView(jump.getAttribute("data-viewjump"))
})
if ($("adminActions")) $("adminActions").addEventListener("click", (ev) => {
  const jump = ev.target.closest("[data-viewjump]")
  if (jump) showView(jump.getAttribute("data-viewjump"))
})
;["dashEventsPager", "dashLogsPager"].forEach((id) => {
  if (!$(id)) return
  $(id).addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-pg]")
    if (!btn) return
    const key = btn.getAttribute("data-pg")
    const d = Number(btn.getAttribute("data-d") || 0)
    dashPage[key] = Math.max(0, (dashPage[key] || 0) + d)
    renderDashboard(cache.dashboard)
  })
})
if ($("dashExportEvents")) $("dashExportEvents").onclick = () => exportCsv("waf-events.csv", (cache.dashboard && cache.dashboard.events) || [], ["when", "action", "country", "ip", "host", "service", "method", "path"])
if ($("dashExportLogs")) $("dashExportLogs").onclick = () => exportCsv("waf-logs.csv", (cache.dashboard && cache.dashboard.logs) || [], ["when", "ip", "host", "path", "method", "ua"])
if ($("mapFilterClear")) $("mapFilterClear").addEventListener("click", () => {
  if (typeof mapUi !== "undefined") mapUi.selected = ""
  applyFilter()
})
$("unbanForm").addEventListener("submit", (ev) => {
  ev.preventDefault()
  unban(new FormData(ev.target).get("ip"))
})
$("banForm").addEventListener("submit", async (ev) => {
  ev.preventDefault()
  const fd = new FormData(ev.target)
  const ip = fd.get("ip")
  if (!ip || !window.confirm(t("decisions.ban_confirm") + ip + " on local LAPI?")) return
  await api("/api/decisions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, duration: fd.get("duration"), reason: fd.get("reason") })
  })
  await loadAll()
})
$("filterForm").addEventListener("submit", async (ev) => {
  ev.preventDefault()
  const fd = new FormData(ev.target)
  const payload = {
    host: fd.get("host"),
    name: fd.get("name"),
    action: fd.get("action"),
    path_prefix: fd.get("path_prefix"),
    rule: fd.get("rule"),
    reason: fd.get("reason"),
    confirm: fd.get("confirm") === "on"
  }
  const id = (fd.get("id") || "").trim()
  if (id) payload.id = id
  if (payload.action === "bypass_host" && !payload.confirm) {
    alert(t("policy.bypass_need"))
    return
  }
  await api("/api/policies", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
  resetPolicyForm()
  await loadAll()
})
$("filterCancel").addEventListener("click", () => resetPolicyForm())
$("allowAddForm").addEventListener("submit", async (ev) => {
  ev.preventDefault()
  const fd = new FormData(ev.target)
  await api("/api/allowlists/items", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cidr: fd.get("cidr"), reason: fd.get("reason") })
  })
  await loadAll()
})
$("allowDelForm").addEventListener("submit", async (ev) => {
  ev.preventDefault()
  const fd = new FormData(ev.target)
  if (!window.confirm(t("allow.remove_confirm") + fd.get("cidr") + "?")) return
  await api("/api/allowlists/items/delete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cidr: fd.get("cidr") })
  })
  await loadAll()
})
document.addEventListener("click", (ev) => {
  const ip = ev.target && ev.target.getAttribute && ev.target.getAttribute("data-unban")
  if (ip) unban(ip)
  const edit = ev.target && ev.target.getAttribute && ev.target.getAttribute("data-fedit")
  if (edit) fillPolicyForm((window.__policies || {})[edit])
  const del = ev.target && ev.target.getAttribute && ev.target.getAttribute("data-fdel")
  if (del && window.confirm(t("policy.delete_confirm") + del + "?")) {
    api("/api/policies/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: del })
    }).then(() => {
      resetPolicyForm()
      return loadAll()
    })
  }
  const tog = ev.target && ev.target.getAttribute && ev.target.getAttribute("data-ftoggle")
  if (tog) {
    api("/api/filters/toggle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: tog, enabled: ev.target.getAttribute("data-fen") === "true" })
    }).then(loadAll)
  }
})
async function loadRulesCatalog() {
  try {
    const data = await api("/api/hub/appsec-rules")
    $("ruleNames").innerHTML = (data.items || []).map((n) => `<option value="${n}"></option>`).join("")
  } catch (err) {
    /* optional catalog */
  }
}
$("checkForm").addEventListener("submit", async (ev) => {
  ev.preventDefault()
  const ip = new FormData(ev.target).get("ip")
  const data = await api("/api/allowlists/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip })
  })
  const node = $("checkResult")
  node.classList.remove("hidden")
  node.textContent = JSON.stringify(data, null, 2)
})
function currentView() {
  const hash = location.hash.replace(/^#/, "")
  if (views.indexOf(hash) >= 0) return hash
  const active = document.querySelector(".nav-btn.active")
  return (active && active.dataset.view) || "dashboard"
}
setInterval(() => {
  $("clock").textContent = new Date().toLocaleTimeString(localeTag(), { hour12: false })
}, 1000)
if ($("langEn")) $("langEn").addEventListener("click", async () => {
  await loadLocale("en")
  showView(currentView())
  await loadAll()
})
if ($("langPt")) $("langPt").addEventListener("click", async () => {
  await loadLocale("pt-BR")
  showView(currentView())
  await loadAll()
})
;(async () => {
  await loadLocale(detectLocale())
  bindMapChrome()
  const boot = location.hash.replace(/^#/, "")
  if (views.indexOf(boot) >= 0) showView(boot)
  loadRulesCatalog()
  await loadAll()
})()
setInterval(loadCore, 15000)
setInterval(loadCoverage, 60000)
