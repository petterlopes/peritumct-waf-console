const $ = (id) => document.getElementById(id)
const views = ["overview", "sites", "map", "decisions", "alerts", "rules", "allowlists", "metrics", "domains", "engine"]
function viewTitles() {
  return {
    overview: t("nav.overview", "Overview"),
    sites: t("nav.sites", "Policies"),
    map: t("nav.map", "Map"),
    decisions: t("nav.decisions", "Decisions"),
    alerts: t("nav.alerts", "Alerts"),
    rules: t("nav.rules", "Rules"),
    allowlists: t("nav.allowlists", "Allowlists"),
    metrics: t("nav.metrics", "Metrics"),
    domains: t("nav.domains", "Domains"),
    engine: t("nav.engine", "Engine")
  }
}
const LAND = [
  "M78 92l38-18 54 8 22 28-10 22-48 10-36-8z",
  "M178 78l92-22 48 18 18 42-28 38-86 12-52-20z",
  "M318 108l70-8 38 22-8 48-54 18-52-14z",
  "M410 128l86 6 48 36-22 58-74 22-62-18-18-48z",
  "M548 148l92-18 46 28 8 52-40 36-86 8-38-24z",
  "M178 198l42 8 18 48-14 62-46 8-28-36z",
  "M248 248l38-6 28 22 6 48-32 18-40-10z",
  "M520 248l58 4 22 28-8 38-48 10-36-16z",
  "M610 268l48 12 18 42-28 18-44-8z",
  "M690 292l42 8 8 28-36 18-28-12z"
]
let cache = { decisions: [], alerts: [], domains: { origin: [], public: [] }, overview: null, coverage: null }

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
  views.forEach((v) => {
    const node = $("view-" + v)
    if (node) node.classList.toggle("hidden", v !== name)
    const btn = document.querySelector('[data-view="' + v + '"]')
    if (btn) btn.classList.toggle("active", v === name)
  })
  $("viewTitle").textContent = viewTitles()[name]
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

function matchesFilter(text) {
  const q = ($("filterBox").value || "").trim().toLowerCase()
  if (!q) return true
  return String(text).toLowerCase().includes(q)
}

function stack(items) {
  if (!items.length) return "<p class='hint'>" + t("empty", "no data") + "</p>"
  return items.map((it) => `<div class="stack-row"><span>${it.l}</span><b>${it.r}</b></div>`).join("")
}

function project(lat, lon) {
  return [((Number(lon) + 180) / 360) * 800, ((90 - Number(lat)) / 180) * 400]
}

function renderMap(svg, payload) {
  if (!svg) return
  const points = (payload && payload.points) || []
  const meridians = []
  for (let x = 0; x <= 800; x += 80) meridians.push(`<line x1="${x}" y1="0" x2="${x}" y2="400" class="graticule"/>`)
  for (let y = 0; y <= 400; y += 40) meridians.push(`<line x1="0" y1="${y}" x2="800" y2="${y}" class="graticule"/>`)
  const land = LAND.map((d) => `<path class="land" d="${d}"/>`).join("")
  const dots = points.map((p) => {
    const [x, y] = project(p.lat, p.lon)
    const r = Math.min(8, 3 + Math.log10(1 + Number(p.capacity || 1)) * 2)
    const cls = p.approx ? "geo-dot approx" : "geo-dot"
    const title = `${p.ip || ""} ${p.cn || ""} ${p.scenario || ""}`.trim()
    return `<circle class="${cls}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(1)}"><title>${title}</title></circle>`
  }).join("")
  svg.innerHTML = `<rect class="ocean" width="800" height="400"/>${meridians.join("")}${land}${dots}`
}

function renderOverview(data) {
  const c = data.counts || {}
  $("kpiDecisions").textContent = c.decisions_local ?? c.decisions ?? "—"
  $("kpiDomains").textContent = (c.domains_ok ?? 0) + "/" + (c.domains ?? 0)
  const pct = c.domains ? Math.round((100 * c.domains_ok) / c.domains) : 0
  setRing("domRing", pct)
  setRing("localRing", c.decisions_local ? Math.min(100, 12 + c.decisions_local * 8) : 8)
  const buckets = hourBuckets(data.alerts)
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
  ;(data.alerts || []).forEach((a) => {
    const ip = ipOf(a)
    if (ip !== "—" && !ips.includes(ip)) ips.push(ip)
  })
  const pad = ips.slice(0, 9)
  while (pad.length < 9) pad.push("—")
  $("ipPad").innerHTML = pad.map((ip) => `<div class="ip-chip">${ip}</div>`).join("")
  const map = data.map || (cache.coverage && cache.coverage.map) || { points: [] }
  renderMap($("mapMini"), map)
  if ($("mapMiniNote")) $("mapMiniNote").textContent = map.note || t("map.note")
  setLive(!data.error && eng.lapi_listen, data.error ? "LAPI: " + data.error : t("live.lapi_up"))
}

function renderMapView(payload) {
  const map = payload || { points: [], countries: [] }
  renderMap($("mapFull"), map)
  $("mapCountries").innerHTML = stack((map.countries || []).map((c) => ({ l: c.cn, r: c.count })))
  $("mapPoints").innerHTML = (map.points || []).map((p) =>
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
  $("allowNote").textContent = data.note || ""
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
  renderMapView(coverage.map)
  renderRules(coverage.rules)
  renderAllowlists(coverage.allowlists)
  renderMetrics(coverage.metrics)
  if (coverage.sites) {
    cache.sites = coverage.sites
    renderSites(coverage.sites)
  }
  if (cache.overview) {
    cache.overview.map = coverage.map
    renderMap($("mapMini"), coverage.map)
  }
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
  const filtered = (items || []).filter((d) => matchesFilter([d.value, d.origin, d.scenario, d.reason].join(" ")))
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
  const filtered = (items || []).filter((a) => matchesFilter([ipOf(a), scenarioOf(a)].join(" ")))
  $("alertsBody").innerHTML = filtered.map((a) => `<tr>
    <td>${fmtTime(a.created_at)}</td>
    <td><code>${ipOf(a)}</code></td>
    <td>${scenarioOf(a)}</td>
    <td>${a.capacity || (a.decisions ? a.decisions.length : "—")}</td>
  </tr>`).join("") || `<tr><td colspan="4">${t("alerts.empty")}</td></tr>`
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

function applyFilter() {
  renderDecisions(cache.decisions)
  renderAlerts(cache.alerts)
}

async function loadCore() {
  const [overview, decisions, alerts, domains, engine] = await Promise.all([
    api("/api/overview"),
    api("/api/decisions"),
    api("/api/alerts"),
    api("/api/domains"),
    api("/api/engine")
  ])
  cache = { ...cache, overview, decisions: decisions.items || [], alerts: alerts.items || [], domains, engine }
  renderOverview(overview)
  renderDecisions(cache.decisions)
  renderAlerts(cache.alerts)
  renderDomains(domains)
  $("enginePre").textContent = JSON.stringify(engine, null, 2)
}

async function loadCoverage() {
  const coverage = await api("/api/coverage")
  applyCoverage(coverage)
}

async function loadAll() {
  try {
    await loadCore()
    await loadCoverage()
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

document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.view))
})
$("refreshBtn").addEventListener("click", loadAll)
$("filterBox").addEventListener("input", applyFilter)
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
setInterval(() => {
  $("clock").textContent = new Date().toLocaleTimeString(localeTag(), { hour12: false })
}, 1000)
if ($("langEn")) $("langEn").addEventListener("click", async () => {
  await loadLocale("en")
  await loadAll()
})
if ($("langPt")) $("langPt").addEventListener("click", async () => {
  await loadLocale("pt-BR")
  await loadAll()
})
;(async () => {
  await loadLocale(detectLocale())
  loadRulesCatalog()
  await loadAll()
})()
setInterval(loadCore, 15000)
setInterval(loadCoverage, 60000)
