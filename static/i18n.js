const BASE = "/waf"
const I18N = {
  defaultLocale: "en",
  fallback: "en",
  supported: ["en", "pt-BR"],
  storageKey: "waf-locale-v2",
  dict: {},
  locale: "en"
}

function detectLocale() {
  const stored = localStorage.getItem(I18N.storageKey)
  if (stored && I18N.supported.includes(stored)) return stored
  return I18N.defaultLocale
}

function t(key, fallback) {
  const value = I18N.dict[key]
  if (value != null && value !== "") return value
  return fallback != null ? fallback : key
}

function applyI18n() {
  document.documentElement.lang = t("html_lang", I18N.locale)
  document.title = t("title", "WAF Console · CrowdSec")
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"))
  })
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")))
  })
  const en = document.getElementById("langEn")
  const pt = document.getElementById("langPt")
  if (en && pt) {
    en.classList.toggle("active", I18N.locale === "en")
    pt.classList.toggle("active", I18N.locale === "pt-BR")
    en.setAttribute("aria-pressed", I18N.locale === "en" ? "true" : "false")
    pt.setAttribute("aria-pressed", I18N.locale === "pt-BR" ? "true" : "false")
  }
}

async function loadLocale(locale) {
  const chosen = I18N.supported.includes(locale) ? locale : I18N.defaultLocale
  const res = await fetch(BASE + "/locales/" + chosen + ".json", { headers: { Accept: "application/json" } })
  I18N.dict = await res.json()
  I18N.locale = chosen
  localStorage.setItem(I18N.storageKey, chosen)
  applyI18n()
}

function localeTag() {
  return I18N.locale === "pt-BR" ? "pt-BR" : "en-GB"
}
