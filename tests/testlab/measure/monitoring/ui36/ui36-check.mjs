#!/usr/bin/env node
// D36 independent measurement: browser check of the website-first dashboard
// against a REAL schild instance (not the mock). Logs in (TEST ONLY password),
// opens Websites, switcher, website Überblick (KPIs, chart, markers, alarms,
// panels, click-to-filter), Angriffe, Ausnahmen, Zugriffe, Server, at
// 1440x900 and 375x812; records requests, API JSON answers, console messages,
// page errors and the visible text of every page.
//
//   node ui36-check.mjs <phase> [base-url] [out-dir]
//   phase: snap | main | mobile | watch | extra | off
//
// Env: PW (TEST ONLY password), TAG (snap file prefix), WATCH_S (default 130).
import { existsSync, mkdirSync, readdirSync, writeFileSync, appendFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, resolve } from 'node:path'

const phase = process.argv[2] ?? 'main'
const base = (process.argv[3] ?? 'http://127.0.0.1:19388').replace(/\/$/, '')
const out = resolve(process.argv[4] ?? '.')
const password = process.env.PW || 'schild-d36-messung-TESTONLY'
const tag = process.env.TAG || phase
const watchS = Number(process.env.WATCH_S || 130)
const uiRoot = process.env.UI_ROOT || '/tmp/m21d36/src2/dashboard'
mkdirSync(out, { recursive: true })

function findPlaywright() {
  const pnpm = join(uiRoot, 'node_modules/.pnpm')
  for (const d of readdirSync(pnpm)) if (d.startsWith('playwright@')) {
    const p = join(pnpm, d, 'node_modules/playwright')
    if (existsSync(p)) return p
  }
  throw new Error('no playwright')
}
const require = createRequire(import.meta.url)
const { chromium } = require(findPlaywright())
const browser = await chromium.launch()
const origin = new URL(base).origin
const result = { phase, tag, base, started: new Date().toISOString(), pages: [], checks: {}, errors: [] }
const textsFile = join(out, `texts-${tag}.txt`)
if (phase !== 'snap') writeFileSync(textsFile, '')

async function session(name, viewport) {
  const ctx = await browser.newContext({ viewport, locale: 'de-DE', timezoneId: 'Europe/Berlin' })
  await ctx.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', e => console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`))
  })
  const page = await ctx.newPage()
  const log = { requests: [], console: [], pageErrors: [], json: {} }
  const t0 = Date.now()
  page.on('request', r => log.requests.push({ t: (Date.now() - t0) / 1000, method: r.method(), url: r.url(), type: r.resourceType() }))
  page.on('response', async (r) => {
    const e = log.requests.findLast(x => x.url === r.url() && x.status === undefined)
    if (e) e.status = r.status()
    if (r.url().includes('/api/v0/') && !r.url().includes('/stream') && (r.headers()['content-type'] ?? '').includes('json')) {
      try { log.json[decodeURIComponent(r.url().replace(origin, ''))] = { t: (Date.now() - t0) / 1000, status: r.status(), body: await r.json() } } catch {}
    }
  })
  page.on('requestfailed', (r) => {
    const e = log.requests.findLast(x => x.url === r.url() && x.status === undefined)
    if (e) e.failed = r.failure()?.errorText
  })
  page.on('console', m => log.console.push({ t: (Date.now() - t0) / 1000, type: m.type(), text: m.text() }))
  page.on('pageerror', e => log.pageErrors.push(e.message))
  await page.goto(`${base}/`, { waitUntil: 'domcontentloaded' })
  const pw = page.locator('input[type="password"]').first()
  await pw.waitFor({ timeout: 15000 })
  const fields = await page.locator('input[type="password"]').count()
  for (let i = 0; i < fields; i++) await page.locator('input[type="password"]').nth(i).fill(password)
  await page.locator('button[type="submit"]').first().click()
  await pw.waitFor({ state: 'detached', timeout: 15000 })
  return { ctx, page, log, t0, name }
}

const txt = s => s.replace(/\s+/g, ' ').trim()

async function measure(page) {
  return page.evaluate(() => {
    const d = document.documentElement
    const t = el => el ? el.innerText.replace(/\s+/g, ' ').trim() : null
    const all = s => [...document.querySelectorAll(s)]
    // Elements painted in the danger tone (computed colour close to the theme's danger red).
    const dangerVar = getComputedStyle(d).getPropertyValue('--status-danger').trim() || getComputedStyle(d).getPropertyValue('--destructive').trim()
    const reds = []
    for (const el of all('body *')) {
      const cs = getComputedStyle(el)
      for (const prop of ['color', 'backgroundColor', 'fill', 'stroke', 'borderTopColor']) {
        const v = cs[prop]
        const m = /rgba?\((\d+), (\d+), (\d+)(?:, ([\d.]+))?\)/.exec(v) || /oklch\(([\d.]+) ([\d.]+) ([\d.]+)/.exec(v)
        if (!m) continue
        let red = false
        if (v.startsWith('rgb')) { const [r, g, b, a] = [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]]; red = a > 0.3 && r > 150 && g < 70 && b < 70 }
        else { const [l, c, h] = [+m[1], +m[2], +m[3]]; red = c > 0.12 && (h < 35 || h > 345) && l > 0.3 }
        if (red && el.getBoundingClientRect().width > 0) { reds.push({ tag: el.tagName, prop, v, cls: (el.getAttribute('class') || '').slice(0, 80), text: t(el)?.slice(0, 60) ?? null }); break }
      }
      if (reds.length > 40) break
    }
    return {
      url: location.href,
      title: document.title,
      overflowPx: d.scrollWidth - d.clientWidth,
      h1: t(document.querySelector('h1')),
      cards: all('[data-testid="website-card"]').map(c => ({ id: c.dataset.website, text: t(c) })),
      kpis: all('[data-testid="kpi-row"] [data-kpi]').map(b => ({ key: b.dataset.kpi, value: t(b.querySelector('[data-slot="kpi-value"]')), change: t(b.querySelector('[data-slot="kpi-change"]')), text: t(b), pressed: b.getAttribute('aria-pressed') })),
      chips: all('[data-testid="filter-chips"] [data-filter]').map(c => c.dataset.filter),
      panels: all('[data-testid^="panel-"]').map(p => ({ id: p.dataset.testid, tabs: [...p.querySelectorAll('[role="tab"]')].map(x => ({ k: x.dataset.tab, sel: x.getAttribute('aria-selected') })), rows: [...p.querySelectorAll('tbody tr')].map(r => ({ key: r.dataset.row, text: t(r) })), note: t(p.querySelector('p.mt-2')), unavailable: t(p.querySelector('[data-testid="filter-unavailable"]')), body: [...p.querySelectorAll('tbody tr')].length ? null : t(p) })),
      alerts: t(document.querySelector('[data-testid="alerts-card"]'))?.slice(0, 1500) ?? null,
      markers: all('[data-slot="marker"] title, [data-testid="main-chart"] title').map(x => x.textContent),
      chartAria: all('svg[role="img"]').map(s => s.getAttribute('aria-label')).filter(Boolean),
      incidents: all('[data-incident]').map(li => ({ id: li.dataset.incident, text: t(li) })),
      blockDurations: all('[data-testid="block-duration"]').map(t),
      blockScope: t(document.querySelector('[data-testid="block-scope"]')),
      sitesAffected: all('[data-testid="sites-affected"]').map(t),
      monitoringOff: all('[data-testid="monitoring-off"]').map(t),
      filterUnavailable: [t(document.querySelector('[data-testid="filter-unavailable-page"]')), ...all('[data-testid="filter-unavailable"]').map(t), t(document.querySelector('[data-testid="chart-unavailable"]')), t(document.querySelector('[data-testid="panels-need-ring"]'))].filter(Boolean),
      nav: all('nav a, [data-sidebar="menu-button"]').map(t).filter(Boolean),
      errorStates: all('[data-slot="error-state"], [role="alert"]').map(t),
      dangerColoured: reds,
      dangerVar,
      bodyText: document.body.innerText,
    }
  })
}

function summarizeLog(slice) {
  const own = slice.requests.filter(r => r.url.startsWith(origin))
  const third = slice.requests.filter(r => !r.url.startsWith(origin) && !r.url.startsWith('data:') && !r.url.startsWith('blob:'))
  const api = own.filter(r => r.url.includes('/api/'))
  const bad = own.filter(r => r.status >= 400 || r.failed)
  const cons = slice.console.filter(c => c.type === 'error' || c.type === 'warning')
  return { requests: slice.requests.length, api: api.length, thirdParty: third.map(r => r.url), errors: bad.map(r => ({ t: r.t, status: r.status, failed: r.failed, url: decodeURIComponent(r.url.replace(origin, '')) })), console: cons, pageErrors: slice.pageErrors }
}

function polling(log, fromT, toT) {
  const groups = {}
  for (const r of log.requests) {
    if (!r.url.startsWith(origin) || !r.url.includes('/api/') || r.t < fromT || r.t > toT) continue
    const u = new URL(r.url)
    u.searchParams.delete('from'); u.searchParams.delete('to')
    const key = `${r.method} ${u.pathname}?${decodeURIComponent(u.searchParams.toString())}`
    ;(groups[key] ??= { ts: [], statuses: [] }).ts.push(+r.t.toFixed(1))
    groups[key].statuses.push(r.status ?? r.failed ?? null)
  }
  const outp = {}
  for (const [k, g] of Object.entries(groups)) {
    const gaps = g.ts.slice(1).map((t, i) => +(t - g.ts[i]).toFixed(1))
    outp[k] = { count: g.ts.length, minGapS: gaps.length ? Math.min(...gaps) : null, gaps, statuses: [...new Set(g.statuses)] }
  }
  return outp
}

async function apiGet(page, path) {
  return page.evaluate(async (p) => { const r = await fetch(`/api/v0${p}`, { credentials: 'same-origin' }); let b = null; try { b = await r.json() } catch {} return { status: r.status, body: b } }, path)
}

async function shot(s, file, full = true) {
  await s.page.screenshot({ path: join(out, `${file}.png`), fullPage: full })
}

async function visit(s, path, file, opts = {}) {
  const { page, log } = s
  const b = { r: log.requests.length, c: log.console.length, e: log.pageErrors.length }
  if (path !== null) {
    await page.goto(`${base}/#${path}`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(opts.wait ?? 5000)
  }
  if (opts.before) await opts.before(page)
  const m = await measure(page)
  if (file) await shot(s, file, opts.full ?? true)
  const slice = { requests: log.requests.slice(b.r), console: log.console.slice(b.c), pageErrors: log.pageErrors.slice(b.e) }
  const entry = { view: s.name, path: path ?? page.url().split('#')[1], file: file ? `${file}.png` : null, measure: { ...m, bodyText: undefined }, log: summarizeLog(slice) }
  appendFileSync(textsFile, `\n===== ${s.name} ${entry.path} (${file ?? '-'}) =====\n${m.bodyText}\n`)
  result.pages.push(entry)
  console.log(`${s.name} ${entry.path}: overflow ${m.overflowPx}px, api ${entry.log.api}, errors ${entry.log.errors.length}, console ${entry.log.console.length}, pageErrors ${entry.log.pageErrors.length}, red ${m.dangerColoured.length}`)
  return entry
}

function save(name) {
  result.finished = new Date().toISOString()
  writeFileSync(join(out, name), JSON.stringify(result, null, 1))
  console.log(`wrote ${join(out, name)}`)
}

const desktop = { width: 1440, height: 900 }
const mobile = { width: 375, height: 812 }
const SITE = process.env.SITE || 'shop.test'

try {
  if (phase === 'snap') {
    // One start page during an event (incident, spike, wave) plus the API at the same moment.
    const s = await session('desktop', desktop)
    await s.page.goto(`${base}/#/`, { waitUntil: 'domcontentloaded' })
    await s.page.waitForTimeout(5000)
    const m = await measure(s.page)
    const api = await apiGet(s.page, '/websites')
    await shot(s, `${tag}-websites-desktop`, true)
    if (process.env.SNAP_SITE) {
      await s.page.goto(`${base}/#/w/${process.env.SNAP_SITE}?zeit=echtzeit`, { waitUntil: 'domcontentloaded' })
      await s.page.waitForTimeout(6000)
      await shot(s, `${tag}-${process.env.SNAP_SITE}-echtzeit-desktop`, true)
      result.siteText = (await measure(s.page)).bodyText.slice(0, 3000)
    }
    result.cards = m.cards
    result.api = api
    result.dangerColoured = m.dangerColoured
    writeFileSync(join(out, `texts-${tag}.txt`), m.bodyText)
    save(`${tag}.json`)
  }
  else if (phase === 'main') {
    const s = await session('desktop', desktop)
    // 1. Start page
    const start = await visit(s, '/', 'd01-websites-desktop', { wait: 6000 })
    result.checks.websitesApi = await apiGet(s.page, '/websites')
    result.checks.startCardsUI = start.measure.cards
    // 2. Switcher
    await visit(s, null, 'd02-switcher-open-desktop', {
      full: false,
      before: async (p) => { await p.locator('[data-testid="website-switcher"]').first().click(); await p.waitForTimeout(800); result.checks.switcherMenu = txt(await p.locator('[data-testid="website-switcher-menu"]').innerText()) },
    })
    await s.page.keyboard.press('Escape')
    // pick shop.test in the switcher
    await s.page.locator('[data-testid="website-switcher"]').first().click()
    await s.page.waitForTimeout(500)
    await s.page.locator(`[data-testid="website-switcher-menu"] [data-website="${SITE}"]`).click()
    await s.page.waitForTimeout(5000)
    result.checks.afterSwitchUrl = s.page.url()
    // 3. Website overview, default range then 6h and echtzeit
    const ov = await visit(s, `/w/${SITE}`, 'd03-shop-overview-default-desktop', { wait: 7000 })
    result.checks.defaultRangeUrl = ov.measure.url
    result.checks.kpisApiDefault = Object.entries(s.log.json).filter(([k]) => k.includes(`/websites/${SITE}/kpis`)).slice(-1)[0] ?? null
    const ov6 = await visit(s, `/w/${SITE}?zeit=6h`, 'd04-shop-overview-6h-desktop', { wait: 7000 })
    result.checks.kpisUI6h = ov6.measure.kpis
    result.checks.kpisApi6h = Object.entries(s.log.json).filter(([k]) => k.includes(`/websites/${SITE}/kpis`)).slice(-1)[0] ?? null
    result.checks.annotationsApi6h = Object.entries(s.log.json).filter(([k]) => k.includes(`/websites/${SITE}/annotations`)).slice(-1)[0] ?? null
    result.checks.alertsApi6h = Object.entries(s.log.json).filter(([k]) => k.includes(`/websites/${SITE}/alerts`)).slice(-1)[0]?.[1]?.body?.items?.slice(0, 5) ?? null
    result.checks.breakdownApi6h = Object.fromEntries(Object.entries(s.log.json).filter(([k]) => k.includes('/monitoring/traffic/breakdown') && k.includes(`site=${SITE}`)).map(([k, v]) => [k, { total: v.body?.total, items: v.body?.items?.slice(0, 5), exact: v.body?.exact }]))
    result.checks.panels6h = ov6.measure.panels
    await visit(s, `/w/${SITE}?zeit=echtzeit`, 'd05-shop-overview-echtzeit-desktop', { wait: 7000 })
    // chart only (viewport) with marker tooltip
    await visit(s, `/w/${SITE}?zeit=6h`, 'd06-shop-chart-marker-desktop', {
      wait: 6000, full: false,
      before: async (p) => {
        const marks = await p.evaluate(() => [...document.querySelectorAll('[data-slot="marker"]')].map((m) => { const r = m.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + Math.min(10, r.height / 2), text: m.textContent?.replace(/\s+/g, ' ').trim() } }))
        result.checks.markerElements = marks
        if (marks.length) {
          await p.mouse.move(marks[marks.length - 1].x, marks[marks.length - 1].y)
          await p.waitForTimeout(500)
          result.checks.markerTooltip = await p.evaluate(() => [...document.querySelectorAll('[data-slot="tooltip"], [role="tooltip"]')].map(e => e.innerText.replace(/\s+/g, ' ')))
        }
      },
    })
    // KPI click: Angriffe gestoppt as chart metric
    await visit(s, null, 'd07-shop-kpi-stopped-desktop', {
      full: false,
      before: async (p) => { await p.locator('[data-kpi="stopped"]').click(); await p.waitForTimeout(3000) },
    })
    // 4. Panels: every tab
    await s.page.goto(`${base}/#/w/${SITE}?zeit=6h`, { waitUntil: 'domcontentloaded' })
    await s.page.waitForTimeout(6000)
    result.checks.panelTabs = {}
    for (const [panel, tabs] of [['panel-referrer', ['all', 'ai']], ['panel-origin', ['country', 'net', 'asn']], ['panel-tech', ['browser', 'os', 'device']], ['panel-bots', ['bots', 'ai']], ['panel-attacks', ['rules', 'pages']]]) {
      for (const tb of tabs) {
        const loc = s.page.locator(`[data-testid="${panel}"] [data-tab="${tb}"]`)
        if (await loc.count()) { await loc.click(); await s.page.waitForTimeout(1800) }
        const p = await s.page.evaluate(id => { const el = document.querySelector(`[data-testid="${id}"]`); return el ? el.innerText.replace(/\s+/g, ' ').trim() : null }, panel)
        result.checks.panelTabs[`${panel}/${tb}`] = p
        if (['country', 'asn', 'rules', 'browser', 'pages'].includes(tb) || tb === 'bots') await s.page.locator(`[data-testid="${panel}"]`).screenshot({ path: join(out, `d08-panel-${panel.slice(6)}-${tb}-desktop.png`) })
      }
    }
    result.checks.breakdownApiAllTabs = Object.fromEntries(Object.entries(s.log.json).filter(([k]) => k.includes('/monitoring/traffic/breakdown') && k.includes(`site=${SITE}`)).map(([k, v]) => [k, { status: v.status, total: v.body?.total, items: v.body?.items?.slice(0, 8), exact: v.body?.exact }]))
    // 5. Click to filter: country row, then net class row (two filters)
    await s.page.locator('[data-testid="panel-origin"] [data-tab="country"]').click()
    await s.page.waitForTimeout(1500)
    const before = await measure(s.page)
    const firstCountry = await s.page.locator('[data-testid="panel-origin"] tbody tr').first().getAttribute('data-row')
    await s.page.locator('[data-testid="panel-origin"] tbody tr').first().locator('button').first().click()
    await s.page.waitForTimeout(6000)
    const f1 = await visit(s, null, 'd09-shop-filter-country-desktop', { full: true })
    result.checks.filter1 = { country: firstCountry, url: f1.measure.url, chips: f1.measure.chips, kpisBefore: before.kpis, kpisAfter: f1.measure.kpis, panelsAfter: f1.measure.panels.map(p => ({ id: p.id, rows: p.rows.slice(0, 4), unavailable: p.unavailable })), alertsAfter: f1.measure.alerts?.slice(0, 400), filterUnavailable: f1.measure.filterUnavailable }
    result.checks.filter1Api = Object.entries(s.log.json).filter(([k]) => k.includes('filter=')).map(([k, v]) => ({ k, status: v.status, body: k.includes('/kpis') ? v.body : (v.body?.total ?? v.body?.title ?? v.body?.code ?? null) }))
    // second filter by URL (the origin panel has no rows under a filter without the request ring)
    const netRow = 'residential'
    await s.page.goto(`${base}/#/w/${SITE}?zeit=6h&filter=country:${firstCountry}&filter=net_class:${netRow}`, { waitUntil: 'domcontentloaded' })
    await s.page.waitForTimeout(6000)
    const f2 = await visit(s, null, 'd10-shop-filter-two-6h-desktop', { full: true })
    result.checks.filter2 = { net: netRow, url: f2.measure.url, chips: f2.measure.chips, kpis: f2.measure.kpis, filterUnavailable: f2.measure.filterUnavailable, panels: f2.measure.panels.map(p => ({ id: p.id, rows: p.rows.slice(0, 3), unavailable: p.unavailable })), errors: f2.log.errors }
    // the UI's own remedy: "Auf 48 Stunden wechseln" with one filter
    await s.page.goto(`${base}/#/w/${SITE}?zeit=48h&filter=country:${firstCountry}`, { waitUntil: 'domcontentloaded' })
    await s.page.waitForTimeout(6000)
    const f48 = await visit(s, null, 'd10b-shop-filter-one-48h-desktop', { full: true })
    result.checks.filter1_48h = { url: f48.measure.url, kpis: f48.measure.kpis, filterUnavailable: f48.measure.filterUnavailable, errors: f48.log.errors }
    // Two filters over 7 days -> 409 filter_unavailable expected
    await s.page.goto(`${base}/#/w/${SITE}?zeit=7d&filter=country:${firstCountry}&filter=net_class:${netRow}`, { waitUntil: 'domcontentloaded' })
    await s.page.waitForTimeout(6000)
    const f3 = await visit(s, null, 'd11-shop-filter-two-7d-desktop', { full: true })
    result.checks.filter2_7d = { url: f3.measure.url, chips: f3.measure.chips, kpis: f3.measure.kpis, filterUnavailable: f3.measure.filterUnavailable, errors: f3.log.errors, errorStates: f3.measure.errorStates }
    // one filter over 7 days
    await s.page.goto(`${base}/#/w/${SITE}?zeit=7d&filter=country:${firstCountry}`, { waitUntil: 'domcontentloaded' })
    await s.page.waitForTimeout(6000)
    const f4 = await visit(s, null, 'd12-shop-filter-one-7d-desktop', { full: true })
    result.checks.filter1_7d = { url: f4.measure.url, kpis: f4.measure.kpis, filterUnavailable: f4.measure.filterUnavailable, errors: f4.log.errors }
    // 6. Other websites
    for (const [id, f] of [['api.test', 'd13-api-overview-6h-desktop'], ['blog.test', 'd14-blog-overview-6h-desktop'], ['status.test', 'd15-status-overview-6h-desktop']]) await visit(s, `/w/${id}?zeit=6h`, f, { wait: 7000 })
    // 7. Angriffe
    const at = await visit(s, `/w/${SITE}/angriffe`, 'd16-shop-angriffe-desktop', { wait: 6000 })
    result.checks.attacks = { blockScope: at.measure.blockScope, blockDurations: at.measure.blockDurations, sitesAffected: at.measure.sitesAffected, incidents: at.measure.incidents.slice(0, 20) }
    result.checks.incidentsApi = Object.entries(s.log.json).filter(([k]) => k.startsWith('/api/v0/incidents?')).slice(-1)[0]?.[1]?.body?.items?.slice(0, 20) ?? null
    result.checks.blockNotesApi = Object.entries(s.log.json).filter(([k]) => k.includes('/annotations')).slice(-1)[0]?.[1]?.body?.items?.filter(a => a.kind === 'block_long') ?? null
    for (const id of ['blog.test', 'api.test']) {
      const a2 = await visit(s, `/w/${id}/angriffe`, `d17-${id.split('.')[0]}-angriffe-desktop`, { wait: 6000 })
      result.checks[`attacks_${id}`] = { blockDurations: a2.measure.blockDurations, sitesAffected: a2.measure.sitesAffected, n: a2.measure.incidents.length }
    }
    await visit(s, '/angriffe', 'd18-all-angriffe-desktop', { wait: 6000 })
    // 8. Ausnahmen, Zugriffe
    await visit(s, `/w/${SITE}/exceptions`, 'd19-shop-ausnahmen-desktop', { wait: 5000 })
    await visit(s, `/w/${SITE}/zugriffe`, 'd20-shop-zugriffe-desktop', { wait: 5000 })
    // 9. Server
    await visit(s, '/server', 'd21-server-desktop', { wait: 6000 })
    await visit(s, '/server/check', 'd22-server-check-desktop', { wait: 4000 })
    // 10. All websites overview / and settings nav (check for Entwicklung / Styleguide)
    await visit(s, '/settings', 'd23-einstellungen-desktop', { wait: 4000 })
    result.checks.navTexts = await s.page.evaluate(() => document.querySelector('[data-sidebar="sidebar"], aside, nav')?.innerText.replace(/\s+/g, ' ') ?? null)
    result.checks.json = Object.keys(s.log.json).length
    writeFileSync(join(out, `api-json-${tag}.json`), JSON.stringify(s.log.json, null, 1))
    result.checks.allConsole = s.log.console.filter(c => c.type === 'error' || c.type === 'warning')
    result.checks.allPageErrors = s.log.pageErrors
    result.checks.allFailed = s.log.requests.filter(r => r.failed || r.status >= 400).map(r => ({ t: r.t, status: r.status, failed: r.failed, url: decodeURIComponent(r.url.replace(origin, '')) }))
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'mobile') {
    const s = await session('mobile', mobile)
    for (const [path, f] of [['/', 'm01-websites-mobile'], [`/w/${SITE}?zeit=6h`, 'm02-shop-overview-mobile'], [`/w/${SITE}?zeit=6h&filter=country:DE`, 'm03-shop-filter-mobile'], [`/w/${SITE}/angriffe`, 'm04-shop-angriffe-mobile'], ['/server', 'm05-server-mobile']]) {
      const e = await visit(s, path, null, { wait: 6000 })
      await s.page.screenshot({ path: join(out, `${f}.png`) })
      // second viewport-sized shot further down
      await s.page.evaluate(() => window.scrollTo(0, 1500))
      await s.page.waitForTimeout(300)
      await s.page.screenshot({ path: join(out, `${f}-2.png`) })
      e.file = `${f}.png`
      // widest elements beyond the viewport
      e.wide = await s.page.evaluate(() => [...document.querySelectorAll('body *')].filter(el => el.getBoundingClientRect().right > window.innerWidth + 1 && getComputedStyle(el).position !== 'fixed').slice(0, 10).map(el => ({ tag: el.tagName, cls: (el.getAttribute('class') || '').slice(0, 60), right: Math.round(el.getBoundingClientRect().right) })))
    }
    // open the mobile navigation
    const trig = s.page.locator('[data-sidebar="trigger"]').first()
    if (await trig.count()) { await trig.click(); await s.page.waitForTimeout(800); await s.page.screenshot({ path: join(out, 'm06-nav-open-mobile.png') }); result.checks.mobileNav = await s.page.evaluate(() => document.body.innerText.slice(0, 1500)) }
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'watch') {
    const s = await session('watch', desktop)
    for (const [path, secs] of [[`/w/${SITE}`, watchS], [`/w/${SITE}?zeit=echtzeit`, 75], ['/', 75], [`/w/${SITE}/angriffe`, 75], ['/server', 45]]) {
      await s.page.goto(`${base}/#${path}`, { waitUntil: 'domcontentloaded' })
      const t1 = (Date.now() - s.t0) / 1000
      await s.page.waitForTimeout(secs * 1000)
      const t2 = (Date.now() - s.t0) / 1000
      result.checks[path] = { seconds: +(t2 - t1).toFixed(1), groups: polling(s.log, t1 + 8, t2) }
      console.log(path, JSON.stringify(Object.fromEntries(Object.entries(result.checks[path].groups).map(([k, v]) => [k.slice(0, 90), [v.count, v.minGapS]]))))
    }
    result.checks.log = summarizeLog(s.log)
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'extra') {
    // Chart markers (kinds, titles), a long-block marker up close, the incident page of a 7-day block.
    const s = await session('desktop', desktop)
    await s.page.goto(`${base}/#/w/${SITE}?zeit=6h`, { waitUntil: 'domcontentloaded' })
    await s.page.waitForTimeout(7000)
    result.checks.markers = await s.page.evaluate(() => {
      const ms = [...document.querySelectorAll('[data-marker]')]
      const kinds = {}
      for (const m of ms) kinds[m.dataset.marker] = (kinds[m.dataset.marker] ?? 0) + 1
      const titles = [...new Set(ms.filter(m => m.dataset.marker !== 'incident').map(m => m.getAttribute('title')))]
      const xs = ms.map(m => Math.round(m.getBoundingClientRect().x))
      return { count: ms.length, kinds, titles, minX: Math.min(...xs), maxX: Math.max(...xs), viewport: window.innerWidth }
    })
    const lb = s.page.locator('[data-marker="block_long"]').first()
    if (await lb.count()) {
      await lb.scrollIntoViewIfNeeded()
      await lb.hover()
      await s.page.waitForTimeout(600)
      await s.page.screenshot({ path: join(out, 'e01-shop-chart-blocklong-hover-desktop.png') })
    }
    // hover the plot near the right end for the chart tooltip
    const box = await s.page.locator('[data-testid="main-chart"] svg[role="img"], svg[role="img"]').first().boundingBox()
    if (box) {
      await s.page.mouse.move(box.x + box.width * 0.93, box.y + box.height * 0.4)
      await s.page.waitForTimeout(600)
      result.checks.chartTooltip = await s.page.evaluate(() => [...document.querySelectorAll('[role="tooltip"], [data-slot="tooltip"], .pointer-events-none.absolute')].map(e => (e.innerText ?? e.textContent ?? '').replace(/\s+/g, ' ')).filter(Boolean).slice(0, 4))
      await s.page.screenshot({ path: join(out, 'e02-shop-chart-tooltip-desktop.png') })
    }
    for (const [path, f] of [[`/incidents/${process.env.LONG_INCIDENT ?? 'QY64-EAW5'}`, 'e03-incident-7d-desktop'], [`/incidents/${process.env.RES_INCIDENT ?? 'QWH2-DM6J'}`, 'e04-incident-24h-residential-desktop'], ['/behaviour', 'e05-verhalten-desktop']]) await visit(s, path, f, { wait: 5000 })
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'off') {
    const s = await session('desktop', desktop)
    for (const [path, f] of [['/', 'off01-websites-desktop'], [`/w/${SITE}`, 'off02-shop-overview-desktop'], [`/w/${SITE}/angriffe`, 'off03-shop-angriffe-desktop'], ['/server', 'off04-server-desktop']]) {
      await visit(s, path, f, { wait: 6000 })
    }
    // stay 75 s on the website overview and the start page: no repeated 409s
    for (const path of [`/w/${SITE}`, '/']) {
      await s.page.goto(`${base}/#${path}`, { waitUntil: 'domcontentloaded' })
      const t1 = (Date.now() - s.t0) / 1000
      await s.page.waitForTimeout(75000)
      const t2 = (Date.now() - s.t0) / 1000
      result.checks[`watch ${path}`] = { groups: polling(s.log, t1, t2) }
      console.log(path, JSON.stringify(Object.fromEntries(Object.entries(result.checks[`watch ${path}`].groups).map(([k, v]) => [k.slice(0, 90), [v.count, v.minGapS, v.statuses]]))))
    }
    const ms = await session('mobile', mobile)
    await visit(ms, `/w/${SITE}`, 'off05-shop-overview-mobile', { wait: 6000, full: false })
    await ms.ctx.close()
    result.checks.log = summarizeLog(s.log)
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
}
catch (e) {
  result.errors.push(String(e?.stack ?? e))
  console.error(e)
  save(`${tag}-check-error.json`)
}
finally {
  await browser.close()
}
