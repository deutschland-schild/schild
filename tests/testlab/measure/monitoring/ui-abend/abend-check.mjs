#!/usr/bin/env node
// TEST ONLY: UI part of the evening measurement 2026-10-29 (commit c54de1b) against a REAL schild
// instance. Based on ../ui36n/ui36n-check.mjs; adds the phases ranges, clicks6h, server, observe,
// styleguide and tooltip collection. Light and dark (localStorage schild-color-scheme-v2), 1440x900 and 375x812.
//
//   node ui36n-check.mjs <phase> <base-url> <out-dir>
//   phase: restart | markers | filters | incident | pages | watch | off
//
// Env: PW (TEST ONLY password), TAG (file prefix), SITE (default shop.test), UI_ROOT (playwright),
//      INCIDENTS (comma list "label=NUMBER" for the incident phase), WATCH_S.
import { existsSync, mkdirSync, readdirSync, writeFileSync, appendFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, resolve } from 'node:path'

const phase = process.argv[2] ?? 'pages'
const base = (process.argv[3] ?? 'http://127.0.0.1:23088').replace(/\/$/, '')
const out = resolve(process.argv[4] ?? '.')
const password = process.env.PW || 'schild-abend-messung-TESTONLY'
const tag = process.env.TAG || phase
const SITE = process.env.SITE || 'shop.test'
const uiRoot = process.env.UI_ROOT || '/tmp/abend/src/dashboard'
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
const textsFile = join(out, `${tag}-texts.txt`)
writeFileSync(textsFile, '')
const VIEW = { desktop: { width: 1440, height: 900 }, mobile: { width: 375, height: 812 } }

async function session(view, theme) {
  const ctx = await browser.newContext({ viewport: VIEW[view], locale: 'de-DE', timezoneId: 'Europe/Berlin' })
  await ctx.addInitScript((th) => {
    try { localStorage.setItem('schild-color-scheme-v2', th) } catch {}
    document.addEventListener('securitypolicyviolation', e => console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`))
  }, theme)
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
  await page.waitForTimeout(1500)
  return { ctx, page, log, t0, name: `${view}-${theme}`, view, theme }
}

async function measure(page) {
  return page.evaluate(() => {
    const d = document.documentElement
    const t = el => el ? el.innerText.replace(/\s+/g, ' ').trim() : null
    const all = s => [...document.querySelectorAll(s)]
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
    // header: breadcrumb box against the other header items (overlap in px)
    const header = document.querySelector('header')
    let crumbOverlap = null
    const bc = header?.querySelector('nav[aria-label="breadcrumb"], [data-slot="breadcrumb"]')
    if (header && bc) {
      const b = bc.getBoundingClientRect()
      const items = [...header.querySelectorAll('*')].filter(e => !bc.contains(e) && !e.contains(bc) && e.getBoundingClientRect().width > 0 && e.children.length === 0 && (e.innerText ?? '').trim())
      let worst = 0; let with_ = null
      // the breadcrumb's own text extent (it may be clipped by overflow)
      const texts = [...bc.querySelectorAll('*')].filter(e => e.children.length === 0 && (e.innerText ?? '').trim()).map(e => e.getBoundingClientRect())
      for (const it of items) {
        const r = it.getBoundingClientRect()
        for (const tr of texts) {
          const ox = Math.min(tr.right, r.right) - Math.max(tr.left, r.left)
          const oy = Math.min(tr.bottom, r.bottom) - Math.max(tr.top, r.top)
          if (ox > 0 && oy > 0 && ox > worst) { worst = ox; with_ = (it.innerText ?? '').trim().slice(0, 60) }
        }
      }
      const hb = header.getBoundingClientRect()
      const ctxEl = header.querySelector('[data-slot="shell-context"]')
      const cb = ctxEl ? ctxEl.getBoundingClientRect() : null
      crumbOverlap = { px: Math.round(worst), with: with_, crumb: t(bc), header: t(header)?.slice(0, 200),
        crumbBox: { top: Math.round(b.top), bottom: Math.round(b.bottom), left: Math.round(b.left), right: Math.round(b.right) },
        headerBox: { top: Math.round(hb.top), bottom: Math.round(hb.bottom) },
        crumbOutsideHeaderPx: Math.round(Math.max(0, hb.top - b.top, b.bottom - hb.bottom)),
        context: ctxEl ? { text: t(ctxEl), visible: cb.width > 0, left: Math.round(cb.left), right: Math.round(cb.right), overlapWithCrumbPx: cb.width > 0 ? Math.round(Math.max(0, Math.min(b.right, cb.right) - Math.max(b.left, cb.left))) : 0 } : null }
    }
    return {
      url: location.href,
      overflowPx: d.scrollWidth - d.clientWidth,
      h1: t(document.querySelector('h1')),
      dark: d.classList.contains('dark'),
      cards: all('[data-testid="website-card"]').map(c => ({ id: c.dataset.website, text: t(c) })),
      kpis: all('[data-testid="kpi-row"] [data-kpi]').map(b => ({ key: b.dataset.kpi, value: t(b.querySelector('[data-slot="kpi-value"]')), change: t(b.querySelector('[data-slot="kpi-change"]')), text: t(b), pressed: b.getAttribute('aria-pressed') })),
      kpiRowText: t(document.querySelector('[data-testid="kpi-row"]')),
      kpiRowNext: t(document.querySelector('[data-testid="kpi-row"]')?.nextElementSibling),
      chips: all('[data-testid="filter-chips"] [data-filter]').map(c => c.dataset.filter),
      panels: all('[data-testid^="panel-"]').map(p => ({ id: p.dataset.testid, tabs: [...p.querySelectorAll('[role="tab"]')].map(x => ({ k: x.dataset.tab, sel: x.getAttribute('aria-selected') })), rows: [...p.querySelectorAll('tbody tr')].length, buttons: [...p.querySelectorAll('tbody tr button')].length, unavailable: t(p.querySelector('[data-testid="filter-unavailable"]')) })),
      alerts: t(document.querySelector('[data-testid="alerts-card"]'))?.slice(0, 800) ?? null,
      incidentCard: t(document.querySelector('[data-testid="incident-card"]')),
      incidentSentence: t(document.querySelector('[data-testid="incident-sentence"]')),
      incidentStatus: (() => { const e = document.querySelector('[data-testid="incident-status"]'); if (!e) return null; const cs = getComputedStyle(e); return { text: t(e), color: cs.color, bg: cs.backgroundColor, border: cs.borderTopColor, cls: e.getAttribute('class') } })(),
      blockDurations: all('[data-testid="block-duration"]').map(t),
      blockScope: t(document.querySelector('[data-testid="block-scope"]')),
      monitoringOff: all('[data-testid="monitoring-off"]').map(t),
      filterUnavailable: [t(document.querySelector('[data-testid="filter-unavailable-page"]')), ...all('[data-testid="filter-unavailable"]').map(t), t(document.querySelector('[data-testid="chart-unavailable"]')), t(document.querySelector('[data-testid="panels-need-ring"]'))].filter(Boolean),
      navLinks: all('[data-sidebar="sidebar"] a, aside a, nav a').map(a => ({ text: t(a), href: a.getAttribute('href') })).filter(a => a.text || a.href),
      errorStates: all('[data-slot="error-state"], [role="alert"]').map(t),
      crumbOverlap,
      titles: [...new Set(all('[title]').map(e => e.getAttribute('title')).filter(Boolean))],
      ariaLabels: [...new Set(all('[aria-label]').map(e => e.getAttribute('aria-label')).filter(Boolean))],
      dangerColoured: reds,
      bodyText: document.body.innerText,
    }
  })
}

function summarizeLog(slice) {
  const own = slice.requests.filter(r => r.url.startsWith(origin))
  const third = slice.requests.filter(r => !r.url.startsWith(origin) && !r.url.startsWith('data:') && !r.url.startsWith('blob:'))
  const bad = own.filter(r => r.status >= 400 || r.failed)
  const cons = slice.console.filter(c => c.type === 'error' || c.type === 'warning')
  return { requests: slice.requests.length, api: own.filter(r => r.url.includes('/api/')).length, n409: own.filter(r => r.status === 409).length, n404: own.filter(r => r.status === 404).length, thirdParty: third.map(r => r.url), errors: bad.map(r => ({ t: r.t, status: r.status, failed: r.failed, url: decodeURIComponent(r.url.replace(origin, '')) })), console: cons, pageErrors: slice.pageErrors }
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
    outp[k] = { count: g.ts.length, minGapS: gaps.length ? Math.min(...gaps) : null, medianGapS: gaps.length ? gaps.sort((a, b) => a - b)[Math.floor(gaps.length / 2)] : null, statuses: [...new Set(g.statuses)] }
  }
  return outp
}

async function apiGet(page, path) {
  return page.evaluate(async (p) => { const r = await fetch(`/api/v0${p}`, { credentials: 'same-origin' }); let b = null; try { b = await r.json() } catch {} return { status: r.status, body: b } }, path)
}

const mark = s => ({ r: s.log.requests.length, c: s.log.console.length, e: s.log.pageErrors.length })
const sliceOf = (s, b) => ({ requests: s.log.requests.slice(b.r), console: s.log.console.slice(b.c), pageErrors: s.log.pageErrors.slice(b.e) })

// Hover tooltip triggers (reka Tooltip) and read the content; title attributes come from measure().
async function collectTips(page, max = 30) {
  const out = []
  const trig = page.locator('[data-slot="tooltip-trigger"]')
  const n = Math.min(await trig.count(), max)
  for (let i = 0; i < n; i++) {
    try {
      const t = trig.nth(i)
      if (!(await t.isVisible())) continue
      await t.hover({ timeout: 1500 })
      await page.waitForTimeout(450)
      const c = await page.evaluate(() => [...document.querySelectorAll('[data-slot="tooltip-content"]')].map(e => e.innerText.replace(/\s+/g, ' ').trim()).filter(Boolean))
      for (const x of c) out.push(x)
      await page.mouse.move(0, 0)
      await page.waitForTimeout(150)
    } catch {}
  }
  return [...new Set(out)]
}

async function visit(s, path, file, opts = {}) {
  const { page } = s
  const b = mark(s)
  if (path !== null) {
    await page.goto(`${base}/#${path}`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(opts.wait ?? 5000)
  }
  if (opts.before) await opts.before(page)
  const m = await measure(page)
  const shotRe = process.env.SHOT_RE ? new RegExp(process.env.SHOT_RE) : null
  if (file && (!shotRe || shotRe.test(file))) await page.screenshot({ path: join(out, `${file}.png`), fullPage: opts.full ?? true })
  else if (file) file = null
  const entry = { view: s.name, path: path ?? page.url().split('#')[1], file: file ? `${file}.png` : null, measure: { ...m, bodyText: undefined }, log: summarizeLog(sliceOf(s, b)) }
  if (opts.tips) entry.tips = await collectTips(page)
  appendFileSync(textsFile, `\n===== ${s.name} ${entry.path} (${file ?? '-'}) =====\n${m.bodyText}\n----- titles -----\n${m.titles.join('\n')}\n----- aria -----\n${m.ariaLabels.join('\n')}\n${entry.tips ? `----- tooltips -----\n${entry.tips.join('\n')}\n` : ''}`)
  result.pages.push(entry)
  console.log(`${s.name} ${entry.path}: overflow ${m.overflowPx}px, 409 ${entry.log.n409}, 404 ${entry.log.n404}, errors ${entry.log.errors.length}, console ${entry.log.console.length}, red ${m.dangerColoured.length}, crumb ${m.crumbOverlap?.px ?? '-'}`)
  return entry
}

function save(name) {
  result.finished = new Date().toISOString()
  writeFileSync(join(out, name), JSON.stringify(result, null, 1))
  console.log(`wrote ${join(out, name)}`)
}

// Marker chips against the chart: overflow of every chip beyond the marker strip, the plot svg and the viewport.
async function markerBoxes(page) {
  return page.evaluate(() => {
    const strip = document.querySelector('[data-slot="markers"]')
    if (!strip) return { strip: null }
    const sb = strip.getBoundingClientRect()
    const svg = strip.parentElement.querySelector('svg')
    const vb = svg ? svg.getBoundingClientRect() : sb
    const card = strip.closest('[data-slot="card"]') ?? strip.parentElement
    const cb = card.getBoundingClientRect()
    const chips = [...strip.querySelectorAll('[data-marker]')].map((c) => { const r = c.getBoundingClientRect(); return { kind: c.dataset.marker, kinds: c.dataset.kinds, count: +c.dataset.count, left: r.left, right: r.right, title: c.getAttribute('title') } })
    const over = (a, b) => Math.max(0, b.left - a.left, a.right - b.right)
    const kinds = {}
    for (const c of chips) for (const k of (c.kinds ?? c.kind).split(' ')) kinds[k] = (kinds[k] ?? 0) + 1
    // overlap of neighbouring chips
    const sorted = [...chips].sort((a, b) => a.left - b.left)
    let overlap = 0
    for (let i = 1; i < sorted.length; i++) overlap = Math.max(overlap, sorted[i - 1].right - sorted[i].left)
    return {
      viewport: window.innerWidth,
      scrollWidthOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      strip: { left: sb.left, right: sb.right }, plot: { left: vb.left, right: vb.right }, card: { left: cb.left, right: cb.right },
      chips: chips.length, markersInChips: chips.reduce((a, c) => a + (c.count || 1), 0), kinds,
      maxOverflowStripPx: Math.round(Math.max(0, ...chips.map(c => over(c, sb)))),
      maxOverflowPlotPx: Math.round(Math.max(0, ...chips.map(c => over(c, vb)))),
      maxOverflowCardPx: Math.round(Math.max(0, ...chips.map(c => over(c, cb)))),
      maxOverflowViewportPx: Math.round(Math.max(0, ...chips.map(c => Math.max(0, -c.left, c.right - window.innerWidth)))),
      maxChipOverlapPx: Math.round(Math.max(0, overlap)),
      clusters: chips.filter(c => c.count > 1).map(c => ({ kind: c.kind, kinds: [...new Set(c.kinds.split(' '))].join(' '), count: c.count, title: c.title?.slice(0, 300) })),
      restartChips: chips.filter(c => (c.kinds ?? c.kind).includes('restart')).map(c => ({ kind: c.kind, count: c.count, left: Math.round(c.left), title: c.title?.slice(0, 200) })),
    }
  })
}

const sessions = []
async function each(views, themes, fn) {
  for (const v of views) for (const th of themes) {
    const s = await session(v, th)
    try { await fn(s) } finally { await s.ctx.close() }
  }
}
const lastJson = (s, frag) => Object.entries(s.log.json).filter(([k]) => k.includes(frag)).slice(-1)[0] ?? null

try {
  if (phase === 'restart') {
    // KPI "Angriffe gestoppt" and the panels over 6 h and 24 h (the UI has no 1 h range) right after a restart in a wave.
    result.checks.kpi = []
    await each(['desktop', 'mobile'], ['light', 'dark'], async (s) => {
      for (const zeit of ['6h', '24h']) {
        const f = `${tag}-kpi-${zeit}-${s.theme}-${s.view}`
        const e = await visit(s, `/w/${SITE}?zeit=${zeit}`, f, { wait: 7000, full: s.view === 'desktop' ? false : false })
        const k = lastJson(s, `/websites/${SITE}/kpis`)
        const bds = Object.entries(s.log.json).filter(([u]) => u.includes('/monitoring/traffic/breakdown') && u.includes(`site=${SITE}`) && !u.includes('filter=')).slice(-12).map(([u, v]) => ({ u, status: v.status, exact: v.body?.exact, total: v.body?.total }))
        result.checks.kpi.push({ view: s.name, zeit, tiles: e.measure.kpis, kpiRowText: e.measure.kpiRowText, kpiRowNext: e.measure.kpiRowNext, apiKpis: k ? { url: k[0], current: k[1].body?.current, source: k[1].body?.source } : null, breakdowns: bds })
        if (s.view === 'mobile') {
          // the KPI row and the panel "Angriffe" further down
          const p = s.page.locator('[data-testid="panel-attacks"]')
          if (await p.count()) await p.screenshot({ path: join(out, `${f}-panel-attacks.png`) })
        }
        else {
          const p = s.page.locator('[data-testid="panel-attacks"]')
          if (await p.count()) await p.screenshot({ path: join(out, `${f}-panel-attacks.png`) })
        }
      }
      if (s.view === 'desktop' && s.theme === 'light') {
        await visit(s, null, `${tag}-kpi-6h-stopped-clicked-light-desktop`, { full: false, before: async (p) => { await p.locator('[data-kpi="stopped"]').click(); await p.waitForTimeout(3000) } })
        for (const id of ['blog.test', 'api.test']) {
          await visit(s, `/w/${id}?zeit=6h`, `${tag}-kpi-6h-${id.split('.')[0]}-light-desktop`, { wait: 7000, full: false })
          const k = lastJson(s, `/websites/${id}/kpis`)
          result.checks.kpi.push({ view: s.name, site: id, zeit: '6h', apiKpis: k ? { url: k[0], current: k[1].body?.current } : null })
        }
        await visit(s, '/', `${tag}-websites-light-desktop`, { wait: 6000, full: false })
        result.checks.websitesApi = await apiGet(s.page, '/websites')
      }
    })
    save(`${tag}-check.json`)
  }
  else if (phase === 'markers') {
    result.checks.markers = []
    await each(['desktop', 'mobile'], ['light', 'dark'], async (s) => {
      for (const [site, zeit] of [[SITE, '6h'], [SITE, '24h'], ['api.test', '6h']]) {
        await s.page.goto(`${base}/#/w/${site}?zeit=${zeit}`, { waitUntil: 'domcontentloaded' })
        await s.page.waitForTimeout(7000)
        const m = await markerBoxes(s.page)
        const ann = lastJson(s, `/websites/${site}/annotations`)
        const kinds = {}
        for (const a of ann?.[1]?.body?.items ?? []) kinds[a.kind] = (kinds[a.kind] ?? 0) + (a.count ?? 1)
        const f = `${tag}-${site.split('.')[0]}-${zeit}-${s.theme}-${s.view}`
        const card = s.page.locator('[data-slot="markers"]').first()
        if (await card.count()) {
          await card.scrollIntoViewIfNeeded()
          // the chart card with the markers
          const c = s.page.locator('[data-slot="markers"]').first().locator('xpath=ancestor::*[@data-slot="card"][1]')
          if (await c.count()) await c.screenshot({ path: join(out, `${f}.png`) })
          else await s.page.screenshot({ path: join(out, `${f}.png`) })
        }
        // hover the biggest cluster for its title (native tooltip text in the title attribute)
        m.annotationsApi = ann ? { url: ann[0], n: ann[1].body?.items?.length, truncated: ann[1].body?.truncated, kinds } : null
        result.checks.markers.push({ view: s.name, site, zeit, ...m })
        console.log(`${s.name} ${site} ${zeit}: chips ${m.chips} (markers ${m.markersInChips}), overflow strip ${m.maxOverflowStripPx} plot ${m.maxOverflowPlotPx} viewport ${m.maxOverflowViewportPx} page ${m.scrollWidthOverflow}, chip overlap ${m.maxChipOverlapPx}, restart chips ${m.restartChips?.length}, api ${JSON.stringify(m.annotationsApi?.kinds)}`)
      }
    })
    save(`${tag}-check.json`)
  }
  else if (phase === 'filters') {
    // Which rows are offered as filter, what a click does, how many 409 / console errors it costs.
    const s = await session('desktop', 'light')
    const ov = await visit(s, `/w/${SITE}?zeit=6h`, `${tag}-overview-6h-light-desktop`, { wait: 7000 })
    result.checks.overviewLoad = ov.log
    result.checks.panelsOffered = {}
    result.checks.clicks = []
    const panels = [['panel-referrer', ['all', 'ai']], ['panel-origin', ['country', 'net', 'asn']], ['panel-tech', ['browser', 'os', 'device']], ['panel-bots', ['bots', 'ai']], ['panel-attacks', ['rules', 'pages']], ['panel-pages', []], ['panel-status', []]]
    const present = await s.page.evaluate(() => [...document.querySelectorAll('[data-testid^="panel-"]')].map(p => ({ id: p.dataset.testid, tabs: [...p.querySelectorAll('[role="tab"]')].map(x => x.dataset.tab) })))
    result.checks.panelsPresent = present
    let shot = 0
    for (const p of present) {
      const tabs = p.tabs.length ? p.tabs : [null]
      for (const tb of tabs) {
        await s.page.goto(`${base}/#/w/${SITE}?zeit=6h`, { waitUntil: 'domcontentloaded' })
        await s.page.waitForTimeout(5000)
        if (tb) { await s.page.locator(`[data-testid="${p.id}"] [data-tab="${tb}"]`).click(); await s.page.waitForTimeout(1500) }
        const info = await s.page.evaluate((id) => {
          const el = document.querySelector(`[data-testid="${id}"]`)
          const rows = [...el.querySelectorAll('tbody tr')]
          return { rows: rows.length, rowButtons: rows.filter(r => r.querySelector('button')).length, links: rows.filter(r => r.querySelector('a')).length, cursor: rows[0] ? getComputedStyle(rows[0]).cursor : null, firstRow: rows[0]?.innerText.replace(/\s+/g, ' ').slice(0, 80) ?? null, footer: el.innerText.replace(/\s+/g, ' ').slice(-300) }
        }, p.id)
        result.checks.panelsOffered[`${p.id}/${tb}`] = info
        if (!info.rowButtons) { console.log(`${p.id}/${tb}: no filter button (${info.rows} rows)`); continue }
        const b = mark(s)
        await s.page.locator(`[data-testid="${p.id}"] tbody tr`).first().locator('button').first().click()
        await s.page.waitForTimeout(6000)
        const m = await measure(s.page)
        const lg = summarizeLog(sliceOf(s, b))
        const file = shot < 6 ? `${tag}-click-${p.id.slice(6)}-${tb ?? 'rows'}-light-desktop` : null
        if (file) { await s.page.screenshot({ path: join(out, `${file}.png`), fullPage: true }); shot++ }
        appendFileSync(textsFile, `\n===== click ${p.id}/${tb} =====\n${m.bodyText}\n`)
        // second click on another row of the same panel (one filter at a time: replaces)
        let second = null
        const rows2 = await s.page.locator(`[data-testid="${p.id}"] tbody tr button`).count()
        if (rows2 > 1) {
          const b2 = mark(s)
          await s.page.locator(`[data-testid="${p.id}"] tbody tr`).nth(1).locator('button').first().click()
          await s.page.waitForTimeout(5000)
          const m2 = await measure(s.page)
          second = { url: m2.url, chips: m2.chips, log: summarizeLog(sliceOf(s, b2)), filterUnavailable: m2.filterUnavailable }
        }
        const c = { panel: p.id, tab: tb, url: m.url, chips: m.chips, kpis: m.kpis.map(k => `${k.key}=${k.value}`), filterUnavailable: m.filterUnavailable, errorStates: m.errorStates, n409: lg.n409, failing: lg.errors, consoleErrors: lg.console.length, console: lg.console.slice(0, 5), panelsAfter: m.panels.map(x => ({ id: x.id, rows: x.rows, unavailable: x.unavailable })), file, second }
        result.checks.clicks.push(c)
        console.log(`${p.id}/${tb}: chips ${c.chips} 409 ${c.n409} failing ${c.failing.length} console ${c.consoleErrors} unavailable ${JSON.stringify(c.filterUnavailable).slice(0, 120)} second ${second ? `${second.chips} 409 ${second.log.n409}` : '-'}`)
      }
    }
    // filter URLs the old UI offered: two filters, 48 h, 7 d
    for (const [q, f] of [[`zeit=6h&filter=country:DE&filter=net_class:residential`, 'two-6h'], [`zeit=48h&filter=country:DE`, 'one-48h'], [`zeit=7d&filter=country:DE`, 'one-7d'], [`zeit=6h&filter=ua_class:browser`, 'uaclass-6h']]) {
      const e = await visit(s, `/w/${SITE}?${q}`, `${tag}-url-${f}-light-desktop`, { wait: 6000 })
      result.checks[`url ${f}`] = { url: e.measure.url, chips: e.measure.chips, kpis: e.measure.kpis.map(k => `${k.key}=${k.value}`), filterUnavailable: e.measure.filterUnavailable, n409: e.log.n409, errors: e.log.errors, console: e.log.console.length }
    }
    // Events links of the panels (Ereignisse with net_class/method/ua_class)
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'incident') {
    const list = (process.env.INCIDENTS || '').split(',').filter(Boolean).map(x => x.split('='))
    result.checks.incidents = []
    await each(['desktop', 'mobile'], ['light', 'dark'], async (s) => {
      for (const [label, num] of list) {
        if (s.view === 'mobile' && s.theme === 'dark' && label !== 'hosting7d') continue
        const e = await visit(s, `/incidents/${num}`, `${tag}-${label}-${s.theme}-${s.view}`, { wait: 4500 })
        const api = await apiGet(s.page, `/incidents/${num}`)
        result.checks.incidents.push({ view: s.name, label, num, sentence: e.measure.incidentSentence, status: e.measure.incidentStatus, card: e.measure.incidentCard, api: api.body })
      }
      if (s.view === 'desktop') {
        await visit(s, '/behaviour', `${tag}-verhalten-${s.theme}-desktop`, { wait: 5000 })
        await visit(s, `/w/${SITE}/angriffe`, `${tag}-shop-angriffe-${s.theme}-desktop`, { wait: 6000 })
        await visit(s, '/incidents', `${tag}-vorfaelle-list-${s.theme}-desktop`, { wait: 4500 })
      }
      if (s.view === 'desktop' && s.theme === 'light') {
        // the block_long marker of the chart (hover) and the angriffe text "7 Tage, weil ..."
        for (const site of ['shop.test', 'blog.test', 'api.test']) {
          await s.page.goto(`${base}/#/w/${site}?zeit=6h`, { waitUntil: 'domcontentloaded' })
          await s.page.waitForTimeout(6000)
          const titles = await s.page.evaluate(() => [...document.querySelectorAll('[data-marker]')].filter(c => (c.dataset.kinds ?? '').includes('block_long')).map(c => c.getAttribute('title')))
          result.checks[`blockLongTitles ${site}`] = titles
          const lb = s.page.locator('[data-kinds*="block_long"]').first()
          if (await lb.count()) { await lb.hover(); await s.page.waitForTimeout(800); await s.page.screenshot({ path: join(out, `${tag}-${site.split('.')[0]}-blocklong-hover-light-desktop.png`) }) }
          const at = await visit(s, `/w/${site}/angriffe`, null, { wait: 5000 })
          result.checks[`angriffe ${site}`] = { blockDurations: at.measure.blockDurations, blockScope: at.measure.blockScope }
        }
      }
    })
    save(`${tag}-check.json`)
  }
  else if (phase === 'pages') {
    const routes = (process.env.ROUTES || `/,/w/${SITE},/w/${SITE}/angriffe,/w/${SITE}/exceptions,/w/${SITE}/zugriffe,/w/${SITE}/charts,/angriffe,/ausnahmen,/zugriffe,/diagramme,/events,/incidents,/server,/server/check,/behaviour,/own-ips,/privacy,/status,/settings,/settings/verbund/regeln,/settings/verbund/freigaben,/settings/verbund/signale`).split(',')
    const views = (process.env.VIEWS || 'desktop-light,desktop-dark,mobile-light,mobile-dark').split(',')
    for (const vt of views) {
      const [v, th] = vt.split('-')
      const s = await session(v, th)
      result.checks[`nav ${vt}`] = null
      let i = 0
      for (const r of routes) {
        i++
        const slug = r === '/' ? 'websites' : r.replace(/^\//, '').replace(/\//g, '_').replace(/\./g, '')
        // full page in light desktop, viewport elsewhere (size)
        await visit(s, r, process.env.NOSHOTS ? null : `${tag}-${String(i).padStart(2, '0')}-${slug}-${th}-${v}`, { wait: 5000, full: vt === 'desktop-light', tips: vt === 'desktop-light' })
      }
      if (v === 'mobile') {
        const trig = s.page.locator('[data-sidebar="trigger"]').first()
        if (await trig.count()) { await trig.click(); await s.page.waitForTimeout(800); await s.page.screenshot({ path: join(out, `${tag}-nav-open-${th}-mobile.png`) }) }
      }
      result.checks[`nav ${vt}`] = await s.page.evaluate(() => [...document.querySelectorAll('[data-sidebar="sidebar"] a, [data-sidebar="menu-button"]')].map(a => ({ text: a.innerText.replace(/\s+/g, ' ').trim(), href: a.getAttribute('href') })))
      // styleguide reachable by URL (not by nav)?
      if (vt === 'desktop-light') {
        await s.page.goto(`${base}/#/styleguide`, { waitUntil: 'domcontentloaded' })
        await s.page.waitForTimeout(3000)
        result.checks.styleguideByUrl = { url: s.page.url(), h1: await s.page.evaluate(() => document.querySelector('h1')?.innerText ?? null) }
      }
      await s.ctx.close()
    }
    // styleguide without a session
    const ctx = await browser.newContext({ viewport: VIEW.desktop })
    const p = await ctx.newPage()
    await p.goto(`${base}/#/styleguide`, { waitUntil: 'domcontentloaded' })
    await p.waitForTimeout(3000)
    result.checks.styleguideNoSession = { url: p.url(), h1: await p.evaluate(() => document.querySelector('h1')?.innerText ?? null) }
    await ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'tabs') {
    // Verhalten & Limits: every tab (the hosting ladder is under Szenarien), the filter "Laufende Sperren".
    await each(['desktop'], ['light', 'dark'], async (s) => {
      await s.page.goto(`${base}/#/behaviour`, { waitUntil: 'domcontentloaded' })
      await s.page.waitForTimeout(4000)
      for (const name of ['Szenarien', 'Limits', 'Wellen']) {
        await visit(s, null, `${tag}-verhalten-tab-${name.toLowerCase()}-${s.theme}-desktop`, { full: true, before: async (p) => { await p.getByRole('tab', { name, exact: true }).first().click(); await p.waitForTimeout(2500) } })
      }
      await s.page.goto(`${base}/#/behaviour`, { waitUntil: 'domcontentloaded' })
      await s.page.waitForTimeout(4000)
      await visit(s, null, `${tag}-verhalten-running-${s.theme}-desktop`, { full: false, before: async (p) => { await p.getByText('Laufende Sperren', { exact: true }).first().click(); await p.waitForTimeout(2500) } })
      result.checks[`ladder ${s.theme}`] = await s.page.evaluate(() => [...document.querySelectorAll('[data-testid^="ladder"]')].map(e => e.innerText))
    })
    save(`${tag}-check.json`)
  }
  else if (phase === 'watch') {
    const s = await session('desktop', 'light')
    const secs = Number(process.env.WATCH_S || 70)
    for (const path of [`/w/${SITE}`, '/', '/server']) {
      await s.page.goto(`${base}/#${path}`, { waitUntil: 'domcontentloaded' })
      const t1 = (Date.now() - s.t0) / 1000
      await s.page.waitForTimeout(secs * 1000)
      const t2 = (Date.now() - s.t0) / 1000
      result.checks[`watch ${path}`] = { seconds: +(t2 - t1).toFixed(1), groups: polling(s.log, t1 + 8, t2) }
      console.log(path, JSON.stringify(Object.fromEntries(Object.entries(result.checks[`watch ${path}`].groups).map(([k, v]) => [k.slice(0, 80), [v.count, v.minGapS, v.statuses]]))))
    }
    result.checks.log = summarizeLog(s.log)
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'off') {
    await each(['desktop', 'mobile'], ['light', 'dark'], async (s) => {
      let i = 0
      for (const r of [`/`, `/w/${SITE}`, `/w/${SITE}/angriffe`, `/w/${SITE}/charts`, '/server', '/behaviour']) {
        i++
        const slug = r === '/' ? 'websites' : r.replace(/^\//, '').replace(/\//g, '_').replace(/\./g, '')
        await visit(s, r, (s.view === 'desktop' || i <= 2) ? `${tag}-${String(i).padStart(2, '0')}-${slug}-${s.theme}-${s.view}` : null, { wait: 6000, full: s.view === 'desktop' && s.theme === 'light' })
      }
      if (s.view === 'desktop' && s.theme === 'light') {
        for (const path of [`/w/${SITE}`, '/']) {
          await s.page.goto(`${base}/#${path}`, { waitUntil: 'domcontentloaded' })
          const t1 = (Date.now() - s.t0) / 1000
          await s.page.waitForTimeout(Number(process.env.WATCH_S || 75) * 1000)
          const t2 = (Date.now() - s.t0) / 1000
          result.checks[`watch ${path}`] = { seconds: +(t2 - t1).toFixed(1), groups: polling(s.log, t1 + 8, t2) }
          console.log(path, JSON.stringify(Object.fromEntries(Object.entries(result.checks[`watch ${path}`].groups).map(([k, v]) => [k.slice(0, 80), [v.count, v.minGapS, v.statuses]]))))
        }
        result.checks.log = summarizeLog(s.log)
      }
    })
    save(`${tag}-check.json`)
  }

  else if (phase === 'ranges') {
    // Per full page load (reload): 409s and console errors on the overview and the website page at every range.
    result.checks.loads = []
    const s = await session('desktop', 'light')
    const routes = (process.env.ROUTES || `/,/w/${SITE}?zeit=6h,/w/${SITE}?zeit=24h,/w/${SITE}?zeit=48h,/w/${SITE}?zeit=7d,/w/${SITE}/angriffe,/w/${SITE}/zugriffe,/server,/behaviour,/incidents,/events`).split(',')
    for (const r of routes) {
      for (let rep = 0; rep < Number(process.env.REPS || 2); rep++) {
        await s.page.goto(`${base}/#${r}`, { waitUntil: 'domcontentloaded' })
        await s.page.waitForTimeout(1500)
        const b = mark(s)
        await s.page.reload({ waitUntil: 'domcontentloaded' })
        await s.page.waitForTimeout(Number(process.env.WAIT || 8000))
        const lg = summarizeLog(sliceOf(s, b))
        const m = await measure(s.page)
        const e = { route: r, rep, n409: lg.n409, n404: lg.n404, failing: lg.errors, consoleErrors: lg.console.filter(c => c.type === 'error').length, console: lg.console.slice(0, 6), pageErrors: lg.pageErrors, api: lg.api, kpis: m.kpis.map(k => `${k.key}=${k.value}`), kpiRowText: m.kpiRowText, monitoringOff: m.monitoringOff, filterUnavailable: m.filterUnavailable, crumb: m.crumbOverlap }
        result.checks.loads.push(e)
        appendFileSync(textsFile, `\n===== ${s.name} ${r} reload ${rep} =====\n${m.bodyText}\n`)
        console.log(`${r} #${rep}: api ${lg.api} 409 ${lg.n409} 404 ${lg.n404} failing ${lg.errors.length} console-err ${e.consoleErrors} ${lg.errors.map(x => `${x.status} ${x.url.slice(0, 70)}`).join(' | ')}`)
        if (rep === 0 && process.env.SHOT_RANGES) await s.page.screenshot({ path: join(out, `${tag}-${r.replace(/[^a-z0-9]+/gi, '_')}-light-desktop.png`) })
      }
    }
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'server') {
    result.checks.server = []
    for (const [v, th] of (process.env.VIEWS || 'desktop-light,desktop-dark').split(',').map(x => x.split('-'))) {
      const s = await session(v, th)
      const e = await visit(s, '/server', `${tag}-server-${th}-${v}`, { wait: Number(process.env.WAIT || 8000), full: true })
      const charts = await s.page.evaluate(() => [...document.querySelectorAll('[data-testid^="chart-"]')].map(c => ({ id: c.dataset.testid, text: c.innerText.replace(/\s+/g, ' ').trim().slice(0, 300) })))
      const env = await apiGet(s.page, '/monitoring/server')
      result.checks.server.push({ view: s.name, charts, bodyHas10s: /nach etwa 10 Sekunden/.test(await s.page.evaluate(() => document.body.innerText)), environment: env.body?.environment ?? null, n409: e.log.n409, console: e.log.console.length })
      console.log(s.name, JSON.stringify(charts.map(c => `${c.id}: ${c.text.slice(0, 120)}`), null, 1))
      await s.ctx.close()
    }
    save(`${tag}-check.json`)
  }
  else if (phase === 'observe') {
    // observe-mode instance: would_block events are "Erkannt"; event detail says why it was let through.
    const s = await session('desktop', 'light')
    for (const r of process.env.DETAIL_ONLY ? [] : ['/', `/w/${SITE}`, `/w/${SITE}/angriffe`, '/events', '/angriffe', '/behaviour', '/diagramme']) {
      const slug = r === '/' ? 'websites' : r.replace(/^\//, '').replace(/\//g, '_').replace(/\./g, '')
      await visit(s, r, `${tag}-${slug}-light-desktop`, { wait: 6000, full: true, tips: true })
    }
    // open the first event row
    await s.page.goto(`${base}/#/events?ergebnis=would_block`, { waitUntil: 'domcontentloaded' })
    await s.page.waitForTimeout(5000)
    const row = s.page.locator('tbody tr').first()
    if (await row.count()) {
      await row.click()
      await s.page.waitForTimeout(2500)
      await visit(s, null, `${tag}-event-detail-light-desktop`, { full: false, tips: true })
    }
    await s.ctx.close()
    save(`${tag}-check.json`)
  }
  else if (phase === 'styleguide') {
    result.checks.styleguide = []
    const probe = async (label, page) => {
      for (const u of [`${base}/#/styleguide`, `${base}/styleguide`]) {
        const resp = await page.goto(u, { waitUntil: 'domcontentloaded' })
        await page.waitForTimeout(3000)
        const r = { label, u, http: resp?.status() ?? null, finalUrl: page.url(), h1: await page.evaluate(() => document.querySelector('h1')?.innerText ?? null), hasPassword: await page.locator('input[type="password"]').count(), text: (await page.evaluate(() => document.body.innerText)).replace(/\s+/g, ' ').slice(0, 200) }
        result.checks.styleguide.push(r)
        console.log(JSON.stringify(r))
      }
    }
    const ctx = await browser.newContext({ viewport: VIEW.desktop })
    const p = await ctx.newPage()
    await probe('no session', p)
    await p.screenshot({ path: join(out, `${tag}-styleguide-nosession-light-desktop.png`) })
    await ctx.close()
    const s = await session('desktop', 'light')
    await probe('session', s.page)
    await s.page.goto(`${base}/#/styleguide`, { waitUntil: 'domcontentloaded' }); await s.page.waitForTimeout(2500)
    await s.page.screenshot({ path: join(out, `${tag}-styleguide-session-light-desktop.png`) })
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
