// UX review harness against the REAL backends (dashboard/scripts/dev-backends.sh up +
// seed-dev.sh): screenshots of every section at 1440x900 and 390x844 in light
// and dark, axe WCAG 2.2 AA per section, console/CSP errors, first-load size
// and timing. Uses the Playwright of the client dashboard (its dev dependency; browsers via
// `pnpm --filter @schild/client-dashboard exec playwright install chromium`).
//
//   node dashboard/scripts/ux-shots.mjs OUT_DIR [sections|flows|perf|all]
//
// Env: CLIENT_URL, LAB_URL, DEV_PASSWORD, SHOTS (all = every viewport/scheme;
// default a reduced set to keep the PNGs small), ONLY (client|lab).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
// Playwright and axe-core as dev dependencies of the client dashboard resolve them.
const client = createRequire(join(here, '../apps/client-dashboard/package.json'))
const { chromium } = client('@playwright/test')
const axeSource = readFileSync(createRequire(client.resolve('@axe-core/playwright')).resolve('axe-core/axe.min.js'), 'utf8')

const out = resolve(process.argv[2] ?? 'ux-out')
const what = process.argv[3] ?? 'all'
const CLIENT = process.env.CLIENT_URL ?? 'http://127.0.0.1:41788'
const LAB = process.env.LAB_URL ?? 'http://127.0.0.1:41789'
const PASSWORD = process.env.DEV_PASSWORD ?? 'schild-dev-passwort'
const ALL = process.env.SHOTS === 'all'
const ONLY = process.env.ONLY
mkdirSync(out, { recursive: true })

const VIEWPORTS = { desktop: { width: 1440, height: 900 }, mobile: { width: 390, height: 844 } }
// Reduced set: desktop light full page, desktop dark and mobile light viewport.
const COMBOS = ALL
  ? [['desktop', 'light', true], ['desktop', 'dark', true], ['mobile', 'light', true], ['mobile', 'dark', true]]
  : [['desktop', 'light', true], ['desktop', 'dark', false], ['mobile', 'light', false], ['mobile', 'dark', false]]

const report = { generated_at: new Date().toISOString(), sections: [], flows: [], perf: [], errors: [] }
const browser = await chromium.launch()

async function newContext(viewport, scheme, state) {
  const ctx = await browser.newContext({ viewport: VIEWPORTS[viewport], colorScheme: scheme, deviceScaleFactor: 1, storageState: state, reducedMotion: 'reduce' })
  return ctx
}

function watch(page, where) {
  const errs = []
  page.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()) })
  page.on('pageerror', e => errs.push(`pageerror: ${e.message}`))
  page.on('response', (r) => { if (r.status() >= 500) errs.push(`${r.status()} ${r.url()}`) })
  return () => {
    const e = errs.splice(0)
    if (e.length) report.errors.push({ where, errors: e })
    return e
  }
}

async function settle(page) {
  // No networkidle: the live streams (SSE) keep a request open.
  await page.locator('main#main h1, main h1, h1').first().waitFor({ timeout: 8000 }).catch(() => {})
  await page.waitForFunction(() => !document.querySelector('[data-slot="skeleton"], .animate-pulse'), null, { timeout: 6000 }).catch(() => {})
  await page.waitForTimeout(500)
}

async function axe(page) {
  await page.evaluate(axeSource)
  const r = await page.evaluate(async () => {
    const res = await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] } })
    return res.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.slice(0, 5).map(n => ({ target: n.target.join(' '), summary: n.failureSummary?.split('\n').slice(0, 3).join(' ') })) }))
  })
  return r
}

async function loginClient() {
  const ctx = await newContext('desktop', 'light')
  const page = await ctx.newPage()
  await page.goto(`${CLIENT}/#/login`)
  await page.getByLabel('Passwort', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Anmelden' }).click()
  await page.waitForURL(u => !u.hash.includes('anmelden'), { timeout: 10000 })
  const state = await ctx.storageState()
  await ctx.close()
  return state
}

async function loginLab(user = 'alice') {
  const ctx = await newContext('desktop', 'light')
  const page = await ctx.newPage()
  await page.goto(`${LAB}/`)
  await settle(page)
  // Localhost sessions are read-only; decisions need a named login (settings > account or the login button).
  const res = await page.evaluate(async ({ user, pw }) => {
    const s = await (await fetch('./api/v0/auth/session')).json()
    const r = await fetch('./api/v0/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': s.csrf_token ?? '' }, body: JSON.stringify({ user, password: pw }) })
    return r.status
  }, { user, pw: PASSWORD })
  if (res !== 200) throw new Error(`lab login ${user}: ${res}`)
  const state = await ctx.storageState()
  await ctx.close()
  return state
}

async function apiGet(state, base, path) {
  const ctx = await newContext('desktop', 'light', state)
  const page = await ctx.newPage()
  await page.goto(`${base}/healthz`).catch(() => {})
  const r = await page.evaluate(async ({ base, path }) => (await fetch(`${base}/api/v0${path}`)).json(), { base, path })
  await ctx.close()
  return r
}

async function shootSections(app, base, state, sections) {
  for (const [name, hash] of sections) {
    for (const [vp, scheme, full] of COMBOS) {
      if (!ALL && vp === 'mobile' && scheme === 'dark') continue
      const ctx = await newContext(vp, scheme, state)
      const page = await ctx.newPage()
      const done = watch(page, `${app} ${name} ${vp} ${scheme}`)
      await page.goto(`${base}/${hash}`)
      await settle(page)
      const file = `${app}-${name}-${vp}-${scheme}.png`
      await page.screenshot({ path: join(out, file), fullPage: full })
      let violations
      if (vp === 'desktop' || name === 'overview') violations = await axe(page)
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)
      report.sections.push({ app, name, vp, scheme, file, axe: violations, horizontal_overflow: overflow, errors: done() })
      await ctx.close()
      process.stdout.write('.')
    }
  }
  process.stdout.write('\n')
}

async function sections() {
  if (ONLY !== 'lab') {
    const cstate = await loginClient()
    const site = (await apiGet(cstate, CLIENT, '/websites')).websites?.[0]?.id
    await shootSections('client', CLIENT, cstate, [
      ['websites', '#/'],
      ...(site
        ? [
            ['website', `#/w/${site}`],
            ['website-events', `#/w/${site}/events`],
            ['website-exceptions', `#/w/${site}/exceptions`],
            ['website-charts', `#/w/${site}/charts`],
            ['website-access', `#/w/${site}/access`],
            ['website-crawlers', `#/w/${site}/ai-crawlers`],
          ]
        : []),
      ['server', '#/server'],
      ['server-load', '#/server/load'],
      ['server-check', '#/server/check'],
      ['events', '#/events'],
      ['incidents', '#/incidents'],
      ['rules', '#/settings/rules'],
      ['rules-crs', '#/settings/rules/crs'],
      ['rules-crowdsec', '#/settings/rules/crowdsec'],
      ['rules-local', '#/settings/rules/local'],
      ['behaviour', '#/behaviour'],
      ['own-ips', '#/own-ips'],
      ['status', '#/status'],
      ['privacy', '#/privacy'],
      ['settings', '#/settings'],
    ])
    await shootSections('client', CLIENT, undefined, [['login', '#/login']])
  }
  if (ONLY !== 'client') {
    const lstate = await loginLab('alice')
    const patterns = await apiGet(lstate, LAB, '/patterns?sort=issuers&limit=50')
    const top = patterns.items?.find(p => p.action_sig.startsWith('sqli/')) ?? patterns.items?.[0]
    const proposals = await apiGet(lstate, LAB, '/proposals?limit=50')
    const open = proposals.items?.find(p => p.status !== 'approved' && p.status !== 'published' && p.status !== 'rejected') ?? proposals.items?.[0]
    await shootSections('lab', LAB, lstate, [
      ['overview', '#/'],
      ['patterns', '#/signals'],
      ['pattern', `#/signals/${top?.pattern_id ?? 'none'}`],
      ['proposals', '#/proposals'],
      ['proposal', `#/proposals/${open?.id ?? 'none'}`],
      ['published', '#/published'],
      ['bundle', '#/published/1'],
      ['withdrawals', '#/published/withdrawals'],
      ['relays', '#/relays'],
      ['clients', '#/clients'],
      ['log', '#/log'],
      ['settings', '#/settings'],
    ])
  }
}

// ------------------------------------------------------------------ flows
async function step(flow, page, name, fn, { full = false } = {}) {
  try {
    if (fn) await fn()
    await page.waitForTimeout(400)
    const file = `flow-${flow}-${name}.png`
    await page.screenshot({ path: join(out, file), fullPage: full })
    report.flows.push({ flow, step: name, file, ok: true })
  }
  catch (e) {
    report.flows.push({ flow, step: name, ok: false, error: String(e.message ?? e).split('\n')[0] })
    console.log(`flow ${flow}/${name}: ${String(e.message ?? e).split('\n')[0]}`)
  }
}

async function flows() {
  if (ONLY !== 'lab') await clientFlows()
  if (ONLY !== 'client') await labFlows()
}

async function clientFlows() {
  const state = await loginClient()
  const events = await apiGet(state, CLIENT, '/events?limit=200')
  const incidentEvent = events.items?.find(e => e.incident)
  const hubRule = (await apiGet(state, CLIENT, '/rules?repository=crowdsec&limit=50')).items?.[0]
  for (const vp of ['desktop', 'mobile']) {
    const ctx = await newContext(vp, 'light', state)
    const page = await ctx.newPage()
    const done = watch(page, `client flows ${vp}`)
    const f = n => `client-${vp}-${n}`
    await page.goto(`${CLIENT}/#/events`)
    await settle(page)
    await step(f('events'), page, '1-filter-blocked', async () => {
      await page.goto(`${CLIENT}/#/events?outcome=blocked`)
      await settle(page)
    })
    await step(f('events'), page, '2-detail', async () => {
      await page.getByRole('table').locator('tbody tr[data-row]').first().click()
      await page.getByRole('dialog').waitFor()
      await page.waitForTimeout(500)
    })
    await page.keyboard.press('Escape')
    if (incidentEvent) {
      await step(f('incident'), page, '1-lookup', async () => {
        await page.goto(`${CLIENT}/#/incidents`)
        await settle(page)
        await page.getByTestId('incident-input').fill(incidentEvent.incident.toLowerCase().replace('-', ''))
        await page.getByTestId('incident-search').click()
        await page.getByTestId('incident-card').waitFor()
      }, { full: vp === 'mobile' })
      await step(f('incident'), page, '2-unblock-dialog', async () => {
        await page.getByTestId('incident-unblock').click()
        await page.getByRole('dialog').waitFor()
      })
      if (vp === 'desktop') {
        await step(f('incident'), page, '3-unblocked', async () => {
          await page.getByRole('dialog').getByTestId('unblock-submit').click()
          await page.getByTestId('incident-status').waitFor()
          await page.waitForTimeout(600)
        })
      }
      else await page.keyboard.press('Escape')
    }
    if (hubRule) {
      await step(f('rule'), page, '1-detail', async () => {
        await page.goto(`${CLIENT}/#/settings/rules/crowdsec?rule=${encodeURIComponent(hubRule.id)}`)
        await settle(page)
        await page.getByRole('dialog').waitFor({ timeout: 5000 })
      })
      await step(f('rule'), page, '2-disable-confirm', async () => {
        await page.getByTestId('rule-disable').click()
        await page.getByTestId('rule-disable-confirm').waitFor()
      })
      await page.keyboard.press('Escape')
      await page.keyboard.press('Escape')
    }
    await step(f('own-ips'), page, '1-allow-mine', async () => {
      await page.goto(`${CLIENT}/#/own-ips`)
      await settle(page)
      // Inline form at the top of the page (no dialog).
      await page.getByTestId('my-ip').waitFor()
    })
    await step(f('privacy'), page, '1-search', async () => {
      await page.goto(`${CLIENT}/#/privacy`)
      await settle(page)
      await page.getByRole('searchbox').or(page.getByLabel(/IP/).first()).first().fill('203.0.113.51')
      await page.keyboard.press('Enter')
      await page.waitForTimeout(1200)
    }, { full: true })
    await step(f('privacy'), page, '2-delete-dialog', async () => {
      await page.getByRole('button', { name: /löschen/i }).first().click()
      await page.getByRole('dialog').or(page.getByRole('alertdialog')).first().waitFor()
    })
    await page.keyboard.press('Escape')
    await step(f('settings'), page, '1-mode', async () => {
      await page.goto(`${CLIENT}/#/settings`)
      await settle(page)
      await page.getByTestId('mode-autoblock').click()
      await page.getByTestId('mode-save').click()
      await page.getByRole('dialog').or(page.getByRole('alertdialog')).first().waitFor()
    })
    await page.keyboard.press('Escape')
    await step(f('palette'), page, '1-open', async () => {
      await page.goto(`${CLIENT}/#/`)
      await settle(page)
      await page.keyboard.press('ControlOrMeta+k')
      await page.getByRole('dialog').waitFor()
    })
    done()
    await ctx.close()
  }
}

async function labFlows() {
  const state = await loginLab('alice')
  const patterns = await apiGet(state, LAB, '/patterns?sort=issuers&limit=50')
  const proposals = await apiGet(state, LAB, '/proposals?limit=50')
  const open = proposals.items?.find(p => !['approved', 'published', 'rejected'].includes(p.status))
  for (const vp of ['desktop', 'mobile']) {
    const ctx = await newContext(vp, 'light', state)
    const page = await ctx.newPage()
    const done = watch(page, `lab flows ${vp}`)
    const f = n => `lab-${vp}-${n}`
    await step(f('patterns'), page, '1-filter', async () => {
      await page.goto(`${LAB}/#/signals?min_issuers=3`)
      await settle(page)
    })
    const pid = patterns.items?.find(p => p.action_sig.startsWith('xss/'))?.pattern_id ?? patterns.items?.[0]?.pattern_id
    await step(f('patterns'), page, '2-drilldown', async () => {
      await page.goto(`${LAB}/#/signals/${pid}`)
      await settle(page)
    }, { full: true })
    if (open) {
      await step(f('proposal'), page, '1-review', async () => {
        await page.goto(`${LAB}/#/proposals/${open.id}`)
        await settle(page)
      }, { full: true })
      await step(f('proposal'), page, '2-approve-dialog', async () => {
        await page.getByRole('button', { name: /^Freigeben/ }).first().click()
        await page.getByRole('dialog').waitFor()
      })
      await page.keyboard.press('Escape')
    }
    await step(f('withdrawals'), page, '1-withdraw-all-dialog', async () => {
      await page.goto(`${LAB}/#/published/withdrawals`)
      await settle(page)
      await page.getByRole('button', { name: /Alle Netzregeln zurückziehen/ }).first().click()
      await page.getByRole('dialog').or(page.getByRole('alertdialog')).first().waitFor()
      await page.getByLabel(/ALLE ZURÜCKZIEHEN/).first().fill('ALLE ZURÜCKZIEHEN')
    })
    await page.keyboard.press('Escape')
    await step(f('log'), page, '1-verify', async () => {
      await page.goto(`${LAB}/#/log`)
      await settle(page)
      await page.getByRole('button', { name: /prüfen/i }).first().click()
      await page.waitForTimeout(1500)
    }, { full: true })
    await step(f('clients'), page, '1-revoke-dialog', async () => {
      await page.goto(`${LAB}/#/clients`)
      await settle(page)
      await page.getByRole('button', { name: /sperren/i }).first().click()
      await page.getByRole('dialog').or(page.getByRole('alertdialog')).first().waitFor()
    })
    await page.keyboard.press('Escape')
    done()
    await ctx.close()
  }
}

// ------------------------------------------------------------------ perf
async function loaded(page) {
  const t = await page.locator('[data-slot="cursor-footer"] p').first().textContent().catch(() => '')
  return Number((t ?? '').split('geladen')[0].replace(/[^0-9]/g, '')) || 0
}
async function perf() {
  for (const [app, base, state, path] of [
    ['client', CLIENT, ONLY === 'lab' ? null : await loginClient(), '#/events'],
    ['lab', LAB, ONLY === 'client' ? null : await loginLab('alice'), '#/'],
  ]) {
    if (!state) continue
    const ctx = await newContext('desktop', 'light', state)
    const page = await ctx.newPage()
    const cdp = await ctx.newCDPSession(page)
    await cdp.send('Network.enable')
    let encoded = 0
    cdp.on('Network.loadingFinished', (e) => { encoded += e.encodedDataLength })
    const t0 = Date.now()
    await page.goto(`${base}/${path}`)
    await page.locator('main#main h1').first().waitFor({ timeout: 15000 })
    const tH1 = Date.now() - t0
    // The live stream (SSE) keeps a request open: networkidle may never come.
    const idle = await page.waitForLoadState('networkidle', { timeout: 5000 }).then(() => true, () => false)
    const tIdle = idle ? Date.now() - t0 : null
    const nav = await page.evaluate(() => {
      const n = performance.getEntriesByType('navigation')[0]
      const res = performance.getEntriesByType('resource')
      const sum = kind => res.filter(r => r.name.match(kind)).reduce((a, r) => a + r.encodedBodySize, 0)
      return { dcl_ms: Math.round(n.domContentLoadedEventEnd), load_ms: Math.round(n.loadEventEnd), js_bytes: sum(/\.js(\?|$)/), css_bytes: sum(/\.css(\?|$)/), font_bytes: sum(/\.woff2?(\?|$)/), resources: res.length }
    })
    const entry = { app, path, first_heading_ms: tH1, network_idle_ms: tIdle, transferred_bytes: encoded, ...nav }
    if (app === 'client') {
      // Scroll the event table (cursor mode loads more on demand) and measure frame times.
      const rows0 = await page.locator('tbody tr[data-row]').count()
      const tLoad = Date.now()
      const clicks = []
      for (let i = 0; i < Number(process.env.PERF_PAGES ?? 120); i++) {
        const more = page.getByRole('button', { name: 'Mehr laden' })
        if (!(await more.isVisible().catch(() => false))) break
        // Loaded rows from the footer ("N geladen"): a virtualized table keeps only a window in the DOM.
        const before = await loaded(page)
        const tc = Date.now()
        await more.click()
        await page.waitForFunction(n => Number((document.querySelector('[data-slot="cursor-footer"]')?.textContent ?? '').replace(/[^0-9]/g, '').slice(0, 7) || 0) > n, before, { timeout: 15000 }).catch(() => {})
        clicks.push(Date.now() - tc)
      }
      entry.load_more = { clicks: clicks.length, total_ms: Date.now() - tLoad, first_ms: clicks[0], last_ms: clicks.at(-1), max_ms: Math.max(0, ...clicks) }
      const rows = await loaded(page)
      const rowsInDom = await page.locator('tbody tr[data-row]').count()
      const frames = await page.evaluate(async () => {
        const times = []
        let last = performance.now()
        let run = true
        const loop = (t) => { times.push(t - last); last = t; if (run) requestAnimationFrame(loop) }
        requestAnimationFrame(loop)
        // Scroll the table's own scroll area (and the page) top to bottom in 300 steps.
        const el = document.querySelector('[data-testid="table-scroll"]') ?? document.scrollingElement
        const step = Math.max(400, Math.ceil(el.scrollHeight / 300))
        for (let y = 0; y < el.scrollHeight; y += step) { el.scrollTo(0, y); await new Promise(r => setTimeout(r, 16)) }
        el.scrollTo(0, 0)
        run = false
        times.sort((a, b) => a - b)
        return { frames: times.length, p50_ms: Math.round(times[Math.floor(times.length / 2)]), p95_ms: Math.round(times[Math.floor(times.length * 0.95)]), max_ms: Math.round(times.at(-1)) }
      })
      const dom = await page.evaluate(() => document.getElementsByTagName('*').length)
      const heap = await page.evaluate(() => performance.memory?.usedJSHeapSize ?? null)
      Object.assign(entry, { rows_initial: rows0, rows_loaded: rows, rows_in_dom: rowsInDom, scroll: frames, dom_nodes: dom, js_heap_bytes: heap })
      // Filter latency on the loaded table.
      const tf = Date.now()
      await page.goto(`${base}/#/events?outcome=blocked`)
      await page.locator('tbody tr[data-row]').first().waitFor({ timeout: 10000 }).catch(() => {})
      entry.filter_ms = Date.now() - tf
    }
    report.perf.push(entry)
    console.log(JSON.stringify(entry))
    await ctx.close()
  }
}

try {
  if (what === 'sections' || what === 'all') await sections()
  if (what === 'flows' || what === 'all') await flows()
  if (what === 'perf') await perf()
}
finally {
  await browser.close()
  writeFileSync(join(out, `report-${what}.json`), `${JSON.stringify(report, null, 2)}\n`)
}
const ax = report.sections.filter(s => s.axe?.length)
console.log(`sections ${report.sections.length}, with axe violations ${ax.length}, overflow ${report.sections.filter(s => s.horizontal_overflow).map(s => `${s.app}/${s.name}/${s.vp}`).join(', ') || 'none'}, flows ok ${report.flows.filter(f => f.ok).length}/${report.flows.length}, error sets ${report.errors.length}`)
