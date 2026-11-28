// Retakes every dashboard screenshot of the website and the gateway docs in one run:
//
//   cd site && npm run shots            # all
//   cd site && npm run shots -- doku-   # only shots whose name starts with "doku-"
//
// What it does: starts the gateway dashboard in mock mode (on a free port), lets the gateway write the pages it
// answers visitors with (block page, login page, maintenance page; gateway/internal/tools/sitepages), takes the
// screenshots with the Playwright of the dashboard and writes them as WebP into site/public/img/dashboards.
// It then puts today's date into app/utils/shots.ts, which the captions read.
//
// Needs: the dashboard dependencies (`cd dashboard && pnpm install`, Chromium via
// `pnpm --filter @schild/client-dashboard exec playwright install chromium`), Go, and `cwebp` (package "webp").
//
// To add a screenshot, add an entry to SHOTS. The screenshots show test data only; IP addresses are blurred,
// because a reader cannot tell a documentation address from a real one.
import { execFileSync, spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repo = resolve(here, '../..')
const dashboard = join(repo, 'dashboard/apps/client-dashboard')
const outDir = join(repo, 'site/public/img/dashboards')
const { chromium } = createRequire(join(dashboard, 'package.json'))('@playwright/test')

const only = process.argv[2]

// The worked example on /funktionen: a blocked SQL injection attempt from a data centre in Singapore. The incident
// number is part of the alt texts (site/app/pages/funktionen.vue, docs/gateway/01-funktionen.md).
const EXAMPLE = { country: 'SG', rule: '942100', incident: 'RN9T-F36Q' }

const DESKTOP = { width: 1440, height: 900, scale: 1.5, widths: [720, 1100, 1600] } // 2160 wide
const DOCS = { width: 1440, height: 900, scale: 1.5, widths: [], full: 1600 } // one file, 1600 wide
const site = 'verein.example'

// name: file name without extension. route: dashboard route, or page: one of the gateway's pages.
// scenario: mock scenario of the dashboard (default 'default').
// run(page, ctx): steps before the screenshot. top: text of a heading to scroll to,
// gap: how far below the upper edge it ends up (pixels, default 110).
const SHOTS = [
  // Start page (site/app/pages/index.vue)
  { name: 'gateway-hero', route: `/w/${site}`, width: 1440, height: 712, scale: 2, widths: [1100, 1600, 2200] },
  { name: 'gateway-hero-mobile', route: `/w/${site}`, width: 430, height: 492, scale: 2, widths: [] },
  { name: 'gateway-website', route: '/', ...DESKTOP },
  { name: 'gateway-requests', route: `/w/${site}`, top: 'Länder', gap: 270, ...DESKTOP },
  { name: 'gateway-attacks', route: `/w/${site}/events`, ...DESKTOP },
  { name: 'gateway-server', route: '/server', ...DESKTOP },

  // /funktionen: the basic protection as it comes (rule repositories, OWASP CRS, CrowdSec Hub), see factory()
  { name: 'funktionen-grundschutz-regeln', route: '/', run: page => factory(page, '/settings/rules'), ...DESKTOP },
  { name: 'funktionen-grundschutz-crs', route: '/', run: page => factory(page, '/settings/rules/crs'), ...DESKTOP },
  { name: 'funktionen-grundschutz-crowdsec', route: '/', run: page => factory(page, '/settings/rules/crowdsec'), ...DESKTOP },

  // /funktionen: login protection as it comes (scenarios, limits per path), and an address it blocked
  { name: 'funktionen-login-szenarien', route: '/', run: page => factory(page, '/settings/rules/behaviour'), ...DESKTOP },
  // The switch column is too narrow for "Begrenzen (empfohlen)": the selects get the width of their text.
  { name: 'funktionen-login-limits', route: '/', run: async (page) => {
    await factory(page, '/settings/rules/behaviour?view=limits')
    await page.locator('#main select').evaluateAll(selects => selects.forEach((s) => { s.style.width = 'auto' }))
  }, ...DESKTOP },
  { name: 'funktionen-login-sperren', route: '/blocks', ...DESKTOP },

  // /funktionen: bots and AI crawlers per website (the preset and the switch for fake crawlers set, as the example
  // describes), the browser check
  { name: 'funktionen-crawler-ki', route: `/w/${site}/ai-crawlers`, run: blockAiTraining, ...DESKTOP },
  { name: 'funktionen-crawler-liste', route: `/w/${site}/ai-crawlers`, run: async (page) => {
    await blockAiTraining(page)
    await page.getByTestId('crawlers-open-ai_training').click()
    await page.waitForTimeout(400)
    await scrollTo(page.locator('[data-crawler-category="ai_training"]'))
    await page.evaluate(() => window.scrollBy(0, -160))
  }, ...DESKTOP },
  // From the top of the page: with maintenance off, the card of the browser check fits below it in full.
  { name: 'funktionen-crawler-pruefung', route: `/w/${site}/access`, ...DESKTOP },

  // /funktionen: a blocked SQL injection attempt
  { name: 'funktionen-sqli-blockpage', page: 'block.html', ...DESKTOP },
  { name: 'funktionen-sqli-event', route: ctx => `/events?event=${ctx.event.id}`, ...DESKTOP },
  { name: 'funktionen-sqli-why', route: ctx => `/events?event=${ctx.event.id}`, run: page => scrollTo(page.getByRole('dialog').first().getByText('Warum', { exact: true })), ...DESKTOP },

  // /funktionen: protect the admin area
  { name: 'funktionen-admin-dialog', route: `/w/${site}/access`, run: fillAccessDialog, ...DESKTOP },
  { name: 'funktionen-admin-active', route: `/w/${site}/access`, run: async (page) => {
    await fillAccessDialog(page)
    await page.getByTestId('access-submit').click()
    await page.waitForTimeout(1000)
    await page.getByTestId('access-ways').evaluate(e => e.scrollIntoView({ block: 'center' }))
  }, ...DESKTOP },
  { name: 'funktionen-admin-login', page: 'login.html', ...DESKTOP },

  // /funktionen: several gateways as a cluster. The page and a server's details show a cluster with nothing to
  // look at (mock scenario `group-ok`: three gateways, all reached and in step); the hints show the scenario
  // `group` (one gateway not reached, one with another configuration).
  { name: 'funktionen-cluster-seite', scenario: 'group-ok', route: '/server/group', ...DESKTOP },
  { name: 'funktionen-cluster-server', scenario: 'group-ok', route: '/server/group', run: async (page) => {
    await page.locator('[data-testid="group-map-node"][data-name="web-2"]').click()
    await page.getByTestId('group-node-sheet').waitFor()
    await page.waitForTimeout(600)
  }, ...DESKTOP },
  { name: 'funktionen-cluster-hinweis', scenario: 'group', route: '/settings', ...DESKTOP },
  // The cluster guide (docs/gateway/03-cluster.md): the page with three gateways in order, one gateway's details,
  // sixteen gateways (upright labels, the table), the hints and the counters with one gateway's data missing.
  { name: 'doku-cluster-seite', scenario: 'group-ok', route: '/server/group', ...DOCS },
  { name: 'doku-cluster-server', scenario: 'group-ok', route: '/server/group', run: async (page) => {
    await page.locator('[data-testid="group-map-node"][data-name="web-2"]').click()
    await page.getByTestId('group-node-sheet').waitFor()
    await page.waitForTimeout(600)
  }, ...DOCS },
  { name: 'doku-cluster-gross', scenario: 'group-large', route: '/server/group', ...DOCS },
  { name: 'doku-cluster-hinweise', scenario: 'group', route: '/settings', ...DOCS },
  { name: 'doku-cluster-zahlen', scenario: 'group', route: '/', ...DOCS },

  // Gateway docs (docs/gateway/01-funktionen.md)
  { name: 'doku-regeln', route: '/settings/rules', ...DOCS },
  { name: 'doku-crs', route: '/settings/rules/crs', ...DOCS },
  { name: 'doku-crowdsec', route: '/settings/rules/crowdsec', ...DOCS },
  { name: 'doku-eigene-regeln', route: '/settings/rules/local', ...DOCS },
  { name: 'doku-ausnahmen', route: '/settings/rules/local?view=exceptions', ...DOCS },
  { name: 'doku-szenarien', route: '/settings/rules/behaviour', ...DOCS },
  { name: 'doku-limits', route: '/settings/rules/behaviour?view=limits', ...DOCS },
  { name: 'doku-wellen', route: '/settings/rules/behaviour?view=detectors', ...DOCS },
  { name: 'doku-sperren', route: '/blocks', ...DOCS },
  { name: 'doku-ki-crawler', route: `/w/${site}/ai-crawlers`, ...DOCS },
  { name: 'doku-eigene-ips', route: '/own-ips', ...DOCS },
  // From "Updates" on: the line above it names the Schild Agent, which is planned and not built.
  { name: 'doku-server-check', route: '/server/check', top: 'Updates', ...DOCS },
  { name: 'doku-browser-pruefung', route: `/w/${site}/access`, top: 'Browser-Prüfung & Under Attack', ...DOCS },
  { name: 'doku-wartungsmodus', route: `/w/${site}/access`, run: async (page) => {
    await page.getByRole('switch').first().click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Einschalten' }).click()
    await page.waitForTimeout(1500)
  }, ...DOCS },
  { name: 'doku-wartungsseite', page: 'maintenance.html', ...DOCS },

  // The audit log (docs/gateway/02-betrieb.md): the list, and one change with the value before and after.
  { name: 'doku-protokoll', route: '/settings/audit', ...DOCS },
  { name: 'doku-protokoll-eintrag', route: '/settings/audit', run: async (page) => {
    await page.getByTestId('audit-row-title').filter({ hasText: 'Aufbewahrung geändert' }).first().click()
    await page.getByTestId('audit-sheet').waitFor()
    await page.waitForTimeout(600)
  }, ...DOCS },
]

async function fillAccessDialog(page) {
  await page.getByTestId('access-setup').click()
  await page.getByTestId('access-scope-paths').click()
  await page.getByTestId('access-paths').fill('/wp-admin/*\n/wp-login.php')
  await page.getByTestId('access-password').fill('korrekt-pferd-batterie')
  await page.getByTestId('access-own-networks').click()
  await page.getByTestId('access-password').blur()
  await page.waitForTimeout(300)
}

// The mock data shows a gateway someone has worked with: an agent put the CrowdSec Hub on "Sperren", two scenarios
// and two preset limits deviate from the recommendation. The shots of the basic protection and the login protection
// show the gateway as it comes instead (docs/gateway/01-funktionen.md, "Ab Werk"): the dashboard's own buttons put
// those switches back, then the page opens within the same session.
async function factory(page, route) {
  const go = async (to) => {
    await page.evaluate(r => { location.hash = `#${r}` }, to)
    await page.locator('h1').first().waitFor()
    await page.waitForTimeout(900)
  }
  const confirm = async () => {
    const dialog = page.locator('[role="dialog"], [role="alertdialog"]').last()
    await dialog.waitFor()
    const pw = dialog.locator('input[type="password"]')
    if (await pw.count()) await pw.fill('mock-passwort-123')
    await dialog.getByRole('button').filter({ hasNotText: /Abbrechen|Schließen|Close/ }).last().click()
    await dialog.waitFor({ state: 'hidden' })
  }
  await go('/settings/rules/crowdsec')
  await page.getByTestId('repository-restore').click()
  await page.waitForTimeout(600)
  if (await page.locator('[role="dialog"], [role="alertdialog"]').count()) await confirm()
  await go('/settings/rules/behaviour')
  await page.getByTestId('apply-recommendation').click()
  await confirm()
  await go('/settings/rules/behaviour?view=limits')
  await page.getByTestId('limit-apply-recommendation').click()
  await confirm()
  await go(route)
  // The notes the changes left ("2 Limits umgestellt") belong to the setup, not to the picture.
  await page.locator('[data-sonner-toast]').evaluateAll(toasts => toasts.forEach(t => t.remove()))
}

async function blockAiTraining(page) {
  await page.getByTestId('crawlers-preset').click()
  await page.waitForTimeout(600)
  await page.getByTestId('crawlers-impersonators').click()
  await page.waitForTimeout(600)
  await page.locator('[data-sonner-toast]').evaluateAll(toasts => toasts.forEach(t => t.remove()))
}

const scrollTo = locator => locator.evaluate(e => e.scrollIntoView({ block: 'start' }))

// Before every screenshot: blur IP addresses, hide the sidebar group "Entwurf" (a draft page that exists in mock
// builds only, never in the dashboard the gateway serves).
const tidy = page => page.evaluate(() => {
  const split = /((?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|2001:db8:[0-9a-f:]*(?:\/\d{1,3})?)/gi
  const isIp = /^(?:(?:\d{1,3}\.){3}\d{1,3}|2001:db8:)/i
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
  const nodes = []
  for (let n; (n = walker.nextNode());) if (n.textContent.search(split) >= 0) nodes.push(n)
  for (const n of nodes) {
    const parts = document.createDocumentFragment()
    for (const part of n.textContent.split(split)) {
      if (!part) continue
      if (!isIp.test(part)) { parts.append(part); continue }
      const span = document.createElement('span')
      span.style.filter = 'blur(5px)'
      span.textContent = part
      parts.append(span)
    }
    n.replaceWith(parts)
  }
  for (const label of document.querySelectorAll('[data-slot="sidebar-group-label"]')) {
    if (label.textContent.trim() === 'Entwurf') label.closest('[data-slot="sidebar-group"]')?.style.setProperty('display', 'none')
  }
})

function need(cmd, args, hint) {
  try { execFileSync(cmd, args, { stdio: 'ignore' }) }
  catch { console.error(`shots: ${cmd} is missing (${hint})`); process.exit(1) }
}

// Starts the dashboard in mock mode and resolves with its address. Vite picks a free port and prints it.
function startDashboard() {
  // Own process group, so stopping it also stops the vite that pnpm started.
  const child = spawn('pnpm', ['exec', 'vite', '--mode', 'mock'], { cwd: dashboard, stdio: ['ignore', 'pipe', 'inherit'], detached: true })
  const stop = () => { try { process.kill(-child.pid) } catch {} }
  const base = new Promise((ok, fail) => {
    let text = ''
    child.stdout.on('data', (d) => {
      text += d
      const m = text.replace(/\x1B\[[0-9;]*m/g, '').match(/Local:\s+(http:\/\/localhost:\d+)/)
      if (m) ok(m[1])
    })
    child.on('exit', code => fail(new Error(`shots: the dashboard stopped (exit ${code})`)))
    setTimeout(() => fail(new Error('shots: the dashboard did not start within 60 s')), 60_000).unref()
  })
  return { base, stop }
}

function webp(png, name, shot) {
  const file = suffix => join(outDir, `${name}${suffix}.webp`)
  execFileSync('cwebp', ['-quiet', '-q', '82', ...(shot.full ? ['-resize', String(shot.full), '0'] : []), png, '-o', file('')])
  for (const w of shot.widths) execFileSync('cwebp', ['-quiet', '-q', '82', '-resize', String(w), '0', png, '-o', file(`-${w}`)])
}

need('cwebp', ['-version'], 'install the package "webp"')
need('go', ['version'], 'the gateway pages are written by a Go tool')

const tmp = mkdtempSync(join(tmpdir(), 'schild-shots-'))
const dash = startDashboard()
let browser
try {
  const BASE = await dash.base
  browser = await chromium.launch()
  const todo = SHOTS.filter(s => !only || s.name.startsWith(only))
  const contexts = new Map()
  const pageFor = async (s) => {
    const key = `${s.width}x${s.height}@${s.scale}`
    if (!contexts.has(key)) {
      const c = await browser.newContext({ viewport: { width: s.width, height: s.height }, deviceScaleFactor: s.scale, colorScheme: 'light', reducedMotion: 'reduce', timezoneId: 'Europe/Berlin', locale: 'de-DE' })
      contexts.set(key, await c.newPage())
    }
    return contexts.get(key)
  }
  // `live` far in the future: no new live events while the pictures are taken.
  const open = async (page, route, scenario = 'default') => {
    await page.goto('about:blank')
    await page.goto(`${BASE}/?scenario=${scenario}&live=9999999#${route}`)
    await page.locator('h1').first().waitFor({ timeout: 10_000 })
    await page.waitForFunction(() => !document.querySelector('[data-slot="skeleton"], .animate-pulse'), null, { timeout: 8000 }).catch(() => {})
    await page.waitForTimeout(1200)
  }

  // The example event: looked up in the mock data, so the block page carries its incident number and time.
  const first = await pageFor(DESKTOP)
  await open(first, '/')
  const event = await first.evaluate(async (want) => {
    let cursor = ''
    for (let i = 0; i < 20; i++) {
      const page = await (await fetch(`/api/v0/events?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`)).json()
      const hit = page.items.find(e => e.outcome === 'blocked' && e.geo?.country === want.country && e.rules?.includes(want.rule) && e.incident)
      if (hit) return hit
      cursor = page.next_cursor
      if (!cursor) break
    }
    return null
  }, EXAMPLE)
  if (!event) throw new Error(`shots: no blocked event from ${EXAMPLE.country} with rule ${EXAMPLE.rule} in the mock data`)
  if (event.incident !== EXAMPLE.incident) console.warn(`shots: the example incident is now ${event.incident}, not ${EXAMPLE.incident}: update EXAMPLE and the alt texts`)
  execFileSync('go', ['run', './internal/tools/sitepages', '-out', tmp, '-incident', event.incident, '-time', event.time], { cwd: join(repo, 'gateway'), stdio: 'inherit' })

  const ctx = { event }
  for (const s of todo) {
    const page = await pageFor(s)
    if (s.page) {
      await page.goto(`file://${join(tmp, s.page)}`)
      await page.evaluate(() => document.activeElement?.blur())
    }
    else {
      await open(page, typeof s.route === 'function' ? s.route(ctx) : s.route, s.scenario)
      if (s.top) {
        // The first element with exactly this text that is not a tab (the page "Zugriffe" has a tab "Länder" too).
        const found = await page.evaluate(([text, gap]) => {
          const el = [...document.querySelectorAll('#main *')].find(e => !e.closest('[role="tablist"]') && e.children.length === 0 && e.textContent.trim() === text)
          if (el) window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY - gap)
          return !!el
        }, [s.top, s.gap ?? 110])
        if (!found) throw new Error(`shots: ${s.name}: no element with the text "${s.top}"`)
      }
      if (s.run) await s.run(page, ctx)
      await page.waitForTimeout(400)
      await tidy(page)
    }
    const png = join(tmp, `${s.name}.png`)
    await page.screenshot({ path: png })
    webp(png, s.name, s)
    console.log(`shots: ${s.name}`)
  }

  if (!only) {
    const date = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: 'Europe/Berlin' }).format(new Date())
    writeFileSync(join(repo, 'site/app/utils/shots.ts'), `// Written by site/scripts/shots.mjs (\`npm run shots\`): the day the dashboard screenshots were taken.\nexport const SHOTS_DATE = '${date}'\n`)
    console.log(`shots: ${todo.length} screenshots, dated ${date}`)
  }
}
finally {
  await browser?.close()
  dash.stop()
  rmSync(tmp, { recursive: true, force: true })
}
