#!/usr/bin/env node
// Browser check of the dashboards served by the real binaries in the running
// test lab (through the gateway on 127.0.0.1): login works, every main view
// renders, and there is no console error, page error or CSP violation.
//
//   node testlab/scripts/browser-check.mjs t0|t1
//
// Env: SCHILD_PLAYWRIGHT (path of a playwright package; default: the newest
// copy in dashboard/node_modules), SMOKE_PASSWORD (TEST ONLY password).
// Screenshots: tests/results/runs/smoke-<profile>/browser/.
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const profile = process.argv[2] ?? 't0'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..') // repository root
const password = process.env.SMOKE_PASSWORD || 'schild-testlab-passwort'
const out = join(root, 'tests/results/runs', `smoke-${profile}`, 'browser')
mkdirSync(out, { recursive: true })

function findPlaywright() {
  const candidates = [process.env.SCHILD_PLAYWRIGHT]
  const pnpm = join(root, 'dashboard/node_modules/.pnpm')
  if (existsSync(pnpm)) {
    for (const d of readdirSync(pnpm).sort().reverse()) if (d.startsWith('playwright@')) candidates.push(join(pnpm, d, 'node_modules/playwright'))
  }
  for (const c of candidates) if (c && existsSync(c)) return c
  throw new Error('no playwright package found (set SCHILD_PLAYWRIGHT)')
}
const require = createRequire(import.meta.url)
const { chromium } = require(findPlaywright())

const ports = profile === 't0'
  ? { clients: { api: 18788 }, labs: { 'lab-a': 18789, 'lab-b': 18790, 'lab-c': 18791 } }
  : { clients: { api: 28788, shop: 28798 }, labs: { 'lab-a': 28789, 'lab-b': 28790, 'lab-c': 28791, 'lab-d': 28792 } }

// D72: the gateway dashboard has no Signale, Freigaben or Verbund page any more.
const clientRoutes = [['#/', 'Überblick'], ['#/events', 'Ereignisse'], ['#/settings/rules', 'Regeln'], ['#/server', 'Server'], ['#/settings', 'Einstellungen']]
const labRoutes = [['#/', 'Überblick'], ['#/signals', 'Signale'], ['#/proposals', 'Vorschläge'], ['#/published', 'Bündel'], ['#/published/withdrawals', 'Not-Aus'], ['#/relays', 'Relays'], ['#/log', 'Log']]

const results = []
const browser = await chromium.launch()
try {
  for (const [name, port] of Object.entries(ports.clients)) results.push(await check('client', name, port, clientRoutes))
  for (const [name, port] of Object.entries(ports.labs)) results.push(await check('lab', name, port, labRoutes))
}
finally {
  await browser.close()
}
writeFileSync(join(out, 'browser-check.json'), `${JSON.stringify({ profile, results }, null, 2)}\n`)
const failed = results.filter(r => !r.ok)
for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.kind} ${r.name} (${r.url}): ${r.views} views, ${r.errors.length} console/page/CSP errors${r.detail ? ` – ${r.detail}` : ''}`)
for (const r of failed) for (const e of r.errors) console.log(`      ${e}`)
console.log(failed.length ? `browser check ${profile}: FAILED` : `browser check ${profile}: OK (${results.length} dashboards, screenshots in results/runs/smoke-${profile}/browser)`)
process.exit(failed.length ? 1 : 0)

async function check(kind, name, port, routes) {
  const url = `http://127.0.0.1:${port}/`
  const r = { kind, name, url, ok: false, views: 0, errors: [], csp: null, detail: '' }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'de-DE' })
  // CSP violations are reported as console errors as well; this listener makes them explicit.
  await ctx.addInitScript(() => document.addEventListener('securitypolicyviolation', e => console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`)))
  const page = await ctx.newPage()
  page.on('console', (m) => { if (m.type() === 'error') r.errors.push(`console: ${m.text()}`) })
  page.on('pageerror', e => r.errors.push(`pageerror: ${e.message}`))
  try {
    const resp = await page.goto(url, { waitUntil: 'domcontentloaded' })
    r.csp = resp?.headers()['content-security-policy'] ?? null
    if (!r.csp || r.csp.includes('unsafe-inline')) throw new Error(`weak or missing CSP: ${r.csp}`)
    // Login (client: admin password; lab: named user).
    const pw = page.locator('input[type="password"]').first()
    await pw.waitFor({ timeout: 15000 })
    if (kind === 'lab') await page.locator('input[autocomplete="username"]').fill('alice')
    await pw.fill(password)
    await page.locator('button[type="submit"]').first().click()
    await page.locator('input[type="password"]').first().waitFor({ state: 'detached', timeout: 15000 })
    for (const [hash, label] of routes) {
      await page.goto(url + hash, { waitUntil: 'domcontentloaded' })
      await page.locator('main').first().waitFor({ timeout: 15000 })
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {})
      await page.waitForTimeout(600)
      if (kind === 'lab' && hash === '#/log') {
        await page.getByTestId('verify-log').click()
        const rc = page.getByTestId('root-check')
        await rc.waitFor({ timeout: 20000 })
        const text = await rc.innerText()
        if (!text.includes('passt zum Kopf') || !text.includes('bestätigt')) throw new Error(`log root check in the browser: ${text}`)
        r.detail = text.trim()
      }
      await page.screenshot({ path: join(out, `${kind}-${name}-${label}.png`), fullPage: false })
      r.views++
    }
    if (kind === 'client') {
      await page.goto(url + '#/', { waitUntil: 'domcontentloaded' })
      await page.getByText('Grundschutz aktiv').first().waitFor({ timeout: 15000 })
    }
    r.ok = r.errors.length === 0
  }
  catch (e) {
    r.errors.push(`check: ${e.message.split('\n')[0]}`)
    await page.screenshot({ path: join(out, `${kind}-${name}-error.png`) }).catch(() => {})
  }
  finally {
    await ctx.close()
  }
  return r
}
