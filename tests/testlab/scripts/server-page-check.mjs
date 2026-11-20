#!/usr/bin/env node
// MVP-11: browser check of the "Server" section against the real backend of a
// running t1 stack with the agents overlay (after `make smoke PROFILE=t1`, so
// app-vm is enrolled and reporting and app-revoked is revoked). Logs into the
// client dashboard of schild-api through the gateway, opens the Server views,
// runs "Jetzt prüfen" end to end (dashboard -> request file -> gw-host-check
// -> new report), opens the enrolment dialog (creates a one-time code, never
// used) and the revoke dialog (cancelled). Fails on console errors, page
// errors, CSP violations or horizontal overflow.
//
//   node testlab/scripts/server-page-check.mjs [out-dir]
//
// Env: SCHILD_PLAYWRIGHT, SMOKE_PASSWORD (TEST ONLY). Default out-dir:
// tests/results/ux/spec11/real (screenshots, server-page-check.json).
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..') // repository root
const out = resolve(process.argv[2] ?? join(root, 'tests/results/ux/spec11/real'))
const password = process.env.SMOKE_PASSWORD || 'schild-testlab-passwort'
const url = 'http://127.0.0.1:28788/'
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

const steps = []
const errors = []
const shots = []
const browser = await chromium.launch()
let failed = false
let expect403 = false

async function session(name, viewport, scheme) {
  const ctx = await browser.newContext({ viewport, locale: 'de-DE', colorScheme: scheme })
  await ctx.addInitScript((s) => {
    localStorage.setItem('schild-color-scheme-v2', s)
    document.addEventListener('securitypolicyviolation', e => console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`))
  }, scheme)
  const page = await ctx.newPage()
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    // The deliberately wrong password is answered 403; Chromium logs every failed response.
    if (expect403 && m.text().includes('status of 403')) return
    errors.push(`${name}: console: ${m.text()}`)
  })
  page.on('pageerror', e => errors.push(`${name}: pageerror: ${e.message}`))
  await page.goto(url, { waitUntil: 'domcontentloaded' })
  const pw = page.locator('input[type="password"]').first()
  await pw.waitFor({ timeout: 15000 })
  await pw.fill(password)
  await page.locator('button[type="submit"]').first().click()
  await pw.waitFor({ state: 'detached', timeout: 15000 })
  return { ctx, page }
}

async function settle(page) {
  await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {})
  await page.waitForTimeout(500)
}

async function overflow(page, label) {
  const w = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  if (w > 1) errors.push(`${label}: horizontal overflow ${w}px`)
}

async function shot(page, file, label) {
  await overflow(page, label)
  await page.screenshot({ path: join(out, file), fullPage: false })
  shots.push(file)
}

async function step(name, fn) {
  const t = Date.now()
  try {
    const detail = await fn()
    steps.push({ name, status: 'pass', seconds: (Date.now() - t) / 1000, detail: detail ?? '' })
    console.log(`PASS  ${name}${detail ? `: ${detail}` : ''}`)
  }
  catch (e) {
    failed = true
    steps.push({ name, status: 'fail', seconds: (Date.now() - t) / 1000, detail: e.message.split('\n')[0] })
    console.log(`FAIL  ${name}: ${e.message.split('\n')[0]}`)
  }
}

try {
  for (const [scheme, vp, tag] of [['light', { width: 1440, height: 900 }, 'desktop-light'], ['dark', { width: 1440, height: 900 }, 'desktop-dark'], ['light', { width: 390, height: 844 }, 'mobile-light']]) {
    const { ctx, page } = await session(tag, vp, scheme)
    await step(`${tag}: overview has the Server card`, async () => {
      await page.goto(`${url}#/`, { waitUntil: 'domcontentloaded' })
      const card = page.getByTestId('servers-card')
      await card.waitFor({ timeout: 15000 })
      await settle(page)
      await card.scrollIntoViewIfNeeded()
      await shot(page, `overview-card-${tag}.png`, `${tag} overview`)
      return (await card.innerText()).replace(/\s+/g, ' ').slice(0, 160)
    })
    await step(`${tag}: gateway first, with findings by area`, async () => {
      await page.goto(`${url}#/server`, { waitUntil: 'domcontentloaded' })
      await page.getByTestId('host-detail').waitFor({ timeout: 15000 })
      await settle(page)
      const first = page.getByTestId('host-item').first()
      if (await first.getAttribute('data-host') !== 'local') throw new Error('first host is not the gateway')
      await shot(page, `server-gateway-${tag}.png`, `${tag} gateway`)
      const hosts = await page.getByTestId('host-item').count()
      const areas = await page.locator('[data-testid^="area-"]').count()
      return `${hosts} hosts listed, ${areas} areas`
    })
    await step(`${tag}: app VM (agent) detail`, async () => {
      const item = page.getByTestId('host-item').filter({ hasText: 'app-vm-canary-k4p8z2' }).first()
      await item.click()
      await page.getByTestId('host-detail').filter({ hasText: 'app-vm-canary-k4p8z2' }).waitFor({ timeout: 15000 })
      await settle(page)
      if (await page.getByTestId('check-now').count()) throw new Error('"Jetzt prüfen" shown for an agent')
      await shot(page, `server-app-vm-${tag}.png`, `${tag} app-vm`)
      return 'no "Jetzt prüfen" for agents'
    })
    await step(`${tag}: revoked host`, async () => {
      const item = page.getByTestId('host-item').filter({ hasText: 'app-revoked' }).first()
      await item.click()
      await page.getByTestId('host-detail').filter({ hasText: 'app-revoked' }).waitFor({ timeout: 15000 })
      await settle(page)
      await shot(page, `server-revoked-${tag}.png`, `${tag} revoked`)
    })
    await step(`${tag}: agents tab`, async () => {
      await page.goto(`${url}#/server?ansicht=agenten`, { waitUntil: 'domcontentloaded' })
      await page.getByTestId('agents-list').waitFor({ timeout: 15000 })
      await settle(page)
      await shot(page, `agents-${tag}.png`, `${tag} agents`)
      return `${await page.getByTestId('agent-row').count()} agents`
    })
    await ctx.close()
  }

  const { ctx, page } = await session('flows', { width: 1440, height: 900 }, 'light')
  await step('"Jetzt prüfen": request file, gw-host-check runs, new report shown', async () => {
    await page.goto(`${url}#/server`, { waitUntil: 'domcontentloaded' })
    await page.getByTestId('check-now').waitFor({ timeout: 15000 })
    const before = await page.getByTestId('footer-summary').innerText().catch(() => '')
    await page.getByTestId('check-now').click()
    await page.getByText('Prüfung angefordert').first().waitFor({ timeout: 10000 })
    await shot(page, 'check-now-running.png', 'check-now running')
    await page.getByText('Prüfung fertig').first().waitFor({ timeout: 120000 })
    await settle(page)
    await shot(page, 'check-now-done.png', 'check-now done')
    return `before: ${before.slice(0, 80)}`
  })
  await step('enrolment dialog: wrong password refused, code and one-line command with --gateway-name', async () => {
    await page.getByTestId('add-server').click()
    const dialog = page.getByTestId('enrol-dialog')
    await dialog.waitFor({ timeout: 10000 })
    await dialog.getByTestId('enrol-label').fill('Browser-Check')
    await dialog.getByTestId('enrol-password').fill('falsches-passwort-123')
    expect403 = true
    await dialog.getByTestId('enrol-create').click()
    await dialog.getByTestId('enrol-password-error').waitFor({ timeout: 10000 })
    await page.waitForTimeout(300)
    expect403 = false
    const err = await dialog.getByTestId('enrol-password-error').innerText()
    await shot(page, 'enrol-wrong-password.png', 'enrol wrong password')
    await dialog.getByTestId('enrol-password').fill(password)
    await dialog.getByTestId('enrol-create').click()
    const cmd = dialog.getByTestId('enrol-command')
    await cmd.waitFor({ timeout: 10000 })
    const text = await cmd.innerText()
    if (!/sudo schild-agent enrol --gateway https:\/\/schild-api:8790 --gateway-name site-api --pin sha256:[0-9a-f]{64} --code /.test(text.replace(/\s+/g, ' '))) throw new Error(`command: ${text}`)
    await shot(page, 'enrol-command.png', 'enrol command')
    await page.keyboard.press('Escape')
    return `wrong password: "${err.trim()}"`
  })
  await step('revoke dialog asks for the password (cancelled)', async () => {
    await page.goto(`${url}#/server?ansicht=agenten`, { waitUntil: 'domcontentloaded' })
    await page.getByTestId('agents-list').waitFor({ timeout: 15000 })
    const row = page.getByTestId('agent-row').filter({ hasText: 'app-vm-canary-k4p8z2' }).first()
    await row.getByTestId('agent-revoke').click()
    await page.getByTestId('confirm-password').waitFor({ timeout: 10000 })
    await shot(page, 'revoke-dialog.png', 'revoke dialog')
    await page.keyboard.press('Escape')
    await settle(page)
    const status = await row.innerText()
    if (/Zurückgezogen/.test(status)) throw new Error('agent revoked although cancelled')
  })
  await ctx.close()
}
finally {
  await browser.close()
}
if (errors.length) failed = true
const report = { spec: 'MVP-11', check: 'server-page-real-backend', url, finished: new Date().toISOString(), ok: !failed, steps, errors, screenshots: shots }
writeFileSync(join(out, 'server-page-check.json'), `${JSON.stringify(report, null, 2)}\n`)
for (const e of errors) console.log(`      ${e}`)
console.log(failed ? 'server page check: FAILED' : `server page check: OK (${steps.length} steps, ${shots.length} screenshots in ${out})`)
process.exit(failed ? 1 : 0)
