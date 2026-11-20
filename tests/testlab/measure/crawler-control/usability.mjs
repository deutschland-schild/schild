#!/usr/bin/env node
// TEST ONLY: MVP-29 measurement. Times the dashboard path "KI-Training für diese Website blocken" in the mock mode of
// the client dashboard (vite --mode mock on BASE). Start on the website overview, find the page by the website
// navigation (as a first-time user would: by its visible name), press the button, wait for the confirmation text.
// Five runs per viewport, each in a fresh browser context. Prints JSON with the times and the clicks.
//
//   node testlab/measure/crawler-control/usability.mjs http://127.0.0.1:5199/
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const base = process.argv[2] ?? 'http://127.0.0.1:5199/'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..') // repository root
const require = createRequire(resolve(root, 'dashboard/apps/client-dashboard/package.json'))
const { chromium } = require('@playwright/test')

const browser = await chromium.launch()
const out = []
for (const vp of [{ name: 'desktop', width: 1440, height: 900 }, { name: 'mobile-390', width: 390, height: 844 }]) {
  for (let run = 0; run < 5; run++) {
    const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, locale: 'de-DE', timezoneId: 'Europe/Berlin', reducedMotion: 'reduce' })
    const page = await ctx.newPage()
    const errors = []
    page.on('pageerror', e => errors.push(String(e)))
    await page.goto(base + '?scenario=default#/w/verein.example')
    await page.getByRole('heading', { level: 1 }).waitFor()
    const t0 = Date.now()
    let clicks = 0
    // The website navigation: on a narrow screen it may sit behind a menu button.
    let link = page.getByRole('link', { name: 'KI-Crawler', exact: true }).first()
    if (!(await link.isVisible().catch(() => false))) {
      const menu = page.getByRole('button', { name: /Menü|Navigation|Seiten|Mehr/i }).first()
      if (await menu.isVisible().catch(() => false)) {
        await menu.click()
        clicks++
      }
      link = page.getByRole('link', { name: 'KI-Crawler', exact: true }).first()
    }
    await link.click()
    clicks++
    const btn = page.getByRole('button', { name: 'KI-Training blocken' })
    await btn.waitFor()
    await btn.click()
    clicks++
    await page.getByText('KI-Training ist geblockt, alle anderen Kategorien sind erlaubt.').waitFor({ timeout: 10000 })
    const ms = Date.now() - t0
    const gptbot = await page.getByTestId('crawlers-open-ai_training').click().then(() => page.locator('[data-crawler="gptbot"]').getAttribute('data-effective'))
    out.push({ viewport: vp.name, run, ms, clicks, gptbot_effective: gptbot, page_errors: errors.length })
    await ctx.close()
  }
}
await browser.close()
console.log(JSON.stringify(out, null, 1))
