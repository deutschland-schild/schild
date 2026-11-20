#!/usr/bin/env node
// TEST ONLY: a few targeted element screenshots of the evening measurement 2026-10-29 (commit c54de1b).
//   PW=... node shots.mjs <base> <out-dir>
import { createRequire } from 'node:module'
import { join } from 'node:path'
const require = createRequire(import.meta.url)
const { chromium } = require('/tmp/abend/src/dashboard/node_modules/.pnpm/playwright@1.56.0/node_modules/playwright')
const [base, out] = process.argv.slice(2)
const b = await chromium.launch()
async function sess(w, h, theme) {
  const ctx = await b.newContext({ viewport: { width: w, height: h }, locale: 'de-DE', timezoneId: 'Europe/Berlin' })
  await ctx.addInitScript(th => localStorage.setItem('schild-color-scheme-v2', th), theme)
  const p = await ctx.newPage()
  await p.goto(base + '/'); await p.locator('input[type=password]').first().fill(process.env.PW); await p.locator('button[type=submit]').first().click(); await p.waitForTimeout(2000)
  return { ctx, p }
}
const res = {}
{ const { ctx, p } = await sess(1440, 900, 'light')
  await p.goto(`${base}/#/w/shop.test?zeit=6h`); await p.waitForTimeout(7000)
  await p.locator('header').first().screenshot({ path: join(out, 'z01-header-breadcrumb-light-desktop.png') })
  const o = p.locator('[data-testid="panel-origin"]'); await o.scrollIntoViewIfNeeded()
  await o.locator('[data-tab="country"]').click().catch(() => {}); await p.waitForTimeout(1500)
  await o.screenshot({ path: join(out, 'z02-panel-origin-haette-gesp-light-desktop.png') })
  res.originHead = await o.locator('thead').innerText()
  await p.goto(`${base}/#/behaviour`); await p.waitForTimeout(5000)
  await p.screenshot({ path: join(out, 'z03-verhalten-pills-light-desktop.png') })
  res.pills = await p.evaluate(() => [...document.querySelectorAll('[class*="rounded-full"]')].slice(0, 400).map(e => ({ t: e.innerText.trim().slice(0, 40), c: getComputedStyle(e).color })).filter(x => /Gesperrt|Freigeschaltet|Begrenzt|Erkannt/.test(x.t)).reduce((a, x) => { const k = `${x.t.split(' ')[0]} ${x.c}`; a[k] = (a[k] || 0) + 1; return a }, {}))
  await ctx.close() }
{ const { ctx, p } = await sess(375, 812, 'light')
  await p.goto(`${base}/#/w/shop.test?zeit=6h`); await p.waitForTimeout(6000)
  await p.screenshot({ path: join(out, 'z04-mobile-header-overflow-light-mobile.png') })
  res.mobile = await p.evaluate(() => ({ overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth, offscreen: [...document.querySelectorAll('header button, header a, header [class*="rounded-full"]')].filter(e => e.getBoundingClientRect().right > window.innerWidth).map(e => (e.getAttribute('aria-label') || e.innerText).trim().slice(0, 40)) }))
  await ctx.close() }
console.log(JSON.stringify(res, null, 1))
await b.close()
