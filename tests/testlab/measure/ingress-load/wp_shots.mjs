// TEST ONLY: screenshots of the waiting page served by schild (D37) during a
// forced waf_timeout. Usage: node wp_shots.mjs <base url with timeout query> <out dir>
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../../../dashboard/apps/client-dashboard/package.json', import.meta.url));
const { chromium } = require('@playwright/test');
const [url, out] = process.argv.slice(2);
const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP shop.example.de 127.0.0.1'] });
const shots = [
  { name: 'get-de-light-desktop', scheme: 'light', vp: { width: 1280, height: 800 }, lang: 'de-DE' },
  { name: 'get-de-dark-desktop', scheme: 'dark', vp: { width: 1280, height: 800 }, lang: 'de-DE' },
  { name: 'get-de-light-mobile', scheme: 'light', vp: { width: 390, height: 844 }, lang: 'de-DE', mobile: true },
  { name: 'get-de-dark-mobile', scheme: 'dark', vp: { width: 390, height: 844 }, lang: 'de-DE', mobile: true },
  { name: 'post-de-light-mobile', scheme: 'light', vp: { width: 390, height: 844 }, lang: 'de-DE', mobile: true, post: true },
  { name: 'get-en-dark-mobile', scheme: 'dark', vp: { width: 390, height: 844 }, lang: 'en-GB', mobile: true },
];
const log = [];
for (const s of shots) {
  const ctx = await browser.newContext({ viewport: s.vp, colorScheme: s.scheme, locale: s.lang, isMobile: !!s.mobile, deviceScaleFactor: 1, extraHTTPHeaders: { 'Accept-Language': s.lang } });
  const page = await ctx.newPage();
  const errs = [];
  page.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
  let resp;
  if (s.post) {
    // a real form submit: a tiny page on about:blank posts to the URL
    await page.setContent(`<form method="post" action="${url}"><input name="name" value="Max"><button>senden</button></form>`);
    [resp] = await Promise.all([page.waitForNavigation(), page.click('button')]);
  } else {
    resp = await page.goto(url);
  }
  await page.waitForTimeout(1200);
  const h = resp.headers();
  const dims = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, sh: document.documentElement.scrollHeight }));
  await page.screenshot({ path: `${out}/wp-${s.name}.png` });
  log.push({ shot: s.name, status: resp.status(), retry_after: h['retry-after'], lang: h['content-language'], overflow_x: dims.sw - dims.cw, height: dims.sh, console_errors: errs });
  await ctx.close();
}
// reload behaviour: does the browser reload by itself after Retry-After?
const ctx = await browser.newContext();
const page = await ctx.newPage();
let navs = 0; page.on('framenavigated', f => { if (f === page.mainFrame()) navs++; });
const r = await page.goto(url);
const ra = Number(r.headers()['retry-after']);
await page.waitForTimeout((ra + 3) * 1000);
log.push({ reload_check: true, retry_after: ra, navigations_in_ra_plus_3s: navs });
await browser.close();
console.log(JSON.stringify(log, null, 1));
