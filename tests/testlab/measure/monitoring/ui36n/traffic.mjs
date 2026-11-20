#!/usr/bin/env node
// TEST ONLY: D36 measurement traffic for four apps behind one schild ingress
// (shop.test, blog.test, api.test, status.test). Client addresses come from
// X-Forwarded-For (schild trusts 127.0.0.1) inside the 10.0.0.0/8 nets of the
// spec21 TEST ONLY geo database, so countries, ASNs and net classes are known.
// The backend is `spec21 backend`, which answers with X-Status / X-Delay-Ms.
//
//   node traffic.mjs -target http://127.0.0.1:19390 -minutes 32 -log events.jsonl
//
// Timeline (minutes since start, fixed seed):
//   all the time  baseline browsing on all four sites (~15 req/s), api 5xx ~6 %,
//                 blog slow (30 % of requests 400-1500 ms)
//   8-11          api incident: 35 % 5xx (status "gestört" expected)
//   12-16         traffic spike on shop.test (5x)
//   18-23         attack wave: 240 addresses (half hosting nets), SQLi/XSS/
//                 traversal/probing on shop, blog and api
//   long blocks are driven by longblocks.mjs (block -> release -> block)
// Extra runs used in the measurement (see run.sh): shop.test x7 more during
// minute 12-16 (spike hint needs >= 5x the previous hour over 5 min) and
// blog.test with every request 2500 ms slow during minute 24-31 (upstream_slow).
import http from 'node:http'
import { appendFileSync, writeFileSync } from 'node:fs'

const arg = (n, d) => { const i = process.argv.indexOf(`-${n}`); return i > 0 ? process.argv[i + 1] : d }
const target = new URL(arg('target', 'http://127.0.0.1:19390'))
const minutes = Number(arg('minutes', 32))
const logFile = arg('log', 'traffic-log.jsonl')
const startOffsetMin = Number(arg('offset', 0)) // resume the timeline after a crash
// Extra load on one site only (no timeline, no attacks): -only shop.test -mult 7 [-delay 2500]
const only = arg('only', '')
const mult = Number(arg('mult', 1))
const forceDelay = Number(arg('delay', 0))
// D36 re-measurement (ui36n): -nowave (baseline only, the waves come from separate runs),
// -attackonly (only the attack wave, the whole run long, -arate attack requests per 200 ms tick),
// -logall (every answered request into the log: t, host, kind, status, app; the sent-side truth).
const noWave = process.argv.includes('-nowave')
const attackOnly = process.argv.includes('-attackonly')
const logAll = process.argv.includes('-logall')
const aRate = Number(arg('arate', 12))
writeFileSync(logFile, '')

// mulberry32, fixed seed
let seed = Number(arg('seed', 3636))
function rnd() { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296 }
const pick = a => a[Math.floor(rnd() * a.length)]
const wpick = (pairs) => { const s = pairs.reduce((a, p) => a + p[1], 0); let r = rnd() * s; for (const [v, w] of pairs) { if ((r -= w) < 0) return v } return pairs[0][0] }

// Net index -> class (from geo.json: index%8 pattern): 0 res DE, 1 hosting NL, 2 business FR, ...
// Visitors: mostly residential/business/education nets; attackers: hosting and residential.
const visitorNets = [[0, 40], [5, 6], [6, 6], [11, 3], [12, 3], [2, 6], [8, 3], [3, 3], [9, 2], [17, 2], [18, 2], [4, 1], [10, 1], [14, 2]]
const hostingNets = [1, 7, 13, 19, 25, 31, 37, 43]
const resNets = [5, 6, 11, 12, 17, 18, 23, 24]
const ip = (net, a = Math.floor(rnd() * 250) + 1, b = Math.floor(rnd() * 250) + 1) => `10.${net}.${a}.${b}`

const UAS = [
  ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 30],
  ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15', 15],
  ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1', 18],
  ['Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0', 10],
  ['Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36', 12],
  ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0', 6],
  ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 4],
  ['Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 2],
  ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)', 2],
  ['curl/8.7.1', 1],
]
const REFS = [
  ['', 35], ['https://www.google.com/', 30], ['https://duckduckgo.com/', 6], ['https://www.bing.com/', 4],
  ['https://chatgpt.com/', 4], ['https://news.ycombinator.com/item?id=1', 3], ['https://www.facebook.com/', 3],
  ['https://t.co/abc', 2], ['https://www.ecosia.org/', 2], ['SELF', 15],
]
const SITES = {
  'shop.test': { w: 45, pages: [['/', 25], ['/produkte', 15], ['/produkte/schild-kaffee', 10], ['/produkte/tasse-blau', 8], ['/warenkorb', 6], ['/kasse', 3], ['/suche?q=kaffee', 5], ['/kontakt', 3], ['/impressum', 1]], assets: ['/static/app.js', '/static/app.css', '/img/logo.png'] },
  'blog.test': { w: 30, pages: [['/', 20], ['/2026/10/caddy-und-schild', 12], ['/2026/09/backup-strategie', 8], ['/2026/08/server-haerten', 6], ['/tag/linux', 4], ['/feed.xml', 4], ['/ueber', 2]], assets: ['/static/blog.css', '/img/header.jpg'] },
  'api.test': { w: 18, pages: [['/v1/products', 30], ['/v1/products/42', 20], ['/v1/cart', 12], ['/v1/search?q=tasse', 8], ['/v1/health', 10], ['/v1/orders', 5]], assets: [], api: true },
  'status.test': { w: 7, pages: [['/', 20], ['/api/status.json', 20], ['/history', 3]], assets: [] },
}

const agent = new http.Agent({ keepAlive: true, maxSockets: 256 })
const stats = { sent: 0, byStatus: {}, bySite: {}, errors: 0 }
let inflight = 0

function send(o) {
  if (inflight > 400) return // never pile up
  inflight++
  stats.sent++
  const h = { 'Host': o.host, 'X-Forwarded-For': o.ip, 'User-Agent': o.ua, 'Accept': o.accept ?? 'text/html,application/xhtml+xml,*/*;q=0.8', 'Accept-Language': 'de-DE,de;q=0.9', ...o.headers }
  if (o.ref) h.Referer = o.ref
  const t0 = Date.now()
  const req = http.request({ host: target.hostname, port: target.port, path: o.path, method: o.method ?? 'GET', headers: h, agent, timeout: 10000 }, (res) => {
    res.resume()
    res.on('end', () => {
      inflight--
      stats.byStatus[res.statusCode] = (stats.byStatus[res.statusCode] ?? 0) + 1
      const k = `${o.host} ${o.kind ?? 'visit'}`
      const s = (stats.bySite[k] ??= { n: 0, blocked: 0, s5xx: 0 })
      s.n++
      if (!res.headers['x-backend']) s.blocked++
      if (res.statusCode >= 500) s.s5xx++
      if (logAll || (o.kind && o.kind !== 'visit')) appendFileSync(logFile, `${JSON.stringify({ t: new Date().toISOString(), kind: o.kind ?? 'visit', host: o.host, ip: o.ip, path: o.path.slice(0, 80), status: res.statusCode, app: !!res.headers['x-backend'], ms: Date.now() - t0 })}\n`)
    })
  })
  req.on('error', () => { inflight--; stats.errors++ })
  req.on('timeout', () => req.destroy())
  if (o.body) req.end(o.body); else req.end()
}

// A visitor: a few page views with assets on one site.
function visitor(host, minute) {
  const site = SITES[host]
  const net = wpick(visitorNets)
  const addr = ip(net)
  const ua = wpick(UAS)
  let ref = wpick(REFS)
  const views = 1 + Math.floor(rnd() * 4)
  let delay = 0
  for (let i = 0; i < views; i++) {
    const path = wpick(site.pages)
    const headers = {}
    if (site.api) {
      const incident = minute >= 8 && minute < 11
      const p5 = incident ? 0.35 : 0.06
      if (rnd() < p5) headers['X-Status'] = String(pick([500, 502, 503]))
      headers['X-Size'] = '800'
    } else {
      headers['X-Size'] = String(2000 + Math.floor(rnd() * 20000))
    }
    if (forceDelay) headers['X-Delay-Ms'] = String(forceDelay)
    else if (host === 'blog.test' && rnd() < 0.3) headers['X-Delay-Ms'] = String(400 + Math.floor(rnd() * 1100))
    if (host === 'status.test' && rnd() < 0.03) headers['X-Status'] = '500'
    const r = ref === 'SELF' ? `http://${host}/` : ref
    setTimeout(() => {
      send({ host, ip: addr, ua, ref: r, path, headers, accept: site.api ? 'application/json' : undefined })
      for (const a of site.assets) if (rnd() < 0.5) send({ host, ip: addr, ua, ref: `http://${host}${path}`, path: a, headers: { 'X-Size': '5000' }, accept: '*/*' })
    }, delay)
    delay += 500 + rnd() * 3000
    ref = 'SELF'
  }
}

const PAYLOADS = [
  '/produkte?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--',
  '/suche?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E',
  '/index.php?page=../../../../etc/passwd',
  '/?q=1%20OR%201=1--',
  '/kommentar?text=%3Cimg%20src=x%20onerror=alert(1)%3E',
  '/download?file=..%2F..%2F..%2Fetc%2Fshadow',
  '/v1/products?filter=%27%3B%20DROP%20TABLE%20orders%3B--',
  '/cgi-bin/;cat%20/etc/passwd',
  '/?cmd=%60id%60',
  '/search?q=%22%3E%3Csvg/onload=alert(1)%3E',
]
const PROBES = ['/wp-login.php', '/.env', '/.git/config', '/phpmyadmin/', '/admin/config.php', '/xmlrpc.php', '/wp-admin/install.php', '/backup.zip', '/server-status', '/config.json', '/.aws/credentials', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/actuator/env', '/.DS_Store', '/db.sql', '/old/', '/test.php', '/info.php', '/shell.php', '/admin/', '/login.action', '/console/', '/manager/html', '/solr/admin/']
const ATTACK_UAS = ['sqlmap/1.8.4#stable (https://sqlmap.org)', 'Mozilla/5.0 zgrab/0.x', 'python-requests/2.32.3', 'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36']

// Attackers of the wave, fixed list so they come back.
const attackers = []
for (let i = 0; i < 240; i++) {
  const hosting = i % 2 === 0
  attackers.push({ ip: ip(hosting ? hostingNets[i % hostingNets.length] : resNets[i % resNets.length], 200 + (i % 50), 1 + i), ua: pick(ATTACK_UAS), kind: i % 3 === 0 ? 'probe' : 'waf' })
}

function attack(a) {
  const host = pick(['shop.test', 'shop.test', 'blog.test', 'api.test'])
  if (a.kind === 'probe') send({ host, ip: a.ip, ua: a.ua, path: pick(PROBES), kind: 'probe' })
  else send({ host, ip: a.ip, ua: a.ua, path: pick(PAYLOADS), kind: 'waf' })
}

const start = Date.now() - startOffsetMin * 60000
const tick = 200 // ms
let lastReport = 0
const timer = setInterval(() => {
  const m = (Date.now() - start) / 60000
  if (m >= minutes) {
    clearInterval(timer)
    setTimeout(() => { console.log(JSON.stringify({ done: true, ...stats })); process.exit(0) }, 3000)
    return
  }
  // baseline visitors per tick: ~1.0 visitor/tick = 5/s, each ~2.5 views + assets ≈ 15 req/s
  if (attackOnly) {
    for (let i = 0; i < aRate; i++) attack(pick(attackers))
    return
  }
  if (only) {
    const rate = SITES[only].w / 100 * mult
    let n = Math.floor(rate) + (rnd() < rate % 1 ? 1 : 0)
    while (n-- > 0) visitor(only, 0)
    return
  }
  for (const host of Object.keys(SITES)) {
    let rate = SITES[host].w / 100 * 1.0
    if (host === 'shop.test' && m >= 12 && m < 16) rate *= 5
    let n = Math.floor(rate) + (rnd() < rate % 1 ? 1 : 0)
    while (n-- > 0) visitor(host, m)
  }
  if (!noWave && m >= 18 && m < 23) {
    // wave: ~60 attack requests/s from 240 addresses
    for (let i = 0; i < 12; i++) attack(pick(attackers))
  }
  // A background scanner now and then outside the wave.
  if (rnd() < 0.01) send({ host: pick(['shop.test', 'blog.test']), ip: ip(pick(hostingNets), 99, 1 + Math.floor(rnd() * 20)), ua: pick(ATTACK_UAS), path: pick(PROBES), kind: 'probe' })
  if (Date.now() - lastReport > 60000) {
    lastReport = Date.now()
    console.log(JSON.stringify({ t: new Date().toISOString(), minute: +m.toFixed(1), inflight, ...stats }))
  }
}, tick)
