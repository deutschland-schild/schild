#!/usr/bin/env node
// TEST ONLY: evening re-measurement 2026-10-29, item 3 (based on ui36n/api-truth.mjs).
// Compares, after a restart (run.sh) in the middle of a 10 min bucket, against the sent-side
// truth (traffic.mjs -logall logs: every answered request, app=false = schild answered = stopped):
//   - getWebsiteKpis (dashboard API, what the KPI row uses) per website for the killed 10 min
//     bucket, aligned windows 1h/6h/24h/48h/7d ending at the last finished 10 min boundary, and
//     now-based windows (from=now-X, to=now, as the dashboard asks): requests, stopped, exact, partial;
//   - the gateway (no KPI endpoint for it): sum of the website KPIs, getTrafficBreakdown total
//     without site, queryMetricSeries 1m and 10m sums without site;
//   - agent API GET /agent/v0/websites/{id} traffic_24h (and the dashboard getWebsite);
//   - getOverview counters_24h (overview sentence "In den letzten 24 Stunden ..." /
//     "Seit dem Neustart ...") plus getMonitoringNow started_at.
// Prints a compact table; writes the raw answers to -out.
//   PW=... node check.mjs -dir /tmp/abend/k/kill -p 223 -bk <epoch> -out check.json
import { readFileSync, writeFileSync, existsSync } from 'node:fs'

const args = process.argv.slice(2)
const arg = (n, d) => { const i = args.indexOf(`-${n}`); return i >= 0 ? args[i + 1] : d }
const dir = arg('dir', '/tmp/abend/k/kill'); const P = arg('p', '223'); const BK = Number(arg('bk')) * 1000
const out = arg('out', `${dir}/check.json`)
const dash = `http://127.0.0.1:${P}88`; const agent = `http://127.0.0.1:${P}89`
const pw = process.env.PW ?? 'schild-abend-messung-TESTONLY'
const token = readFileSync(`${dir}/token`, 'utf8').trim()
const SITES = ['shop.test', 'blog.test', 'api.test', 'status.test']

const truth = Object.fromEntries(SITES.map(s => [s, []]))
for (const f of ['base-log.jsonl', 'wave-log.jsonl']) {
  if (!existsSync(`${dir}/${f}`)) continue
  for (const line of readFileSync(`${dir}/${f}`, 'utf8').split('\n')) {
    if (!line) continue
    let r; try { r = JSON.parse(line) } catch { continue }
    const site = r.host === 'www.shop.test' ? 'shop.test' : r.host
    if (!truth[site]) continue
    truth[site].push([Date.parse(r.t), r.app ? 0 : 1])
  }
}
const count = (site, from, to) => {
  let n = 0, st = 0
  for (const [t, s] of (site ? truth[site] : SITES.flatMap(x => truth[x]))) if (t >= from && t < to) { n++; st += s }
  return { requests: n, stopped: st }
}

let cookie = ''
async function api(base, path, auth) {
  const headers = auth ? { Authorization: `Bearer ${token}` } : { Cookie: cookie }
  const r = await fetch(`${base}${path}`, { headers })
  let j = null; try { j = await r.json() } catch {}
  return { status: r.status, body: j }
}
{
  const r = await fetch(`${dash}/api/v0/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) })
  cookie = (r.headers.get('set-cookie') ?? '').split(';')[0]
}
const now = Date.now()
const bend = Math.floor(now / 600e3) * 600e3
const iso = ms => new Date(ms).toISOString()
const H = 3600e3
// kill-10m: the killed bucket; full-run: from the first full bucket (BK-10 min) to the last finished boundary,
// i.e. without the start-up bucket (schild was not running before it, so that bucket is partial anyway)
const wins = [{ label: 'kill-10m', from: BK, to: BK + 600e3 }, { label: 'full-run', from: BK - 600e3, to: bend }]
for (const [l, ms] of [['1h', H], ['6h', 6 * H], ['24h', 24 * H], ['48h', 48 * H], ['7d', 168 * H]]) wins.push({ label: `al-${l}`, from: bend - ms, to: bend })
for (const [l, ms] of [['1h', H], ['6h', 6 * H], ['24h', 24 * H], ['48h', 48 * H], ['7d', 168 * H]]) wins.push({ label: `now-${l}`, from: now - ms, to: now })

let sig = null
if (existsSync(`${dir}/sig.time`)) sig = Date.parse(readFileSync(`${dir}/sig.time`, 'utf8').split('\n')[0].split(' ')[0])
const res = { generated_at: iso(now), bk: iso(BK), last_finished_boundary: iso(bend), signal_at: sig ? iso(sig) : null, windows: [], kill_minute: {}, agent: {}, overview: null }
const pct = (a, b) => b ? `${((a - b) / b * 100).toFixed(1)} %` : '-'
if (sig) {
  const m0 = Math.floor(sig / 60e3) * 60e3
  for (const s of SITES) res.kill_minute[s] = { minute: iso(m0), before_signal: count(s, m0, sig), whole_minute: count(s, m0, m0 + 60e3) }
  res.kill_minute.gateway = { before_signal: count(null, m0, sig), whole_minute: count(null, m0, m0 + 60e3) }
  console.log(`signal ${iso(sig)}; truth in the signal minute before the signal (gateway): ${JSON.stringify(res.kill_minute.gateway.before_signal)}`)
}
console.log(`window        site         truth req/stop     kpi req/stop       diff req/stop     exact partial`)
for (const w of wins) {
  const q = `from=${iso(w.from)}&to=${iso(w.to)}`
  let gk = { requests: 0, stopped: 0, partial: false }
  for (const site of SITES) {
    const k = await api(dash, `/api/v0/websites/${site}/kpis?${q}`)
    const c = k.body?.current
    const t = count(site, w.from, w.to)
    const row = { window: w.label, site, from: iso(w.from), to: iso(w.to), truth: t, kpi_status: k.status,
      requests: c?.requests, stopped: c?.stopped }
    res.windows.push(row)
    const kr = c?.requests?.value, ks = c?.stopped?.value
    gk.requests += kr ?? 0; gk.stopped += ks ?? 0; gk.partial ||= !!c?.requests?.partial
    console.log(`${w.label.padEnd(13)} ${site.padEnd(12)} ${String(t.requests).padStart(7)}/${String(t.stopped).padEnd(7)} ${String(kr).padStart(8)}/${String(ks).padEnd(8)} ${String(kr - t.requests).padStart(7)}/${String(ks - t.stopped).padEnd(7)} ${c?.requests?.exact}/${c?.stopped?.exact} ${c?.requests?.partial}/${c?.stopped?.partial}`)
  }
  const t = count(null, w.from, w.to)
  const bd = await api(dash, `/api/v0/monitoring/traffic/breakdown?by=country&${q}&top=5`)
  const ser = {}
  for (const r of ['1m', '10m']) {
    const s = await api(dash, `/api/v0/monitoring/series?metric=traffic.requests:sum&metric=traffic.stopped:sum&${q}&resolution=${r}`)
    const b = s.body
    if (s.status !== 200 || !b?.series) { ser[r] = { status: s.status, body: b }; continue }
    const sum = v => Math.round(v.reduce((a, x) => a + (x ?? 0), 0))
    ser[r] = { requests: sum(b.series[0].values), stopped: sum(b.series[1].values), partial_points: (b.partial ?? []).filter(Boolean).length }
  }
  const g = { window: w.label, site: 'gateway', truth: t, kpi_sum: gk, breakdown: bd.status === 200 ? { status: 200, total: bd.body.total?.requests, stopped: bd.body.total?.stopped, exact: bd.body.exact, resolution: bd.body.resolution } : { status: bd.status }, series: ser }
  res.windows.push(g)
  console.log(`${w.label.padEnd(13)} ${'GATEWAY'.padEnd(12)} ${String(t.requests).padStart(7)}/${String(t.stopped).padEnd(7)} ${String(gk.requests).padStart(8)}/${String(gk.stopped).padEnd(8)} ${String(gk.requests - t.requests).padStart(7)}/${String(gk.stopped - t.stopped).padEnd(7)} (sum of KPIs, partial any=${gk.partial}) | bd ${g.breakdown.total}/${g.breakdown.stopped} ${g.breakdown.resolution ?? g.breakdown.status} | 1m ${ser['1m']?.requests}/${ser['1m']?.stopped} p=${ser['1m']?.partial_points} | 10m ${ser['10m']?.requests}/${ser['10m']?.stopped} p=${ser['10m']?.partial_points}`)
}
// agent API and dashboard getWebsite traffic_24h: "now-24h" truth
console.log('traffic_24h (truth = now-24h)')
let ag = { requests: 0, stopped: 0 }, tg = { requests: 0, stopped: 0 }
for (const site of SITES) {
  const a = await api(agent, `/agent/v0/websites/${site}`, true)
  const d = await api(dash, `/api/v0/websites/${site}`)
  const t = count(site, now - 24 * H, now)
  const tr = a.body?.traffic_24h
  res.agent[site] = { status: a.status, traffic_24h: tr, keys: a.body ? Object.keys(a.body) : null, website_keys: a.body?.website ? Object.keys(a.body.website) : null,
    website_status: a.body?.website?.status, reasons: a.body?.website?.reasons, dash_traffic_24h: d.body?.traffic_24h ? { requests: d.body.traffic_24h.requests, stopped: d.body.traffic_24h.stopped } : d.status, truth: t }
  ag.requests += tr?.requests ?? 0; ag.stopped += tr?.stopped ?? 0; tg.requests += t.requests; tg.stopped += t.stopped
  console.log(`  ${site.padEnd(12)} agent ${tr?.requests}/${tr?.stopped}  dash ${d.body?.traffic_24h?.requests}/${d.body?.traffic_24h?.stopped}  truth ${t.requests}/${t.stopped}  diff ${tr?.requests - t.requests} (${pct(tr?.requests, t.requests)}) / ${tr?.stopped - t.stopped}  marker keys: ${Object.keys(tr ?? {}).filter(k => /partial|exact|gap|complete|missing/i.test(k)).join(',') || 'none'}`)
}
console.log(`  SUM          agent ${ag.requests}/${ag.stopped} truth ${tg.requests}/${tg.stopped} diff ${ag.requests - tg.requests} (${pct(ag.requests, tg.requests)}) / ${ag.stopped - tg.stopped} (${pct(ag.stopped, tg.stopped)})`)
const ov = await api(dash, '/api/v0/overview')
const mn = await api(dash, '/api/v0/monitoring/now')
const c = ov.body?.counters_24h
const t24 = count(null, now - 24 * H, now)
res.overview = { status: ov.status, counters_24h: c, started_at: mn.body?.started_at ?? mn.body?.server?.started_at ?? null, now_keys: mn.body ? Object.keys(mn.body) : null, truth_24h: t24 }
console.log(`overview counters_24h requests ${c?.requests} blocked ${c?.blocked} would_block ${c?.would_block} | truth 24h ${t24.requests}/${t24.stopped} (${pct(c?.requests, t24.requests)}) | started_at ${res.overview.started_at}`)
writeFileSync(out, JSON.stringify(res, null, 1))
