#!/usr/bin/env node
// TEST ONLY: D36 re-measurement, numbers of the API against the sent-side truth.
// Truth: the traffic logs written with traffic.mjs -logall (every answered request:
// t, host, kind, status, app; app=false means schild answered, i.e. stopped).
// For every website and window: getWebsiteKpis (requests, stopped with exact),
// getTrafficBreakdown (total, exact) and queryMetricSeries 1m / 10m (sums, partial).
//
//   PW=... node api-truth.mjs -dash http://127.0.0.1:20388 -out file.json -logs a.jsonl,b.jsonl \
//     -win "label=2026-10-29T14:30:00Z/2026-10-29T14:40:00Z" -win ... [-last 1h,6h]
import { readFileSync, writeFileSync } from 'node:fs'

const args = process.argv.slice(2)
const arg = (n, d) => { const i = args.indexOf(`-${n}`); return i >= 0 ? args[i + 1] : d }
const all = n => args.flatMap((a, i) => a === `-${n}` ? [args[i + 1]] : [])
const dash = arg('dash', 'http://127.0.0.1:20388')
const out = arg('out', 'api-truth.json')
const pw = process.env.PW
const SITES = ['shop.test', 'blog.test', 'api.test', 'status.test']

// truth per site: sorted [ms, stopped]
const truth = Object.fromEntries(SITES.map(s => [s, []]))
for (const f of arg('logs', '').split(',').filter(Boolean)) {
  for (const line of readFileSync(f, 'utf8').split('\n')) {
    if (!line) continue
    let r; try { r = JSON.parse(line) } catch { continue }
    const site = r.host === 'www.shop.test' ? 'shop.test' : r.host
    if (!truth[site]) continue
    truth[site].push([Date.parse(r.t), r.app ? 0 : 1])
  }
}
// the log time is when the answer arrived; the request was counted a few ms earlier: good enough at minute scale
const count = (site, from, to) => {
  let n = 0, st = 0
  for (const [t, s] of truth[site]) if (t >= from && t < to) { n++; st += s }
  return { requests: n, stopped: st }
}

let cookie = ''
async function api(method, path, body) {
  const r = await fetch(`${dash}/api/v0${path}`, { method, headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: body ? JSON.stringify(body) : undefined })
  const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0]
  let j = null; try { j = await r.json() } catch {}
  return { status: r.status, body: j }
}
await api('POST', '/auth/login', { password: pw })

const now = Date.now()
const wins = all('win').map((w) => { const [label, range] = w.split('='); const [a, b] = range.split('/'); return { label, from: Date.parse(a), to: Date.parse(b) } })
for (const l of (arg('last', '') || '').split(',').filter(Boolean)) {
  const ms = { '1h': 3600e3, '6h': 6 * 3600e3, '24h': 86400e3 }[l]
  wins.push({ label: `last-${l}`, from: now - ms, to: now })
}
const iso = ms => new Date(ms).toISOString()
const res = { generated_at: iso(now), dash, windows: [] }
for (const w of wins) {
  for (const site of SITES) {
    const q = `from=${iso(w.from)}&to=${iso(w.to)}`
    const k = await api('GET', `/websites/${site}/kpis?${q}`)
    const bd = await api('GET', `/monitoring/traffic/breakdown?by=country&${q}&site=${site}&top=5`)
    const bs = await api('GET', `/monitoring/traffic/breakdown?by=status_class&${q}&site=${site}&top=5`)
    const ser = {}
    for (const resn of ['1m', '10m']) {
      const s = await api('GET', `/monitoring/series?metric=traffic.requests:sum&metric=traffic.stopped:sum&${q}&resolution=${resn}&site=${site}`)
      const b = s.body
      if (s.status !== 200 || !b?.series) { ser[resn] = { status: s.status, body: b }; continue }
      const sum = v => Math.round(v.reduce((a, x) => a + (x ?? 0), 0))
      ser[resn] = { status: 200, step_s: b.step_s, requests: sum(b.series[0].values), stopped: sum(b.series[1].values), exact: b.series.map(x => x.exact), partial_points: (b.partial ?? []).map((p, i) => p ? i : -1).filter(i => i >= 0).map(i => iso(Date.parse(b.from) + i * b.step_s * 1000)), null_points: b.series[0].values.filter(v => v === null).length, points: b.points }
    }
    const c = k.body?.current
    const row = {
      window: w.label, site, from: iso(w.from), to: iso(w.to),
      truth: count(site, w.from, w.to),
      kpis: k.status === 200 ? { status: 200, source: k.body.source, requests: c.requests, stopped: c.stopped, would_block: c.would_block, page_views: c.page_views, visitors: c.visitors } : { status: k.status, body: k.body },
      breakdown_country: bd.status === 200 ? { exact: bd.body.exact, total: bd.body.total, resolution: bd.body.resolution } : { status: bd.status, body: bd.body },
      breakdown_status: bs.status === 200 ? { exact: bs.body.exact, total: bs.body.total, items: bs.body.items } : { status: bs.status, body: bs.body },
      series: ser,
    }
    res.windows.push(row)
    const t = row.truth
    console.log(`${w.label.padEnd(16)} ${site.padEnd(11)} truth ${t.requests}/${t.stopped}  kpi ${c?.requests?.value}/${c?.stopped?.value} exact=${c?.requests?.exact}/${c?.stopped?.exact}  bd ${bd.body?.total?.requests}/${bd.body?.total?.stopped} exact=${bd.body?.exact}  1m ${ser['1m']?.requests}/${ser['1m']?.stopped} p=${ser['1m']?.partial_points?.length}  10m ${ser['10m']?.requests}/${ser['10m']?.stopped} p=${ser['10m']?.partial_points?.length}`)
  }
}
writeFileSync(out, JSON.stringify(res, null, 1))
