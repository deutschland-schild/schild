#!/usr/bin/env node
// TEST ONLY: list incidents (all pages) and pick behaviour-block incidents of the long-block addresses.
const dash = process.argv[2] ?? 'http://127.0.0.1:20388'
let cookie = ''
async function api(path, body) {
  const r = await fetch(`${dash}/api/v0${path}`, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: body ? JSON.stringify(body) : undefined })
  const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0]
  return { status: r.status, body: await r.json().catch(() => null) }
}
await api('/auth/login', { password: process.env.PW })
const items = []
let cursor = ''
for (let i = 0; i < 400; i++) {
  const r = await api(`/incidents?limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`)
  if (r.status !== 200) { console.error(r); break }
  items.push(...r.body.items)
  cursor = r.body.next_cursor ?? r.body.cursor ?? ''
  if (!cursor) break
}
const withBlock = items.filter(x => x.block)
const by = {}
for (const x of items) { const k = `${x.block ? 'block:' + x.block.source + ':L' + x.block.level + ':' + (x.block.net_class ?? '') : 'waf'}:${x.status}`; by[k] = (by[k] ?? 0) + 1 }
console.log(JSON.stringify({ total: items.length, withBlock: withBlock.length, by }, null, 1))
const lb = ['10.1.250.11', '10.7.250.12', '10.13.250.13', '10.5.250.14']
for (const x of items.filter(x => lb.includes(x.request?.ip ?? x.ip))) console.log(JSON.stringify({ incident: x.incident, status: x.status, ip: x.request?.ip, host: x.request?.host, reason: x.reason, block: x.block }))
console.log('sample keys', Object.keys(items[0] ?? {}))
