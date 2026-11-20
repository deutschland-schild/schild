#!/usr/bin/env node
// TEST ONLY: drive a few addresses up the block ladder (D29 amendment) with
// operator actions only: two distinct WAF rules in a minute -> waf_repeat
// block; the operator ends it in the dashboard (POST /behaviour/release,
// allow none); the address comes back -> next step. Hosting nets reach 7 days
// at step 4, residential nets stop at 24 h.
//
//   PW=... node longblocks.mjs -dash http://127.0.0.1:19388 -target http://127.0.0.1:19390 -out longblocks.json
import http from 'node:http'
import { writeFileSync } from 'node:fs'

const arg = (n, d) => { const i = process.argv.indexOf(`-${n}`); return i > 0 ? process.argv[i + 1] : d }
const dash = arg('dash', 'http://127.0.0.1:19388')
const target = new URL(arg('target', 'http://127.0.0.1:19390'))
const out = arg('out', 'longblocks.json')
const pw = process.env.PW
const steps = Number(arg('steps', 4))
const sleep = ms => new Promise(r => setTimeout(r, ms))

const ADDRS = [
  { ip: '10.1.250.11', host: 'shop.test', cls: 'hosting' },
  { ip: '10.7.250.12', host: 'blog.test', cls: 'hosting' },
  { ip: '10.13.250.13', host: 'api.test', cls: 'hosting' },
  { ip: '10.5.250.14', host: 'shop.test', cls: 'residential' },
]

function hit(host, ipaddr, path) {
  return new Promise((res) => {
    const req = http.request({ host: target.hostname, port: target.port, path, headers: { Host: host, 'X-Forwarded-For': ipaddr, 'User-Agent': 'sqlmap/1.8.4#stable (https://sqlmap.org)' } }, (r) => { r.resume(); r.on('end', () => res(r.statusCode)) })
    req.on('error', () => res(0))
    req.end()
  })
}

let cookie = ''
let csrf = ''
async function api(method, path, body) {
  const r = await fetch(`${dash}/api/v0${path}`, { method, headers: { 'Content-Type': 'application/json', Cookie: cookie, ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }, body: body ? JSON.stringify(body) : undefined })
  const sc = r.headers.get('set-cookie')
  if (sc) cookie = sc.split(';')[0]
  const t = await r.text()
  let j; try { j = JSON.parse(t) } catch { j = t }
  return { status: r.status, body: j }
}

const login = await api('POST', '/auth/login', { password: pw })
csrf = login.body.csrf_token
const log = []
for (const a of ADDRS) {
  for (let s = 1; s <= steps; s++) {
    const st = []
    st.push(await hit(a.host, a.ip, `/?id=1%27%20UNION%20SELECT%20password%20FROM%20users--&s=${s}`))
    st.push(await hit(a.host, a.ip, `/?q=%3Cscript%3Ealert(1)%3C/script%3E&s=${s}`))
    st.push(await hit(a.host, a.ip, `/index.php?page=../../../../etc/passwd&s=${s}`))
    await sleep(1500)
    const after = await hit(a.host, a.ip, '/')
    const entry = { ip: a.ip, cls: a.cls, host: a.host, step: s, statuses: st, after_status: after }
    if (s < steps) {
      const rel = await api('POST', '/behaviour/release', { ip: a.ip, allow: 'none', confirm: { password: pw } })
      entry.release = { status: rel.status, body: rel.body }
      await sleep(1000)
    }
    log.push(entry)
    console.log(JSON.stringify(entry))
  }
}
writeFileSync(out, JSON.stringify(log, null, 1))
