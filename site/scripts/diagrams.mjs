// Pre-renders the Mermaid diagrams of the docs into site/diagrams/<hash>.svg (committed). The build inlines them
// (nuxt.config.ts, content:file:afterParse), so doc pages ship no Mermaid JavaScript (~1 MB compressed).
//
// Usage (from site/):
//   npm run diagrams -- [base URL]   render: opens each doc page with ?mermaid=live in headless Chrome against a
//                                    running site (default http://localhost:3000; `npm run dev`, or `npm run generate`
//                                    + `npx serve .output/public`), stores every diagram, removes stale files
//   npm run diagrams -- --check      exit 1 if a diagram has no SVG yet or an SVG belongs to no diagram
// The browser is rendering in the real page (same CSS, fonts, Mermaid config as MermaidDiagram.vue), driven over the
// Chrome DevTools protocol without extra packages. Chrome binary: $CHROME or the usual install locations.
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DIAGRAM_DIR, docDiagrams } from './mermaid-svgs.mjs'

const wanted = docDiagrams()
const hashes = new Set(wanted.map(d => d.hash))
const files = existsSync(DIAGRAM_DIR) ? readdirSync(DIAGRAM_DIR).filter(f => f.endsWith('.svg')) : []

if (process.argv.includes('--check')) {
  const missing = wanted.filter(d => !files.includes(`${d.hash}.svg`))
  const stale = files.filter(f => !hashes.has(f.slice(0, -4)))
  for (const d of missing) console.error(`missing: ${d.hash} (${d.route})`)
  for (const f of stale) console.error(`stale: ${f}`)
  console.log(`${wanted.length} diagrams, ${missing.length} missing, ${stale.length} stale`)
  process.exit(missing.length || stale.length ? 1 : 0)
}

const base = (process.argv.slice(2).find(a => !a.startsWith('-')) ?? 'http://localhost:3000').replace(/\/$/, '')
const CHROME = [process.env.CHROME, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'].find(p => p && existsSync(p))
if (!CHROME) throw new Error('No Chrome found, set CHROME=/path/to/chrome')

const profile = mkdtempSync(join(tmpdir(), 'schild-diagrams-'))
const chrome = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--window-size=1440,900', 'about:blank'], { stdio: 'ignore' })
const sleep = ms => new Promise(r => setTimeout(r, ms))

try {
  let port
  for (let i = 0; i < 100 && !port; i++) {
    await sleep(100)
    try { port = readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').split('\n')[0] } catch {}
  }
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()
  const ws = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl)
  await new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = fail })
  let seq = 0
  const pending = new Map()
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data)
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id) }
  }
  const send = (method, params = {}) => new Promise((ok) => { const id = ++seq; pending.set(id, ok); ws.send(JSON.stringify({ id, method, params })) })
  const evaluate = async expression => (await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })).result?.result?.value

  const found = {}
  for (const route of [...new Set(wanted.map(d => d.route))]) {
    await send('Page.navigate', { url: `${base}${route}?mermaid=live` })
    let result
    for (let i = 0; i < 300; i++) {
      await sleep(100)
      result = await evaluate(`(() => {
        if (document.readyState !== 'complete') return null
        const figs = [...document.querySelectorAll('figure[data-diagram]')]
        // Diagrams below the fold only render once they come into view: scroll to the next one still waiting.
        const waiting = figs.find(f => !f.querySelector('.mermaid-svg svg, pre'))
        if (waiting) waiting.scrollIntoView()
        if (!figs.length || waiting) return null
        return figs.map(f => ({ hash: f.dataset.diagram, svg: f.querySelector('.mermaid-svg')?.innerHTML ?? null }))
      })()`)
      if (result) break
    }
    if (!result) { console.error(`timeout: ${route}`); continue }
    for (const { hash, svg } of result) {
      if (svg) found[hash] = svg
      else console.error(`render failed: ${hash} (${route})`)
    }
  }
  ws.close()

  mkdirSync(DIAGRAM_DIR, { recursive: true })
  for (const [hash, svg] of Object.entries(found)) if (hashes.has(hash)) writeFileSync(join(DIAGRAM_DIR, `${hash}.svg`), `${svg}\n`)
  for (const f of files) if (!hashes.has(f.slice(0, -4))) unlinkSync(join(DIAGRAM_DIR, f))
  const missing = wanted.filter(d => !found[d.hash])
  for (const d of missing) console.error(`not rendered: ${d.hash} (${d.route})`)
  console.log(`${Object.keys(found).length} of ${hashes.size} diagrams rendered into ${DIAGRAM_DIR}`)
  if (missing.length) process.exitCode = 1
} finally {
  chrome.kill()
  await sleep(300)
  rmSync(profile, { recursive: true, force: true })
}
