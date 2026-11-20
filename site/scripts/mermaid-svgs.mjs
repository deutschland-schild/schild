// Pre-rendered Mermaid diagrams: one committed SVG per diagram in site/diagrams/<hash>.svg.
// Shared by nuxt.config.ts (content:file:afterParse inlines the SVG) and scripts/diagrams.mjs (renders and checks).
// Keep it free of Nuxt imports.
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const DIAGRAM_DIR = fileURLToPath(new URL('../diagrams', import.meta.url))
const DOCS_DIR = fileURLToPath(new URL('../../docs', import.meta.url))

// Bump when the Mermaid theme in MermaidDiagram.vue changes, so every SVG counts as stale.
const THEME_VERSION = '1'

export const diagramHash = code => createHash('sha256').update(`${THEME_VERSION}\n${code.trim()}`).digest('hex').slice(0, 12)

export function diagramSvg(hash) {
  const file = `${DIAGRAM_DIR}/${hash}.svg`
  return existsSync(file) ? readFileSync(file, 'utf8') : undefined
}

// Published doc folders and their routes (see COLLECTIONS in app/utils/hub.ts).
const ROUTES = { gateway: '/doku/gateway', concept: '/doku/konzept', brand: '/doku/marke', stories: '/doku/personas' }

// Every ```mermaid block in the published docs: { route, hash }.
export function docDiagrams() {
  const out = []
  for (const [dir, base] of Object.entries(ROUTES)) {
    for (const f of readdirSync(`${DOCS_DIR}/${dir}`).filter(f => f.endsWith('.md'))) {
      const md = readFileSync(`${DOCS_DIR}/${dir}/${f}`, 'utf8')
      for (const m of md.matchAll(/^```mermaid[^\n]*\n([\s\S]*?)^```/gm)) out.push({ route: `${base}/${f.slice(0, -3)}`, hash: diagramHash(m[1]) })
    }
  }
  return out
}

// Fingerprint of all SVGs, part of the content cache key in nuxt.config.ts.
export function diagramsStamp() {
  const h = createHash('sha256')
  if (existsSync(DIAGRAM_DIR)) for (const f of readdirSync(DIAGRAM_DIR).filter(f => f.endsWith('.svg')).sort()) h.update(f).update(readFileSync(`${DIAGRAM_DIR}/${f}`))
  return h.digest('hex').slice(0, 12)
}
