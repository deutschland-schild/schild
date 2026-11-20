import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import { hubHref, LEGACY_BRAND } from './app/utils/hub'
import { diagramHash, diagramsStamp, diagramSvg } from './scripts/mermaid-svgs.mjs'
import { SITE_URL } from './app/utils/site'

// Status markers (FIXIERT, ENTWURF, …) are for the agents working on docs/. The rendered docs keep them out of the
// way: status lines and "Als Nächstes" todo sections move into a collapsed block at the end of the page, marker
// legends and status table columns are dropped, a parenthesis
// that only holds a marker (plus date/initiator) disappears, markers inside a sentence become plain words.
const STATUS_WORDS = 'FIXIERT|ZIEL|ENTWURF|ZU PRÜFEN|OFFEN|ENTSCHIEDEN|ERSETZT|IDEE'
const STATUS_PLAIN: Record<string, string> = { 'FIXIERT': 'fixiert', 'ZIEL': 'Ziel', 'ENTWURF': 'Entwurf', 'ZU PRÜFEN': 'zu prüfen', 'OFFEN': 'offen', 'ENTSCHIEDEN': 'entschieden', 'ERSETZT': 'ersetzt', 'IDEE': 'Idee' }
const STATUS_WORD = new RegExp(`\\b(${STATUS_WORDS})\\b`, 'g')
const STATUS_ONLY = new RegExp(`^\\s*(${STATUS_WORDS}):?\\s*$`)
const STATUS_PAREN = new RegExp(`\\s*\\((?:${STATUS_WORDS})(?:,?\\s*(?:\\d{1,2}\\.\\d{1,2}\\.\\d{4}|Initiator))*\\)`, 'g')
// In headings (and the TOC) any parenthesis starting with a marker goes, e.g. "Logs (ENTWURF)", "schild (ENTSCHIEDEN für v1)".
const STATUS_PAREN_HEADING = new RegExp(`\\s*\\((?:${STATUS_WORDS})\\b[^)]*\\)`, 'g')
const capitalize = (w: string) => w.charAt(0).toUpperCase() + w.slice(1)
const plainStatus = (text: string, heading = false) => text
  .replace(heading ? STATUS_PAREN_HEADING : STATUS_PAREN, '')
  .replace('FIXIERT-Grundsätz', 'festgelegten Grundsätz')
  // capitalised at the start of a text node or a sentence ("zu prüfen: …" → "Zu prüfen: …")
  .replace(STATUS_WORD, (w, _, at: number, all: string) => {
    const plain = STATUS_PLAIN[w] ?? w
    return at === 0 || /[.!?]\s+$/.test(all.slice(0, at)) ? capitalize(plain) : plain
  })
// h2 sections for the agents, not for readers: open todos and struck story IDs (kept so IDs are never reused).
const WORK_SECTIONS = new Set(['Als Nächstes', 'Gestrichene Stories'])
// Inline code up to this length never wraps.
const CODE_NOWRAP_MAX = 32

// Old /handbuch/** URLs that get a redirect page (pages/handbuch/[...path].vue).
const LEGACY_HANDBOOK = ['00-ueberblick', '01-installieren', '02-dashboard', '03-modi', '04-freischalten', '05-laender-und-bots', '06-formulare-und-passwort', '07-admin-zugang-vpn', '08-server-check-und-zustand', '09-logs-und-fehler', '10-hilfe-aus-dem-netz', '11-erste-hilfe', '12-fuer-profis']
const LEGACY_SPEC = ['13-technik-kompakt', '14-testkonzept', '18-manipulation-und-poisoning', '19-spezifikation', '20-events-und-geschwindigkeit', '21-architektur-v1', '22-quellen-cve-ip-crowdsec']
const STORIES = readdirSync(fileURLToPath(new URL('../docs/stories', import.meta.url))).filter(f => /^\d{2}-.*\.md$/.test(f)).map(f => f.slice(0, -3))
const LEGACY_ROUTES = [
  '/handbuch',
  ...LEGACY_HANDBOOK.map(s => `/handbuch/${s}`),
  ...LEGACY_SPEC.map(s => `/handbuch/spec/${s}`),
  ...STORIES.map(s => `/handbuch/personas/${s}`),
  // Old brand pages merged into /doku/marke/01-marke (redirect in pages/doku/[kind]/[slug].vue).
  ...Object.keys(LEGACY_BRAND).map(s => `/doku/marke/${s}`),
]

// Footer "Stand": the date of the last commit, so nobody has to keep it by hand. Without git (tarball build) the build date.
function siteStand(): string {
  let iso = new Date().toISOString().slice(0, 10)
  try { iso = execFileSync('git', ['log', '-1', '--format=%cs'], { encoding: 'utf8' }).trim() || iso }
  catch { /* no git here */ }
  const [y, m, d] = iso.split('-')
  return `${d}.${m}.${y}`
}

// robots.txt and sitemap.xml from the prerendered pages. Left out: redirect pages (meta refresh), pages marked
// noindex and the SPA fallbacks.
function writeSitemap(publicDir: string, routes: { route: string, fileName?: string }[]) {
  const urls = routes
    .filter(r => r.fileName?.endsWith('.html') && !['/200.html', '/404.html'].includes(r.fileName))
    .filter((r) => {
      const file = join(publicDir, r.fileName!)
      if (!existsSync(file)) return false
      const html = readFileSync(file, 'utf8')
      return !/http-equiv="refresh"/i.test(html) && !/<meta name="robots" content="[^"]*noindex/i.test(html)
    })
    .map(r => `${SITE_URL}${r.route === '/' ? '/' : r.route.replace(/\/$/, '')}`)
    .sort()
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${[...new Set(urls)].map(u => `  <url><loc>${u}</loc></url>`).join('\n')}\n</urlset>\n`
  writeFileSync(join(publicDir, 'sitemap.xml'), xml)
  writeFileSync(join(publicDir, 'robots.txt'), `User-agent: *\nAllow: /\n\nSitemap: ${SITE_URL}/sitemap.xml\n`)
}

// Cache key for parsed docs, see content.build.markdown below.
const HOOK_INPUTS = createHash('sha256')
  .update(readFileSync(fileURLToPath(import.meta.url)))
  .update(readFileSync(fileURLToPath(new URL('./app/utils/hub.ts', import.meta.url))))
  .update(diagramsStamp())
  .digest('hex').slice(0, 12)

// Minimum table width in rem from the longest cell text per column; 0 = no minimum needed.
function tableMinRem(sections: any[]): number {
  const max: number[] = []
  for (const sec of sections) {
    if (!Array.isArray(sec)) continue
    for (const row of sec.slice(2)) {
      if (!Array.isArray(row) || row[0] !== 'tr') continue
      row.slice(2).filter((c: any) => Array.isArray(c)).forEach((cell: any, i: number) => {
        max[i] = Math.max(max[i] ?? 0, textOf(cell).length)
      })
    }
  }
  const ch = max.reduce((sum, len) => sum + Math.min(45, Math.max(8, len / 3.5)), 0)
  const rem = Math.round(ch * 0.45 + max.length * 1.5)
  return max.length >= 3 && rem > 44 ? rem : 0
}

const textOf = (node: any): string => typeof node === 'string' ? node : Array.isArray(node) ? node.slice(2).map(textOf).join('') : ''

// Bodies are minimark: a node is a string (text) or [tag, props, ...children].
// Leaves out status markers (see STATUS_WORDS) and maps doc links to hub routes (links to unpublished docs become
// plain text, see hubHref).
const isTag = (node: any, tag: string) => Array.isArray(node) && node[0] === tag
const startsWithStrong = (node: any, test: (text: string) => boolean) => {
  const first = node.slice(2).find((c: any) => !(typeof c === 'string' && !c.trim()))
  return isTag(first, 'strong') && test(textOf(first))
}
// "**Status:** ENTWURF · Stand …" paragraphs and "- **FIXIERT:** …" legend items
const isStatusLine = (node: any) => isTag(node, 'p') && startsWithStrong(node, t => /^Status\b/.test(t.trim()))
const isLegendItem = (node: any) => isTag(node, 'li') && startsWithStrong(node, t => STATUS_ONLY.test(t))
const isTodoItem = (node: any) => isTag(node, 'li') && node.slice(2).some((c: any) => isTag(c, 'input'))

// Moves the status lines and the WORK_SECTIONS (h2 up to the next h2) out of the page body;
// they end up collapsed in a <details> at the end of the page (workState).
function splitWorkState(children: any[]): { body: any[], work: any[] } {
  const body: any[] = []
  const work: any[] = []
  let todo = false
  for (const node of children) {
    if (isTag(node, 'h2')) todo = WORK_SECTIONS.has(textOf(node).trim())
    if (todo) { if (!isTag(node, 'h2')) work.push(node) }
    else if (isStatusLine(node)) work.unshift(node)
    else body.push(node)
  }
  return { body, work }
}

// Removes a column headed "Status" from a table.
function dropStatusColumn(rest: any[]): any[] {
  const head = rest.find(n => isTag(n, 'thead'))?.slice(2).find((n: any) => isTag(n, 'tr'))
  const col = head ? head.slice(2).filter((c: any) => Array.isArray(c)).findIndex((c: any) => textOf(c).trim() === 'Status') : -1
  if (col < 0) return rest
  return rest.map(sec => !Array.isArray(sec) ? sec : [sec[0], sec[1], ...sec.slice(2).map((row: any) => {
    if (!isTag(row, 'tr')) return row
    let i = -1
    return row.filter((c: any, k: number) => k < 2 || !Array.isArray(c) || ++i !== col)
  })])
}

function transformDoc(children: any[], collection: string, heading = false, keepWork = false): any[] {
  return children.flatMap((node) => {
    if (Array.isArray(node)) {
      let [tag, props, ...rest] = node
      if (tag === 'pre') {
        // Mermaid: inline the pre-rendered SVG (MermaidDiagram.vue); missing ones render in the browser.
        if (props?.language === 'mermaid' && typeof props.code === 'string') {
          const diagram = diagramHash(props.code)
          const svg = diagramSvg(diagram)
          if (!svg) console.warn(`[diagrams] no pre-rendered SVG for ${diagram} (${collection}), falling back to client rendering – run: npm run diagrams`)
          node[1] = { ...props, diagram, ...(svg ? { svg } : {}) }
        }
        return [node]
      }
      if (tag === 'code') {
        if (textOf(node).length <= CODE_NOWRAP_MAX) node[1] = { ...props, class: 'whitespace-nowrap' }
        return [node]
      }
      if (isLegendItem(node) || (!keepWork && (isStatusLine(node) || isTodoItem(node)))) return []
      if (tag === 'a' && typeof props?.href === 'string') {
        const href = hubHref(props.href, collection)
        if (href === null) return transformDoc(rest, collection, heading, keepWork)
        props.href = href
      }
      // Brand images live in docs/brand/assets, served under /doku/marke/assets (nitro.publicAssets).
      if (tag === 'img' && collection === 'brand' && typeof props?.src === 'string' && props.src.startsWith('assets/')) {
        props.src = `/doku/marke/${props.src}`
      }
      if (tag === 'table') rest = dropStatusColumn(rest)
      // Wide tables scroll inside the content column instead of squeezing cells into tall strips (ProseTable.vue):
      // estimate a minimum width from the longest cell per column (about 3–4 lines for the longest cell).
      if (tag === 'table' && props) props['data-min-rem'] = tableMinRem(rest)
      const kids = transformDoc(rest, collection, heading || /^h[1-6]$/.test(tag), keepWork)
      // a list or paragraph left empty (only legend or todo items, only a marker) disappears
      if ((tag === 'ul' || tag === 'ol' || tag === 'p') && !kids.some(k => Array.isArray(k) || k.trim())) return []
      return [[tag, props, ...kids]]
    }
    if (typeof node !== 'string') return [node]
    const text = plainStatus(node, heading)
    return text === '' ? [] : [text]
  })
}

const cleanToc = (links: any[] = []): any[] => links
  .filter(l => !WORK_SECTIONS.has(l.text?.trim()))
  .map(l => ({ ...l, text: plainStatus(l.text ?? '', true), children: l.children ? cleanToc(l.children) : undefined }))

export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: false },
  modules: ['@nuxt/content', '@vueuse/nuxt'],
  css: ['~/assets/css/main.css'],
  vite: {
    plugins: [tailwindcss()],
    optimizeDeps: { include: ['mermaid'] },
  },
  content: {
    experimental: { sqliteConnector: 'native' },
    build: {
      markdown: {
        toc: { depth: 3 },
        // Not a parser option: Nuxt Content reuses parsed files from .data while content and markdown options are
        // unchanged. This key makes a change to the afterParse hook (this file, hub.ts) or to a diagram SVG reparse.
        ...{ hookInputs: HOOK_INPUTS },
      },
    },
  },
  hooks: {
    'nitro:init'(nitro: any) {
      nitro.hooks.hook('prerender:done', ({ prerenderedRoutes }: any) => writeSitemap(nitro.options.output.publicDir, prerenderedRoutes))
    },
    'content:file:afterParse'(ctx: any) {
      const body = ctx.content?.body
      if (body?.type !== 'minimark') return
      const collection = ctx.collection?.name ?? 'concept'
      const { body: main, work } = splitWorkState(body.value)
      body.value = transformDoc(main, collection)
      if (work.length) body.value.push(['details', { class: 'doku-work' }, ['summary', {}, 'Arbeitsstand und nächste Schritte'], ...transformDoc(work, collection, false, true)])
      if (body.toc?.links) body.toc.links = cleanToc(body.toc.links)
      if (typeof ctx.content.title === 'string') ctx.content.title = plainStatus(ctx.content.title, true)
    },
  },
  runtimeConfig: {
    public: {
      siteStand: siteStand(),
    },
  },
  nitro: {
    // Fully static site everywhere: without this, Nuxt switches to the netlify-static preset on Netlify (output in dist/).
    preset: 'static',
    // Logo files referenced from docs/brand/01-marke.md, served without copies.
    publicAssets: [{ dir: fileURLToPath(new URL('../docs/brand/assets', import.meta.url)), baseURL: '/doku/marke/assets', maxAge: 0 }],
    prerender: {
      crawlLinks: true,
      routes: ['/', '/doku', '/api', '/api/gateway-agent.openapi.json', '/architektur', '/doku-search.json', ...LEGACY_ROUTES],
    },
  },
  app: {
    head: {
      htmlAttrs: { lang: 'de' },
      title: 'Schild Gateway – die kostenlose Firewall für deine Website',
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { name: 'theme-color', content: '#0A1A33' },
        // Max. 160 characters. Pages override description via useSeoMeta; og:url and canonical are set per route in app.vue.
        { name: 'description', content: 'Schild Gateway ist eine kostenlose, quelloffene Firewall für deine Website. Läuft auf deinem eigenen Server, deine Daten bleiben dort.' },
        { property: 'og:type', content: 'website' },
        { property: 'og:locale', content: 'de_DE' },
        { property: 'og:site_name', content: 'Deutschland-Schild' },
        { property: 'og:title', content: 'Schild Gateway – die kostenlose Firewall für deine Website' },
        { property: 'og:description', content: 'Schild Gateway ist eine kostenlose, quelloffene Firewall für deine Website. Läuft auf deinem eigenen Server, deine Daten bleiben dort.' },
        { property: 'og:image', content: `${SITE_URL}/og-image.png` },
        { property: 'og:image:width', content: '1200' },
        { property: 'og:image:height', content: '630' },
        { property: 'og:image:alt', content: 'Deutschland-Schild: Grundschutz für alle Websites. Gemeinnützig, überparteilich, Open Source. Gebaut in Deutschland.' },
        { name: 'twitter:card', content: 'summary_large_image' },
      ],
      link: [
        { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' },
        { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' },
      ],
    },
  },
})
