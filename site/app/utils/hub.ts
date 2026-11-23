// Documentation hub (/doku): the Company-as-Code knowledge base rendered from docs/.
// Shared by nuxt.config.ts / content.config.ts (build time) and the hub pages – keep it free of Nuxt imports.

export type DocCollection = 'gateway' | 'concept' | 'brand' | 'stories'

// Source folder and public route base per collection. Routes mirror the files, sections only group them.
export const COLLECTIONS: Record<DocCollection, { dir: string, base: string }> = {
  gateway: { dir: 'docs/gateway', base: '/doku/gateway' },
  concept: { dir: 'docs/concept', base: '/doku/konzept' },
  brand: { dir: 'docs/brand', base: '/doku/marke' },
  stories: { dir: 'docs/stories', base: '/doku/personas' },
}

// Concept files that are NOT published (publishing check). Links to them render as plain text.
// 08: budget figures (the concept itself decides "no amounts in public"), unconfirmed network named as
// source of alpha testers, reference to the internal contact list.
export const UNPUBLISHED_CONCEPT = ['08-finanzierung-und-partner']

// Brand docs have no frontmatter (they stay plain Markdown on GitHub); navigation data lives here.
export const BRAND_META: Record<string, { short: string, description: string }> = {
  '01-marke': { short: 'Marke, Sprache und Gestaltung', description: 'Markenkern, Sprachregeln und Glossar, Logo, Farben, Schriften und Bilder, Kultur. Die Regeln für alle öffentlichen Texte und Oberflächen.' },
}

// Old brand pages, merged into 01-marke: each old URL becomes a redirect page to the matching section
// (pages/doku/[kind]/[slug].vue, prerendered via nuxt.config.ts).
export const LEGACY_BRAND: Record<string, string> = {
  '01-markenkern': '/doku/marke/01-marke#markenkern',
  '02-sprache-und-tonalitaet': '/doku/marke/01-marke#sprache',
  '03-visuelle-identitaet': '/doku/marke/01-marke#gestaltung',
  '04-unternehmenskultur': '/doku/marke/01-marke#kultur',
}

// Built and usable today, or planned. Planned sections carry a notice on every page (HubChapter.vue), so nobody
// mistakes the target picture of labs and relays for something they can run now.
export type HubStatus = 'live' | 'planned'

export const STATUS_LABEL: Record<HubStatus, string> = {
  live: 'Verfügbar (Alpha)',
  planned: 'Geplant',
}

export type HubSectionDef = {
  id: string
  label: string
  intro: string
  status?: HubStatus
  // Under "Allgemeines": everything that is not one part of Deutschland-Schild (collapsed in the sidebar by default).
  general?: boolean
  // Chapters in reading order as '<collection>/<slug>'; omitted = every file of `collection`.
  docs?: string[]
  collection?: DocCollection
  // Website pages shown before the chapters (e.g. the install section).
  links?: { to: string, label: string, description: string }[]
}

// The parts of Deutschland-Schild (docs/brand/01-marke.md, Glossar), as they are rolled out (/netz#fahrplan).
// Shown at the top of /doku. Managed Schild has no docs yet and links to the roadmap.
export const COMPONENTS: { name: string, status: HubStatus, text: string, to: string }[] = [
  { name: 'Gateway', status: 'live', text: 'Firewall, Dashboard und Server-Check auf deinem Server. Läuft allein, ohne Labs. Damit fängst du an.', to: '/doku#gateway' },
  { name: 'Lab-Server', status: 'planned', text: 'Unabhängige Prüfstellen, die neue Angriffsversuche gemeinsam prüfen und Regeln freigeben. Bisher nur im Testlabor.', to: '/doku#labs' },
  { name: 'Relays', status: 'planned', text: 'Verteilen signierte Regeln an alle Gateways. Bisher nur im Testlabor.', to: '/doku#relays' },
  { name: 'Managed Schild', status: 'planned', text: 'Hoster betreiben Schild Gateways als Dienst für ihre Kund:innen. Ziel, noch nicht begonnen.', to: '/netz#fahrplan' },
]

// Sections follow the parts of Deutschland-Schild: first the gateway (usable today), then labs and relays (planned),
// then "Allgemeines": what spans the whole system and the project. Routes do not depend on this order. The section id 'system'
// also collects concept files that are not mapped anywhere (see useHub).
export const HUB_SECTIONS: HubSectionDef[] = [
  {
    id: 'gateway',
    label: 'Gateway',
    status: 'live',
    intro: 'Das Programm auf deinem Server: prüft jede Anfrage, bevor sie deine Website erreicht, mit Dashboard und Server-Check. Braucht keine Labs und kein Konto.',
    docs: ['gateway/00-installieren', 'gateway/01-funktionen', 'gateway/02-betrieb', 'gateway/03-cluster', 'concept/25-zugriffsregeln'],
    links: [
      { to: '/doku/gateway/00-installieren', label: 'Gateway installieren', description: 'Installieren, 14 Tage beobachten, einschalten. Auch auf alten Servern.' },
    ],
  },
  {
    id: 'labs',
    label: 'Lab-Server',
    status: 'planned',
    intro: 'Unabhängige Labs bündeln Signale vieler Gateways, schlagen Regeln vor und geben sie erst frei, wenn mehrere Betreiber zustimmen. Im Testlabor erprobt, noch nicht im Betrieb.',
    docs: ['concept/21-architektur-v1', 'concept/18-manipulation-und-poisoning', 'concept/22-quellen-cve-ip-crowdsec'],
    links: [
      { to: '/netz#so-arbeitet-schild', label: 'Schild erklärt in 5 Minuten', description: 'Zwei Beispiele von der Erkennung bis zur Reaktion: ein Zero-Day in einem WordPress-Plugin und eine bekannte Lücke in einem Laravel-Package, beide mit virtuellem Patch.' },
    ],
  },
  {
    id: 'relays',
    label: 'Relays',
    status: 'planned',
    intro: 'Relays bringen Signale zu den Labs und verteilen signierte Regeln in Sekunden an alle Gateways. Ändern können sie nichts. Im Testlabor erprobt, noch nicht im Betrieb.',
    docs: ['concept/20-events-und-geschwindigkeit'],
  },
  {
    id: 'system',
    general: true,
    label: 'Gesamtsystem & Forschung',
    intro: 'Was alle Teile verbindet: Technik im Überblick, Sicherheitsarchitektur, Datenschutz, Produkt, stabile IDs, Stand der Technik und Forschung.',
    docs: ['concept/13-technik-kompakt', 'concept/04-technologie-und-security', 'concept/24-datenschutz', 'concept/03-produkt-und-ux', 'concept/12-schnell-check', 'concept/19-spezifikation', 'concept/16-stand-der-technik', 'concept/17-forschung-waf-und-ki-angriffe'],
  },
  {
    id: 'qualitaet',
    general: true,
    label: 'Qualität & Risiken',
    intro: 'Was offen ist, wie wir testen und wo uns Kritik am härtesten treffen würde.',
    docs: ['concept/11-offene-fragen-und-risiken', 'concept/14-testkonzept', 'concept/23-verifikation', 'concept/15-red-team-review'],
  },
  {
    id: 'strategie',
    general: true,
    label: 'Strategie & Organisation',
    intro: 'Zielgruppen, Trägerschaft, Arbeitsweise, Community, Pilot und Kommunikation.',
    docs: ['concept/02-zielgruppen-und-discovery', 'concept/05-governance-und-traegerschaft', 'concept/06-company-as-code-und-agents', 'concept/07-community-und-wissensaufbau', 'concept/09-pilot-und-betrieb', 'concept/10-kommunikation-und-pitch'],
  },
  {
    id: 'personas',
    general: true,
    label: 'Personas & User Stories',
    intro: 'Für wen wir bauen, was diese Menschen brauchen und woran wir merken, dass es funktioniert.',
    collection: 'stories',
  },
  {
    id: 'werte',
    general: true,
    label: 'Werte & Grundsätze',
    intro: 'Die Projektverfassung und warum es Deutschland-Schild gibt. Alles andere muss hierzu passen.',
    docs: ['concept/00-grundsaetze', 'concept/01-mission-und-wirkung'],
  },
  {
    id: 'marke',
    general: true,
    label: 'Marke',
    intro: 'Marke, Sprache und Gestaltung in einem Dokument.',
    collection: 'brand',
  },
]

// Repo-relative source file of a hub route, shown on every page for discussion via issue / pull request.
export function sourceFile(path: string): string | null {
  for (const c of Object.values(COLLECTIONS)) {
    if (path.startsWith(`${c.base}/`)) return `${c.dir}/${path.slice(c.base.length + 1)}.md`
  }
  return null
}

function route(collection: DocCollection, slug: string, hash = ''): string | null {
  const s = slug.toLowerCase()
  if (s === 'readme') return '/doku'
  if (!/^\d{2}-/.test(s)) return null
  if (collection === 'concept' && UNPUBLISHED_CONCEPT.includes(s)) return null
  return `${COLLECTIONS[collection].base}/${s}${hash}`
}

const DIRS: Record<string, DocCollection> = { gateway: 'gateway', concept: 'concept', brand: 'brand', stories: 'stories' }

// Docs link each other as relative .md files (works on GitHub). Map them to hub routes.
// Returns null when the target is not published on the site – the link then renders as plain text.
export function hubHref(href: string, collection: string): string | null {
  if (/^(https?:|mailto:|#)/i.test(href)) return href
  // Legacy absolute form.
  let m = href.match(/^\/docs\/concept\/([\w-]+)(#.*)?$/i)
  if (m) return route('concept', m[1]!, m[2])
  // Cross-folder links: ../gateway/xx.md, ../concept/xx.md, ../stories/xx.md, ../brand/xx.md (handbook, AGENTS.md, intern → null).
  m = href.match(/^\.\.\/(\w+)\/([\w-]+?)(?:\.md)?(#.*)?$/i)
  if (m) {
    const target = DIRS[m[1]!.toLowerCase()]
    return target ? route(target, m[2]!, m[3]) : null
  }
  // Same-folder links: xx.md
  m = href.match(/^(?:\.\/)?([\w-]+?)\.md(#.*)?$/i) ?? href.match(/^(?:\.\/)?(\d{2}-[\w-]+?)(#.*)?$/i)
  if (m) {
    // Image credits stay a repo document (docs/brand/bildnachweise.md, not published): plain text on the site.
    if (m[1]!.toLowerCase() === 'bildnachweise') return null
    return collection in COLLECTIONS ? route(collection as DocCollection, m[1]!, m[2]) : null
  }
  if (href.startsWith('/') && !href.startsWith('/docs/')) return href
  return null
}

// Old /handbuch/** URLs → new /doku routes (pages/handbuch/[...path].vue). The user handbook was removed.
export function legacyHubRoute(path: string): string {
  const p = path.replace(/\/+$/, '').toLowerCase()
  let m = p.match(/^\/handbuch\/personas\/([\w-]+)$/)
  if (m) return `/doku/personas/${m[1]}`
  m = p.match(/^\/handbuch\/spec\/([\w-]+)$/)
  if (m) return route('concept', m[1]!) ?? '/doku'
  return '/doku'
}
