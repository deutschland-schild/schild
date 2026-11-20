import type { CrawlerAction, CrawlerCatalogueEntry, CrawlerCategory, CrawlerPolicy, CrawlerPolicyInput } from '@/api/crawlers'
import type { BotOverview } from '@/api/requests'
import { formatNumber } from '@schild/ui'
import { botCategoryLabel } from './requests'

/**
 * Copy of the KI-Crawler page (D57, MVP-29). German, du-form, calm; labels name the mechanism (the User-Agent,
 * the published addresses), never an unqualified "geschützt" or "sicher". Humanizer pass applied.
 */
export const CRAWLERS_COPY = {
  title: 'KI-Crawler',
  lead: 'Hier legst du fest, welche Crawler diese Website abrufen dürfen.',
  scope: 'Das gilt nur für Crawler, die sich im User-Agent mit Namen melden. Deine robots.txt ändert Schild dabei nicht.',
  preset: 'KI-Training blocken',
  presetExplain: 'Blockt die Crawler der Kategorie KI-Training aus der Bot-Liste, also die, die Inhalte für das Training von KI-Modellen sammeln. Alle anderen Kategorien sind danach erlaubt, Regeln für einzelne Crawler fallen weg.',
  presetActive: 'KI-Training ist geblockt, alle anderen Kategorien sind erlaubt.',
  presetBlocked: 'KI-Training ist geblockt.',
  presetUndo: 'KI-Training wieder erlauben',
  impersonators: 'Falsche Crawler blocken',
  impersonatorsExplain: 'Anfragen, die sich als Crawler mit veröffentlichten Adressen ausgeben, aber von anderen Adressen kommen.',
  rangesStale: 'Adressbereiche veraltet: Die Adresslisten der Betreiber sind älter als 30 Tage. Bis neue Listen da sind, erkennt Schild keine falschen Crawler.',
  rangesOff: 'Die Prüfung der Adressbereiche ist aus (bots.verify.ranges). Schild erkennt so keine falschen Crawler.',
  categories: 'Kategorien',
  categoriesLead: 'Eine Regel für einen einzelnen Crawler geht der Regel seiner Kategorie vor.',
  allow: 'Erlauben',
  block: 'Blocken',
  inherit: 'Wie Kategorie',
  allowed: 'erlaubt',
  blocked: 'geblockt',
  observe: 'Testprofil: Schild blockt gerade keinen Crawler. Es zählt nur, was es blockiert hätte.',
  ownIps: 'Adressen aus „Eigene IPs“ blockt eine Crawler-Regel nie.',
  window: 'Zahlen der letzten 24 Stunden aus dem Zugriffsprotokoll.',
  statsMissing: 'Die Zahlen pro Crawler lassen sich gerade nicht laden. Die Regeln kannst du trotzdem ändern.',
  noCrawlers: 'Die Bot-Liste kennt in dieser Kategorie keine Crawler.',
  notBehindSchild: 'Nicht jede Anfrage dieser Website läuft durch Schild. Eine Crawler-Regel würde nicht überall greifen. Prüf die Caddyfile.',
  saved: 'Gespeichert',
  failed: 'Das hat nicht geklappt',
} as const

/** The eleven catalogue categories in the order of the page (likely_automated and likely_browser are no crawlers). */
export const CRAWLER_CATEGORIES: readonly CrawlerCategory[] = [
  'ai_training', 'ai_search', 'ai_assistant', 'search_engine', 'preview_social', 'feed_reader',
  'monitoring', 'seo_tool', 'archive_research', 'security_scanner', 'tool_library',
]

export type CrawlerRule = CrawlerAction | 'inherit'

export const ACTION_LABEL: Record<CrawlerAction, string> = { allow: CRAWLERS_COPY.allowed, block: CRAWLERS_COPY.blocked }

export const emptyPolicy = (): CrawlerPolicy => ({ categories: {}, bots: {}, impersonators: 'allow' })

/** The rule of a category; absent means allow. */
export function categoryAction(p: CrawlerPolicy, c: CrawlerCategory): CrawlerAction {
  return p.categories[c] ?? 'allow'
}

/** The own rule of a crawler, or 'inherit' when it follows its category. */
export function ownRule(p: CrawlerPolicy, id: string): CrawlerRule {
  return p.bots[id] ?? 'inherit'
}

/**
 * What applies to a crawler that names itself: its own rule, else its category, else allow.
 * likely_automated and likely_browser are no crawlers: always allow.
 */
export function effectiveAction(p: CrawlerPolicy, c: { id: string, category: string }): CrawlerAction {
  if (!isCrawlerCategory(c.category)) return 'allow'
  return p.bots[c.id] ?? categoryAction(p, c.category)
}

export function isCrawlerCategory(c: string): c is CrawlerCategory {
  return (CRAWLER_CATEGORIES as readonly string[]).includes(c)
}

/** The policy with a category set. Allow is the default, so it is stored as an absent key. */
export function withCategory(p: CrawlerPolicy, c: CrawlerCategory, a: CrawlerAction): CrawlerPolicy {
  const categories = { ...p.categories }
  if (a === 'block') categories[c] = 'block'
  else delete categories[c]
  return { ...p, categories }
}

/** The policy with the own rule of a crawler set, or dropped with 'inherit'. */
export function withBot(p: CrawlerPolicy, id: string, r: CrawlerRule): CrawlerPolicy {
  const bots = { ...p.bots }
  if (r === 'inherit') delete bots[id]
  else bots[id] = r
  return { ...p, bots }
}

export function withImpersonators(p: CrawlerPolicy, a: CrawlerAction): CrawlerPolicy {
  return { ...p, impersonators: a }
}

/** The PUT body for a whole policy. */
export function policyInput(p: CrawlerPolicy): CrawlerPolicyInput {
  return { categories: { ...p.categories }, bots: { ...p.bots }, impersonators: p.impersonators }
}

/** The PUT body of the preset: it keeps the stored impersonator switch. */
export function presetInput(): CrawlerPolicyInput {
  return { preset: 'block_ai_training' }
}

/** What the preset leaves behind, as the gateway applies it (D57): only ai_training blocked, no bot rules. */
export function applyPreset(p: CrawlerPolicy): CrawlerPolicy {
  return { categories: { ai_training: 'block' }, bots: {}, impersonators: p.impersonators }
}

/** True when the policy is what the preset sets (explicit allows count as allow). */
export function isPresetApplied(p: CrawlerPolicy): boolean {
  if (Object.keys(p.bots).length) return false
  return CRAWLER_CATEGORIES.every(c => categoryAction(p, c) === (c === 'ai_training' ? 'block' : 'allow'))
}

export type BotStats = BotOverview['bots'][number]

/**
 * Why the impersonator switch would do nothing (measurement 1): the check of the address ranges is off, or
 * every range snapshot is older than 30 days. null when the check works for at least one operator.
 */
export function rangesNote(o: Pick<BotOverview, 'verification' | 'ranges'> | undefined): string | null {
  if (!o) return null
  if (!o.verification.ranges) return CRAWLERS_COPY.rangesOff
  if (o.ranges.length && o.ranges.every(r => r.stale)) return CRAWLERS_COPY.rangesStale
  return null
}

/** "12" blocked, "hätte 3 blockiert" in observe mode or for an allowlisted address, "–" without either. */
export function blockedText(b: Pick<BotStats, 'blocked' | 'would_block'> | undefined): string {
  const blocked = b?.blocked ?? 0
  const would = b?.would_block ?? 0
  const parts: string[] = []
  if (blocked) parts.push(formatNumber(blocked))
  if (would) parts.push(`hätte ${formatNumber(would)} blockiert`)
  return parts.length ? parts.join(', ') : '–'
}

/** "3 Crawler, 1 mit eigener Regel" for the collapsed category row. */
export function categorySummary(p: CrawlerPolicy, crawlers: readonly Pick<CrawlerCatalogueEntry, 'id'>[]): string {
  const own = crawlers.filter(c => p.bots[c.id]).length
  return `${crawlers.length} Crawler${own ? `, ${own} mit eigener Regel` : ''}`
}

/** The toast line of a change: "KI-Training: Blocken", "GPTBot: Wie Kategorie". */
export function changeText(what: { category: CrawlerCategory } | { bot: string, name: string } | { impersonators: CrawlerAction }, r: CrawlerRule): string {
  const label = r === 'inherit' ? CRAWLERS_COPY.inherit : r === 'allow' ? CRAWLERS_COPY.allow : CRAWLERS_COPY.block
  if ('category' in what) return `${botCategoryLabel(what.category)}: ${label}`
  if ('bot' in what) return `${what.name}: ${label}`
  return `${CRAWLERS_COPY.impersonators}: ${what.impersonators === 'block' ? 'an' : 'aus'}`
}
