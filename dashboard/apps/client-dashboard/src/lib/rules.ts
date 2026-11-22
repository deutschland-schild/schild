import type { MetaItem, StatusTone } from '@schild/ui'
import type { Rule, RuleDecision, RuleEffect, RuleException, RuleRepository, RuleRepositoryId, RuleRepositoryState, RuleStatus } from '@/api/types'
import { formatNumber, formatRelative } from '@schild/ui'
import { HUB_LABEL, hubRuleText } from './crowdsec'
import { explainRule } from './explain'

/**
 * Rule repositories in the dashboard (D73): OWASP CRS, CrowdSec Hub and the operator's own rules. One
 * page each below /settings/rules, the URL segment is the repository id.
 */
export const RULES_PATH = '/settings/rules'
export const REPOSITORY_IDS: RuleRepositoryId[] = ['crs', 'crowdsec', 'local']

export const REPOSITORIES: Record<RuleRepositoryId, { name: string, nav?: string, one: string, lead: string, keywords: string[] }> = {
  crs: {
    name: 'OWASP CRS',
    one: 'OWASP CRS',
    lead: 'Das frei verfügbare Regelwerk der OWASP gegen die häufigsten Angriffsmuster. Es ist in Schild eingebaut und läuft lokal auf deinem Server.',
    keywords: ['crs', 'owasp', 'core rule set', 'grundregeln', 'paranoia', 'anomalie'],
  },
  crowdsec: {
    name: 'CrowdSec Hub',
    one: HUB_LABEL,
    lead: 'Öffentliche virtuelle Patches aus dem CrowdSec Hub gegen bekannte Lücken, MIT-Lizenz. Schild lädt sie ohne Konto und schickt keine Daten an CrowdSec.',
    keywords: ['crowdsec', 'hub', 'cve', 'virtuelle patches', 'freigeben', 'updates'],
  },
  local: {
    name: 'Eigene Regeln und Ausnahmen',
    // The sidebar has room for about 20 characters.
    nav: 'Eigene & Ausnahmen',
    one: 'Eigene Regel',
    lead: 'Was du selbst festlegst: Regeln aus deinen Dateien im Ordner rules.d auf diesem Server und Ausnahmen für einzelne Felder.',
    keywords: ['eigene regeln', 'ausnahmen', 'ausnahme', 'fehlalarm', 'false positive', 'rules.d', 'seclang', 'lokal'],
  },
}

/** The first tab of "Eigene Regeln und Ausnahmen": the rule files (rules.d), what its switch and counts are about. */
export const LOCAL_RULES = 'Eigene Regeln'

/** Page of a repository, with a rule open in its sheet. */
export function rulesPath(repository?: RuleRepositoryId, rule?: string): string {
  if (!repository) return RULES_PATH
  return `${RULES_PATH}/${repository}${rule ? `?rule=${encodeURIComponent(rule)}` : ''}`
}

// ------------------------------------------------------------------ the switch of a repository

export const REPOSITORY_STATES: Record<RuleRepositoryState, { label: string, explain: string }> = {
  off: { label: 'Aus', explain: 'Keine dieser Regeln läuft.' },
  detect: { label: 'Erkennen', explain: 'Die Regeln laufen und notieren Treffer. Gesperrt wird nichts.' },
  block: { label: 'Sperren', explain: 'Die Regeln sperren Treffer.' },
}

/** What the chosen state means for this repository. */
export function stateExplain(r: Pick<RuleRepository, 'id' | 'state' | 'crs'>): string {
  if (r.id === 'crowdsec' && r.state === 'off') return 'Keine dieser Regeln läuft, und Schild lädt keine neuen.'
  if (r.id === 'crs' && r.state === 'block')
    return `Jeder Treffer zählt Punkte. Ab ${r.crs?.inbound_anomaly_threshold ?? 5} Punkten sperrt Schild die Anfrage.`
  return REPOSITORY_STATES[r.state].explain
}

// ------------------------------------------------------------------ the values of the CRS (D101)

export const CRS_LEVELS = [
  { value: 1, label: 'Stufe 1 (ab Werk)' },
  { value: 2, label: 'Stufe 2' },
  { value: 3, label: 'Stufe 3' },
  { value: 4, label: 'Stufe 4' },
]

/** Points of one critical CRS hit: a threshold above it lets a request with a single such hit through. */
export const CRS_SINGLE_HIT = 5

export function crsSettingsText(level: number, threshold: number): string {
  return `Stufe ${level}, sperrt ab ${threshold} Punkten`
}

/** The dashboard set a value that differs from schild.yaml. */
export function crsSettingsChanged(c: NonNullable<RuleRepository['crs']>): { level: boolean, threshold: boolean } {
  return { level: c.paranoia_level !== c.config_paranoia_level, threshold: c.inbound_anomaly_threshold !== c.config_inbound_anomaly_threshold }
}

/**
 * What the repository does right now. The switch keeps showing what was chosen; this line says when the
 * test profile holds Sperren back, and how updates wait (D89: they settle, nobody approves them).
 */
export function effectText(r: Pick<RuleRepository, 'id' | 'state' | 'effect' | 'limited_by' | 'crowdsec'>): string | null {
  if (r.limited_by === 'gateway_observe')
    return 'Im Testprofil sperrt Schild nichts. Es notiert nur, was gesperrt worden wäre.'
  if (r.id !== 'crowdsec' || r.state === 'off') return null
  const hours = Math.round((r.crowdsec?.settling_s ?? 0) / 3600)
  if (r.state === 'block' && hours > 0)
    return `Neue oder geänderte Regeln aus dem Hub erkennen zuerst ${hours === 1 ? 'eine Stunde' : `${hours} Stunden`} lang nur und sperren danach von selbst.`
  return null
}

/** Short state of a repository for lists and the overview: what it does now. */
export const REPOSITORY_EFFECT: Record<RuleEffect, { label: string, tone: StatusTone }> = {
  block: { label: 'Sperrt', tone: 'signal' },
  would_block: { label: 'Würde sperren', tone: 'info' },
  detect: { label: 'Erkennt nur', tone: 'neutral' },
  off: { label: 'Aus', tone: 'neutral' },
}

/** Who set the switch, when it is not schild.yaml or the default. */
export function ownerText(r: Pick<RuleRepository, 'state_source' | 'state_set_at' | 'state_set_by'>): string | null {
  const when = r.state_set_at ? `, ${formatRelative(r.state_set_at)}` : ''
  if (r.state_source === 'agent') return `Über Agent „${r.state_set_by?.label ?? 'ohne Namen'}“ gesetzt${when}.`
  if (r.state_source === 'dashboard') return `Hier im Dashboard gesetzt${when}.`
  return null
}

const n = (count: number, one: string, many: string) => count === 1 ? `1 ${one}` : `${formatNumber(count)} ${many}`

/** Counts of a repository: rules, disabled, waiting, not loaded, last change. */
export function countFacts(r: Pick<RuleRepository, 'counts' | 'last_change_at' | 'state'>): MetaItem[] {
  const c = r.counts
  const out: MetaItem[] = [n(c.rules, 'Regel', 'Regeln')]
  if (c.settling) out.push(`${formatNumber(c.settling)} ${c.settling === 1 ? 'wartet' : 'warten'} noch`)
  if (c.disabled) out.push(`${formatNumber(c.disabled)} ausgeschaltet`)
  if (c.skipped) out.push(`${formatNumber(c.skipped)} nicht geladen`)
  if (r.last_change_at) out.push(`zuletzt geändert ${formatRelative(r.last_change_at)}`)
  return out
}

/** The text of a toast after the switch moved. */
export function switchedText(r: RuleRepository): string {
  return effectText(r) ?? stateExplain(r)
}

// ------------------------------------------------------------------ one rule

export const RULE_STATUS: Record<RuleStatus, { label: string, tone: StatusTone, explain: string }> = {
  active: { label: 'Aktiv', tone: 'signal', explain: 'Die Regel läuft.' },
  settling: { label: 'Wartet noch', tone: 'info', explain: 'Neu oder geändert: erkennt zuerst nur und sperrt nach der Wartezeit von selbst.' },
  disabled: { label: 'Ausgeschaltet', tone: 'neutral', explain: 'Die Regel läuft nicht.' },
}
/** Order of the status filter and of the table: what changes soon first. */
export const RULE_STATUS_ORDER: RuleStatus[] = ['settling', 'active', 'disabled']

export const DISABLED_BY: Record<NonNullable<Rule['disabled_by']>, string> = {
  config: 'in schild.yaml',
  dashboard: 'im Dashboard',
  agent: 'über einen Agenten',
}

export const RULE_EFFECT: Record<RuleEffect, { label: string, explain: string }> = {
  block: { label: 'Sperrt', explain: 'Ein Treffer sperrt die Anfrage.' },
  would_block: { label: 'Würde sperren', explain: 'Schild lässt die Anfrage durch und zeigt den Treffer als „Erkannt“.' },
  detect: { label: 'Erkennt', explain: 'Schild lässt die Anfrage durch und zeigt den Treffer als „Erkannt“.' },
  off: { label: 'Aus', explain: 'Die Regel läuft nicht.' },
}

/** Why the effect is lower than Sperren, in one short sentence. */
export function limitText(r: Pick<Rule, 'repository' | 'limited_by' | 'crowdsec'>): string | null {
  switch (r.limited_by) {
    case 'gateway_observe': return 'Im Testprofil sperrt Schild nichts.'
    case 'repository_detect': return `${REPOSITORIES[r.repository].name} steht auf „${REPOSITORY_STATES.detect.label}“.`
    case 'settling': return r.crowdsec?.settling_until ? `Sperrt ${formatRelative(r.crowdsec.settling_until)} von selbst.` : 'Sperrt nach der Wartezeit von selbst.'
    default: return null
  }
}
/** Title and explanation of a rule: a hub rule by its own label, a CRS or own rule by its id and message. */
export function ruleText(r: Pick<Rule, 'id' | 'msg' | 'crowdsec' | 'name'> & { repository?: Rule['repository'] }): { title: string, explain: string } {
  if (r.crowdsec) return hubRuleText(r.crowdsec)
  if (r.name && !r.msg) return { title: r.name, explain: '' }
  const e = explainRule(r.id, r.msg)
  // An own rule says what it does in its message; "Eigene Regel" is the page it is on.
  return r.repository === 'local' ? { title: e.title, explain: '' } : e
}

/** Meta line of a rule: CVE, version, 24 h hits, id. */
export function ruleMeta(r: Pick<Rule, 'id' | 'hits_24h' | 'crowdsec' | 'version' | 'repository' | 'paranoia_level'>, opts: { repository?: boolean } = {}): MetaItem[] {
  const items: MetaItem[] = []
  if (opts.repository) items.push(REPOSITORIES[r.repository]?.name ?? r.repository)
  if (r.crowdsec?.cves?.length) items.push(r.crowdsec.cves.join(', '))
  if (r.paranoia_level && r.paranoia_level > 1) items.push(`Strenge ${r.paranoia_level}`)
  items.push({ text: r.id, mono: true })
  return items
}

/** "ARGS:json.updates.body" as a person reads it: a form field, a cookie or a header, and its name. */
export function exceptionField(target: string): { kind: string, name: string } {
  const i = target.indexOf(':')
  const [collection, name] = i < 0 ? [target, ''] : [target.slice(0, i), target.slice(i + 1)]
  const kind = collection === 'ARGS' ? 'Feld' : collection === 'REQUEST_COOKIES' ? 'Cookie' : collection === 'REQUEST_HEADERS' ? 'Header' : collection
  return { kind, name: name.replace(/^json\./, '') }
}

/** What an exception can name (D84), as the form offers it. The prefix is the target without the name. */
/** Exceptions for the same field shown as one entry: the parts an agent had to cut it into (16 rules each). */
export interface ExceptionGroup {
  key: string
  first: RuleException
  parts: RuleException[]
  rules: string[]
  reasons: string[]
}

/**
 * One entry per website, page, field and repository. An exception holds at most 16 rules, so one field
 * left out for more rules arrives as several exceptions that differ in their rules only.
 */
export function groupExceptions(items: RuleException[]): ExceptionGroup[] {
  const groups = new Map<string, ExceptionGroup>()
  for (const x of items) {
    const key = [x.website, x.path, x.target, x.repository].join('\n')
    const g = groups.get(key) ?? { key, first: x, parts: [], rules: [], reasons: [] }
    g.parts.push(x)
    if (Date.parse(x.created) < Date.parse(g.first.created)) g.first = x
    for (const r of x.rules) if (!g.rules.includes(r)) g.rules.push(r)
    if (x.reason && !g.reasons.includes(x.reason)) g.reasons.push(x.reason)
    groups.set(key, g)
  }
  for (const g of groups.values()) g.rules.sort((a, b) => Number(a) - Number(b))
  return [...groups.values()]
}

/** The rules of an entry by what they look for ("Versuchter Dateizugriff": 930100, 930110), in rule order. */
export function exceptionRuleFamilies(g: Pick<ExceptionGroup, 'rules'>): { title: string, rules: string[] }[] {
  const out: { title: string, rules: string[] }[] = []
  for (const id of g.rules) {
    // A rule without a family of its own (a hub rule, an unknown number) has only its number as a title.
    const named = explainRule(id).title
    const title = named === `Regel ${id}` ? 'Weitere Regeln' : named
    const f = out.find(x => x.title === title)
    if (f) f.rules.push(id)
    else out.push({ title, rules: [id] })
  }
  return out
}

export const EXCEPTION_KINDS = {
  form: { label: 'Formularfeld', prefix: 'ARGS:', placeholder: 'nachricht', hint: 'Der Name des Felds, wie er im Formular oder in der Adresse nach dem ? steht.' },
  json: { label: 'JSON-Feld', prefix: 'ARGS:json.', placeholder: 'updates.body', hint: 'Der Weg zum Feld im JSON, mit Punkten getrennt. Ein Stern steht für einen Teil, etwa components.*.body.' },
  cookie: { label: 'Cookie', prefix: 'REQUEST_COOKIES:', placeholder: 'session', hint: 'Der Name des Cookies.' },
  header: { label: 'Header', prefix: 'REQUEST_HEADERS:', placeholder: 'X-Signature', hint: 'Der Name des Headers.' },
} as const
export type ExceptionKind = keyof typeof EXCEPTION_KINDS

export function exceptionTarget(kind: ExceptionKind, name: string): string {
  return EXCEPTION_KINDS[kind].prefix + name.trim()
}

/** The form's two fields for a target; an unknown target starts as an empty form field. */
export function parseExceptionTarget(target: string): { kind: ExceptionKind, name: string } {
  // json before form: both start with ARGS:
  for (const kind of ['json', 'form', 'cookie', 'header'] as const) {
    const { prefix } = EXCEPTION_KINDS[kind]
    if (target.startsWith(prefix)) return { kind, name: target.slice(prefix.length) }
  }
  return { kind: 'form', name: '' }
}

/** Where a rule matched ("ARGS_POST:message") as the target of an exception; '' when it names no single value. */
export function exceptionTargetOf(location: string | undefined): string {
  const i = location?.indexOf(':') ?? -1
  if (!location || i < 0 || !location.slice(i + 1)) return ''
  const base = location.slice(0, i)
  const name = location.slice(i + 1)
  if (base === 'ARGS' || base === 'ARGS_GET' || base === 'ARGS_POST') return `ARGS:${name}`
  if (base === 'REQUEST_COOKIES' || base === 'REQUEST_HEADERS') return `${base}:${name}`
  return ''
}

/** "942100, 942110 942100" as the list the API takes: split, without doubles. */
export function parseExceptionRules(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).filter(Boolean))]
}

/** File name for the download of a rule's text: "schild-crs-942100.conf". */
export function ruleFileName(r: Pick<Rule, 'id' | 'repository'>): string {
  return `schild-${r.repository}-${r.id.replace(/[^\w.-]+/g, '-')}.conf`
}

/** A decision on a rule in one line: "Ausgeschaltet im Dashboard, vor 2 Stunden". */
export function decisionText(d: RuleDecision): string {
  const by = d.by === 'agent' ? `über Agent „${d.token?.label ?? 'ohne Namen'}“` : d.by === 'config' ? 'in schild.yaml' : 'im Dashboard'
  const when = d.at ? `, ${formatRelative(d.at)}` : ''
  return `Ausgeschaltet ${by}${when}`
}
