import type { FilterChip, StatusTone } from '@schild/ui'
import type { LocationQuery } from 'vue-router'
import type { AuditActor, AuditClass, AuditEntry, AuditField, AuditHidden, AuditQuery, AuditWay } from '@/api/audit'
import type { RuleRepositoryId } from '@/api/types'
import { INCIDENT_RE } from './incident'
import { BEHAVIOUR_RULES_PATH, GROUP_PATH, websitePath } from './nav'
import { REPOSITORY_IDS, RULES_PATH, rulesPath } from './rules'

/**
 * Wording and links of the audit log (MVP-36, contracts/audit.md): German names for every action, class
 * and way of contracts/audit-actions.json, the filters of the page in the URL, and where a name in an
 * entry leads. Reasons, labels and names in an entry are text from outside: this file only passes them on
 * as strings, the components show them as text. Humanizer pass applied.
 */

export const AUDIT_PATH = '/settings/audit'

export const AUDIT_COPY = {
  title: 'Protokoll',
  lead: 'Wer was geändert hat, auf welchem Weg, und wie es vorher war.',
  keep: 'Schild behält Änderungen ein Jahr. Mit audit.keep_days in schild.yaml stellst du eine andere Frist ein. Anmeldungen und abgelehnte Aufrufe bleiben höchstens 90 Tage.',
  addresses: 'Ein Eintrag behält die IP-Adressen und Namen, die in ihm stehen, bis Schild ihn löscht. Die Fristen für Ereignisse und volle IP-Adressen gelten für das Protokoll nicht.',
  emptyTitle: 'Noch keine Einträge',
  emptyText: 'Sobald jemand etwas ändert oder sich anmeldet, steht es hier.',
  emptyFilteredTitle: 'Kein Eintrag passt',
  emptyFilteredText: 'Nimm einen Filter heraus. Einträge, die älter als die Aufbewahrung sind, hat Schild gelöscht.',
  loadFailed: 'Das Protokoll lässt sich gerade nicht laden',
  older: 'Älter als die Aufbewahrung des Protokolls',
  noChange: 'Im Protokoll steht dazu keine Änderung. Entweder gab es keine, oder sie ist älter als die Aufbewahrung des Protokolls.',
  lastChanged: 'Zuletzt geändert von',
  history: 'Alle Einträge dazu',
  objectGone: 'Gibt es nicht mehr. Die Einträge dazu bleiben.',
  eventGone: 'Das Ereignis ist nicht mehr gespeichert. Es war älter als die Aufbewahrung der Ereignisse.',
  incidentGone: 'Den Vorfall gibt es nicht mehr.',
  onHost: 'Auf dem Server selbst, ohne Adresse',
  noName: 'Ohne Namen. Bei einer abgelehnten Anmeldung zeichnet Schild nicht auf, was eingetippt wurde.',
  cliHint: 'So hat der Befehl das Konto gesehen. Ein Hinweis, kein Beweis.',
} as const

// ------------------------------------------------------------------ names

/** Every action of contracts/audit-actions.json in words (test: no action of the catalogue is missing). */
export const ACTIONS: Record<string, string> = {
  'access_lock.set': 'Zugriffsschutz eingerichtet',
  'access_lock.remove': 'Zugriffsschutz entfernt',
  'maintenance.set': 'Wartungsseite geschaltet',
  'crawlers.set': 'Vorgaben für KI-Crawler geändert',
  'human_check.set': 'Browser-Prüfung eingestellt',
  'human_check.remove': 'Browser-Prüfung entfernt',
  'block.set': 'Adresse gesperrt',
  'block.lift': 'Sperre aufgehoben',
  'client.release': 'Adresse wieder durchgelassen',
  'wave.end': 'Welle beendet',
  'allowlist.add': 'Eigene IP eingetragen',
  'allowlist.remove': 'Eigene IP entfernt',
  'rule_exception.set': 'Ausnahme für Regeln gesetzt',
  'rule_exception.remove': 'Ausnahme für Regeln entfernt',
  'rule.set': 'Regel ein- oder ausgeschaltet',
  'rule_repository.set': 'Regelquelle eingestellt',
  'rule_repository.sync': 'Regelquelle aktualisiert',
  'rule_repository.reset': 'Regelquelle zurückgesetzt',
  'behaviour.set': 'Szenarien eingestellt',
  'distributed.set': 'Erkennung von Wellen eingestellt',
  'rate_limit.add': 'Limit angelegt',
  'rate_limit.update': 'Limit geändert',
  'rate_limit.remove': 'Limit entfernt',
  'settings.set': 'Aufbewahrung geändert',
  'agent_api.set': 'Agent-API umgeschaltet',
  'host_finding.accept': 'Befund akzeptiert',
  'host_finding.reopen': 'Befund wieder geöffnet',
  'config.apply': 'Konfiguration geändert',
  'cluster.join': 'Server ist dem Cluster beigetreten',
  'cluster.remove': 'Server aus dem Cluster entfernt',
  'cluster.drain': 'Server aus dem Betrieb genommen',
  'audit.start': 'Neues Protokoll begonnen',
  'password.setup': 'Passwort eingerichtet',
  'password.change': 'Passwort geändert',
  'password.setup_code_shown': 'Einrichtungscode angezeigt',
  'password.reset': 'Dashboard-Zugang zurückgesetzt',
  'token.add': 'Token angelegt',
  'token.revoke': 'Token widerrufen',
  'token.expire': 'Token abgelaufen',
  'host_agent.enrol': 'Anmeldung eines Agenten begonnen',
  'host_agent.confirm': 'Agent bestätigt',
  'host_agent.revoke': 'Agent entzogen',
  'privacy.export': 'Daten zu einer Adresse exportiert',
  'privacy.erase': 'Daten zu einer Adresse gelöscht',
  'incident.export': 'Vorfall gesichert',
  'session.start': 'Angemeldet',
  'session.end': 'Abgemeldet',
  'agent_api.call': 'Aufruf der Agent-API',
}

/** What a refused call tried, where the plain name would read as if it had happened. */
const REFUSED_ACTIONS: Record<string, string> = {
  'session.start': 'Anmeldung abgelehnt',
  'agent_api.call': 'Aufruf der Agent-API abgelehnt',
}

/** An action a later build of another node knows reads as its raw name. */
export function actionLabel(action: string): string {
  return ACTIONS[action] ?? action
}

/** The headline of an entry: the action, or for a refused call what was tried. */
export function entryTitle(e: Pick<AuditEntry, 'action' | 'result'>): string {
  if (e.result !== 'refused') return actionLabel(e.action)
  return REFUSED_ACTIONS[e.action] ?? `Abgelehnt: ${actionLabel(e.action)}`
}

export const ACTION_OPTIONS = Object.entries(ACTIONS).map(([value, label]) => ({ value, label })).sort((a, b) => a.label.localeCompare(b.label, 'de'))

export const CLASSES: Record<AuditClass, { label: string, tone: StatusTone }> = {
  change: { label: 'Änderung', tone: 'neutral' },
  credential: { label: 'Zugangsdaten', tone: 'info' },
  privacy: { label: 'Datenschutz', tone: 'info' },
  access: { label: 'Anmeldung', tone: 'neutral' },
  refused: { label: 'Abgelehnt', tone: 'warning' },
}
export const CLASS_ORDER: AuditClass[] = ['change', 'credential', 'privacy', 'access', 'refused']

export const WAYS: Record<AuditWay, string> = {
  dashboard: 'Dashboard',
  agent: 'Agent-API',
  integration: 'Portal',
  cli: 'Kommandozeile',
  config: 'Konfigurationsdatei',
  system: 'Schild selbst',
}
export const WAY_ORDER = Object.keys(WAYS) as AuditWay[]

/** `dashboard:addAllowlistEntry` -> the way and what was called there. */
export function splitOperation(operation: string): { way: string, name: string } {
  const at = operation.indexOf(':')
  return at < 0 ? { way: operation, name: '' } : { way: operation.slice(0, at), name: operation.slice(at + 1) }
}

export function wayLabel(way: string): string {
  return (WAYS as Record<string, string>)[way] ?? way
}

export const SUBJECTS: Record<string, string> = {
  website: 'Website',
  block: 'Sperre',
  client: 'Adresse',
  wave: 'Welle',
  allowlist_entry: 'Eigene IP',
  rule_exception: 'Ausnahme',
  rule: 'Regel',
  rule_repository: 'Regelquelle',
  setting: 'Einstellung',
  rate_limit: 'Limit',
  host_finding: 'Befund',
  config: 'Konfiguration',
  node: 'Server',
  audit: 'Protokoll',
  user: 'Benutzer',
  token: 'Token',
  host_agent: 'Agent',
  address: 'Adresse',
  incident: 'Vorfall',
  agent_api: 'Agent-API',
}
export const SUBJECT_OPTIONS = Object.entries(SUBJECTS).map(([value, label]) => ({ value, label })).sort((a, b) => a.label.localeCompare(b.label, 'de'))

export function subjectLabel(kind: string): string {
  return SUBJECTS[kind] ?? kind
}

/** Why an entry names a changed field without its values. */
export const HIDDEN: Record<AuditHidden, string> = {
  secret: 'Geheimer Wert. Schild zeichnet ihn nie auf.',
  unlisted: 'Geändert. Den Wert dieses Feldes zeichnet Schild nicht auf.',
  list: 'Liste geändert. Den Inhalt zeichnet Schild nicht auf.',
  order: 'Nur die Reihenfolge hat sich geändert.',
  size: 'Der Wert war zu groß für den Eintrag.',
  operator: 'Vom Betreiber gesetzt. Der Wert ist hier nicht sichtbar.',
}

export function hiddenText(reason: string): string {
  return (HIDDEN as Record<string, string>)[reason] ?? `Wert nicht aufgezeichnet (${reason}).`
}

export const FIELD_CHANGE: Record<AuditField['change'], string> = {
  added: 'neu',
  changed: 'geändert',
  removed: 'entfernt',
}

/** A recorded value as text: booleans in words, everything else as written. */
export function valueText(v: string | number | boolean): string {
  if (typeof v === 'boolean') return v ? 'ja' : 'nein'
  return String(v)
}

/** "12 Versuche" of a gathered refused entry. */
export function countText(count: number): string {
  return count === 1 ? '1 Versuch' : `${new Intl.NumberFormat('de-DE').format(count)} Versuche`
}

/** "3 weitere Felder …" for more_fields. */
export function moreFieldsText(n: number): string {
  return n === 1
    ? 'Ein weiteres Feld hat sich geändert. Der Eintrag nennt es nicht einzeln.'
    : `${new Intl.NumberFormat('de-DE').format(n)} weitere Felder haben sich geändert. Der Eintrag nennt sie nicht einzeln.`
}

// ------------------------------------------------------------------ who

/** The short name of who did it, for the list and for "Zuletzt geändert von …". Names are text from outside. */
export function actorName(a: AuditActor): string {
  switch (a.kind) {
    case 'dashboard': return a.user ?? 'Unbekannt'
    case 'agent': return a.label ?? a.id ?? 'Unbekanntes Token'
    case 'integration': return a.label ?? a.id ?? 'Portal'
    case 'cli': return a.account ?? 'Kommandozeile'
    case 'config': return WAYS.config
    case 'system': return WAYS.system
    default: return (a as { kind: string }).kind
  }
}

/** What kind of actor that is, next to the name: "Dashboard", "Agent mit Token", … */
export function actorKind(a: AuditActor): string {
  switch (a.kind) {
    case 'dashboard': return 'im Dashboard'
    case 'agent': return 'Agent mit Token'
    case 'integration': return 'Portal'
    case 'cli': return 'Konto auf dem Server'
    case 'config': return 'schild.yaml oder Caddyfile'
    case 'system': return 'ohne Zutun einer Person'
    default: return ''
  }
}

/** The token or portal key of an entry, the value of the filter `actor`. */
export function actorId(a: AuditActor): string | null {
  return (a.kind === 'agent' || a.kind === 'integration') && a.id ? a.id : null
}

/** The session of an entry, the value of the filter `session`. */
export function actorSession(a: AuditActor): string | null {
  return (a.kind === 'dashboard' || a.kind === 'integration') && a.session ? a.session : null
}

// ------------------------------------------------------------------ filters in the URL

/** The filters of listAudit as the URL of the page carries them; from and to are days (YYYY-MM-DD). */
export const AUDIT_FIELDS = ['website', 'class', 'action', 'way', 'actor', 'subject', 'subject_id', 'session', 'event', 'incident', 'from', 'to'] as const
export type AuditField_ = typeof AUDIT_FIELDS[number]
export type AuditFilters = Partial<Record<AuditField_, string>>

const PATTERNS: Record<AuditField_, RegExp> = {
  website: /^[a-z0-9_][a-z0-9_.-]{0,252}$/,
  class: /^(change|credential|privacy|access|refused)$/,
  action: /^[a-z][a-z_]*\.[a-z][a-z_]*$/,
  way: /^(dashboard|agent|integration|cli|config|system)$/,
  actor: /^(tok|pk)_[0-9a-f]{12}$/,
  subject: /^[a-z][a-z_]{0,31}$/,
  subject_id: /^.{1,253}$/,
  session: /^[0-9a-f]{8}$/,
  event: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  incident: INCIDENT_RE,
  from: /^\d{4}-\d{2}-\d{2}$/,
  to: /^\d{4}-\d{2}-\d{2}$/,
}

/** Whether a value fits its filter; the page sends nothing the API would answer with 400. */
export function validFilter(field: AuditField_, value: string): boolean {
  return PATTERNS[field].test(value)
}

const first = (v: LocationQuery[string]) => (Array.isArray(v) ? v[0] : v) ?? undefined

export function parseAuditFilters(q: LocationQuery): AuditFilters {
  const out: AuditFilters = {}
  for (const k of AUDIT_FIELDS) {
    let v = first(q[k])?.trim()
    if (!v) continue
    if (k === 'incident') v = v.toUpperCase()
    if (k === 'event' || k === 'session' || k === 'actor') v = v.toLowerCase()
    if (validFilter(k, v)) out[k] = v
  }
  // An id alone names nothing: it belongs to a kind.
  if (!out.subject) delete out.subject_id
  return out
}

/** Start of a local day as RFC 3339 UTC; `plus` days later for the end of a range (to is exclusive). */
export function dayIso(day: string, plus = 0): string | undefined {
  const [y, m, d] = day.split('-').map(Number)
  const t = new Date(y!, m! - 1, d! + plus).getTime()
  return Number.isNaN(t) ? undefined : new Date(t).toISOString().replace('.000Z', 'Z')
}

export function toAuditQuery(f: AuditFilters): AuditQuery {
  const q: AuditQuery = {}
  if (f.website) q.website = f.website
  if (f.class) q.class = f.class as AuditClass
  if (f.action) q.action = f.action
  if (f.way) q.way = f.way as AuditWay
  if (f.actor) q.actor = f.actor
  if (f.subject) q.subject = f.subject
  if (f.subject && f.subject_id) q.subject_id = f.subject_id
  if (f.session) q.session = f.session
  if (f.event) q.event = f.event
  if (f.incident) q.incident = f.incident
  const from = f.from ? dayIso(f.from) : undefined
  // "Bis" is the last day shown: the API takes the first instant after it.
  const to = f.to ? dayIso(f.to, 1) : undefined
  if (from) q.from = from
  if (to) q.to = to
  return q
}

const FILTER_LABELS: Record<AuditField_, string> = {
  website: 'Website',
  class: 'Art',
  action: 'Aktion',
  way: 'Weg',
  actor: 'Token',
  subject: 'Objekt',
  subject_id: 'Objekt',
  session: 'Sitzung',
  event: 'Ereignis',
  incident: 'Vorfall',
  from: 'Von',
  to: 'Bis',
}

const dayText = (day: string) => day.split('-').reverse().join('.')

/** The active filters as chips. `names` gives a website its name and a token its label. */
export function auditChips(f: AuditFilters, names: { website?: (id: string) => string, token?: (id: string) => string } = {}): FilterChip[] {
  const chips: FilterChip[] = []
  const add = (key: AuditField_, value: string) => chips.push({ key, label: FILTER_LABELS[key], value })
  if (f.website) add('website', names.website?.(f.website) ?? f.website)
  if (f.class) add('class', CLASSES[f.class as AuditClass]?.label ?? f.class)
  if (f.action) add('action', actionLabel(f.action))
  if (f.way) add('way', wayLabel(f.way))
  if (f.actor) add('actor', names.token?.(f.actor) ?? f.actor)
  if (f.subject) add('subject', f.subject_id ? `${subjectLabel(f.subject)} ${f.subject_id}` : subjectLabel(f.subject))
  if (f.session) add('session', f.session)
  if (f.event) add('event', f.event.slice(0, 8))
  if (f.incident) add('incident', f.incident)
  if (f.from) add('from', dayText(f.from))
  if (f.to) add('to', dayText(f.to))
  return chips
}

/** A link to the page with these filters, and with `entry` the entry that opens there. */
export function auditLink(filters: AuditFilters, entry?: string): { path: string, query: Record<string, string> } {
  const query: Record<string, string> = {}
  for (const k of AUDIT_FIELDS) {
    const v = filters[k]
    if (v) query[k] = v
  }
  if (entry) query.entry = entry
  return { path: AUDIT_PATH, query }
}

/** Every entry of the object an entry is about; null when the entry names no kind worth a history. */
export function historyFilters(e: Pick<AuditEntry, 'subject'>): AuditFilters {
  return { subject: e.subject.kind, ...(e.subject.id ? { subject_id: e.subject.id } : {}) }
}

/** The filters of the API query a component asked with, back as filters of the page. */
export function filtersOfQuery(q: AuditQuery): AuditFilters {
  const out: AuditFilters = {}
  for (const k of AUDIT_FIELDS) {
    if (k === 'from' || k === 'to') continue
    const v = (q as Record<string, unknown>)[k]
    if (typeof v === 'string' && v) out[k] = v
  }
  return out
}

// ------------------------------------------------------------------ where an object lives

export interface ObjectLink { to: string, label: string }

const SETTING_PAGES: Record<string, ObjectLink> = {
  'settings.set': { to: '/settings#retention', label: 'Zur Aufbewahrung' },
  'agent_api.set': { to: '/settings#agent-api', label: 'Zur Agent-API' },
  'behaviour.set': { to: BEHAVIOUR_RULES_PATH, label: 'Zu den Szenarien' },
  'distributed.set': { to: `${BEHAVIOUR_RULES_PATH}?view=detectors`, label: 'Zur Erkennung von Wellen' },
}

/**
 * The page on which the object of an entry is shown and changed. Whether the object still exists the
 * panel asks the API (AuditEntryPanel); this only knows the way.
 */
export function objectLink(e: Pick<AuditEntry, 'action' | 'subject' | 'website'>): ObjectLink | null {
  const id = e.subject.id
  switch (e.subject.kind) {
    case 'website': {
      const site = id ?? e.website
      if (!site) return null
      if (e.action.startsWith('access_lock.') || e.action === 'maintenance.set') return { to: websitePath(site, 'access'), label: 'Zum Zugriffsschutz' }
      if (e.action === 'crawlers.set') return { to: websitePath(site, 'ai-crawlers'), label: 'Zu den KI-Crawlern' }
      return { to: websitePath(site), label: 'Zur Website' }
    }
    case 'allowlist_entry': return { to: '/own-ips', label: 'Zu den eigenen IPs' }
    case 'rule_exception': return { to: `${rulesPath('local')}?view=exceptions`, label: 'Zu den Ausnahmen' }
    case 'token': return { to: '/settings#agent-api', label: 'Zu den Tokens' }
    case 'agent_api': return { to: '/settings#agent-api', label: 'Zur Agent-API' }
    case 'setting': return SETTING_PAGES[e.action] ?? { to: '/settings', label: 'Zu den Einstellungen' }
    case 'block':
    case 'incident': return id && INCIDENT_RE.test(id) ? { to: `/incidents/${id}`, label: 'Zum Vorfall' } : null
    case 'rule_repository': return { to: id && (REPOSITORY_IDS as readonly string[]).includes(id) ? rulesPath(id as RuleRepositoryId) : RULES_PATH, label: 'Zur Regelquelle' }
    case 'rule': return { to: RULES_PATH, label: 'Zu den Regeln' }
    case 'rate_limit': return { to: `${BEHAVIOUR_RULES_PATH}?view=limits`, label: 'Zu den Limits' }
    case 'wave': return { to: `${BEHAVIOUR_RULES_PATH}?view=detectors`, label: 'Zu den Wellen' }
    case 'host_finding':
    case 'host_agent': return { to: '/server/check', label: 'Zum Server-Check' }
    case 'node': return { to: GROUP_PATH, label: 'Zum Cluster' }
    default: return null
  }
}

/** "Zuletzt geändert von admin": who, in the words that fit the kind of actor. */
export function lastChangedText(a: AuditActor): string {
  if (a.kind === 'config') return 'Zuletzt geändert über die Konfigurationsdatei'
  if (a.kind === 'cli' && !a.account) return 'Zuletzt geändert auf der Kommandozeile'
  return `${AUDIT_COPY.lastChanged} ${actorName(a)}`
}
