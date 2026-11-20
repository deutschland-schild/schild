import type { StatusTone } from '@schild/ui'
import type { BehaviourBlock, BehaviourHit, BehaviourMode, BehaviourPreset, BehaviourReason, BehaviourSettings, LimitMode, RateLimit, RateLimitDryRun, ScenarioId, ScenarioSetting, ScenarioThresholds } from '@/api/behaviour'
import { formatNumber } from '@schild/ui'
import { explainRule } from './explain'
import { incidentBlockText, RULE_CATEGORIES, ruleCategoryOf } from './websites'

/**
 * Plain German for "Verhalten & Limits" (MVP-17): every hit as one sentence
 * ("37 falsche Anmeldungen in 2 Minuten an wp-login.php von 198.51.100.7"), what happened or
 * would have happened, thresholds in words, the block ladder and rate limits. Pure functions only.
 */

// ------------------------------------------------------------------ durations

const UNITS = [
  { s: 86400, one: 'Tag', many: 'Tagen', short: 'Tag', shortMany: 'Tage' },
  { s: 3600, one: 'Stunde', many: 'Stunden', short: 'Std', shortMany: 'Std' },
  { s: 60, one: 'Minute', many: 'Minuten', short: 'Min', shortMany: 'Min' },
  { s: 1, one: 'Sekunde', many: 'Sekunden', short: 'Sek', shortMany: 'Sek' },
] as const

function unitOf(seconds: number) {
  // The largest unit that divides the duration evenly: 90 s stays "90 Sekunden", 7200 s is "2 Stunden".
  // Days only up to a week of whole days; 24 h reads better as "24 Stunden".
  return UNITS.find(u => seconds % u.s === 0 && (u.s !== 86400 || seconds > 86400)) ?? UNITS[3]
}

/** "1 Minute", "2 Minuten", "30 Sekunden", "4 Stunden" (dative plural, as used after "in" and "pro"). */
export function formatDuration(seconds: number): string {
  const s = Math.max(1, Math.round(seconds))
  const u = unitOf(s)
  const n = s / u.s
  return `${formatNumber(n)} ${n === 1 ? u.one : u.many}`
}

/** "15 Min", "1 Std", "24 Std" for the block ladder. */
export function formatDurationShort(seconds: number): string {
  const s = Math.max(1, Math.round(seconds))
  const u = unitOf(s)
  const n = s / u.s
  return `${formatNumber(n)} ${n === 1 ? u.short : u.shortMany}`
}

/** "pro Minute", "pro 10 Minuten", "pro Stunde". */
export function formatPer(seconds: number): string {
  const s = Math.max(1, Math.round(seconds))
  const u = unitOf(s)
  const n = s / u.s
  return n === 1 ? `pro ${u.one}` : `pro ${formatNumber(n)} ${u.many}`
}

/** Seconds of a rate limit period ("30s", "1m", "10m", "1h"); NaN when malformed. */
export function perSeconds(per: string): number {
  const m = /^(\d+)([smh])$/.exec(per.trim())
  if (!m) return Number.NaN
  return Number(m[1]) * ({ s: 1, m: 60, h: 3600 } as const)[m[2] as 's' | 'm' | 'h']
}

/** Same pattern as RateLimitDraft.per in the contract: 1-59 s or min, 1-24 h. */
export function validPer(per: string): boolean {
  return /^(([1-9]|[1-5]\d)[sm]|([1-9]|1\d|2[0-4])h)$/.test(per)
}

const dayFmt = new Intl.DateTimeFormat('de-DE', { day: 'numeric', month: 'long' })
/** "3. November". */
export function formatDay(value: string | number | Date): string {
  return dayFmt.format(new Date(value))
}

const clockFmt = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit' })
/** "09:29" in the browser's time zone. */
export function formatClock(value: string | number | Date): string {
  return clockFmt.format(new Date(value))
}

function n(count: number, one: string, many: string) {
  return `${formatNumber(count)} ${count === 1 ? one : many}`
}

// ------------------------------------------------------------------ scenarios

export interface ScenarioMeta {
  name: string
  description: string
  /** What is counted, singular and plural ("falsche Anmeldung"). */
  one: string
  many: string
}

export const SCENARIOS: Record<ScenarioId, ScenarioMeta> = {
  login_bruteforce: {
    name: 'Passwort-Raten',
    description: 'Viele falsche Anmeldungen von einer Adresse an einer bekannten Anmeldeseite, etwa wp-login.php.',
    one: 'falsche Anmeldung',
    many: 'falsche Anmeldungen',
  },
  credential_stuffing: {
    name: 'Ausprobieren von Zugangsdaten',
    description: 'Viele verschiedene Benutzernamen an einer Anmeldeseite, oft aus geleakten Listen. Die Namen werden nicht gespeichert, Schild zählt nur, wie viele verschiedene es sind.',
    one: 'verschiedener Benutzername',
    many: 'verschiedene Benutzernamen',
  },
  path_probing: {
    name: 'Suche nach Schwachstellen',
    description: 'Viele Abrufe von Adressen, die es nicht gibt, etwa .env, .git oder alte Sicherungen.',
    one: 'nicht vorhandene Adresse',
    many: 'verschiedene nicht vorhandene Adressen',
  },
  aggressive_crawl: {
    name: 'Aggressives Abrufen',
    description: 'Ein Bot ruft viel mehr Seiten ab als sonst üblich. Echte Suchmaschinen werden nur gezählt.',
    one: 'Anfrage',
    many: 'Anfragen',
  },
  waf_repeat: {
    name: 'Wiederholte Angriffsversuche',
    description: 'Eine Adresse löst kurz hintereinander mehrere verschiedene Regeln des Filters aus.',
    one: 'WAF-Regel',
    many: 'verschiedene WAF-Regeln',
  },
}

export const SCENARIO_ORDER: ScenarioId[] = ['login_bruteforce', 'credential_stuffing', 'path_probing', 'aggressive_crawl', 'waf_repeat']

export const SCENARIO_MODES: Record<BehaviourMode, { label: string, explain: string }> = {
  off: { label: 'Aus', explain: 'Schild zählt nichts für dieses Szenario.' },
  observe: { label: 'Beobachten', explain: 'Schild zählt und zeigt, was es gesperrt hätte. Gesperrt wird nichts.' },
  block: { label: 'Sperren', explain: 'Wer auffällt, wird für eine Weile gesperrt und sieht die Sperrseite mit Vorfallnummer.' },
}

/** Why the recommendation of a scenario is not "Sperren" (D92). */
export const RECOMMENDED_WHY: Partial<Record<ScenarioId, string>> = {
  aggressive_crawl: 'Suchmaschinen-Tools, Monitoring und Büros hinter einer Adresse rufen auch schnell viele Seiten ab. Sieh dir erst die Zahlen an.',
}

/** What scenarios and limits do as a whole, in the words of the rule sources (D94). */
export type BehaviourEffect = 'block' | 'would_block' | 'observe' | 'off'
export const BEHAVIOUR_EFFECT: Record<BehaviourEffect, { label: string, tone: StatusTone }> = {
  block: { label: 'Sperrt', tone: 'signal' },
  would_block: { label: 'Würde sperren', tone: 'info' },
  observe: { label: 'Beobachtet nur', tone: 'neutral' },
  off: { label: 'Aus', tone: 'neutral' },
}

/** Whether the learning period still runs: until learning_until, or open-ended when the first start is unknown. */
export function isLearning(s: Pick<BehaviourSettings, 'learning_until'>, now = Date.now()): boolean {
  return s.learning_until === null || (!!s.learning_until && Date.parse(s.learning_until) > now)
}

/** The preset limits whose switch differs from its recommendation, in list order (D95). */
export function limitRecommendationChanges(limits: Pick<RateLimit, 'id' | 'label' | 'route' | 'mode' | 'recommended' | 'source'>[]): LimitChange[] {
  return limits
    .filter(l => l.source === 'preset' && l.recommended && l.mode !== l.recommended)
    .map(l => ({ id: l.id, mode: l.recommended!, name: l.label ?? l.route, from: LIMIT_MODES[l.mode].label, to: LIMIT_MODES[l.recommended!].label }))
}
export interface LimitChange { id: string, mode: LimitMode, name: string, from: string, to: string }

/**
 * The status of scenarios and limits as one word, and the line under it. "Sperrt" as soon as one scenario
 * blocks or one limit limits; "Würde sperren" while a scenario is set to it and the learning period or the
 * test profile holds it back. It is a status, there is no switch behind it (D89). Limits act from the
 * first day; without the list of limits (still loading) the line names the scenarios only. The wave
 * detectors count like the rest: one that answers makes it "Sperrt" (D97).
 */
export function behaviourStatus(s: Pick<BehaviourSettings, 'scenarios' | 'learning_until'>, limits: Pick<RateLimit, 'mode'>[] | null, now = Date.now(), detectors: { mode: string, effective_mode: string }[] | null = null): { effect: BehaviourEffect, facts: string[] } {
  const learning = isLearning(s, now)
  const set = s.scenarios.filter(x => x.mode === 'block')
  const acting = learning ? [] : set.filter(x => x.effective_mode === 'block')
  const limiting = (limits ?? []).filter(l => l.mode === 'block').length
  const answering = (detectors ?? []).filter(d => d.effective_mode === 'respond').length
  const wouldAnswer = (detectors ?? []).some(d => d.mode === 'respond')
  const watching = s.scenarios.some(x => x.mode !== 'off') || (limits ?? []).some(l => l.mode !== 'off') || (detectors ?? []).some(d => d.mode !== 'off')
  const effect: BehaviourEffect = acting.length || limiting || answering ? 'block' : set.length || wouldAnswer ? 'would_block' : watching ? 'observe' : 'off'
  const of = `${set.length} von ${s.scenarios.length} Szenarien`
  const scenarios = !set.length
    ? (s.scenarios.some(x => x.mode !== 'off') ? 'Kein Szenario sperrt, alle beobachten nur' : 'Alle Szenarien sind aus')
    : acting.length === set.length
      ? `${of} sperren`
      : learning
        ? `${of} stehen auf „Sperren“, Schild lernt noch${s.learning_until ? ` bis ${formatDay(s.learning_until)}` : ''} und beobachtet bis dahin nur`
        : `${of} stehen auf „Sperren“, im Testprofil beobachten sie nur`
  const limitFact = !limits ? [] : [limits.length ? `${limiting} von ${limits.length} Limits begrenzen` : 'Keine Limits']
  const waveFact = !detectors ? [] : [`${answering} von ${detectors.length} Wellen-Erkennungen reagieren`]
  return { effect, facts: [scenarios, ...limitFact, ...waveFact] }
}

/** One scenario switch that differs from its recommendation. */
export interface RecommendationChange { kind: 'scenario', id: ScenarioId, mode: BehaviourMode, name: string, from: string, to: string }

/** The scenario switches that differ from the recommendation, in display order (D92). Limits have their own list (D95). */
export function recommendationChanges(s: Pick<BehaviourSettings, 'scenarios'>): RecommendationChange[] {
  const out: RecommendationChange[] = []
  for (const id of SCENARIO_ORDER) {
    const sc = s.scenarios.find(x => x.id === id)
    if (sc && sc.mode !== sc.recommended)
      out.push({ kind: 'scenario', id, mode: sc.recommended, name: SCENARIOS[id].name, from: SCENARIO_MODES[sc.mode].label, to: SCENARIO_MODES[sc.recommended].label })
  }
  return out
}

export const LIMIT_MODES: Record<LimitMode, { label: string, tone: StatusTone }> = {
  off: { label: 'Aus', tone: 'neutral' },
  observe: { label: 'Beobachten', tone: 'info' },
  block: { label: 'Begrenzen', tone: 'signal' },
}

export const PRESETS: Record<BehaviourPreset, string> = {
  wordpress: 'WordPress',
  joomla: 'Joomla',
  drupal: 'Drupal',
  nextcloud: 'Nextcloud',
  typo3: 'TYPO3',
  laravel: 'Laravel',
  generic: 'Allgemein',
}

export const REASONS: Record<BehaviourReason, string> = {
  net_class: 'Mobilfunk-, CGNAT- oder Tor-Adresse: viele Menschen teilen sie, deshalb nie gesperrt',
  allowlisted: 'eigene Adresse, nie gesperrt',
  released: 'freigegeben',
  unverified_bot: 'gibt sich als Suchmaschine aus, wird nur gezählt',
  site_scope: 'über viele Adressen verteilt, keine einzelne Adresse zum Sperren',
  learning: 'Schild lernt noch den Normalzustand dieser Website, deshalb nur beobachtet',
}

// ------------------------------------------------------------------ addresses

function expandIpv6(ip: string): number[] | null {
  if (!ip.includes(':')) return null
  const [head, tail] = ip.split('::')
  const h = head ? head.split(':') : []
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : []
  if (tail === undefined && h.length !== 8) return null
  const groups = [...h, ...Array.from({ length: 8 - h.length - t.length }, () => '0'), ...t]
  const out = groups.map(g => Number.parseInt(g, 16))
  return out.length === 8 && out.every(x => Number.isInteger(x) && x >= 0 && x <= 0xFFFF) ? out : null
}

/** The client key as a network: "2001:db8:4:7::/64", "198.51.100.0/24"; null for single addresses. */
export function networkOf(ip: string, bits: number | undefined): string | null {
  if (!bits) return null
  if (ip.includes(':')) {
    if (bits >= 128) return null
    const g = expandIpv6(ip)
    if (!g || bits % 16 !== 0) return null
    const keep = g.slice(0, bits / 16)
    while (keep.length && keep[keep.length - 1] === 0) keep.pop()
    return `${keep.map(x => x.toString(16)).join(':')}::/${bits}`
  }
  if (bits >= 32) return null
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || bits % 8 !== 0) return null
  return `${parts.map((p, i) => (i < bits / 8 ? p : 0)).join('.')}/${bits}`
}

/** "von 198.51.100.7", "aus dem Netz 2001:db8:4:7::/64", "von vielen Adressen". */
export function whoText(hit: Pick<BehaviourHit, 'ip' | 'key_bits' | 'scope'>): string {
  if (hit.scope === 'site' || !hit.ip) return 'von vielen Adressen'
  const net = networkOf(hit.ip, hit.key_bits)
  return net ? `aus dem Netz ${net}` : `von ${hit.ip}`
}

/** "wp-login.php" for a single file at the root, otherwise the route as is. */
export function routeText(route: string): string {
  return /^\/[^/*]+\.[a-z0-9]+$/i.test(route) ? route.slice(1) : route
}

// ------------------------------------------------------------------ one hit in one sentence

export function hitTitle(hit: BehaviourHit): string {
  if (hit.kind === 'rate_limit') return hit.limit_label ?? 'Ratenbegrenzung'
  return hit.scenario ? SCENARIOS[hit.scenario].name : 'Verhalten'
}

/**
 * "37 falsche Anmeldungen in 2 Minuten an wp-login.php von 198.51.100.7",
 * "48 Anfragen über dem Limit von 10 pro Minute an /xmlrpc.php von 192.0.2.150".
 */
export function explainHit(hit: BehaviourHit): string {
  const who = whoText(hit)
  if (hit.kind === 'rate_limit') {
    const per = formatPer(hit.per_s ?? hit.window_s)
    const route = hit.route ? ` an ${hit.route}` : ''
    return `${n(hit.count, 'Anfrage', 'Anfragen')} über dem Limit von ${formatNumber(hit.threshold)} ${per}${route} ${who}`
  }
  const meta = hit.scenario ? SCENARIOS[hit.scenario] : { one: 'Ereignis', many: 'Ereignisse' }
  const what = n(hit.count, meta.one, meta.many)
  const within = `in ${formatDuration(hit.window_s)}`
  switch (hit.scenario) {
    case 'path_probing':
      return `${what} ${within} ${who}${hit.route ? `, z. B. ${hit.route}` : ''}`
    case 'waf_repeat':
      return `${what} ${within} ${who}`
    case 'aggressive_crawl':
      return `${what} ${within}${hit.host ? ` an ${hit.host}` : ''} ${who}, weit mehr als üblich`
    default:
      return `${what} ${within}${hit.route ? ` an ${routeText(hit.route)}` : ''} ${who}`
  }
}

export interface HitOutcome {
  label: string
  tone: StatusTone
  /** The reason in words, if the action stayed below the mode. */
  reason: string | null
}

/** What happened (or would have happened) with this hit. */
/**
 * The learning period of a fresh installation. Events carry reason `learning`
 * (v0.4 addendum); events written before it have no reason, so a scenario set
 * to block that only observed without another reason means the same.
 */
export const LEARNING_REASON = REASONS.learning

function learningHit(hit: BehaviourHit): boolean {
  return hit.kind !== 'rate_limit' && !hit.reason && !hit.released && hit.action === 'observe' && hit.mode === 'block'
}

export function hitOutcome(hit: BehaviourHit): HitOutcome {
  const reason = hit.reason ? REASONS[hit.reason] : (hit.released ? REASONS.released : (learningHit(hit) ? LEARNING_REASON : null))
  const limit = hit.kind === 'rate_limit'
  const level = hit.level ? ` (Stufe ${hit.level})` : ''
  if (hit.action === 'block') {
    const until = hit.until ? ` bis ${formatClock(hit.until)}` : ''
    // How long and why (D29 amendment): "Gesperrt für 7 Tage, weil Rechenzentrum und wiederholt, bis 14:02".
    const label = !limit && hit.duration_s && hit.level
      ? `Gesperrt für ${incidentBlockText({ duration_s: hit.duration_s, net_class: hit.geo?.net_class, level: hit.level })}${until ? `,${until}` : ''}`
      : `${limit ? 'Begrenzt' : 'Gesperrt'}${until}${level}`
    // One calm tone for a running block, as on the incident page (D36 re-measurement D: red here, amber there).
    return { label, tone: hitBlockRunning(hit) ? 'warning' : 'neutral', reason }
  }
  // Observe mode: "Erkannt" as everywhere else (initiator 2026-10-29), Probelauf says nothing was done.
  if (hit.would_action === 'block') return { label: 'Erkannt (Probelauf)', tone: 'warning', reason }
  return { label: 'Nur beobachtet', tone: 'info', reason }
}

/**
 * A timed block (BehaviourBlock) runs exactly while ended_at is absent (contracts v0.5, initiator 2026-10-29).
 * The gateway sets ended_at when it ran out, was lifted or ended with a restart; the UI never compares until
 * with its own clock.
 */
export function blockRunning(block: { ended_at?: string | null } | null | undefined): boolean {
  return !!block && !block.ended_at
}
/** A hit still blocks exactly while the gateway says active. */
export function hitBlockRunning(hit: Pick<BehaviourHit, 'active'>): boolean {
  return hit.active
}

export type IncidentState = 'blocked' | 'stopped' | 'ended' | 'unblocked'
/**
 * blocked: the address is blocked and the block runs; stopped: a rule stopped this one request, the address
 * is not blocked (review 2026-11-19: it read "Gesperrt" forever and hid "IP sperren"); "Durchlassen" lets it
 * pass the rules that stopped it for 24 hours; ended: a timed block with ended_at, also when the status still
 * says blocked (Messung 2026-10-29 abend 4.4 D29: blocks that ended with a restart kept "Gesperrt");
 * unblocked: lifted or let through by hand.
 */
export function incidentState(inc: { status: 'blocked' | 'unblocked', block?: Pick<BehaviourBlock, 'until' | 'ended_at'> | null }): IncidentState {
  if (inc.status === 'unblocked') return 'unblocked'
  if (!inc.block) return 'stopped'
  if (!blockRunning(inc.block)) return 'ended'
  return 'blocked'
}

/** The pill of an incident in every list and on its page: the same words everywhere. */
export const INCIDENT_STATE: Record<IncidentState, { label: string, tone: 'warning' | 'neutral' | 'success' }> = {
  blocked: { label: 'Gesperrt', tone: 'warning' },
  stopped: { label: 'Anfrage gestoppt', tone: 'neutral' },
  ended: { label: 'Abgelaufen', tone: 'neutral' },
  unblocked: { label: 'Aufgehoben', tone: 'success' },
}

/** Release, exception and "dauerhaft erlauben" need one concrete address. */
export function canRelease(hit: BehaviourHit): boolean {
  return hit.scope !== 'site' && !!hit.ip
}

/** "behaviour:login_bruteforce" -> "Passwort-Raten", "ratelimit:x" -> "Limit x". */
export function blockSourceText(source: string, limitLabel?: (id: string) => string | undefined): string {
  const [kind, id = ''] = source.split(':')
  if (kind === 'behaviour' && id in SCENARIOS) return SCENARIOS[id as ScenarioId].name
  if (kind === 'ratelimit') return `Limit ${limitLabel?.(id) ?? id}`
  return source
}

// ------------------------------------------------------------------ scenario settings

/** "mindestens 5 falsche Anmeldungen in 1 Minute oder 30 in 1 Stunde". */
export function thresholdsText(id: ScenarioId, t: ScenarioThresholds): string {
  const meta = SCENARIOS[id]
  if (id === 'waf_repeat') return `${formatNumber(t.count)} oder mehr ${t.count === 1 ? meta.one : meta.many} in ${formatDuration(t.window_s)}`
  let text = `mindestens ${n(t.count, meta.one, meta.many)} in ${formatDuration(t.window_s)}`
  if (t.slow_count && t.slow_window_s) text += ` oder ${formatNumber(t.slow_count)} in ${formatDuration(t.slow_window_s)}`
  if (t.baseline_factor) text += ` und mindestens das ${formatNumber(t.baseline_factor)}-Fache des Üblichen`
  return text
}

/** Bounds of the thresholds form, as in schild.schema.json (D93). The gateway decides. */
export const THRESHOLD_BOUNDS: Record<ScenarioId, { minCount: number, minWindowS: number, maxWindowS: number }> = {
  login_bruteforce: { minCount: 2, minWindowS: 1, maxWindowS: 86400 },
  credential_stuffing: { minCount: 2, minWindowS: 1, maxWindowS: 86400 },
  path_probing: { minCount: 2, minWindowS: 1, maxWindowS: 86400 },
  aggressive_crawl: { minCount: 10, minWindowS: 10, maxWindowS: 3600 },
  waf_repeat: { minCount: 2, minWindowS: 1, maxWindowS: 86400 },
}

export const WINDOW_UNITS = [
  { value: 's', label: 'Sekunden', s: 1 },
  { value: 'm', label: 'Minuten', s: 60 },
  { value: 'h', label: 'Stunden', s: 3600 },
] as const
export type WindowUnit = typeof WINDOW_UNITS[number]['value']

/** 120 → 2 Minuten, 90 → 90 Sekunden: the largest unit that divides the window evenly. */
export function splitWindow(seconds: number): { n: number, unit: WindowUnit } {
  const u = [...WINDOW_UNITS].reverse().find(x => seconds % x.s === 0) ?? WINDOW_UNITS[0]
  return { n: seconds / u.s, unit: u.value }
}

export function windowSeconds(n: number, unit: WindowUnit): number {
  return n * WINDOW_UNITS.find(x => x.value === unit)!.s
}

const THRESHOLD_FIELDS = ['count', 'window_s', 'slow_count', 'slow_window_s', 'baseline_factor'] as const

/** Whether the thresholds of a scenario differ from the built-in ones. */
export function thresholdsChanged(sc: Pick<ScenarioSetting, 'thresholds' | 'defaults'>): boolean {
  return THRESHOLD_FIELDS.some(f => (sc.thresholds[f] ?? 0) !== (sc.defaults[f] ?? 0))
}

/** "4 Treffer, 0 erkannt" (last 24 h; erkannt = would_block). */
export function scenarioCountsText(s: Pick<ScenarioSetting, 'hits_24h' | 'would_block_24h'>): string {
  return `${formatNumber(s.hits_24h)} Treffer, ${formatNumber(s.would_block_24h)} erkannt`
}

export function activeBlocksText(count: number): string {
  if (!count) return 'keine Sperre läuft'
  return count === 1 ? '1 Sperre läuft' : `${formatNumber(count)} Sperren laufen`
}

/** "15 Min, 1 Std, 4 Std, höchstens 24 Std". */
export function ladderText(steps: number[], cap: number): string {
  const below = steps.filter(s => s < cap).map(formatDurationShort)
  return [...below, `höchstens ${formatDurationShort(cap)}`].join(', ')
}

/** Scenario name of a behaviour reason ("behaviour waf_repeat: 9 in 60 s (step 4, 7 d)" -> "Wiederholte Angriffe"); null for others. */
export function behaviourReasonName(reason: string | undefined | null): string | null {
  const m = /^behaviour ([a-z_]+)/.exec(reason ?? '')
  return m && m[1]! in SCENARIOS ? SCENARIOS[m[1] as ScenarioId].name : null
}

/**
 * The stored reason of an incident in German (D36 re-measurement D: "913100, 930130 Found User-Agent
 * associated with security scanner" stood in English in the lists). title: the scenario or the rule
 * family of the first rule that is not the anomaly sum; detail: the stored text, as secondary detail;
 * tooltip: German category and rule ids first, the English CRS text only in brackets (Messung
 * 2026-10-29 abend 4.5: "930130 Restricted File Access Attempt" stood in English in 7 tooltips).
 */
export function incidentReason(reason: string | undefined | null): { title: string, detail: string | null, tooltip: string | null } | null {
  if (!reason) return null
  const scenario = behaviourReasonName(reason)
  if (scenario) return { title: scenario, detail: null, tooltip: null }
  const m = /^(\d{6,8}(?:, ?\d{6,8})*)\s*(.*)$/.exec(reason)
  if (m) {
    const ids = m[1]!.split(/, ?/)
    const main = ids.find(id => !/^9(49|59|80)\d{3}$/.test(id)) ?? ids[0]!
    const category = ruleCategoryOf(main)
    const text = m[2]?.trim()
    const source = category === 'local' ? '' : 'CRS: '
    return {
      title: explainRule(main, m[2] || null).title,
      detail: reason,
      tooltip: `${RULE_CATEGORIES[category]} · ${ids.join(', ')}${text ? ` (${source}${text})` : ''}`,
    }
  }
  return { title: reason, detail: null, tooltip: null }
}

// ------------------------------------------------------------------ rate limits

/** "10 pro Minute, kurzzeitig 10". */
export function limitText(l: { limit: number, per: string, burst?: number }): string {
  const s = perSeconds(l.per)
  const base = `${formatNumber(l.limit)} ${Number.isNaN(s) ? `pro ${l.per}` : formatPer(s)}`
  return l.burst ? `${base}, kurzzeitig ${formatNumber(l.burst)}` : base
}

/** "222 Anfragen, 37 über dem Limit, 1 Adresse" (last 24 h): whether the route is requested at all, and how often too much (D96). */
export function limitUsageText(l: Pick<RateLimit, 'mode' | 'matched_24h' | 'exceeded_24h' | 'clients_24h'>): string {
  if (l.mode === 'off') return 'zählt nicht'
  if (!l.matched_24h && !l.exceeded_24h) return 'keine Anfragen'
  const matched = n(Math.max(l.matched_24h, l.exceeded_24h), 'Anfrage', 'Anfragen')
  if (!l.exceeded_24h) return `${matched}, nichts über dem Limit`
  return `${matched}, ${formatNumber(l.exceeded_24h)} über dem Limit, ${n(l.clients_24h, 'Adresse', 'Adressen')}`
}

/**
 * A preset limit nobody needs to look at: on its recommendation and without a request to its route in
 * 24 hours, so the system it is for most likely does not run here (D96). Own limits are never idle.
 */
export function isIdlePreset(l: Pick<RateLimit, 'source' | 'mode' | 'recommended' | 'matched_24h' | 'exceeded_24h'>): boolean {
  return l.source === 'preset' && l.mode === l.recommended && !l.matched_24h && !l.exceeded_24h
}

export const LIMIT_SOURCES: Record<'preset' | 'config' | 'dashboard', string> = {
  preset: 'Voreinstellung',
  config: 'schild.yaml',
  dashboard: 'Dashboard',
}

/** A route of only "/" and "*" applies to the whole site at once. */
export function isSiteWide(route: string): boolean {
  const r = route.trim()
  return r.length > 0 && /^[/*]+$/.test(r)
}

/** "In den letzten 24 Stunden hätte dieses Limit 12 Anfragen von 2 Adressen begrenzt." */
export function dryRunText(d: RateLimitDryRun): string {
  const window = `In den letzten ${d.window_h === 1 ? 'Stunde' : `${formatNumber(d.window_h)} Stunden`}`
  if (!d.would_limit) return `${window} hätte dieses Limit keine Anfrage begrenzt.`
  const atLeast = d.sampled ? 'mindestens ' : ''
  return `${window} hätte dieses Limit ${atLeast}${n(d.would_limit, 'Anfrage', 'Anfragen')} von ${n(d.clients, 'Adresse', 'Adressen')} begrenzt.`
}
