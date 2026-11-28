import { REPOSITORIES, REPOSITORY_STATES, rulesPath } from './rules'
import type { StatusTone } from '@schild/ui'
import type { BreakdownDimension, HealthHintCode } from '@/api/monitoring'
import type { Annotation, RuleCategory, ServerHealth, WebsiteStatus, WebsiteStatusReason, WebsiteSummary } from '@/api/websites'
import { formatDuration, formatNumber } from '@schild/ui'
import { isIP } from './ip'
import { keyLabel, NET_CLASSES } from './monitoring'

/**
 * Wording of the website-first dashboard (D36): every German string of the website pages lives here,
 * so a later extraction to vue-i18n is mechanical (one key per entry). Du-form, calm, no fear wording;
 * "pseudonym", never "anonym"; never an unqualified "geschützt" or "sicher". Humanizer pass applied.
 */
export const WEBSITE_COPY = {
  allWebsites: 'Alle Websites',
  startTitle: 'Websites',
  startDescription: 'Jede Website, die Schild auf diesem Server prüft. Klick auf eine Website, um zu sehen, wer sie besucht und was Schild abfängt.',
  switcherSearch: 'Website suchen …',
  switcherEmpty: 'Keine Website gefunden.',
  switcherLabel: 'Website wählen',
  navServer: 'Server',
  navSettings: 'Einstellungen',
  overview: 'Überblick',
  requests: 'Zugriffe',
  events: 'Ereignisse',
  access: 'Zugriffsschutz',
  crawlers: 'KI-Crawler',
  perSecond: 'Anfragen/s',
  requests24h: 'Anfragen 24 h',
  stoppedShare: 'gestoppt',
  /** p95 in words: the label says Antwortzeit, the explanation what the number means. */
  p95: 'Antwortzeit',
  p95Explain: '95 von 100 Anfragen waren schneller.',
  runsOnThis: 'läuft auf diesem Server',
  runsOnN: (n: number) => `läuft auf ${n} Servern`,
  unprotected: 'Schild prüft diese Website nicht (ingress.unprotected_sites). Darum gibt es hier keine Zahlen.',
  untracked: 'Mehr als 32 Websites: Diese zählt Schild zusammen mit den übrigen unter „Weitere Websites“.',
  noNumbers: 'Noch keine Messwerte.',
  otherWebsites: (n: number) => `${n} weitere ${n === 1 ? 'Website wird' : 'Websites werden'} zusammen gezählt.`,
  blockScope: 'Die Sperre gilt für alle Websites auf diesem Server.',
  blockScopeShort: 'gilt für alle Websites auf diesem Server',
  sitesAffected: (count: number, total: number) => `betrifft ${count} von ${total} Websites`,
  estimate: 'Näherungswert',
  gap: 'Lücke im Zeitraum',
  gapText: 'Schild hat in diesem Zeitraum nicht jede Minute gezählt, zum Beispiel wegen eines Neustarts oder einer Messlücke. Für diese Zeit fehlen Anfragen in den Zahlen.',
  gapDetail: 'Neustarts und Messlücken siehst du als Markierung im Diagramm.',
  gapPrevious: 'Auch im Zeitraum davor gibt es eine Lücke. Der Vergleich ist darum etwas ungenauer.',
  gapRestart: 'Neustart im Zeitraum',
  gapRestartText: 'Schild wurde in diesem Zeitraum neu gestartet, zum Beispiel für ein Update. Jede Anfrage, die Schild beantwortet hat, ist gezählt. Anfragen während des Neustarts kamen nicht bei Schild an.',
  gapLost: 'Messlücke im Zeitraum',
  gapLostText: 'Schild hat in diesem Zeitraum nicht jede Minute gezählt, zum Beispiel nach einem harten Abbruch. Für diese Zeit fehlen Anfragen in den Zahlen.',
  previousPeriod: 'gegenüber dem Zeitraum davor',
  liveNow: (n: number) => `≈ ${n} Besucher · letzte 5 Min.`,
  liveNowTitle: 'Verschiedene Besucher der letzten 5 Minuten ohne erkannte Bots (Näherungswert). Klick zeigt die Echtzeit-Ansicht.',
  visitorsTitle: 'Besucher ohne erkannte Bots: verschiedene Adressen pro Tag, die mit einem Browser kamen und die Schild durchgelassen hat (Näherungswert). Bots, Werkzeuge und gestoppte Anfragen zählen nicht mit.',
  botClients: 'Bot-Clients',
  botClientsTitle: 'Verschiedene Adressen, die als Bot oder Werkzeug kamen (Näherungswert). Sie zählen nicht als Besucher.',
  filterUnavailableTitle: 'Diese Kombination gibt es nur für einen kürzeren Zeitraum',
  filterUnavailable: 'Mehrere Filter zusammen und Filter auf Besucher oder Antwortzeit rechnet Schild aus den einzelnen Anfragen. Die bewahrt es so lange auf wie IP-Adressen, normalerweise 14 Tage. Für längere Zeiträume merkt es sich nur Summen.',
  filterUnavailableShort: 'Mit diesem Filter nur für einen kürzeren Zeitraum verfügbar.',
  to48h: 'Zeitraum verkürzen',
  removeFilters: 'Filter entfernen',
  filterHint: 'Klick auf eine Zeile, um die ganze Seite danach zu filtern.',
  oneFilter: 'Schild filtert nach einem Merkmal zur Zeit. Ein Klick auf eine andere Zeile ersetzt den Filter.',
  panelsUnfiltered: 'Die Tabellen zeigen alle Anfragen dieser Website. Gefiltert sind die Kennzahlen und das Diagramm.',
  panelsUnfilteredRing: 'Die Tabellen zeigen alle Anfragen dieser Website. Mit Filter gibt es sie nur für den Zeitraum, für den Schild einzelne Anfragen aufbewahrt.',
  keptFrom: (date: string) => `Einzelne Anfragen reichen bis ${date} zurück. Gefilterte Zahlen davor fehlen.`,
  chartFallback: (label: string) => `Für ${label} gibt es keinen Filter. Darum zeigt das Diagramm hier die Anfragen.`,
  notFoundTitle: 'Diese Website gibt es hier nicht',
  notFound: 'Schild kennt keine Website mit dieser Adresse. Vielleicht wurde sie aus dem Caddyfile entfernt.',
  alertsWithoutMonitoring: 'Die Alarme kommen aus den gespeicherten Ereignissen und laufen auch ohne Messung weiter.',
  monitoringOff: 'Die Messung ist ausgeschaltet (monitoring.enabled: false in schild.yaml). Die Websites stehen hier trotzdem, nur ohne Zahlen.',
  // Status line on Zugriffe (D68).
  statusDegraded: 'Grundschutz aktiv, eingeschränkt',
  statusPartial: 'Einige Adressen dieser Website prüft Schild nicht',
  statusNoBlocks: 'Gerade keine laufende Sperre',
  statusBlocks: (n: number) => n === 1 ? '1 laufende Sperre' : `${n} laufende Sperren`,
  statusToEvents: 'Zu den Ereignissen',
} as const

// ------------------------------------------------------------------ status

export type GapKind = 'restart' | 'lost'
/**
 * Label and text of the gap note (contracts v0.5, gap_kind on KpiValue, TrafficBreakdown and MetricBucket):
 * restart = an orderly stop and start ("Neustart"), lost = real loss ("Messlücke"), absent = unknown
 * (the general wording).
 */
export function gapCopy(kind?: GapKind | null): { label: string, text: string } {
  if (kind === 'restart') return { label: WEBSITE_COPY.gapRestart, text: WEBSITE_COPY.gapRestartText }
  if (kind === 'lost') return { label: WEBSITE_COPY.gapLost, text: WEBSITE_COPY.gapLostText }
  return { label: WEBSITE_COPY.gap, text: WEBSITE_COPY.gapText }
}
/** One kind for several partial values: lost wins, any value without a kind makes it unknown, else restart. */
export function combineGapKind(values: ({ partial?: boolean, gap_kind?: GapKind } | null | undefined)[]): GapKind | undefined {
  const kinds = values.filter(v => v?.partial).map(v => v!.gap_kind)
  if (!kinds.length) return undefined
  if (kinds.includes('lost')) return 'lost'
  if (kinds.includes(undefined)) return undefined
  return 'restart'
}

export const STATUS: Record<WebsiteStatus, { label: string, tone: StatusTone }> = {
  ok: { label: 'läuft', tone: 'success' },
  attention: { label: 'bitte ansehen', tone: 'warning' },
  disrupted: { label: 'gestört', tone: 'danger' },
  unknown: { label: 'keine Messwerte', tone: 'neutral' },
}

/** Short German line of a server hint at a website ("web-1: Platte fast voll"), spec MVP-21 websites.copy. */
export const HINT_SHORT: Record<HealthHintCode, string> = {
  cpu_high: 'CPU stark ausgelastet',
  cpu_throttled: 'CPU-Limit des Containers erreicht',
  load_high: 'sehr hohe Last',
  memory_low: 'Arbeitsspeicher knapp',
  swap_active: 'lagert Speicher aus',
  oom_kill: 'Prozesse wegen Speichermangel beendet',
  disk_full_soon: 'Platte fast voll',
  disk_io_busy: 'Platte ausgelastet',
  net_errors: 'Netzwerkfehler',
  conntrack_high: 'Verbindungstabelle fast voll',
  fd_high: 'zu viele offene Dateien',
  listen_drops: 'Verbindungen abgewiesen',
  waf_saturated: 'Prüfplätze voll',
  events_dropped: 'Ereignisse nicht gespeichert',
  monitoring_degraded: 'Messung lückenhaft',
  disk_fill_projection: 'Platte bald voll',
  // Server only (contract/websites.ServerOnlyHintCodes): never shown at a website, kept for the server page.
  store_near_cap: 'Ereignisspeicher fast voll',
  store_cap_unreachable: 'Ereignisspeicher über der Grenze',
  storage_budget: 'Speichergrenzen größer als der freie Platz',
  audit_stuck: 'Protokoll wartet auf audit.db',
  audit_size: 'Protokoll ist groß',
  // website-scoped hints
  upstream_errors: 'deine App beantwortet Anfragen mit Fehlern',
  upstream_slow: 'deine App antwortet langsam',
  fail_closed: 'Schild beantwortet Anfragen mit 503',
  traffic_spike: 'gerade viel mehr Anfragen als üblich',
}

/** One short line per status reason, deciding reasons first (as the API orders them). */
export function reasonText(r: WebsiteStatusReason): string {
  switch (r.code) {
    case 'server_hint': return `${r.node ?? 'Server'}: ${r.hint ? HINT_SHORT[r.hint] : 'Hinweis'}`
    case 'site_hint': return r.hint ? capital(HINT_SHORT[r.hint]) : 'Hinweis zur Website'
    case 'upstream_unreachable': return 'Deine App antwortet auf viele Anfragen nicht'
    case 'errors_5xx': return 'Viele Anfragen enden mit einem Serverfehler (5xx)'
    case 'fail_closed': return 'Schild beantwortet viele Anfragen mit 503'
    case 'not_ready': return `${r.node ?? 'Schild'} ist noch nicht bereit`
    case 'baseline_off': return `Grundschutz auf ${r.node ?? 'dem Server'} aus`
    case 'baseline_degraded': return 'Grundschutz eingeschränkt'
    case 'unreachable': return `${r.node ?? 'Ein Server'} ist nicht erreichbar`
    case 'unprotected': return 'Schild prüft diese Website nicht'
    case 'no_server': return 'Läuft auf keinem Server'
    case 'monitoring_off': return 'Messung ausgeschaltet'
    case 'untracked': return 'Zusammen mit weiteren Websites gezählt'
    case 'no_data': return 'Noch keine Anfragen gezählt'
  }
  return 'Hinweis'
}

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

/** Label of a website: Unicode label from the API; _any and default in words. */
export function websiteName(w: Pick<WebsiteSummary, 'id' | 'label'> | undefined | null, fallback = ''): string {
  if (!w) return fallback
  if (w.id === '_any') return 'Alle anderen Adressen'
  if (w.id === 'default') return 'Deine Website'
  return w.label
}

export function runsOnText(runsOn: ServerHealth[]): string {
  if (runsOn.length === 1 && runsOn[0]!.this) return WEBSITE_COPY.runsOnThis
  if (runsOn.length === 1) return `läuft auf ${runsOn[0]!.node}`
  return WEBSITE_COPY.runsOnN(runsOn.length)
}

// ------------------------------------------------------------------ rule categories ("Letzte Alarme")

export const RULE_CATEGORIES: Record<RuleCategory, string> = {
  scanner: 'Scanner',
  protocol: 'Ungültige Anfrage',
  protocol_attack: 'Protokoll-Trick',
  lfi: 'Versuchter Dateizugriff',
  rfi: 'Versuch, fremde Datei zu laden',
  rce: 'Versuch, Befehle auszuführen',
  php: 'Versuch, PHP-Code einzuschleusen',
  generic: 'Allgemeiner Angriffsversuch',
  xss: 'Versuch, Skript einzuschleusen (XSS)',
  sqli: 'SQL-Injection-Versuch',
  session_fixation: 'Versuch, Sitzung zu übernehmen',
  java: 'Java-Angriffsversuch',
  anomaly: 'Viele Auffälligkeiten',
  local: 'Eigene Regel',
  behaviour: 'Verhalten',
  rate_limit: 'Zu viele Anfragen',
}

/** CRS id range -> category (contract/websites.RuleCategory), for rows that only carry a rule id. */
export function ruleCategoryOf(rule: string): RuleCategory {
  if (!/^\d+$/.test(rule)) return 'local'
  const n = Number(rule)
  if (n < 900000 || n >= 1000000) return 'local'
  const p = Math.floor(n / 1000)
  const map: Record<number, RuleCategory> = { 913: 'scanner', 920: 'protocol', 921: 'protocol_attack', 930: 'lfi', 931: 'rfi', 932: 'rce', 933: 'php', 934: 'generic', 941: 'xss', 942: 'sqli', 943: 'session_fixation', 944: 'java', 949: 'anomaly', 959: 'anomaly', 980: 'anomaly' }
  return map[p] ?? 'local'
}

export const ALERT_OUTCOMES: Record<string, { label: string, strong: boolean }> = {
  // "Erkannt" and "Gesperrt" everywhere (initiator 2026-10-29, MVP-22 UI).
  blocked: { label: 'Gesperrt', strong: true },
  rate_limited: { label: 'Gebremst', strong: true },
  would_block: { label: 'Erkannt', strong: false },
  would_rate_limit: { label: 'Erkannt (Limit)', strong: false },
}

// ------------------------------------------------------------------ annotations

const DETECTORS: Record<string, string> = {
  route_wave: 'Verteilter Angriffsversuch auf eine Seite erkannt',
  account_wave: 'Verteilte Login-Versuche erkannt',
  shape_wave: 'Gleichförmige Anfragen von vielen Adressen erkannt',
  fingerprint_cluster: 'Viele Adressen mit gleichem Fingerabdruck erkannt',
  inconsistency: 'Widersprüchliche Angaben vieler Adressen erkannt',
}
// Modes of gateways before D89, only in old annotations.
const MODES: Record<string, string> = { observe: 'Beobachten', review: 'Freigeben', autoblock: 'Automatisch sperren' }

/**
 * Why a long block lasts that long, in words ("Rechenzentrum, wiederholt"). The block_long annotation
 * carries the ladder step in count (1 = first block, D36 open items): "wiederholt" = count >= 2.
 */
export function blockWhy(a: Pick<Annotation, 'net_class' | 'count'>): string {
  const parts: string[] = []
  if (a.net_class === 'hosting') parts.push('Rechenzentrum')
  else if (a.net_class) parts.push(NET_CLASSES[a.net_class] ?? a.net_class)
  if ((a.count ?? 1) >= 2) parts.push('wiederholt')
  return parts.join(', ')
}

/**
 * How long and why a behaviour block lasts, from Incident.block (D36 amendment): the ladder is longer
 * for data-centre addresses and grows with every repeat. "7 Tage, weil Rechenzentrum und wiederholt",
 * "15 Minuten, erster Verstoß".
 */
export function incidentBlockText(b: { duration_s?: number, net_class?: string | null, level: number }): string {
  const d = formatDuration(b.duration_s ?? 0)
  const why: string[] = []
  if (b.net_class === 'hosting') why.push('Rechenzentrum')
  if (b.level > 1) why.push('wiederholt')
  if (why.length) return `${d}, weil ${why.join(' und ')}`
  return b.level === 1 ? `${d}, erster Verstoß` : d
}

export function annotationLabel(a: Annotation): string {
  switch (a.kind) {
    case 'wave_detected': return a.detector ? (DETECTORS[a.detector] ?? 'Welle erkannt') : 'Welle erkannt'
    case 'wave_ended': return 'Welle vorbei'
    // Grouped marker (contracts v0.5): count incidents in the bin [t, until), ref = the newest of them.
    case 'incident': return (a.count ?? 0) > 1 ? `${formatNumber(a.count!)} Vorfälle${a.ref ? `, zuletzt ${a.ref}` : ''}` : `Vorfall ${a.ref ?? ''}`.trim()
    case 'block_long': return `${formatDuration(a.duration_s ?? 0)} gesperrt${blockWhy(a) ? `: ${blockWhy(a)}` : ''}`
    case 'mode_changed': return `Modus geändert${a.mode_to ? `: ${MODES[a.mode_to] ?? a.mode_to}` : ''}`
    case 'config_changed': return 'Konfiguration geändert'
    case 'restart': return 'Neustart von Schild'
    case 'monitoring_gap': return 'Messlücke'
    case 'agent_block_set': return `${a.effect === 'would_block' ? 'Erkannt' : 'Gesperrt'}, über Agent ${a.token_label ?? ''}`.trimEnd()
    case 'agent_block_lifted': return `Sperre aufgehoben, über Agent ${a.token_label ?? ''}`.trimEnd()
    case 'rule_repository_changed': {
      const name = a.repository ? REPOSITORIES[a.repository].name : 'Regeln'
      const to = a.state_to ? REPOSITORY_STATES[a.state_to].label : ''
      return `${name}${to ? `: ${to}` : ' geändert'}${a.actor === 'agent' ? `, über Agent ${a.token_label ?? ''}`.trimEnd() : ''}`
    }
  }
  return 'Markierung'
}

/** One-letter glyph on the chart marker (the label is in the tooltip and the list). */
export const ANNOTATION_GLYPH: Record<Annotation['kind'], string> = {
  wave_detected: 'W',
  wave_ended: 'W',
  incident: 'V',
  block_long: 'S',
  mode_changed: 'M',
  config_changed: 'K',
  restart: 'N',
  monitoring_gap: 'L',
  rule_repository_changed: 'R',
  agent_block_set: 'A',
  agent_block_lifted: 'A',
}

/** Order of importance when several markers share one place on the chart (the first one names the group). */
export const ANNOTATION_RANK: Annotation['kind'][] = ['restart', 'monitoring_gap', 'mode_changed', 'rule_repository_changed', 'config_changed', 'wave_detected', 'wave_ended', 'block_long', 'incident']

export interface MarkerGroup<T> {
  /** Position in px, inside [lo, hi]. */
  x: number
  items: T[]
}

/**
 * Visitors are an estimate the gateway leaves out of a bucket nobody visited, so the line would break
 * at every quiet stretch. Between the first and the last bucket with a value, a bucket without one had
 * no visitors: 0. Buckets inside a monitoring gap stay gaps, and so does the time before the first value.
 */
export function fillQuietBuckets(values: (number | null)[], gaps: { from: number, until: number }[] = []): (number | null)[] {
  const first = values.findIndex(v => v !== null)
  if (first < 0) return values
  let last = values.length - 1
  while (values[last] === null) last--
  const inGap = (i: number) => gaps.some(g => i >= g.from && i <= g.until)
  return values.map((v, i) => v === null && i > first && i < last && !inGap(i) ? 0 : v)
}

/**
 * Groups chart markers that would overlap (closer than minGap px) into one, so a real attack with many
 * incidents never pushes markers sideways out of the chart (D36 measurement D.2: 4,700 px overflow).
 * Each group starts at its first marker; groups are at least minGap apart and stay within [lo, hi].
 */
export function groupMarkers<T>(points: { x: number, item: T }[], minGap: number, lo: number, hi: number): MarkerGroup<T>[] {
  const sorted = [...points].sort((a, b) => a.x - b.x)
  const out: MarkerGroup<T>[] = []
  for (const p of sorted) {
    const x = Math.min(hi, Math.max(lo, p.x))
    const last = out[out.length - 1]
    if (last && x - last.x < minGap) last.items.push(p.item)
    else out.push({ x, items: [p.item] })
  }
  return out
}

export function annotationLink(a: Annotation, site = ''): string | null {
  switch (a.kind) {
    case 'wave_detected':
    case 'wave_ended': return '/settings/rules/behaviour?view=detectors'
    // A grouped marker has no single number: the incidents of the last 7 days on the website's Ereignisse (D68).
    case 'incident':
    case 'block_long': return a.ref && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(a.ref) ? `/incidents/${a.ref}` : site ? `/w/${encodeURIComponent(site)}/events` : '/blocks?view=requests'
    case 'mode_changed':
    case 'config_changed': return '/settings'
    case 'rule_repository_changed': return rulesPath(a.repository)
    default: return null
  }
}

// ------------------------------------------------------------------ KPIs

export type KpiKey = 'visitors' | 'page_views' | 'requests' | 'stopped' | 'latency_p95_ms' | 'error_rate'
export interface KpiDef {
  key: KpiKey
  label: string
  /** Metric for the main chart (queryMetricSeries). */
  metric: string
  /** Chart and tooltip unit. */
  unit: 'count' | 'perMin' | 'ms' | 'ratio'
  chartLabel: string
  /** Filters work on this series over every range (rings); else only within 48 h. */
  filterable: boolean
  /** Tooltip of the tile: what the number counts. */
  hint?: string
  /** More is not "better" here: the change is shown without judgement anyway. */
}
export const KPIS: KpiDef[] = [
  { key: 'visitors', label: 'Besucher', metric: 'traffic.clients_unique', unit: 'count', chartLabel: 'Besucher je Zeitabschnitt', filterable: false, hint: WEBSITE_COPY.visitorsTitle },
  { key: 'page_views', label: 'Seitenaufrufe', metric: 'traffic.page_views:rate', unit: 'perMin', chartLabel: 'Seitenaufrufe pro Minute', filterable: false },
  { key: 'requests', label: 'Anfragen', metric: 'traffic.requests:rate', unit: 'perMin', chartLabel: 'Anfragen pro Minute', filterable: true },
  { key: 'stopped', label: 'Anfragen gestoppt', metric: 'traffic.stopped:rate', unit: 'perMin', chartLabel: 'Gestoppt pro Minute', filterable: true },
  { key: 'latency_p95_ms', label: 'Antwortzeit', metric: 'traffic.latency_total:p95', unit: 'ms', chartLabel: 'Antwortzeit (95 von 100 Anfragen schneller)', filterable: false }, // gitleaks:allow (KPI id, not a secret)
  { key: 'error_rate', label: 'Fehlerquote', metric: 'traffic.status_5xx:rate', unit: 'ratio', chartLabel: 'Fehlerquote (5xx)', filterable: false },
]
export function kpiOf(v: unknown): KpiDef {
  return KPIS.find(k => k.key === v) ?? KPIS[2]!
}

/** Change vs the previous period as text ("+12 %", "−3 %", "neu", "gleich"). */
export function changeText(cur: number | null | undefined, prev: number | null | undefined): { text: string, dir: 'up' | 'down' | 'flat' } | null {
  if (cur === null || cur === undefined || prev === null || prev === undefined) return null
  if (prev === 0) return cur === 0 ? { text: 'gleich', dir: 'flat' } : { text: 'neu', dir: 'up' }
  const ch = (cur - prev) / prev
  if (Math.abs(ch) < 0.005) return { text: 'gleich', dir: 'flat' }
  const pct = Math.abs(ch) >= 10 ? '>999' : new Intl.NumberFormat('de-DE', { maximumFractionDigits: Math.abs(ch) < 0.1 ? 1 : 0 }).format(Math.abs(ch) * 100)
  return { text: `${ch > 0 ? '+' : '−'}${pct} %`, dir: ch > 0 ? 'up' : 'down' }
}

// ------------------------------------------------------------------ filters

export const FILTER_DIMENSIONS: Record<string, string> = {
  path: 'Seite',
  country: 'Land',
  asn: 'Netzbetreiber',
  net_class: 'Netzart',
  ua_class: 'Client',
  method: 'Methode',
  status_class: 'Status',
  referrer: 'Herkunft',
  browser: 'Browser',
  os: 'System',
  device: 'Gerät',
  bot_category: 'Bot',
  rule: 'Regel',
  ip: 'IP',
  user_agent: 'User-Agent',
}

/** A breakdown dimension, or a filter without a breakdown that only the request ring answers (D64). */
export type FilterDimension = BreakdownDimension | 'ip' | 'user_agent'

export interface FilterChipView {
  expr: string
  dimension: string
  label: string
  value: string
}

export function parseFilter(expr: string): { dimension: FilterDimension, value: string } | null {
  const i = expr.indexOf(':')
  if (i < 1) return null
  const dimension = expr.slice(0, i)
  if (!(dimension in FILTER_DIMENSIONS)) return null
  const value = expr.slice(i + 1)
  if (!value || value.length > 512 || (dimension === 'ip' && !isIP(value))) return null
  return { dimension: dimension as FilterDimension, value }
}

export function filterChip(expr: string): FilterChipView | null {
  const p = parseFilter(expr)
  if (!p) return null
  const value = p.dimension === 'ip' || p.dimension === 'user_agent' ? p.value : keyLabel(p.dimension, p.value)
  return { expr, dimension: p.dimension, label: FILTER_DIMENSIONS[p.dimension]!, value }
}

/** The filter for a search text: an address filters by IP, anything else by a part of the User-Agent (D64). */
export function searchFilter(text: string): string | null {
  const v = text.trim().slice(0, 512)
  if (!v) return null
  return isIP(v) ? `ip:${v}` : `user_agent:${v}`
}

/** Filters from the URL (`filter`, repeated), valid and unique, at most 4 like the API. */
export function filtersFromQuery(v: unknown): string[] {
  const list = (Array.isArray(v) ? v : [v]).filter((x): x is string => typeof x === 'string')
  const out: string[] = []
  for (const x of list) if (parseFilter(x) && !out.includes(x)) out.push(x)
  return out.slice(0, 4)
}
