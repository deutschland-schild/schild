import type { StatusTone } from '@schild/ui'
import type { BreakdownDimension, HealthHint, HealthHintCode, RangeDef, ServerSnapshot } from '@/api/monitoring'
import { countryName, formatBytes, formatDecimal, formatDuration, formatMs, formatNumber } from '@schild/ui'

/**
 * German wording of the monitoring pages (MVP-21 spec, dashboard.copy; humanizer pass):
 * du-form, calm, "Näherungswert" for estimates, never red for normal traffic.
 */

export const COPY = {
  empty: 'Noch keine Werte. Die ersten erscheinen nach etwa 10 Sekunden.',
  monitoringOff: 'Die Auslastungsanzeige ist ausgeschaltet (monitoring.enabled: false in schild.yaml).',
  container: 'Schild läuft in einem Container. CPU und Arbeitsspeicher zeigen den ganzen Server, das Limit des Containers steht daneben.',
  ownNetwork: 'Netzwerkwerte zeigen nur den Container. Mit network_mode: host siehst du die Werte des Servers.',
  noHints: 'Keine Auffälligkeiten. CPU, Speicher und Festplatte sind im üblichen Rahmen.',
  restart: 'Neustart von Schild',
  sinceRestart: 'seit dem letzten Neustart von Schild',
  // The HyperLogLog error of 3.3 % is one standard error, not a hard bound (MVP-21 measurement).
  clientsEstimate: 'Näherungswert: meist innerhalb von ±3 %, einzelne Werte weichen auch etwas mehr ab.',
  botsUnverified: 'Überprüfung noch nicht verfügbar: Die Einordnung beruht auf dem, was der Browser oder Bot über sich sagt.',
} as const

/** "Näherungswert: kann um bis zu {n} abweichen." */
export function estimateText(bound: string): string {
  return `Näherungswert: kann um bis zu ${bound} abweichen.`
}

/**
 * Chart tones (packages/ui index.css): one brand hue in steps plus a neutral grey, never --danger for traffic.
 * wash/light/mid are fills, main/deep/neutral also work as lines (>= 3:1 on the card).
 */
export const TONES = {
  wash: 'var(--tone-wash)',
  light: 'var(--tone-light)',
  mid: 'var(--tone-mid)',
  main: 'var(--tone-main)',
  deep: 'var(--tone-deep)',
  neutral: 'var(--tone-neutral)',
} as const

/**
 * Traffic outcomes on the tonal scale: normal traffic is the pale wash under the total line, the more severe
 * outcome the stronger the step; 503 is neutral grey (an operational state, not an attack).
 */
export const OUTCOME_COLORS = {
  passed: TONES.wash,
  would: TONES.mid,
  stopped: TONES.deep,
  failClosed: TONES.neutral,
  data: TONES.main,
} as const

// ------------------------------------------------------------------ hints

export interface HintContext {
  now?: number
  cores?: number | null
  cpuLimitCores?: number | null
  overheadP95Ms?: number | null
  storeBytes?: number | null
  storeMaxBytes?: number | null
}

export interface HintView {
  code: HealthHintCode
  tone: StatusTone
  levelLabel: string
  text: string
  next?: string
  to?: string
  action?: string
}

/** Bytes in the MB of retention.max_size_mb (1 MiB each, so the configured number comes back). */
const mb = (bytes: number) => formatNumber(Math.round(bytes / 1_048_576))
/** "in etwa 9 Tagen", "in etwa einem Tag", "in weniger als einem Tag". */
function daysText(v: number | null): string {
  if (v === null) return 'bald'
  const d = Math.floor(v)
  if (d < 1) return 'in weniger als einem Tag'
  return d === 1 ? 'in etwa einem Tag' : `in etwa ${formatNumber(d)} Tagen`
}
const pct = (v: number | null | undefined) => v === null || v === undefined ? '–' : formatNumber(Math.round(v * 100))

export function hintContext(s: ServerSnapshot | undefined, overheadP95Ms?: number | null): HintContext {
  return {
    cores: s?.cpu?.cores ?? null,
    cpuLimitCores: s?.container?.cpu_limit_cores ?? null,
    overheadP95Ms: overheadP95Ms ?? null,
    storeBytes: s?.schild.store_bytes ?? null,
    storeMaxBytes: s?.schild.store_max_bytes ?? null,
  }
}

/** One sentence per hint and the next step (spec MVP-21 dashboard.copy.hints). */
export function hintView(h: HealthHint, ctx: HintContext = {}): HintView {
  const now = ctx.now ?? Date.now()
  const since = formatDuration((now - Date.parse(h.since)) / 1000)
  const v = h.value ?? null
  const n = v === null ? '–' : formatNumber(Math.round(v))
  const obj = h.object ?? ''
  const tone: StatusTone = h.level === 'warning' ? 'warning' : h.level === 'notice' ? 'info' : 'neutral'
  const levelLabel = h.level === 'warning' ? 'Bitte prüfen' : h.level === 'notice' ? 'Bitte ansehen' : 'Zur Info'
  const base = { code: h.code, tone, levelLabel }
  // Charts belong to a website: a website hint opens its Diagramme, a server-wide one the list of websites.
  const charts = (query = '') => h.site ? `/w/${encodeURIComponent(h.site)}/charts${query}` : '/'
  switch (h.code) {
    case 'cpu_high':
      return { ...base, text: `Die CPU ist seit ${since} zu über 90 % ausgelastet. Anfragen können dadurch langsamer werden.`, next: 'Unter Server siehst du, ob die App oder Schild die Last erzeugt.', to: '/server/load', action: 'Auslastung ansehen' }
    case 'cpu_throttled':
      return { ...base, text: `Der Container stößt an sein CPU-Limit${ctx.cpuLimitCores ? ` (${formatDecimal(ctx.cpuLimitCores)} Kerne)` : ''}. Das Limit steht in deiner Container-Konfiguration.`, to: '/server/load', action: 'Auslastung ansehen' }
    case 'load_high': {
      const cores = ctx.cores ?? (h.threshold ? Math.round(h.threshold / 2) : null)
      return { ...base, text: `Es warten mehr Prozesse auf Rechenzeit, als Kerne da sind (Last ${formatDecimal(v)} bei ${cores ?? '–'} Kernen).`, to: '/server/load', action: 'Auslastung ansehen' }
    }
    case 'memory_low':
      return { ...base, text: 'Weniger als 10 % Arbeitsspeicher frei. Wird er knapp, beendet der Kernel Prozesse.', next: 'Prüf, welcher Dienst mehr Speicher braucht als sonst.', to: '/server/load', action: 'Speicher ansehen' }
    case 'swap_active':
      return { ...base, text: 'Der Server lagert Arbeitsspeicher auf die Festplatte aus. Das macht ihn spürbar langsamer.', to: '/server/load', action: 'Speicher ansehen' }
    case 'oom_kill':
      return { ...base, text: `Der Kernel hat in den letzten 24 Stunden ${n} ${v === 1 ? 'Prozess' : 'Prozesse'} wegen Speichermangels beendet.`, next: 'Schau in das Systemprotokoll (journalctl -k), welcher Prozess betroffen war.' }
    case 'disk_full_soon':
      return { ...base, text: `${obj || 'Eine Festplatte'} ist zu ${pct(v)} % belegt. Bei 100 % können App und Datenbank nichts mehr schreiben.`, next: 'Räum alte Dateien, Logs oder Container-Images auf oder vergrößere den Speicher.', to: '/server/load', action: 'Festplatten ansehen' }
    case 'disk_io_busy':
      return { ...base, text: `${obj || 'Eine Festplatte'} ist seit ${since} fast durchgehend mit Lesen und Schreiben beschäftigt.`, to: '/server/load', action: 'Festplatten ansehen' }
    case 'net_errors':
      return { ...base, text: `${obj || 'Eine Netzwerkschnittstelle'} meldet Übertragungsfehler oder verworfene Pakete.`, to: '/server/load', action: 'Netzwerk ansehen' }
    case 'conntrack_high':
      return { ...base, text: `Die Verbindungstabelle der Firewall ist zu ${pct(v)} % voll. Ist sie voll, verwirft der Kernel neue Verbindungen.`, next: 'Erhöhe net.netfilter.nf_conntrack_max, wenn das öfter vorkommt.' }
    case 'fd_high':
      return { ...base, text: `Schild nutzt ${pct(v)} % der erlaubten offenen Dateien. Erhöhe das Limit (LimitNOFILE oder ulimit -n).` }
    case 'listen_drops':
      return { ...base, text: 'Der Server hat neue Verbindungen abgewiesen, weil die Warteschlange voll war.', to: '/server/load', action: 'Verbindungen ansehen' }
    case 'upstream_errors':
      return { ...base, text: `Deine App hat ${n} Anfragen nicht oder mit einem Fehler (502, 504) beantwortet.`, next: 'Prüf, ob die App läuft und erreichbar ist.', to: charts(), action: 'Traffic ansehen' }
    case 'upstream_slow':
      return { ...base, text: `Deine App antwortet langsamer als sonst (p95 ${formatMs(v)}).${ctx.overheadP95Ms !== null && ctx.overheadP95Ms !== undefined ? ` Schild selbst braucht davon ${formatMs(ctx.overheadP95Ms)}.` : ''}`, to: charts(), action: 'Antwortzeiten ansehen' }
    case 'fail_closed':
      return { ...base, text: `Schild hat ${n} Anfragen mit 503 beantwortet, weil die Prüfung nicht rechtzeitig fertig wurde. Ungeprüft geht keine Anfrage durch.`, to: charts(), action: 'Traffic ansehen' }
    case 'waf_saturated':
      return { ...base, text: `Alle Prüfplätze waren belegt. ${n} Anfragen bekamen 503 und können es gleich noch einmal versuchen.`, next: 'Mehr Prüfplätze stellst du mit waf.max_concurrent_evals in schild.yaml ein.' }
    case 'events_dropped':
      return { ...base, text: `${n} Ereignisse wurden nicht gespeichert, weil zu viele auf einmal kamen. Die Zahlen hier sind trotzdem vollständig.` }
    case 'store_near_cap': {
      const used = ctx.storeBytes ? mb(ctx.storeBytes) : '–'
      const max = ctx.storeMaxBytes ? mb(ctx.storeMaxBytes) : '–'
      return { ...base, text: `Der Speicher für Ereignisse ist fast voll (${used} von ${max} MB). Ältere Ereignisse werden früher gelöscht.`, next: 'Mehr Platz gibt retention.max_size_mb in schild.yaml.' }
    }
    // v0.5 (D38, contracts/storage-bounds.md): value = used bytes, threshold = the cap in bytes.
    case 'store_cap_unreachable': {
      const cap = h.threshold ?? ctx.storeMaxBytes ?? null
      return { ...base, text: `Der Ereignisspeicher bleibt über der Grenze von ${cap ? mb(cap) : '–'} MB. Die neuesten Einträge löscht Schild nicht.`, next: 'Erhöhe retention.max_size_mb oder sieh nach, was so viel schreibt.', to: '/settings#retention', action: 'Speicher ansehen' }
    }
    // object = storage.path; the reserve is max(1 GiB, min(5 % of the file system, 20 GiB)) (D38, the 20 GiB cap
    // since 2026-10-29), sent as threshold when known.
    case 'storage_budget': {
      // GiB in the rule: formatBytes shows decimal units (20 GiB = 21,5 GB).
      const free = h.threshold ? `weniger als ${formatBytes(h.threshold)} frei` : 'weniger frei als die Reserve'
      return { ...base, text: `Wenn alle Speichergrenzen von Schild ausgeschöpft sind, bleibt auf ${obj || 'der Platte von Schild'} ${free}. Die Reserve sind 5 % der Platte, mindestens 1 GiB und höchstens 20 GiB.`, next: 'Senke retention.max_size_mb oder schaffe Platz.', to: '/settings#retention', action: 'Speicher ansehen' }
    }
    // object = mount, value = days left (Theil-Sen slope of the last 7 days).
    case 'disk_fill_projection':
      return { ...base, text: `${obj || 'Eine Festplatte'} ist ${daysText(v)} voll, wenn es so weitergeht wie in den letzten 7 Tagen.`, next: 'Unter „Server“ siehst du große Logdateien.', to: '/server/check', action: 'Server-Check ansehen' }
    case 'traffic_spike':
      return { ...base, text: `Gerade kommen etwa ${formatDecimal(v)}-mal so viele Anfragen wie in der letzten Stunde üblich.`, to: charts('?time=1h'), action: 'Traffic ansehen' }
    case 'monitoring_degraded':
      return { ...base, text: 'Die Messung braucht gerade länger als geplant und lässt einzelne Werte aus.' }
  }
  return { ...base, text: 'Ein Hinweis zur Auslastung.' }
}

// ------------------------------------------------------------------ dimensions

export const UA_CLASSES: Record<string, string> = {
  browser: 'Browser',
  bot_verified: 'Bots, bestätigt',
  bot_unverified: 'Bots, unbestätigt',
  tool: 'Werkzeuge (curl, Skripte)',
  none: 'Ohne Kennung',
  other: 'Sonstige',
}
export const NET_CLASSES: Record<string, string> = {
  residential: 'Privatanschlüsse',
  mobile: 'Mobilfunk',
  cgnat: 'Geteilte Anschlüsse (CGNAT)',
  hosting: 'Rechenzentren',
  business: 'Firmennetze',
  education: 'Hochschulen',
  government: 'Behörden',
  tor: 'Tor',
  vpn: 'VPN',
  proxy: 'Proxy',
  unknown: 'Unbekannt',
}
export const BROWSERS: Record<string, string> = {
  chrome: 'Chrome',
  edge: 'Edge',
  firefox: 'Firefox',
  safari: 'Safari',
  opera: 'Opera',
  samsung: 'Samsung Internet',
  ie: 'Internet Explorer',
  other: 'Anderer Browser',
  none: 'Kein Browser',
}
export const OS_FAMILIES: Record<string, string> = {
  windows: 'Windows',
  macos: 'macOS',
  ios: 'iOS',
  android: 'Android',
  linux: 'Linux',
  chromeos: 'ChromeOS',
  other: 'Anderes System',
  none: 'Kein System genannt',
}
export const DEVICES: Record<string, string> = {
  desktop: 'Computer',
  mobile: 'Smartphone',
  tablet: 'Tablet',
  other: 'Anderes Gerät',
  unknown: 'Unbekannt',
}
export const BOT_CATEGORIES: Record<string, string> = {
  search_engine: 'Suchmaschine',
  ai_training: 'KI-Training',
  ai_search: 'KI-Suche',
  ai_assistant: 'KI-Assistent',
  preview_social: 'Vorschau/Social',
  feed_reader: 'Feed-Reader',
  monitoring: 'Monitoring',
  seo_tool: 'SEO-Werkzeug',
  archive_research: 'Archiv/Forschung',
  security_scanner: 'Sicherheitsscanner',
  tool_library: 'Werkzeug/Bibliothek',
  likely_automated: 'Wahrscheinlich automatisiert',
  likely_browser: 'Wahrscheinlich Browser',
}
export const METHODS: Record<string, string> = { OTHER: 'Andere' }
export const STATUS_CLASSES: Record<string, string> = {
  '1xx': '1xx Information',
  '2xx': '2xx Erfolg',
  '3xx': '3xx Weiterleitung',
  '4xx': '4xx Fehler der Anfrage',
  '5xx': '5xx Fehler des Servers',
}

export function referrerLabel(key: string, label?: string): string {
  if (key === '_direct') return 'Direkt (ohne Herkunft)'
  if (key === '_intern') return 'Eigene Websites'
  if (key === '_other') return 'Sonstige'
  if (key.startsWith('ai:')) return `KI-Assistent: ${label ?? key.slice(3)}`
  return key
}

/** Display name of a breakdown key. */
export function keyLabel(by: BreakdownDimension, key: string, label?: string, sites?: Map<string, string>): string {
  switch (by) {
    case 'country': return key === 'ZZ' ? 'Unbekannt' : countryName(key)
    case 'asn': return label ? `${label} (AS${key})` : `AS${key}`
    case 'net_class': return NET_CLASSES[key] ?? key
    case 'ua_class': return UA_CLASSES[key] ?? key
    case 'method': return METHODS[key] ?? key
    case 'status_class': return STATUS_CLASSES[key] ?? key
    case 'site': return key === '_other' ? 'Weitere Websites' : sites?.get(key) ?? key
    case 'referrer': return referrerLabel(key, label)
    case 'browser': return BROWSERS[key] ?? key
    case 'os': return OS_FAMILIES[key] ?? key
    case 'device': return DEVICES[key] ?? key
    case 'bot_category': return BOT_CATEGORIES[key] ?? key
    case 'rule': return label ? `${key} · ${label}` : `Regel ${key}`
    default: return key
  }
}

/** Ereignisse filter for a breakdown row (that is where IP addresses are), or null. */
export function eventsLinkFor(by: BreakdownDimension, key: string, range: RangeDef): string | null {
  const time = range.seconds <= 3600 ? '1h' : range.seconds <= 24 * 3600 ? '24h' : range.seconds <= 7 * 86400 ? '7d' : 'all'
  const q = new URLSearchParams({ time })
  if (by === 'country' && /^[A-Z]{2}$/.test(key) && key !== 'ZZ') q.set('country', key)
  else if (by === 'asn' && /^\d+$/.test(key)) q.set('asn', key)
  else if (by === 'path' && key.startsWith('/')) q.set('path', key.replace(/\{[^}]*\}.*$/, ''))
  else if (by === 'rule') q.set('rule', key)
  // D36 amendment: listEvents filters net_class, method (OTHER) and ua_class.
  else if (by === 'net_class' && key in NET_CLASSES) q.set('net', key)
  else if (by === 'method' && /^[A-Z]{1,16}$/.test(key)) q.set('method', key)
  else if (by === 'ua_class' && key in UA_CLASSES) q.set('client', key)
  else return null
  return `/events?${q.toString()}`
}

// ------------------------------------------------------------------ time labels

const hm = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit' })
const dm = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit' })
const long = new Intl.DateTimeFormat('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
const longSec = new Intl.DateTimeFormat('de-DE', { weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' })

/**
 * Axis and tooltip labels for steps from `from` (ms), plus the start of each step for round axis ticks.
 * Over more than a day a local midnight is labelled with its date ("29.10.") instead of "00:00".
 */
export function timeLabels(from: number, stepS: number, points: number): { short: string[], long: string[], times: number[] } {
  const short: string[] = []
  const lg: string[] = []
  const times: number[] = []
  const days = points * stepS > 2 * 86400
  const multiDay = points * stepS > 86400
  for (let i = 0; i < points; i++) {
    const t = from + i * stepS * 1000
    const d = new Date(t)
    const midnight = d.getHours() === 0 && d.getMinutes() === 0
    times.push(t)
    short.push(stepS >= 600 && days ? dm.format(d) : multiDay && midnight ? dm.format(d) : hm.format(d))
    lg.push(stepS < 60 ? longSec.format(d) : long.format(d))
  }
  return { short, long: lg, times }
}

/** Restart markers on a step grid. */
export function restartMarkers(restarts: number[], from: number, stepS: number, points: number) {
  return restarts
    .map(t => Math.floor((t - from) / (stepS * 1000)))
    .filter(i => i >= 0 && i < points)
    .map(index => ({ index, label: COPY.restart }))
}

// ------------------------------------------------------------------ units

export function perSecond(v: number | null | undefined): string {
  if (v === null || v === undefined) return '–'
  return formatDecimal(v)
}
export const bytesPerSecond = (v: number | null | undefined) => v === null || v === undefined ? '–' : `${formatBytes(v)}/s`
export const ratioText = (v: number | null | undefined) => v === null || v === undefined ? '–' : `${formatDecimal(v * 100)} %`
