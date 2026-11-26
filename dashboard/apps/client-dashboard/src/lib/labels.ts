import type { StatusTone } from '@schild/ui'
import type { EventSummary, BaselineReason, Health, Outcome, Ttl, WouldBlockReason } from '@/api/types'

/**
 * German wording for everything the API returns as codes (brand glossary, docs/brand/01-marke.md#glossar):
 * "Grundschutz aktiv" never "geschützt"/"sicher". There is no protection mode (D89): every rule source,
 * scenario and limit has its own switch.
 */

/**
 * would_block in the dashboard (initiator 2026-10-29): "Erkannt". Schild found the request suspicious and
 * let it through; the text says why when the API tells it (would_block_reason, D36 open items, contracts
 * v0.5: events, alerts), else the generic sentence.
 */
export const WOULD_BLOCK_EXPLAIN = 'Erkannt, aber durchgelassen. Schild hätte die Anfrage sonst gesperrt.'
/** Counts of several would_block (KPIs, chart bins) have no single reason: where to find it. */
export const WOULD_BLOCK_MIXED = 'Erkannt, aber durchgelassen, zum Beispiel wegen einer Freigabe oder der Lernphase. Den Grund siehst du bei jedem Alarm und Ereignis.'
/** Text for an aggregate of would_block: in the test profile the reason is the profile, else it varies. */
export function wouldBlockNote(observe: boolean): string {
  return observe ? letThroughText('gateway_observe') : WOULD_BLOCK_MIXED
}
/** Short, calm labels of WouldBlockReason (contract enum, first applicable in this order). */
export const WOULD_BLOCK_REASON: Record<WouldBlockReason, string> = {
  gateway_observe: 'Testprofil',
  site_observe: 'diese Website wird nur beobachtet',
  learning: 'Lernphase',
  scenario_observe: 'Verhaltensprüfung beobachtet nur',
  source_detect: 'Regelquelle steht auf Erkennen',
  settling: 'Update wartet noch',
  allowlist: 'Freigabe',
  shared_address: 'geteilte Adresse',
}
/** "Erkannt, aber durchgelassen: Testprofil"; without a known reason the generic text. */
export function letThroughText(reason?: string | null): string {
  const r = reason ? WOULD_BLOCK_REASON[reason as WouldBlockReason] : undefined
  return r ? `Erkannt, aber durchgelassen: ${r}` : WOULD_BLOCK_EXPLAIN
}

export const OUTCOMES: Record<Outcome, { label: string, tone: StatusTone, explain: string }> = {
  passed: { label: 'Durchgelassen', tone: 'neutral', explain: 'Unauffällig, die Anfrage kam durch.' },
  logged: { label: 'Notiert', tone: 'info', explain: 'Etwas fiel auf, aber zu wenig zum Sperren, oder eine Ausnahme deckt die Anfrage. Schild hat es notiert.' },
  blocked: { label: 'Gesperrt', tone: 'danger', explain: 'Schild hat die Anfrage gesperrt. Die Person sah eine Sperrseite mit Vorfallnummer.' },
  would_block: { label: 'Erkannt', tone: 'warning', explain: WOULD_BLOCK_EXPLAIN },
}

export const OUTCOME_ORDER: Outcome[] = ['blocked', 'would_block', 'logged', 'passed']

export const HEALTH: Record<Health, { label: string, tone: StatusTone }> = {
  ok: { label: 'Erreichbar', tone: 'success' },
  slow: { label: 'Langsam', tone: 'warning' },
  down: { label: 'Nicht erreichbar', tone: 'danger' },
  unknown: { label: 'Noch kein Kontakt', tone: 'neutral' },
}

export const REASONS: Record<BaselineReason, { title: string, next: string, severe: boolean, to?: string }> = {
  waf_down: { title: 'Der lokale Filter läuft nicht.', next: 'Starte Schild neu (z. B. „systemctl restart schild“) und schau ins Server-Log.', severe: true },
  crs_off: { title: 'Die Grundregeln (OWASP CRS) sind ausgeschaltet.', next: 'Schalte sie unter Regeln > OWASP CRS wieder ein.', severe: true, to: '/settings/rules/crs' },
  crs_detect: { title: 'Die Grundregeln (OWASP CRS) erkennen nur und sperren nichts.', next: 'Stell sie unter Regeln > OWASP CRS auf Sperren.', severe: false, to: '/settings/rules/crs' },
  geo_db_old: { title: 'Die Länder-Datenbank fehlt oder ist älter als 60 Tage.', next: 'Land und Netz einer Adresse sind dann ungenau oder unbekannt, alles andere läuft weiter. Im Container-Image kommt mit jedem Update eine neue Datenbank mit.', severe: false },
  trusted_proxies_too_broad: { title: 'Die Proxy-Liste in schild.yaml ist zu weit gefasst.', next: 'Schild glaubt deshalb keinem Weiterleitungs-Header und wertet jede Anfrage unter der direkten Verbindungsadresse. Grenz ingress.trusted_proxies auf die Adressen deines Proxys ein und starte Schild neu.', severe: false },
  trusted_proxies_missing: { title: 'Schild sieht nur die Adresse deines Proxys, nicht die deiner Besucher:innen.', next: 'Die Anfragen kommen von einer privaten Adresse mit Weiterleitungs-Header, der Schild nicht vertraut, etwa nginx vor einem Docker-Container. Dann zählen alle als eine Adresse, und Szenarien sperren niemanden. Trag die Adresse deines Proxys unter ingress.trusted_proxies in schild.yaml ein und starte Schild neu.', severe: false },
  dashboard_settings_dropped: { title: 'Einstellungen aus dem Dashboard passen nicht mehr zur schild.yaml.', next: 'Schild hat sie beim Start nicht übernommen, es gilt die schild.yaml. Prüf die Schalter der Regeln, Szenarien und Limits sowie die Aufbewahrung und speichere sie neu. Der Grund steht im Server-Log und in „schild status“.', severe: false, to: '/settings' },
  cluster_peers_unreachable: { title: 'Ein Server des Clusters ist von hier aus nicht erreichbar.', next: 'Dieser Server arbeitet weiter und gleicht ab, sobald der andere wieder da ist. Welcher fehlt, steht auf der Seite Cluster.', severe: false, to: '/server/group' },
  cluster_config_drift: { title: 'Die Server des Clusters laufen mit unterschiedlicher Konfiguration.', next: 'Verteile schild.yaml und rules.d auf alle Server gleich. Welcher abweicht, steht auf der Seite Cluster.', severe: false, to: '/server/group' },
  cluster_state_differs: { title: 'Dieser Server hat nicht denselben Stand wie ein anderer Server im Cluster.', next: 'Sperren, Einstellungen, Freigaben oder Logins weichen seit mehr als 30 Sekunden ab. Der Server gleicht von selbst neu ab, höchstens einmal pro Minute. Bleibt der Hinweis stehen, steht der Grund im Server-Log. Welcher Server abweicht, steht auf der Seite Cluster.', severe: false, to: '/server/group' },
  cluster_clock_skew: { title: 'Die Uhren der Server im Cluster gehen auseinander.', next: 'Im Cluster gilt die spätere Änderung, dafür brauchen die Server gleiche Uhren. Richte auf jedem Server eine Zeitsynchronisation ein, etwa chrony oder systemd-timesyncd.', severe: false, to: '/server/group' },
  cluster_clock_out_of_service: { title: 'Dieser Server nimmt gerade keine Anfragen an, weil seine Uhr falsch geht.', next: 'Die anderen Server des Clusters sind sich über die Uhrzeit einig, und die Uhr dieses Servers weicht um eine Minute oder mehr davon ab. Er meldet sich deshalb als nicht bereit. Stell die Uhr richtig, am besten über eine Zeitsynchronisation wie chrony oder systemd-timesyncd. Danach nimmt er von selbst wieder Anfragen an.', severe: true, to: '/server/group' },
  cluster_counts_not_taken: { title: 'Dieser Server hat beim Start die laufenden Zähler des Clusters nicht übernommen.', next: 'Limits und Szenarien zählen auf diesem Server deshalb von null, bis ihre Zeitfenster abgelaufen sind. Sperren, Einstellungen und Logins sind davon nicht betroffen. Der Server versucht es alle 30 Sekunden erneut. Sobald es gelingt, verschwindet der Hinweis. Der Grund steht im Server-Log.', severe: false, to: '/server/group' },
  disk_full: { title: 'Der Speicher für Ereignisse ist voll.', next: 'Älteste Ereignisse werden zuerst gelöscht. Erhöhe die Obergrenze oder verkürze die Aufbewahrung.', severe: false, to: '/settings' },
}

export const TTLS: { value: Ttl, label: string }[] = [
  { value: '24h', label: '24 Stunden' },
  { value: '7d', label: '7 Tage' },
  { value: '30d', label: '30 Tage' },
  { value: 'never', label: 'Dauerhaft' },
]

export const ALLOW_LEVELS: Record<'no_block' | 'bypass_waf', { label: string, explain: string }> = {
  no_block: { label: 'Nie sperren', explain: 'Diese Absender werden nie gesperrt. Schild prüft und notiert weiter, was sie tun. Empfohlen.' },
  bypass_waf: { label: 'Filter überspringen', explain: 'Der Filter wird für diese Absender komplett übersprungen. Nur für eigene Monitoring- oder Deploy-Server.' },
}

/** German wording for the build marker that buildinfo.String() appends to the version (API field version). */
export const TEST_BUILD_TEXT = 'Testversion: Testschlüssel und Testprofil erlaubt'
/**
 * "schild 0.1.0-alpha (non-release: test keys and test profile allowed)" -> "schild 0.1.0-alpha · Testversion: …"
 * and "schild 1.0.0 (release)" -> "schild 1.0.0" (Messung 2026-10-29 abend 4.5: English in header and Schutzstatus).
 */
export function versionText(version: string): string {
  return version
    .replace(/\s*\(non-release[^)]*\)/i, ` · ${TEST_BUILD_TEXT}`)
    .replace(/\s*\(release\)/i, '')
    .trim()
}

export const ATTRIBUTION: Record<string, string> = {
  tcp_peer: 'direkte Verbindung',
  trusted_proxy: 'über einen vertrauenswürdigen Proxy',
  localhost: 'von diesem Server, localhost',
  untrusted_header: 'aus einem nicht vertrauenswürdigen Header',
}

export const NET_CLASS: Record<string, string> = {
  hosting: 'Rechenzentrum',
  residential: 'Privatanschluss',
  mobile: 'Mobilfunk',
  business: 'Firmennetz',
  education: 'Hochschule',
  government: 'Behörde',
  vpn: 'VPN',
  tor: 'Tor',
  unknown: 'unbekannt',
}

const EVENT_TYPES: Record<string, string> = {
  'schild.request.evaluated.v1': 'Anfrage geprüft',
  'schild.request.blocked.v1': 'Anfrage gesperrt',
  'schild.request.unblocked.v1': 'Sperre aufgehoben',
  'schild.session.flagged.v1': 'Auffällige Sitzung',
  'schild.environment.changed.v1': 'Umgebung geändert',
  'schild.environment.anomaly.v1': 'Ungewöhnlicher Serverzustand',
  'schild.advisory.assessed.v1': 'Sicherheitswarnung abgeglichen',
  'schild.rule.repository_switched.v1': 'Schalter einer Regelquelle geändert',
  'schild.rule.repository_updated.v1': 'Regeln einer Quelle aktualisiert',
  'schild.rule.disabled.v1': 'Regel ausgeschaltet',
  'schild.rule.enabled.v1': 'Regel eingeschaltet',
  'schild.rule.approved.v1': 'Regel freigegeben',
  'schild.rule.rejected.v1': 'Regel abgelehnt',
  'schild.rule.exception_set.v1': 'Ausnahme für eine Regel gesetzt',
  'schild.rule.exception_removed.v1': 'Ausnahme für eine Regel entfernt',
  'schild.block.set.v1': 'IP gesperrt',
  'schild.block.lifted.v1': 'Sperre aufgehoben',
  'schild.behaviour.triggered.v1': 'Szenario ausgelöst',
  'schild.ratelimit.exceeded.v1': 'Limit überschritten',
  'schild.distributed.detected.v1': 'Welle erkannt',
  'schild.distributed.ended.v1': 'Welle beendet',
  'schild.dashboard.access_reset.v1': 'Dashboard-Zugang zurückgesetzt',
  'schild.incident.exported.v1': 'Vorfall exportiert',
  'schild.access.protection_set.v1': 'Zugriffsschutz eingerichtet',
  'schild.access.protection_removed.v1': 'Zugriffsschutz entfernt',
  'schild.access.login.v1': 'Anmeldung am Zugriffsschutz',
  'schild.access.prefix_locked.v1': 'Zugriffsschutz: zu viele Fehlversuche',
  'schild.crawler.policy_set.v1': 'Vorgaben für Crawler geändert',
}

export const EVENT_TYPE_OPTIONS = Object.entries(EVENT_TYPES).map(([value, label]) => ({ value, label }))

export function eventTypeLabel(type: string): string {
  return EVENT_TYPES[type] ?? 'Ereignis'
}

export function isRequestEvent(e: Pick<EventSummary, 'type'>): boolean {
  return e.type.startsWith('schild.request.')
}

/** One-line German description of an event for lists. */
export function eventHeadline(e: EventSummary): string {
  if (isRequestEvent(e)) {
    const target = `${e.method ?? ''} ${e.path ?? ''}`.trim()
    return target || eventTypeLabel(e.type)
  }
  // A block that a gateway in the test profile only recorded.
  if (e.type === 'schild.block.set.v1' && e.outcome === 'would_block') return 'IP wäre gesperrt worden'
  // "behaviour path_probing block": name the scenario.
  if (e.type === 'schild.behaviour.triggered.v1') {
    const id = /^behaviour (\w+) /.exec(e.summary ?? '')?.[1]
    const name = id ? SCENARIO_NAMES[id] : undefined
    if (name) return `Szenario: ${name}`
  }
  return eventTypeLabel(e.type)
}

/** Names of the behaviour scenarios, as in lib/behaviour (kept here so labels has no import from it). */
const SCENARIO_NAMES: Record<string, string> = {
  login_bruteforce: 'Passwort-Raten',
  credential_stuffing: 'Ausprobieren von Zugangsdaten',
  path_probing: 'Suche nach Schwachstellen',
  aggressive_crawl: 'Aggressives Abrufen',
  waf_repeat: 'Wiederholte Angriffsversuche',
}

/** Severity of matched rules in German. */
export const SEVERITY: Record<string, string> = {
  critical: 'kritisch',
  error: 'hoch',
  warning: 'mittel',
  notice: 'gering',
}
