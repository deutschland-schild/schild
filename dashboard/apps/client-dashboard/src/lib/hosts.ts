/**
 * Labels and helpers for the "Server" section (MVP-11, contracts/host-check.md).
 * Everything here is pure: German copy, ordering, evidence formatting, fingerprint handling.
 */
import type { MetaItem, StatusTone } from '@schild/ui'
import type { AcceptedFinding, HostSummary, HostReport, HostFinding, InventoryItem, Severity, SeverityCounts, ServersSummary, Agent } from '@/api/hosts'
import { formatBytes, formatNumber, formatRelative } from '@schild/ui'
import { plural } from './summary'

export type Area = HostFinding['area']

/**
 * App servers with a schild-agent (MVP-11) stay out of the dashboard for now (initiator 2026-11-02: "dann lass
 * uns agenten erstmal ausschließen"): no agents in the switcher, no "Server hinzufügen", no Agenten tab, the
 * Server-Check shows the gateway only. The code and the API stay; tests switch it on. Set VITE_HOST_AGENTS=true
 * to see it in a dev build.
 */
export const FEATURES = { hostAgents: import.meta.env.VITE_HOST_AGENTS === 'true' }

/**
 * Detail order on the page (spec: Distribution & Kernel, Updates, Offene Ports, Firewall, SSH, TLS, Software;
 * v0.5 D38 adds Logs before Software, so the inventory table stays last).
 */
export const AREAS: { id: Area, label: string, hint: string }[] = [
  { id: 'distribution', label: 'Distribution & Kernel', hint: 'Welches System läuft und wie lange es noch Updates bekommt.' },
  { id: 'updates', label: 'Updates', hint: 'Wartende Updates, automatische Sicherheitsupdates und nötige Neustarts.' },
  { id: 'ports', label: 'Offene Ports', hint: 'Dienste, die auf Adressen außerhalb von localhost lauschen.' },
  { id: 'firewall', label: 'Firewall', hint: 'Ob eine Firewall aktiv ist und Docker sie umgeht.' },
  { id: 'ssh', label: 'SSH', hint: 'Wie man sich am Server anmelden kann.' },
  { id: 'tls', label: 'TLS', hint: 'Zertifikate der Websites auf diesem Gateway.' },
  { id: 'logs', label: 'Logs', hint: 'Ob Logdateien eine Obergrenze haben und regelmäßig gekürzt werden.' },
  { id: 'software', label: 'Software', hint: 'Laufzeiten, Server, Datenbanken und Apps mit Version und Support-Ende.' },
]

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY: Record<Severity, { label: string, tone: StatusTone }> = {
  critical: { label: 'Dringend', tone: 'danger' },
  high: { label: 'Hoch', tone: 'danger' },
  medium: { label: 'Mittel', tone: 'warning' },
  low: { label: 'Niedrig', tone: 'info' },
  info: { label: 'Hinweis', tone: 'neutral' },
}

export const HOST_STATUS: Record<HostSummary['status'], { label: string, tone: StatusTone }> = {
  ok: { label: 'Alles in Ordnung', tone: 'success' },
  findings: { label: 'Offene Befunde', tone: 'warning' },
  silent: { label: 'Meldet sich nicht', tone: 'neutral' },
  waiting: { label: 'Wartet auf ersten Bericht', tone: 'info' },
  revoked: { label: 'Zurückgezogen', tone: 'neutral' },
}

export const AGENT_STATUS: Record<Agent['status'], { label: string, tone: StatusTone }> = {
  pending: { label: 'Wartet auf Bestätigung', tone: 'warning' },
  enrolled: { label: 'Aktiv', tone: 'success' },
  revoked: { label: 'Zurückgezogen', tone: 'neutral' },
}

export const UNREADABLE_REASON: Record<NonNullable<HostFinding['unreadable']>['reason'], string> = {
  permission_denied: 'keine Leserechte',
  not_installed: 'Werkzeug nicht installiert',
  not_supported: 'auf diesem System nicht unterstützt',
  not_configured: 'nicht eingerichtet',
  timeout: 'hat zu lange gedauert',
  parse_error: 'Ausgabe nicht verstanden',
}

/** What the check would need, in words ("needs" is root, a capability or group:<name>). */
export function needsText(needs: string | undefined): string {
  if (!needs) return ''
  if (needs === 'root') return 'braucht root'
  if (needs.startsWith('group:')) return `braucht die Gruppe ${needs.slice(6)}`
  if (needs.startsWith('CAP_')) return `braucht ${needs}`
  return `braucht ${needs}`
}

/** Why the gateway rejected the last delivery (contract codes), calm and with the next step. */
export const REJECT_REASON: Record<string, string> = {
  expired: 'Der Bericht war zu alt. Meist geht die Uhr des App-Servers falsch: prüf, ob dort NTP läuft.',
  clock_skew: 'Die Uhr des App-Servers geht vor. Prüf, ob dort NTP läuft.',
  signature: 'Die Signatur passte zu keinem bestätigten Agent-Schlüssel.',
  revoked: 'Der Schlüssel dieses Agents ist zurückgezogen.',
  replay: 'Derselbe Bericht kam zweimal an. Der zweite wurde verworfen, das ist so gewollt.',
  channel: 'Der Bericht war für ein anderes Gateway bestimmt.',
  forbidden_field: 'Der Bericht enthielt ein Feld, das nie im Bericht stehen darf. Schild hat ihn deshalb nicht gespeichert.',
  forbidden_content: 'Der Bericht enthielt etwas, das wie ein Geheimnis aussieht. Schild hat ihn deshalb nicht gespeichert.',
  schema: 'Der Bericht hatte nicht das erwartete Format. Passt die Version von schild-agent auf dem App-Server?',
  oversize: 'Der Bericht war zu groß.',
  malformed: 'Der Bericht war beschädigt.',
}

export function rejectReason(code: string): string {
  return REJECT_REASON[code] ?? `Abgelehnt (${code}).`
}

const SOURCE: Record<string, string> = {
  os_release: '/etc/os-release',
  uname: 'uname',
  eol_table: 'EOL-Tabelle',
  apt: 'apt',
  dnf: 'dnf',
  yum: 'yum',
  dpkg: 'dpkg',
  rpm: 'rpm',
  unattended_upgrades: 'unattended-upgrades',
  dnf_automatic: 'dnf-automatic',
  reboot_required: 'reboot-required',
  needs_restarting: 'needs-restarting',
  ss: 'ss',
  proc_net: '/proc/net',
  nft: 'nftables',
  iptables: 'iptables',
  ufw: 'ufw',
  firewalld: 'firewalld',
  sshd_t: 'sshd -T',
  sshd_config: 'sshd_config',
  journal: 'Journal',
  auth_log: 'auth.log',
  cert_store: 'Zertifikatsspeicher',
  tls_handshake: 'TLS-Verbindung',
  binary: 'Programmversion',
  app_path: 'App-Verzeichnis',
  systemd: 'systemd',
  // v0.5 (D38, area logs)
  docker_daemon: '/etc/docker/daemon.json',
  docker_container: 'Docker-Container',
  journald_conf: 'journald.conf',
  logrotate_conf: 'logrotate-Regeln',
  logrotate_status: 'logrotate-Status',
  stat: 'Dateigröße',
  caddyfile: 'Caddyfile',
}

const dateFmt = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: 'UTC' })
/** "10.06.2026" for a YYYY-MM-DD date or a timestamp. */
export function formatDay(value: string): string {
  const d = new Date(/^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : value)
  return Number.isNaN(d.getTime()) ? value : dateFmt.format(d)
}

/** Typed evidence as MetaLine parts: facts only, never free text (the report has none). */
export function evidenceItems(f: HostFinding): MetaItem[] {
  const e = f.evidence ?? {}
  const out: MetaItem[] = []
  if (e.port !== undefined) {
    const where = e.address ? (e.address === '*' ? ' auf allen Adressen' : ` auf ${e.address}`) : ''
    out.push(`Port ${e.port}/${e.protocol ?? 'tcp'}${where}`)
  }
  if (e.process) out.push({ text: e.process, mono: true })
  if (e.setting) {
    out.push({ text: `${e.setting} ${e.value ?? ''}`.trim(), mono: true })
    if (e.expected && e.expected !== e.value) out.push(`empfohlen: ${e.expected}`)
  }
  if (e.package) {
    const v = e.installed_version ? ` ${e.installed_version}` : ''
    const to = e.candidate_version ? ` → ${e.candidate_version}` : ''
    out.push({ text: `${e.package}${v}${to}`, mono: true })
  }
  if (e.packages?.length) {
    const shown = e.packages.slice(0, 5).join(', ')
    const more = e.packages.length > 5 ? ` und ${e.packages.length - 5} weitere` : ''
    out.push({ text: `${shown}${more}`, mono: true, title: e.packages.join(', ') })
  }
  if (e.count !== undefined && !e.packages?.length) {
    out.push(e.window_hours ? `${formatNumber(e.count)} in ${e.window_hours} h` : `Anzahl: ${formatNumber(e.count)}`)
  }
  if (e.not_after) out.push(`gültig bis ${formatDay(e.not_after)}${e.days_left !== undefined ? ` (noch ${plural(e.days_left, 'Tag', 'Tage')})` : ''}`)
  else if (e.days_left !== undefined) out.push(`noch ${plural(e.days_left, 'Tag', 'Tage')}`)
  if (e.date) out.push(`Datum: ${formatDay(e.date)}`)
  // v0.5 (D38, area logs): size, growth and the share of the file system.
  if (e.size_bytes !== undefined) out.push(`Größe ${formatBytes(e.size_bytes)}`)
  if (e.growth_bytes_per_day !== undefined) out.push(`wächst um ${formatBytes(e.growth_bytes_per_day)} pro Tag`)
  if (e.fs_percent !== undefined) out.push(`${formatNumber(e.fs_percent)} % von ${e.mount ?? 'der Platte'}`)
  else if (e.mount) out.push({ text: e.mount, mono: true })
  if (e.policy) out.push(`Standard eingehend: ${e.policy}`)
  if (e.enabled !== undefined && e.policy === undefined) out.push(e.enabled ? 'an' : 'aus')
  if (e.path) out.push({ text: e.path, mono: true })
  if (e.source) out.push(`Quelle: ${SOURCE[e.source] ?? e.source}`)
  return out
}

export type FixConfig = NonNullable<HostFinding['fix_config']>

/**
 * How a config file of a fix takes effect (host-check.md section 2, fix_config): the dashboard says which
 * step applies it. The command itself, when there is one, is the finding's fix_command (shown below it).
 */
export function fixConfigApply(f: Pick<HostFinding, 'id' | 'fix_command'>, fc: FixConfig): string {
  switch (f.id) {
    case 'logs.docker_unbounded':
      return 'Docker liest die Datei beim Start. Die Grenze gilt nur für neu erstellte Container: Starte Docker neu und roll deine Apps danach neu aus.'
    case 'logs.journald_size':
      return f.fix_command ? 'Mit dem Befehl darunter liest journald die Datei neu ein.' : 'Starte journald danach neu: sudo systemctl restart systemd-journald'
    case 'logs.logrotate_config':
    case 'logs.large_file':
      return `logrotate liest die Datei beim nächsten täglichen Lauf. Teste vorher, ohne etwas zu ändern: sudo logrotate -d ${fc.path}`
  }
  return 'Lege die Datei mit genau diesem Inhalt an.'
}

/** Findings of one area, open ones first (by severity), then unreadable, then ok. */
export function sortFindings(list: HostFinding[]): HostFinding[] {
  const rank = (f: HostFinding) => f.status === 'finding' ? SEVERITY_ORDER.indexOf(f.severity) : f.status === 'unreadable' ? 10 : 20
  return [...list].sort((a, b) => rank(a) - rank(b) || a.title.localeCompare(b.title, 'de'))
}

/** Key of a finding within a report: check id plus subject. */
export function findingKey(f: { id: string, subject?: string | null }): string {
  return `${f.id}:${f.subject ?? ''}`
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

/**
 * Accepted findings in force (D102), keyed like the findings of the report: an acceptance covers
 * a finding of the same check and subject at the accepted severity or lower, never a higher one.
 */
export function acceptedInForce(report: HostReport | null | undefined, accepted: AcceptedFinding[] | undefined): Map<string, AcceptedFinding> {
  const by = new Map((accepted ?? []).map(a => [findingKey(a), a]))
  const out = new Map<string, AcceptedFinding>()
  for (const f of report?.findings ?? []) {
    const a = by.get(findingKey(f))
    if (f.status === 'finding' && a && SEVERITY_RANK[f.severity] <= SEVERITY_RANK[a.severity]) out.set(findingKey(f), a)
  }
  return out
}

export interface AreaGroup {
  id: Area
  label: string
  hint: string
  open: HostFinding[]
  /** Open in the report, accepted by the admin (D102): not counted as open. */
  accepted: HostFinding[]
  unreadable: HostFinding[]
  ok: HostFinding[]
}

/** Group a report by area in page order; areas the report does not cover are left out. */
export function groupByArea(report: HostReport, accepted?: AcceptedFinding[]): AreaGroup[] {
  const inForce = acceptedInForce(report, accepted)
  return AREAS.map((a) => {
    const all = sortFindings(report.findings.filter(f => f.area === a.id))
    return {
      ...a,
      open: all.filter(f => f.status === 'finding' && !inForce.has(findingKey(f))),
      accepted: all.filter(f => f.status === 'finding' && inForce.has(findingKey(f))),
      unreadable: all.filter(f => f.status === 'unreadable'),
      ok: all.filter(f => f.status === 'ok'),
    }
  }).filter(g => g.open.length || g.accepted.length || g.unreadable.length || g.ok.length || (g.id === 'software' && report.inventory.length))
}

/** Open findings above "info" (what the counts call findings). */
export function openCount(c: SeverityCounts): number {
  return c.critical + c.high + c.medium + c.low
}

/** "2 hoch, 1 mittel" for the severities that are not zero (info left out unless it is all there is). */
export function countsText(c: SeverityCounts, withInfo = false): string {
  const parts = SEVERITY_ORDER
    .filter(s => (withInfo || s !== 'info') && c[s] > 0)
    .map(s => `${formatNumber(c[s])} ${SEVERITY[s].label.toLowerCase()}`)
  return parts.join(', ')
}

/** Status dot tone of a host in the list. */
export function hostTone(h: HostSummary): StatusTone {
  if (h.silent || h.status === 'silent') return 'neutral'
  if (h.status === 'revoked') return 'neutral'
  if (h.status === 'waiting') return 'info'
  if (h.counts.critical || h.counts.high) return 'danger'
  if (openCount(h.counts)) return 'warning'
  return 'success'
}

/** Short status for the list entry: "meldet sich nicht" wins over counts. */
export function hostStatusText(h: HostSummary): string {
  if (h.silent || h.status === 'silent') return 'meldet sich nicht'
  if (h.status === 'revoked') return 'zurückgezogen'
  if (h.status === 'waiting') return 'wartet auf ersten Bericht'
  const n = openCount(h.counts)
  return n ? plural(n, 'offener Befund', 'offene Befunde') : 'keine offenen Befunde'
}

export function lastReportText(h: { last_report_at?: string | null }): string {
  return h.last_report_at ? `letzter Bericht ${formatRelative(h.last_report_at)}` : 'noch kein Bericht'
}

/** "alle 24 Stunden" for an interval in minutes. */
export function intervalText(minutes: number | null | undefined): string {
  if (!minutes) return ''
  if (minutes % 1440 === 0) return minutes === 1440 ? 'täglich' : `alle ${minutes / 1440} Tage`
  if (minutes % 60 === 0) return minutes === 60 ? 'stündlich' : `alle ${minutes / 60} Stunden`
  return `alle ${minutes} Minuten`
}

export type EolState = 'past' | 'soon' | 'ok' | 'unknown'
/** Support end relative to now: past, within 180 days, later, or unknown. */
export function eolState(eol: string | null | undefined, now = Date.now()): EolState {
  if (!eol) return 'unknown'
  const t = Date.parse(`${eol}T00:00:00Z`)
  if (Number.isNaN(t)) return 'unknown'
  if (t <= now) return 'past'
  if (t - now <= 180 * 24 * 3600_000) return 'soon'
  return 'ok'
}

export const INVENTORY_KIND: Record<InventoryItem['kind'], string> = {
  os_package: 'Paket',
  runtime: 'Laufzeit',
  server: 'Server',
  database: 'Datenbank',
  app: 'App',
}

/** Inventory sorted for the table: support ended first, then ending soon, then by kind and name; plugins follow their app. */
export function sortInventory(items: InventoryItem[], now = Date.now()): InventoryItem[] {
  const rank: Record<EolState, number> = { past: 0, soon: 1, ok: 2, unknown: 3 }
  const kinds = Object.keys(INVENTORY_KIND)
  const apps = items.filter(i => !i.parent)
  const plugins = items.filter(i => i.parent)
  const sorted = [...apps].sort((a, b) => rank[eolState(a.eol, now)] - rank[eolState(b.eol, now)] || kinds.indexOf(a.kind) - kinds.indexOf(b.kind) || a.name.localeCompare(b.name))
  const out: InventoryItem[] = []
  for (const a of sorted) {
    out.push(a)
    out.push(...plugins.filter(p => p.parent === a.name && (!a.path || !p.path || p.path.startsWith(a.path))))
  }
  for (const p of plugins) if (!out.includes(p)) out.push(p)
  return out
}

/** Lower-case sha256 hex without prefix and separators, for comparing what a person pasted. */
export function normalizeFingerprint(input: string): string {
  return input.trim().toLowerCase().replace(/^sha256:/, '').replace(/[^0-9a-f]/g, '')
}

/** "sha256:" plus 64 hex in groups of four, so two fingerprints can be compared by eye. */
export function groupFingerprint(fp: string): string {
  const hex = normalizeFingerprint(fp)
  return hex.match(/.{1,4}/g)?.join(' ') ?? hex
}

/** The fingerprint in API form (sha256:<64 hex>) or null when the input is not one. */
export function toApiFingerprint(input: string): string | null {
  const hex = normalizeFingerprint(input)
  return /^[0-9a-f]{64}$/.test(hex) ? `sha256:${hex}` : null
}

/** Overview card: one calm sentence. */
export function serversSentence(s: ServersSummary): string {
  const open = openCount(s.findings)
  const hosts = plural(s.hosts, 'Server', 'Server')
  const findings = open ? `${plural(open, 'offener Befund', 'offene Befunde')} (${countsText(s.findings)})` : 'keine offenen Befunde'
  return `${hosts} im Blick, ${findings}.`
}
