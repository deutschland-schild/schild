/** Words for the mode a gateway runs in and for the state of its group (MVP-27, D105). */
import type { StatusTone } from '@schild/ui'
import type { GroupMember, GroupState, GroupStatus } from '@/api/group'
import { formatDuration, formatNumber } from '@schild/ui'
import { plural } from './summary'

const list = (names: string[]) => names.length <= 1 ? names.join('') : `${names.slice(0, -1).join(', ')} und ${names.at(-1)}`

/** Gateways that are members, this node included. */
export const gateways = (s: GroupStatus): GroupMember[] => (s.members ?? []).filter(m => m.role === 'gateway' && m.state !== 'removed')
export const edges = (s: GroupStatus): GroupMember[] => (s.members ?? []).filter(m => m.role === 'edge' && m.state !== 'removed')
export const removedMembers = (s: GroupStatus): GroupMember[] => (s.members ?? []).filter(m => m.state === 'removed')

export interface ModeView {
  /** "Einzelner Server" or "Cluster · 3 Server". */
  label: string
  /** The same for narrow screens. */
  short: string
  tone: StatusTone
  /** One sentence for the tooltip and for screen readers. */
  title: string
}

const STATE: Record<GroupState, { tone: StatusTone, label: string }> = {
  no_group: { tone: 'warning', label: 'Kein Cluster' },
  syncing: { tone: 'info', label: 'Abgleich startet' },
  active: { tone: 'success', label: 'Abgleich aktiv' },
  degraded: { tone: 'warning', label: 'Abgleich eingeschränkt' },
  interrupted: { tone: 'warning', label: 'Abgleich unterbrochen' },
  removed: { tone: 'danger', label: 'Aus dem Cluster entfernt' },
}

/** The indicator that is on every page: alone or a node of a group, and how the group is doing. */
export function modeView(s: GroupStatus): ModeView {
  if (s.mode === 'single') {
    return s.state === 'no_group'
      ? { label: 'Einzelner Server', short: 'Einzeln', tone: 'warning', title: 'Dieser Server läuft allein. In schild.yaml ist ein Cluster eingeschaltet, er gehört aber zu keinem.' }
      : { label: 'Einzelner Server', short: 'Einzeln', tone: 'neutral', title: 'Dieser Server läuft allein, ohne Cluster.' }
  }
  const n = gateways(s).length
  const st = STATE[s.state ?? 'active']
  return { label: `Cluster · ${formatNumber(n)} Server`, short: `Cluster · ${formatNumber(n)}`, tone: st.tone, title: `Dieser Server ist Teil eines Clusters aus ${formatNumber(n)} Servern. ${st.label}.` }
}

export interface StateView {
  tone: StatusTone
  label: string
  text: string
}

/** The state of the group in calm words, as this server sees it. */
export function stateView(s: GroupStatus): StateView {
  const key = s.state ?? 'active'
  const base = STATE[key]
  const all = gateways(s)
  const away = all.filter(m => m.state === 'unreachable' || m.state === 'no_contact').map(m => m.name)
  const text: Record<GroupState, string> = {
    no_group: 'In schild.yaml ist cluster.enabled gesetzt, aber dieser Server gehört zu keinem Cluster. Er läuft allein. Den Grund nennt das Server-Log.',
    syncing: 'Dieser Server holt gerade den Stand des Clusters.',
    active: all.length > 1 ? `Alle ${formatNumber(all.length)} Server haben denselben Stand.` : 'Dieser Server ist bisher der einzige im Cluster.',
    degraded: `${list(away)} ${away.length === 1 ? 'ist' : 'sind'} gerade nicht erreichbar. Mit den anderen Servern läuft der Abgleich weiter.`,
    interrupted: 'Dieser Server arbeitet mit dem letzten Stand weiter.',
    removed: 'Dieser Server wurde aus dem Cluster genommen. Er arbeitet mit seinem letzten Stand weiter und teilt nichts mehr.',
  }
  return { ...base, text: text[key] }
}

export const MEMBER_STATE: Record<GroupMember['state'], { tone: StatusTone, label: string, title?: string }> = {
  self: { tone: 'neutral', label: 'Dieser Server' },
  ok: { tone: 'success', label: 'Erreichbar' },
  unreachable: { tone: 'warning', label: 'Nicht erreichbar' },
  no_contact: { tone: 'warning', label: 'Kein Kontakt' },
  asks_elsewhere: { tone: 'neutral', label: 'Fragt einen anderen Server', title: 'Eine Balancer-VM fragt immer nur ein Gateway. Dieses hat sie zuletzt nicht gefragt.' },
  removed: { tone: 'neutral', label: 'Entfernt' },
}

export const CONFIG_STATE: Record<NonNullable<GroupMember['config']>, string> = {
  same: 'gleich',
  differs: 'weicht ab',
  unknown: 'unbekannt',
}

export interface NodeView {
  tone: StatusTone
  /** Whether the server takes traffic, in two or three words. */
  label: string
  /** One sentence on what that means. */
  text: string
}

/**
 * One gateway on the page of the group: whether it takes traffic. What this server last heard of it comes
 * first (a server that is not reached may still serve visitors), then what the server said of itself.
 */
export function nodeView(m: GroupMember): NodeView {
  if (m.state === 'unreachable' || m.state === 'no_contact') {
    return { tone: 'warning', label: m.state === 'unreachable' ? 'Nicht erreichbar' : 'Kein Kontakt', text: 'Dieser Server erreicht ihn gerade nicht. Ob er Besucher:innen bedient, ist von hier aus nicht zu sehen.' }
  }
  switch (m.vitals?.service) {
    case 'ready':
      return { tone: 'success', label: 'Nimmt Anfragen an', text: 'Er meldet sich als bereit.' }
    case 'draining':
      return { tone: 'warning', label: 'Wird angehalten', text: 'Er meldet sich als nicht mehr bereit und bedient noch seine offenen Verbindungen.' }
    case 'not_ready':
      return { tone: 'warning', label: 'Noch nicht bereit', text: 'Er holt den Stand des Clusters oder lädt seine Regeln. Bis dahin meldet er sich nicht als bereit.' }
    default:
      return { tone: 'neutral', label: 'Erreichbar', text: 'Er hat noch nicht gemeldet, wie es ihm geht. Eine ältere Version meldet das nicht.' }
  }
}

export interface GroupTotals {
  gateways: number
  /** Gateways that said they are ready for the balancer, this one included. */
  ready: number
  /** Gateways this server does not reach. */
  away: number
  /** Sum of what the gateways told, null when none told anything. */
  requestsPerS: number | null
  /** Gateways whose numbers are in the sum. */
  reporting: number
}

/** The numbers above the servers: how many take traffic and what they serve together. */
export function groupTotals(s: GroupStatus): GroupTotals {
  const all = gateways(s)
  const told = all.filter(m => m.vitals && m.state !== 'unreachable' && m.state !== 'no_contact')
  return {
    gateways: all.length,
    ready: told.filter(m => m.vitals?.service === 'ready').length,
    away: all.filter(m => m.state === 'unreachable' || m.state === 'no_contact').length,
    requestsPerS: told.length ? told.reduce((sum, m) => sum + (m.vitals?.requests_per_s ?? 0), 0) : null,
    reporting: told.length,
  }
}

/** From this difference on the clock of a server is named as off (the gateway: cluster_clock_skew). */
export const CLOCK_SKEW_HINT_MS = 10_000

/** The clock of a member against this server's, in words; '' when it named no time. Below 2 s it counts as the same. */
export function clockText(skewMs: number | undefined): string {
  if (skewMs === undefined) return ''
  const abs = Math.abs(skewMs)
  if (abs < 2000) return 'gleich'
  const amount = abs < 120_000 ? plural(Math.round(abs / 1000), 'Sekunde', 'Sekunden') : formatDuration(abs / 1000)
  return `${amount} ${skewMs > 0 ? 'vor' : 'nach'}`
}

const STATE_CLASS: Record<string, string> = { blocks: 'Sperren', settings: 'Einstellungen', access: 'Freigaben', logins: 'Logins' }

/**
 * Whether what is in force on a member is what is in force on this server (GroupMember.shared_state): the servers
 * compare a hash per area every five seconds. '' when the API names nothing (this server itself, an edge).
 */
export function stateText(st: GroupMember['shared_state']): { text: string, differs: boolean } {
  if (!st) return { text: '', differs: false }
  const classes = ['blocks', 'settings', 'access', 'logins'] as const
  const differing = classes.filter(c => st[c] === 'differs').map(c => STATE_CLASS[c]!)
  if (differing.length) return { text: `weicht ab: ${list(differing)}`, differs: true }
  if (classes.some(c => st[c] === 'unknown')) return { text: 'unbekannt', differs: false }
  return { text: 'gleich', differs: false }
}

/** Tone of a load bar: calm up to 80 %, a warning above, red from 95 %. */
export const loadTone = (ratio: number | null | undefined): StatusTone => ratio == null ? 'neutral' : ratio >= 0.95 ? 'danger' : ratio >= 0.8 ? 'warning' : 'success'

/** The hint on config drift; null when no gateway differs. */
export function configHint(s: GroupStatus): string | null {
  const names = s.config?.differing ?? []
  if (!names.length) return null
  return `Die Konfiguration von ${list(names)} weicht von diesem Server ab. Verteile schild.yaml und rules.d auf alle Server gleich.`
}

/** The short version of a build: "schild 0.1.0-alpha.4 (…)" becomes "0.1.0-alpha.4". */
export const shortVersion = (v: string | undefined) => (v ?? '').replace(/^schild\s+/, '').replace(/\s*\(.*\)$/, '')

/** What the group shares, in one sentence. */
export function sharedText(s: GroupStatus): string {
  const sh = s.shared
  if (!sh) return ''
  const data = 'Ereignisse und Anfragen hält jeder Server auch von den anderen.'
  return `Geteilt: ${plural(sh.blocks, 'laufende Sperre', 'laufende Sperren')}, ${plural(sh.settings, 'Einstellung', 'Einstellungen')}, ${plural(sh.access, 'Liste', 'Listen')} mit Freigaben und ${plural(sh.logins, 'Liste', 'Listen')} mit Logins. ${data}`
}

/** The counters of the sync since the start of this server. */
export function countersText(s: GroupStatus): string {
  const c = s.counters
  if (!c) return ''
  return `Seit dem Start: ${plural(c.taken, 'Änderung', 'Änderungen')} übernommen, ${formatNumber(c.refused)} abgelehnt, ${formatNumber(c.deferred)} zurückgestellt, ${formatNumber(c.unread)} aus einer neueren Version ungelesen.`
}

/** Where a block was decided, for the list of blocked addresses; empty on a single gateway. */
export function blockNodeText(b: { node?: string, node_self?: boolean }): string {
  if (!b.node) return ''
  return b.node_self ? 'Auf diesem Server entschieden' : `Von ${b.node} entschieden`
}

/** How far an erasure got in the group; empty on a single gateway. */
export function erasureNodesText(nodes: { reached: string[], open: string[] } | undefined): string {
  if (!nodes) return ''
  const done = `Gelöscht auf ${list(nodes.reached)}.`
  return nodes.open.length ? `${done} Noch offen: ${list(nodes.open)}. Dort wird gelöscht, sobald der Server den Cluster wieder erreicht.` : done
}
