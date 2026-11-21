/** Words for the mode a gateway runs in and for the state of its group (MVP-27, D103). */
import type { StatusTone } from '@schild/ui'
import type { GroupMember, GroupState, GroupStatus } from '@/api/group'
import { formatNumber } from '@schild/ui'
import { plural } from './summary'

const list = (names: string[]) => names.length <= 1 ? names.join('') : `${names.slice(0, -1).join(', ')} und ${names.at(-1)}`

/** Gateways that are members, this node included. */
export const gateways = (s: GroupStatus): GroupMember[] => (s.members ?? []).filter(m => m.role === 'gateway' && m.state !== 'removed')
export const edges = (s: GroupStatus): GroupMember[] => (s.members ?? []).filter(m => m.role === 'edge' && m.state !== 'removed')
export const removedMembers = (s: GroupStatus): GroupMember[] => (s.members ?? []).filter(m => m.state === 'removed')

export interface ModeView {
  /** "Einzelner Server" or "Gruppe · 3 Server". */
  label: string
  /** The same for narrow screens. */
  short: string
  tone: StatusTone
  /** One sentence for the tooltip and for screen readers. */
  title: string
}

const STATE: Record<GroupState, { tone: StatusTone, label: string }> = {
  no_group: { tone: 'warning', label: 'Keine Gruppe' },
  syncing: { tone: 'info', label: 'Abgleich startet' },
  active: { tone: 'success', label: 'Abgleich aktiv' },
  degraded: { tone: 'warning', label: 'Abgleich eingeschränkt' },
  interrupted: { tone: 'warning', label: 'Abgleich unterbrochen' },
  paused: { tone: 'warning', label: 'Abgleich pausiert' },
  removed: { tone: 'danger', label: 'Aus der Gruppe entfernt' },
}

/** The indicator that is on every page: alone or a node of a group, and how the group is doing. */
export function modeView(s: GroupStatus): ModeView {
  if (s.mode === 'single') {
    return s.state === 'no_group'
      ? { label: 'Einzelner Server', short: 'Einzeln', tone: 'warning', title: 'Dieser Server läuft allein. In schild.yaml ist eine Gruppe eingeschaltet, er gehört aber zu keiner.' }
      : { label: 'Einzelner Server', short: 'Einzeln', tone: 'neutral', title: 'Dieser Server läuft allein, ohne Gruppe.' }
  }
  const n = gateways(s).length
  const st = STATE[s.state ?? 'active']
  return { label: `Gruppe · ${formatNumber(n)} Server`, short: `Gruppe · ${formatNumber(n)}`, tone: st.tone, title: `Dieser Server ist Teil einer Gruppe aus ${formatNumber(n)} Servern. ${st.label}.` }
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
    no_group: 'In schild.yaml ist cluster.enabled gesetzt, aber dieser Server gehört zu keiner Gruppe. Er läuft allein. Den Grund nennt das Server-Log.',
    syncing: 'Dieser Server holt gerade den Stand der Gruppe.',
    active: all.length > 1 ? `Alle ${formatNumber(all.length)} Server haben denselben Stand.` : 'Dieser Server ist bisher der einzige in der Gruppe.',
    degraded: `${list(away)} ${away.length === 1 ? 'ist' : 'sind'} gerade nicht erreichbar. Mit den anderen Servern läuft der Abgleich weiter.`,
    interrupted: 'Dieser Server arbeitet mit dem letzten Stand weiter.',
    paused: 'Dieser Server nimmt nichts aus der Gruppe an und gibt nichts weiter. Er arbeitet mit seinem Stand, bis du auf dem Server „schild cluster resume“ aufrufst.',
    removed: 'Dieser Server wurde aus der Gruppe genommen. Er arbeitet mit seinem letzten Stand weiter und teilt nichts mehr.',
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
  const data = sh.share_data
    ? 'Ereignisse und Anfragen hält jeder Server auch von den anderen.'
    : 'Ereignisse und Anfragen bleiben auf dem Server, der sie geschrieben hat.'
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
  return nodes.open.length ? `${done} Noch offen: ${list(nodes.open)}. Dort wird gelöscht, sobald der Server die Gruppe wieder erreicht.` : done
}
