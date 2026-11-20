import type { StatusTone } from '@schild/ui'
import type { LabHealth, Proposal, Relay, Withdrawal } from '@/api/types'
import { ACK_P99_TARGET_MS } from './labels'
import { splitSubscribers } from './relays'

export interface Alert {
  id: string
  tone: StatusTone
  title: string
  text: string
  to?: string
  linkLabel?: string
}

export interface AlertInput {
  health?: LabHealth
  /** Feed subscribers; peer labs (Relay.kind, contracts v0.2) are reported apart from relays. */
  relays?: Relay[]
  withdrawals?: Withdrawal[]
  review?: Proposal[]
  checkpointTtlS?: number
  now?: Date
}

/** Open points for the overview, most urgent first. Calm wording, always with the next step. */
export function computeAlerts(i: AlertInput): Alert[] {
  const out: Alert[] = []
  const h = i.health
  const now = i.now ?? new Date()
  if (h) {
    if (h.queue.full) out.push({ id: 'queue-full', tone: 'danger', title: 'Warteschlange voll', text: 'Neue Signale bekommen ein „später erneut“ (retry_after). Prüf, ob die Worker hinterherkommen.', to: '/', linkLabel: 'Worker ansehen' })
    if (h.ack_ms.p99 >= ACK_P99_TARGET_MS) out.push({ id: 'ack', tone: 'danger', title: 'Ack-Latenz über dem Ziel', text: `p99 liegt bei ${h.ack_ms.p99.toLocaleString('de-DE')} ms, Ziel unter ${ACK_P99_TARGET_MS} ms.` })
    for (const w of h.workers) {
      if (w.status === 'failed') out.push({ id: `worker-${w.name}`, tone: 'danger', title: `Worker ${w.name} mit Fehler`, text: w.last_error ?? 'Ohne Fehlermeldung beendet.' })
      else if (w.status === 'lagging') out.push({ id: `worker-${w.name}`, tone: 'warning', title: `Worker ${w.name} hängt hinterher`, text: `Rückstand ${Math.round(w.lag_s ?? 0)} s.` })
      else if (w.status === 'stopped') out.push({ id: `worker-${w.name}`, tone: 'warning', title: `Worker ${w.name} gestoppt`, text: 'Er verarbeitet gerade nichts.' })
    }
    const ttl = i.checkpointTtlS ?? 600
    if (h.feed.last_checkpoint_at && now.getTime() - Date.parse(h.feed.last_checkpoint_at) > ttl * 1000) {
      out.push({ id: 'checkpoint', tone: 'warning', title: 'Checkpoint veraltet', text: 'Clients halten den Feed für eingefroren, wenn kein frischer Checkpoint kommt.', to: '/log', linkLabel: 'Log ansehen' })
    }
  }
  const subs = splitSubscribers((i.relays ?? []).filter(r => r.status === 'disconnected'))
  const down = subs.relays
  if (down.length) out.push({ id: 'relays', tone: 'warning', title: down.length === 1 ? '1 Relay getrennt' : `${down.length} Relays getrennt`, text: down.map(r => r.id).join(', '), to: '/relays', linkLabel: 'Relays ansehen' })
  const peersDown = subs.peerLabs
  if (peersDown.length) out.push({ id: 'peer-feeds', tone: 'info', title: peersDown.length === 1 ? '1 Peer-Lab folgt dem Feed gerade nicht' : `${peersDown.length} Peer-Labs folgen dem Feed gerade nicht`, text: peersDown.map(r => r.id).join(', '), to: '/relays', linkLabel: 'Peers ansehen' })
  const collecting = (i.withdrawals ?? []).filter(w => w.status === 'collecting')
  const stop = collecting.find(w => w.scope === 'all')
  if (stop) out.push({ id: 'stop', tone: 'warning', title: 'Rückzug aller Netzregeln sammelt Mitzeichnungen', text: `Vorgeschlagen von ${stop.proposed_by ?? 'einem Lab'}. Der Grundschutz auf den Servern bleibt aktiv.`, to: '/published/withdrawals', linkLabel: 'Status ansehen' })
  const rules = collecting.filter(w => w.scope === 'rules')
  if (rules.length) out.push({ id: 'withdrawals', tone: 'info', title: rules.length === 1 ? '1 Rückzug wartet auf Mitzeichnung' : `${rules.length} Rückzüge warten auf Mitzeichnung`, text: 'Andere Labs bitten um deine Signatur.', to: '/published/withdrawals', linkLabel: 'Prüfen' })
  if (i.review?.length) out.push({ id: 'review', tone: 'info', title: i.review.length === 1 ? '1 Vorschlag wartet auf Prüfung' : `${i.review.length} Vorschläge warten auf Prüfung`, text: 'Nichts wird ohne menschliche Freigabe veröffentlicht.', to: '/proposals', linkLabel: 'Prüfen' })
  const rank: Record<StatusTone, number> = { danger: 0, warning: 1, info: 2, signal: 3, success: 4, neutral: 5 }
  return out.sort((a, b) => rank[a.tone] - rank[b.tone])
}
