import type { StatusTone } from '@schild/ui'
import type {
  Bundle,
  LogKind,
  MaxAction,
  PatternStatus,
  Peer,
  ProposalClass,
  ProposalStatus,
  Relay,
  Reproduction,
  Withdrawal,
  Worker,
} from '@/api/types'

export interface Label { text: string, tone: StatusTone }

export const ACTION_LABEL: Record<MaxAction, string> = {
  observe: 'Beobachten',
  challenge: 'Challenge',
  block: 'Sperren',
}

export const ACTION_HINT: Record<MaxAction, string> = {
  observe: 'Zählt nur mit, sperrt nichts.',
  challenge: 'Clients sollen prüfen statt sperren, höchstens 7 Tage. Die Prototyp-Clients können das noch nicht und notieren solche Anfragen nur.',
  block: 'Sperrt passende Anfragen auf Servern im Modus „automatisch sperren“.',
}

export const ACTION_TONE: Record<MaxAction, StatusTone> = {
  observe: 'neutral',
  challenge: 'warning',
  block: 'danger',
}

export const CLASS_LABEL: Record<ProposalClass, string> = {
  virtual_patch: 'Virtueller Patch',
  heuristic: 'Heuristik',
  behavioral: 'Verhaltensmuster',
}

export const STAGE_LABEL: Record<string, string> = {
  shadow: 'Probelauf',
  canary: 'Canary',
  general: 'Allgemein',
}

export const PATTERN_STATUS: Record<PatternStatus, Label> = {
  new: { text: 'Neu', tone: 'info' },
  watching: { text: 'Beobachtet', tone: 'neutral' },
  proposed: { text: 'Vorgeschlagen', tone: 'warning' },
  published: { text: 'Veröffentlicht', tone: 'signal' },
  ignored: { text: 'Ignoriert', tone: 'neutral' },
}

export const PROPOSAL_STATUS: Record<ProposalStatus, Label> = {
  draft: { text: 'Entwurf', tone: 'neutral' },
  review: { text: 'In Prüfung', tone: 'warning' },
  approved: { text: 'Freigegeben', tone: 'success' },
  rejected: { text: 'Abgelehnt', tone: 'neutral' },
  published: { text: 'Veröffentlicht', tone: 'signal' },
  withdrawn: { text: 'Zurückgezogen', tone: 'neutral' },
}

export const BUNDLE_STATUS: Record<Bundle['status'], Label> = {
  collecting: { text: 'Sammelt Signaturen', tone: 'warning' },
  published: { text: 'Veröffentlicht', tone: 'signal' },
  superseded: { text: 'Abgelöst', tone: 'neutral' },
  expired: { text: 'Abgelaufen', tone: 'danger' },
}

export const WITHDRAWAL_STATUS: Record<Withdrawal['status'], Label> = {
  collecting: { text: 'Sammelt Mitzeichnungen', tone: 'warning' },
  effective: { text: 'Wirksam', tone: 'success' },
  superseded: { text: 'Abgelöst', tone: 'neutral' },
}

export const WITHDRAWAL_REASON: Record<Withdrawal['reason'], string> = {
  emergency_stop: 'Unklare Lage',
  false_positives: 'Fehlalarme',
  superseded: 'Ersetzt',
  compromised_key: 'Schlüssel kompromittiert',
  other: 'Anderer Grund',
}

export const REPRO_STATUS: Record<Reproduction['status'], Label> = {
  pending: { text: 'Läuft', tone: 'info' },
  reproduced: { text: 'Reproduziert', tone: 'success' },
  not_reproduced: { text: 'Nicht reproduziert', tone: 'neutral' },
  error: { text: 'Fehler', tone: 'danger' },
}

export const WORKER_STATUS: Record<Worker['status'], Label> = {
  running: { text: 'Läuft', tone: 'success' },
  idle: { text: 'Wartet', tone: 'neutral' },
  lagging: { text: 'Hängt hinterher', tone: 'warning' },
  stopped: { text: 'Gestoppt', tone: 'warning' },
  failed: { text: 'Fehler', tone: 'danger' },
}

export const RELAY_STATUS: Record<Relay['status'], Label> = {
  connected: { text: 'Verbunden', tone: 'success' },
  lagging: { text: 'Hängt hinterher', tone: 'warning' },
  disconnected: { text: 'Getrennt', tone: 'danger' },
}

export const PEER_STATUS: Record<Peer['status'], Label> = {
  ok: { text: 'In Ordnung', tone: 'success' },
  slow: { text: 'Langsam', tone: 'warning' },
  down: { text: 'Nicht erreichbar', tone: 'danger' },
  unknown: { text: 'Unbekannt', tone: 'neutral' },
}

export const LOG_KIND: Record<LogKind, string> = {
  proposal: 'Vorschlag',
  bundle: 'Bündel',
  withdrawal: 'Rückzug',
  checkpoint: 'Checkpoint',
}

export const QUEUE_LABEL: Record<'new_pattern' | 'repeat' | 'baseline', { text: string, hint: string }> = {
  new_pattern: { text: 'Neue Muster', hint: 'Höchste Priorität' },
  repeat: { text: 'Wiederholungen', hint: 'Mittlere Priorität' },
  baseline: { text: 'Grundrauschen', hint: 'Niedrigste Priorität' },
}

export const REJECT_REASON_LABEL: Record<string, string> = {
  signature: 'Signatur ungültig',
  schema: 'Schema verletzt',
  expired: 'Abgelaufen',
  quota: 'Kontingent erschöpft',
  revoked: 'Gesperrt',
  replay: 'Wiederholt gesendet',
  clock_skew: 'Uhrzeit weicht ab',
  forbidden_field: 'Verbotenes Feld',
  envelope: 'Umschlag ungültig',
  malformed: 'Nicht lesbar',
  oversize: 'Zu groß',
}

/** Target for the ack latency (M6). */
export const ACK_P99_TARGET_MS = 50

/** What the operator types to withdraw all network rules. Calm on purpose; never reachable by one key press. */
export const WITHDRAW_ALL_PHRASE = 'ALLE ZURÜCKZIEHEN'
/** Wire value of `confirm_text` for POST /emergency-stop. Stays until contracts v0.4; never shown in the UI. */
export const WITHDRAW_ALL_WIRE_CONFIRM = 'NOT-AUS' as const
