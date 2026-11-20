import type { StatusTone } from '@schild/ui'
import type { BlockList, RunningBlock } from '@/api/blocks'
import { SCENARIOS } from './behaviour'
import { NET_CLASS } from './labels'

/** Copy of the page Sperren (D87). German, du-form, calm; a block is a block of web requests, not of the server. */
export const BLOCKS_COPY = {
  title: 'Sperren',
  lead: 'Welche Adressen Schild gerade sperrt, und welche einzelnen Anfragen es gestoppt hat. Eine Sperre gilt für alle Websites dieses Servers. Ohne Firewall sieht die Adresse die Sperrseite mit ihrer Vorfallnummer, mit Firewall kommt sie gar nicht mehr durch.',
  addresses: 'Gesperrte Adressen',
  requests: 'Gestoppte Anfragen',
  none: 'Gerade ist keine Adresse gesperrt.',
  noneExplain: 'Adressen sperren die Szenarien unter Regeln, wenn sie auf „Sperren“ stehen, Agenten mit eigener Berechtigung und du selbst mit „Adresse sperren“ oder aus einem Ereignis. Einzelne Anfragen stoppen die Regeln, das steht im Reiter „Gestoppte Anfragen“.',
  lift: 'Sperre aufheben',
} as const

/** Why a block runs: the scenario's name, or the agent. */
export function blockReason(b: RunningBlock): string {
  if (b.source === 'agent') return 'Von einem Agenten gesperrt'
  if (b.source === 'dashboard') return 'Im Dashboard gesperrt'
  return b.scenario ? SCENARIOS[b.scenario].name : 'Szenario'
}

export function netClassText(c: string): string {
  return NET_CLASS[c] ?? c
}

/** The firewall per row. */
export const FIREWALL_ROW: Record<RunningBlock['firewall'], { label: string, tone: StatusTone, title: string }> = {
  banned: { label: 'in der Firewall', tone: 'success', title: 'Die Firewall des Servers (nftables) lässt diese Adresse nicht mehr an die Ports 80 und 443, bis die Sperre endet.' },
  pending: { label: 'wird eingetragen', tone: 'info', title: 'Die Firewall trägt die Sperre gerade ein, in der Regel innerhalb einer Sekunde.' },
  stale: { label: 'unbekannt', tone: 'warning', title: 'Die Firewall hat sich seit über 2 Minuten nicht gemeldet oder meldet einen Fehler. Die Sperre gilt in Schild trotzdem.' },
  off: { label: 'nur Schild', tone: 'neutral', title: 'Die Firewall ist nicht angebunden. Die Sperre gilt in Schild: Die Adresse bekommt die Sperrseite statt der Website.' },
}

/** One sentence on the handoff to the firewall as a whole. */
export function firewallText(f: BlockList['firewall']): { tone: StatusTone, text: string } {
  switch (f.state) {
    case 'ok':
      return { tone: 'success', text: `Die Firewall ist angebunden: ${f.banned ?? 0} ${f.banned === 1 ? 'Adresse kommt' : 'Adressen kommen'} nicht mehr an die Ports 80 und 443 des Servers, bis ihre Sperre endet.` }
    case 'error':
      return { tone: 'danger', text: `Der Abgleich mit der Firewall schlug fehl: ${f.error ?? 'ohne Meldung'}. Die Sperren gelten in Schild weiter.` }
    case 'stale':
      return { tone: 'warning', text: 'Die Firewall hat sich seit über 2 Minuten nicht gemeldet. Läuft der Firewall-Container (schild firewall run) noch, und ist sein Token gültig? Die Sperren gelten in Schild weiter, in der Firewall laufen sie von selbst ab.' }
    default:
      return { tone: 'neutral', text: 'Die Firewall ist nicht angebunden. Die Sperren gelten in Schild: Gesperrte Adressen bekommen die Sperrseite statt der Website. Wie du die Firewall anbindest, steht in der Doku unter „Sperren in der Firewall“.' }
  }
}
