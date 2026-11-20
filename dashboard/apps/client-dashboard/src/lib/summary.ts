import type { StatusTone } from '@schild/ui'
import type { Overview } from '@/api/types'
import { formatNumber } from '@schild/ui'
import { REASONS } from './labels'

/** German plural helper: plural(1, 'Regel', 'Regeln') -> "1 Regel". */
export function plural(n: number, one: string, many: string): string {
  return `${formatNumber(n)} ${n === 1 ? one : many}`
}

export interface PartialView {
  /** Short marker next to the numbers: "seit 14:32", "seit gestern 23:10" or "mit Lücke". */
  short: string
  /** One calm sentence for the title and screen readers. */
  text: string
}

/**
 * Counters of "the last 24 hours" that do not cover the full window (D36 open items, contracts v0.5:
 * WebsiteDetail.traffic_24h_partial/_since, Overview.counters_24h.partial/.since): from when they count,
 * or a gap hint when the start is unknown (kind events: the overview, whose counters also lose events the
 * size cap deleted). Never "Näherungswert": the numbers are exact, only shorter.
 * null when the counters cover the full 24 hours.
 */
export function partialView(partial: boolean | undefined, since: string | undefined, nowMs = Date.now(), kind: 'traffic' | 'events' = 'traffic'): PartialView | null {
  const t = since ? Date.parse(since) : Number.NaN
  if (Number.isFinite(t) && nowMs - t < 24 * 3600_000) {
    const d = new Date(t)
    const hm = d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })
    const day = d.toDateString() === new Date(nowMs).toDateString() ? '' : 'gestern '
    return {
      short: `seit ${day}${hm}`,
      text: `Gezählt seit ${day}${hm} Uhr. Davor hat Schild hier nicht gezählt, zum Beispiel weil es neu gestartet wurde.`,
    }
  }
  if (partial) {
    return {
      short: 'mit Lücke',
      text: kind === 'events'
        ? 'Die Zahlen decken nicht die vollen 24 Stunden ab, zum Beispiel wegen eines Neustarts oder weil die Speichergrenze ältere Ereignisse gelöscht hat. Was gezählt wurde, stimmt.'
        : 'Die Zahlen decken nicht die vollen 24 Stunden ab, zum Beispiel wegen eines Neustarts oder einer Messlücke. Was gezählt wurde, stimmt.',
    }
  }
  return null
}

export interface BaselineView {
  title: string
  tone: StatusTone
  pill: string
  subtitle: string
}

/** Headline of the overview: "Grundschutz aktiv" or what needs attention. Never "geschützt"/"sicher". */
export function baselineView(o: Overview): BaselineView {
  const g = o.baseline
  const severe = g.reasons.some(r => REASONS[r.code]?.severe)
  if (g.state === 'off' || severe) {
    return { title: 'Grundschutz aus', tone: 'danger', pill: 'Aus', subtitle: 'Der lokale Filter arbeitet gerade nicht. Anfragen kommen ungeprüft durch.' }
  }
  if (g.state === 'degraded') {
    return { title: 'Grundschutz aktiv', tone: 'warning', pill: 'Eingeschränkt', subtitle: 'Der lokale Filter arbeitet. Etwas anderes braucht deine Aufmerksamkeit.' }
  }
  return {
    title: 'Grundschutz aktiv',
    tone: 'signal',
    pill: 'Aktiv',
    subtitle: o.profile === 'test'
      ? 'Der lokale Filter prüft jede Anfrage. Im Testprofil sperrt er nichts.'
      : 'Der lokale Filter prüft jede Anfrage und wehrt bekannte Angriffe ab.',
  }
}

export interface AttentionItem {
  id: string
  tone: StatusTone
  title: string
  next: string
  to?: string
  action?: string
}

/** Things worth doing now, most important first. Empty when all is fine. */
export function attentionItems(o: Overview): AttentionItem[] {
  const out: AttentionItem[] = []
  for (const r of o.baseline.reasons) {
    const meta = REASONS[r.code]
    if (!meta) continue
    out.push({ id: `reason-${r.code}`, tone: meta.severe ? 'danger' : 'warning', title: meta.title, next: meta.next, to: meta.to, action: meta.to ? 'Ansehen' : undefined })
  }
  return out
}
