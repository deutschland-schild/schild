/** Incident numbers as shown on the block page: 4+4 characters of A-H J-N P-Z 2-9, e.g. K7QM-4XWD. */
export const INCIDENT_RE = /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/

/** Upper-case, drop spaces and other separators, insert the dash after 4 characters. */
export function normalizeIncident(raw: string): string {
  const clean = raw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8)
  return clean.length > 4 ? `${clean.slice(0, 4)}-${clean.slice(4)}` : clean
}

export function validIncident(s: string): boolean {
  return INCIDENT_RE.test(s)
}

const hms = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
function fmtTime(s: string): string {
  const d = new Date(s)
  return Number.isNaN(d.getTime()) ? s : hms.format(d)
}

/**
 * An aggregated incident (contracts v0.5, D38): blocks of one client, rule and UTC minute share one number.
 * "12 gesperrte Anfragen von 14:32:05 bis 14:32:51"; null for a single request (count absent or 1).
 */
export function aggregateText(i: { count?: number, first_seen?: string, last_seen?: string, time: string }): string | null {
  const n = i.count ?? 1
  if (n <= 1) return null
  const what = `${new Intl.NumberFormat('de-DE').format(n)} gesperrte Anfragen`
  const first = i.first_seen ?? i.time
  return i.last_seen && i.last_seen !== first ? `${what} von ${fmtTime(first)} bis ${fmtTime(i.last_seen)}` : what
}

/** Why several requests share one number, for the incident page. */
export const AGGREGATE_EXPLAIN = 'Alle Anfragen dieser Adresse, die in derselben Minute dieselbe Regel auslösen, bekommen dieselbe Vorfallnummer. Unten steht die erste davon.'
