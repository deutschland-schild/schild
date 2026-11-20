import type { CrowdsecRule, CrowdsecSkipCode, RuleRepository } from '@/api/types'
import { formatDateTime, formatRelative } from '@schild/ui'

/** The CrowdSec Hub repository (D39, D43, D73): its id range, skip and refusal reasons, and its update line. */
export type CrowdsecRepository = NonNullable<RuleRepository['crowdsec']>

/** The one label of the source (contracts/crowdsec-hub.md section 7): no logo, nothing that looks like a partnership. */
export const HUB_LABEL = 'Regel aus dem CrowdSec Hub, MIT'

/** SecRule ids of the source; a rule has one base id and up to 8 ids (one per group). */
const HUB_ID_MIN = 60000000
const HUB_ID_MAX = 99999999
const HUB_STRIDE = 8

export function isHubId(id: string | number): boolean {
  const n = Number(id)
  return Number.isInteger(n) && n >= HUB_ID_MIN && n <= HUB_ID_MAX
}

/** The stable id of a hub rule from the id of the group that matched. Rule pages and filters use it. */
export function hubBaseId(id: number): number {
  return id - (id - HUB_ID_MIN) % HUB_STRIDE
}

const SKIP: Partial<Record<CrowdsecSkipCode, string>> = {
  raw_seclang: 'bringt eigenen Regeltext mit, den Schild nicht übernimmt',
  forbidden_header: 'liest einen Header, den Schild für diese Regeln nicht freigibt',
  catch_all: 'würde zu viele Anfragen treffen',
  value_chars: 'enthält Zeichen, die Schild nicht übernimmt',
  regex: 'nutzt ein Suchmuster, das Schild nicht übernimmt',
  regex_cost: 'ihr Suchmuster wäre zu aufwendig',
  compile_failed: 'ließ sich nicht laden',
  deprecated: 'im Hub als veraltet markiert',
  digest_mismatch: 'Inhalt passt nicht zur Prüfsumme im Hub',
  id_collision: 'ihre Nummer gehört schon einer anderen Regel',
}

export const skipText = (code: CrowdsecSkipCode): string => SKIP[code] ?? code

const REFUSAL: Record<string, string> = {
  index_oversize: 'die Datei war zu groß',
  index_malformed: 'die Datei war nicht lesbar',
  too_many_rules: 'sie enthielt zu viele Regeln',
  set_too_large: 'die Regeln waren zu umfangreich',
  set_empty: 'keine Regel ließ sich laden',
  shrink: 'sie enthielt weniger als die Hälfte der Regeln aus dem Image',
  set_too_costly: 'die Regeln hätten jede Anfrage spürbar gebremst',
  compile_failed: 'die Regeln ließen sich nicht laden',
  compile_timeout: 'das Laden dauerte zu lange',
}

/**
 * The calm line about updates. Nothing here is an error: the running rules stay, and without outgoing
 * network the rules of the image keep working.
 */
export function updateText(c: CrowdsecRepository): string | null {
  const commit = c.pin ? c.pin.slice(0, 12) : ''
  switch (c.update_state) {
    case 'current': return c.last_check_at ? `Auf dem neuesten Stand, zuletzt geprüft ${formatRelative(c.last_check_at)}.` : 'Auf dem neuesten Stand.'
    case 'unreachable': return 'Der Hub ist gerade nicht erreichbar, oder dieser Server darf nicht nach außen. Die vorhandenen Regeln laufen weiter.'
    case 'refused': {
      const why = c.last_refusal ? REFUSAL[c.last_refusal.code] : undefined
      return `Das letzte Update hat Schild nicht übernommen${why ? `: ${why}` : ''}. Die vorhandenen Regeln laufen weiter.`
    }
    case 'updates_off': return c.snapshot_at && c.set_source === 'image'
      ? `Automatische Updates sind aus. Es laufen die Regeln aus dem Image vom ${formatDateTime(c.snapshot_at)}.`
      : 'Automatische Updates sind aus. Es laufen die zuletzt geladenen Regeln.'
    case 'pinned': return `Fester Stand ${commit} aus schild.yaml. Schild lädt keine neueren Regeln.`
    case 'pin_pending': return `Fester Stand ${commit} ist noch nicht geladen. Bis dahin laufen die vorhandenen Regeln.`
    default: return null
  }
}

const dayFmt = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' })

/** Where the running rules come from, for the facts line: an update, or the image. */
export function setText(c: CrowdsecRepository): string | null {
  if (c.set_source === 'stored') return 'Regeln aus einem Update'
  if (c.set_source === 'image') return c.snapshot_at ? `Regeln aus dem Image vom ${dayFmt.format(new Date(c.snapshot_at))}` : 'Regeln aus dem Image'
  return null
}

/** The last update in words: "2 neu, 1 geändert". */
export function changeText(c: CrowdsecRepository): string | null {
  const ch = c.last_change
  if (!ch) return null
  const parts = [ch.added && `${ch.added} neu`, ch.changed && `${ch.changed} geändert`, ch.removed && `${ch.removed} entfernt`].filter(Boolean)
  return parts.length ? parts.join(', ') : null
}

/** The attack type at the end of a hub label, in plain German. The hub text itself stays English. */
const CODE = { title: 'Versuch, Code auf dem Server auszuführen', goal: 'eigenen Code auf dem Server auszuführen' }
const AUTH = { title: 'Versuch, die Anmeldung zu umgehen', goal: 'die Anmeldung zu umgehen' }
const SQL = { title: 'Versuchter Datenbank-Angriff (SQL-Injection)', goal: 'Befehle an die Datenbank zu schicken' }
const FILES = { title: 'Versuch, Dateien vom Server zu lesen', goal: 'Dateien vom Server zu lesen' }
const DATA = { title: 'Versuch, Daten auszulesen', goal: 'Daten auszulesen, die nicht öffentlich sind' }
const SECRETS = { title: 'Versuch, Zugangsdaten auszulesen', goal: 'Zugangsdaten auszulesen' }
const ACCESS = { title: 'Versuch, den Zugriffsschutz zu umgehen', goal: 'den Zugriffsschutz zu umgehen' }
const UPLOAD = { title: 'Versuch, eine schädliche Datei hochzuladen', goal: 'eine schädliche Datei hochzuladen' }
const HUB_KINDS: Record<string, { title: string, goal: string }> = {
  'rce': CODE,
  'command injection': { title: 'Versuch, Befehle auf dem Server auszuführen', goal: 'Befehle auf dem Server auszuführen' },
  'authentication bypass': AUTH,
  'auth bypass & rce': { title: 'Versuch, die Anmeldung zu umgehen und Code auszuführen', goal: 'die Anmeldung zu umgehen und Code auf dem Server auszuführen' },
  'sql injection': SQL,
  'sqli': SQL,
  'path traversal': FILES,
  'local file inclusion': FILES,
  'lfi': FILES,
  'arbitrary file read': FILES,
  'information disclosure': DATA,
  'exposure': DATA,
  'credentials disclosure': SECRETS,
  'password disclosure': SECRETS,
  'ntlm hash disclosure': SECRETS,
  'hardcoded credentials': { title: 'Versuch, ein fest eingebautes Passwort zu nutzen', goal: 'ein fest eingebautes Passwort zu nutzen' },
  'ssrf': { title: 'Versuchte Anfragen über den Server (SSRF)', goal: 'den Server Anfragen an fremde Ziele schicken zu lassen' },
  'xss': { title: 'Versuch, Schadcode für Browser einzuschleusen (XSS)', goal: 'Skripte einzuschleusen, die im Browser anderer laufen' },
  'xxe': { title: 'Versuchter XML-Angriff (XXE)', goal: 'über präparierte XML-Daten Dateien zu lesen oder Anfragen auszulösen' },
  'privilege escalation': { title: 'Versuch, mehr Rechte zu erlangen', goal: 'mehr Rechte zu erlangen, als das Konto hat' },
  'arbitrary file upload': UPLOAD,
  'file upload': UPLOAD,
  'parameter injection': { title: 'Versuch, Parameter einzuschleusen', goal: 'eigene Parameter einzuschleusen' },
  'cache poisoning': { title: 'Versuch, den Zwischenspeicher zu manipulieren', goal: 'den Zwischenspeicher zu manipulieren' },
  'account takeover': { title: 'Versuch, ein Konto zu übernehmen', goal: 'ein fremdes Konto zu übernehmen' },
  'account creation': { title: 'Versuch, unbefugt ein Konto anzulegen', goal: 'unbefugt ein Konto anzulegen' },
  'incorrect authorization': ACCESS,
  'missing authorization': ACCESS,
  'access control bypass': ACCESS,
  'middleware bypass': ACCESS,
}

/** Title and explanation of a hub rule: in German from the attack type of its label, else its label or name. */
export function hubRuleText(hub: Pick<CrowdsecRule, 'name' | 'cves'> & { label?: string, description?: string }): { title: string, explain: string } {
  const cut = hub.label?.lastIndexOf(' - ') ?? -1
  const product = cut > 0 ? hub.label!.slice(0, cut).trim() : ''
  const kind = cut > 0 ? HUB_KINDS[hub.label!.slice(cut + 3).trim().toLowerCase()] : undefined
  const title = hub.label || hub.name.replace(/^crowdsecurity\//, '')
  const cve = hub.cves?.length ? ` (${hub.cves.join(', ')})` : ''
  if (!product) return { title, explain: hub.description || HUB_LABEL }
  if (!kind) return { title, explain: `Erkennt Versuche, eine bekannte Lücke in ${product} auszunutzen${cve}.` }
  return { title: `${product}: ${kind.title}`, explain: `Erkennt Versuche, über eine bekannte Lücke in ${product} ${kind.goal}${cve}.` }
}
