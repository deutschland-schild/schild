import type { AccessProtection } from '@/api/access'
import { isCidr, isIP } from './ip'

/** Copy of the Zugriffsschutz module (D56, D58: every condition ticked must hold; on until lifted). German, du-form, calm; no "geschützt" without a "wodurch". */
export const ACCESS_COPY = {
  title: 'Zugriffsschutz',
  lead: 'Du kannst für diese Website unterschiedliche Schutzstufen festlegen.',
  waysLabel: 'Zugang',
  scopeLabel: 'Gilt für',
  off: 'Aus',
  setup: 'Zugriffsschutz einrichten',
  change: 'Ändern',
  remove: 'Aufheben',
  site: 'Ganze Website',
  siteExplain: 'Die ganze Website ist nur noch über den Zugang erreichbar, den du unten festlegst. Alle anderen sehen eine Wartungsseite, bei der App kommt von ihnen nichts an. Gut, wenn eine Lücke bekannt ist und es noch kein Update gibt.',
  paths: 'Nur bestimmte Bereiche',
  pathsExplain: 'Zum Beispiel /wp-admin/* oder /intern/*. Der Rest der Website bleibt offen.',
  waysExplain: 'Alles, was du anhakst, muss zutreffen. Mit Passwort und IPs sehen nur diese IPs das Anmeldeformular.',
  password: 'Passwort',
  passwordExplain: 'Ein gemeinsames Passwort für alle, die hinein sollen.',
  passwordKeep: 'Ein Passwort ist gesetzt. Lass das Feld leer, um es zu behalten.',
  addresses: 'Nur bestimmte IPs',
  addressesExplain: 'Nur von diesen Adressen aus, zum Beispiel aus dem Büro. Eine pro Zeile.',
  addressesShared: 'Eine Adresse im Mobilfunk oder hinter dem Router deines Providers teilst du oft mit Fremden. Nimm dann lieber das Passwort dazu.',
  ownNetworks: 'Eigene IPs',
  ownNetworksExplain: 'Nur Adressen, die bei „Eigene IPs“ stehen.',
  ipsTogether: 'Bestimmte IPs und eigene IPs zählen zusammen: Eine passende Adresse reicht.',
  stays: 'Der Schutz bleibt aktiv, bis du ihn aufhebst.',
  except: 'Ausnahmen (optional)',
  exceptExplain: 'Pfade, die für alle erreichbar bleiben, zum Beispiel der Webhook deines Zahlungsanbieters. Eine pro Zeile. Dort erreicht jeder die App, auch die Stelle mit der Lücke.',
  message: 'Text der Wartungsseite (optional)',
  messagePlaceholder: 'An dieser Website wird gerade gearbeitet. Schau bitte später noch einmal vorbei.',
  submitNew: 'Schutz aktivieren',
  submitChange: 'Speichern',
  sessionsEnd: 'Wer schon angemeldet war, muss sich danach neu anmelden.',
  noWayIn: 'Wähl mindestens einen Zugang: Passwort, bestimmte IPs oder eigene IPs.',
  notBehindSchild: 'Nicht jede Anfrage dieser Website läuft durch Schild. Der Zugriffsschutz würde nicht überall greifen. Prüf die Caddyfile.',
  httpsNote: 'Die Anmeldung mit Passwort braucht HTTPS.',
} as const

/** Copy of the maintenance switch (D98): the whole website closed, only Eigene IPs get through; a switch of its own next to the Zugriffsschutz. */
export const MAINTENANCE_COPY = {
  title: 'Wartungsmodus',
  lead: 'Alle Besucher:innen sehen die Wartungsseite „Wir sind gleich wieder da.“, bei der App kommt von ihnen nichts an. Suchmaschinen bekommen den Code 503 und schauen später wieder vorbei.',
  switchLabel: 'Wartungsmodus an',
  on: 'Die Website ist im Wartungsmodus.',
  ownIps: (n: number) => n === 1 ? 'Deine eine eigene IP kommt weiter durch.' : `Deine ${n} eigenen IPs kommen weiter durch.`,
  noOwnIps: 'Du hast keine eigenen IPs eingetragen. Auch du siehst dann die Wartungsseite. Das Dashboard bleibt erreichbar.',
  withProtection: 'Der Zugriffsschutz unten bleibt bestehen. Wer von einer eigenen IP kommt, braucht dafür weiter Passwort oder Freigabe.',
  message: 'Text der Wartungsseite (optional)',
  saveMessage: 'Text speichern',
  confirmOn: 'Wartungsmodus einschalten?',
  confirmOnText: 'Ab sofort sieht jede Besucherin und jeder Besucher die Wartungsseite.',
  confirmOff: 'Wartungsmodus ausschalten?',
  confirmOffText: 'Die Website ist danach sofort wieder für alle erreichbar.',
} as const

/** Lines of a textarea: trimmed, without empty ones and duplicates. */
export function lines(s: string): string[] {
  return [...new Set(s.split('\n').map(l => l.trim()).filter(Boolean))]
}

/** A path as the gateway takes it: starts with /, * only as /* at the end, no escapes. */
export function isAccessPath(s: string, except = false): boolean {
  const re = except ? /^\/[\w.~!$&'()+,=:@/-]*(?:\/\*)?$/ : /^\/[\w.~!$&'()+,;=:@/-]*(?:\/\*)?$/
  return s.length <= 255 && re.test(s) && s !== '/*'
}

/** An IP or a network the gateway takes: IPv4 up to /16, IPv6 up to /32. */
export function isAccessAddress(s: string): boolean {
  if (isIP(s)) return true
  if (!isCidr(s)) return false
  const bits = Number(s.split('/')[1])
  return s.includes(':') ? bits >= 32 : bits >= 16
}

/** What a protection means for a visitor, by its conditions: "Nur mit Passwort erreichbar". */
export function accessTitle(p: AccessProtection): string {
  const ips = !!p.addresses?.length || p.own_networks
  if (p.password && ips) return 'Nur mit Passwort und von freigegebenen IPs erreichbar'
  if (p.password) return 'Nur mit Passwort erreichbar'
  return 'Nur von freigegebenen IPs erreichbar'
}

/** "Passwort und Eigene IPs", "IP 203.0.113.7 oder Eigene IPs": every part joined by "und" must hold. */
export function waysText(p: AccessProtection): string {
  const ips: string[] = []
  const n = p.addresses?.length ?? 0
  if (n) ips.push(n === 1 ? `IP ${p.addresses![0]}` : `${n} IPs`)
  if (p.own_networks) ips.push(ACCESS_COPY.ownNetworks)
  const from = ips.join(' oder ')
  if (!p.password) return from
  return from ? `${ACCESS_COPY.password} und ${from}` : ACCESS_COPY.password
}

/** "Ganze Website" or "/wp-admin/*, /wp-login.php" */
export function scopeText(p: AccessProtection): string {
  return p.scope === 'site' ? ACCESS_COPY.site : (p.paths ?? []).join(', ')
}
