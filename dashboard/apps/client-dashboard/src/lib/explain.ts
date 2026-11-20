import { HUB_LABEL, isHubId } from './crowdsec'

/**
 * Plain German explanations for rule ids, attack categories and match locations,
 * so non-experts understand "why" without knowing CRS numbers.
 */

/** A link to a public reference, opened in a new tab without referrer (the dashboard URL is private). */
export interface RuleLink { label: string, href: string }

interface CrsFamily { from: number, to: number, title: string, explain: string, links?: RuleLink[] }

/** Verified 2026-11-05. All English; the labels say so. */
const CRS_RULES_DOC: RuleLink = { label: 'OWASP CRS: Die Regelgruppen', href: 'https://coreruleset.org/docs/3-about-rules/rules/' }
const CRS_SCORING_DOC: RuleLink = { label: 'OWASP CRS: So werden Punkte gezählt', href: 'https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/' }
const owasp = (label: string, path: string): RuleLink => ({ label: `OWASP: ${label}`, href: `https://owasp.org/www-community/${path}` })

// OWASP CRS v4 rule id families (https://coreruleset.org/docs/3-about-rules/rules/).
const CRS_FAMILIES: CrsFamily[] = [
  { from: 911000, to: 911999, title: 'Ungewöhnliche Anfrage-Methode', explain: 'Die Anfrage nutzt eine Methode, die deine Website normalerweise nicht braucht.' },
  { from: 913000, to: 913999, title: 'Bekannter Scanner', explain: 'Ein Werkzeug, das automatisch nach Lücken sucht, hat sich verraten.' },
  { from: 920000, to: 920999, title: 'Fehlerhafte Anfrage', explain: 'Die Anfrage hält sich nicht an die Regeln des Webprotokolls. Das machen vor allem Angriffswerkzeuge.' },
  { from: 921000, to: 921999, title: 'Versuchter Angriff auf das Webprotokoll', explain: 'Versuch, Anfragen einzuschmuggeln oder Kopfzeilen zu manipulieren.' },
  { from: 922000, to: 922999, title: 'Manipulierter Upload-Versuch', explain: 'Ein Formular-Upload ist so gebaut, dass er Prüfungen umgehen soll.' },
  { from: 930000, to: 930999, title: 'Versuchter Dateizugriff', explain: 'Versuch, Dateien vom Server zu lesen, die nicht öffentlich sind (z. B. Passwortdateien oder Konfiguration).', links: [owasp('Path Traversal', 'attacks/Path_Traversal')] },
  { from: 931000, to: 931999, title: 'Versuch, fremden Code nachzuladen', explain: 'Versuch, deine Website Code von einem fremden Server ausführen zu lassen.' },
  { from: 932000, to: 932999, title: 'Versuch, Befehle auf dem Server auszuführen', explain: 'Versuch, Befehle des Betriebssystems über die Website auszuführen.', links: [owasp('Command Injection', 'attacks/Command_Injection')] },
  { from: 933000, to: 933999, title: 'Versuch, PHP-Code einzuschleusen', explain: 'Versuch, eigenen PHP-Code auf deinem Server ausführen zu lassen.', links: [owasp('Code Injection', 'attacks/Code_Injection')] },
  { from: 934000, to: 934999, title: 'Versuch, Code einzuschleusen', explain: 'Versuch, Code für Node.js, Ruby oder andere Umgebungen einzuschleusen.', links: [owasp('Code Injection', 'attacks/Code_Injection')] },
  { from: 941000, to: 941999, title: 'Versuch, Schadcode für Browser einzuschleusen (XSS)', explain: 'Versuch, Skripte einzuschleusen, die im Browser anderer Besucher:innen laufen.', links: [owasp('Cross Site Scripting (XSS)', 'attacks/xss/')] },
  { from: 942000, to: 942999, title: 'Versuchter Datenbank-Angriff (SQL-Injection)', explain: 'Versuch, über Eingabefelder Befehle an deine Datenbank zu schicken.', links: [owasp('SQL Injection', 'attacks/SQL_Injection')] },
  { from: 943000, to: 943999, title: 'Versuch, eine Sitzung zu übernehmen', explain: 'Versuch, eine fremde Anmeldung zu übernehmen.', links: [owasp('Session Fixation', 'attacks/Session_fixation')] },
  { from: 944000, to: 944999, title: 'Versuchter Angriff auf Java-Anwendungen', explain: 'Typische Angriffsversuche auf Java-Software, z. B. Log4Shell.', links: [owasp('Deserialization of untrusted data', 'vulnerabilities/Deserialization_of_untrusted_data')] },
  { from: 949000, to: 949999, title: 'Auswertung: Sperrschwelle', explain: 'Diese Regel sucht nicht selbst nach Angriffen. Sie zählt die Punkte der Regeln zusammen, die bei einer Anfrage angeschlagen haben. Erreicht die Summe die Sperrschwelle, sperrt Schild die Anfrage, wenn OWASP CRS auf „Sperren“ steht. Ein einziger schwerer Fund kann dafür schon reichen.', links: [CRS_SCORING_DOC] },
  { from: 951000, to: 951999, title: 'Datenbank-Fehler in der Antwort', explain: 'Die Antwort deiner Website zeigt eine Fehlermeldung der Datenbank. Das hilft Angreifer:innen, die Datenbank zu erkunden.' },
  { from: 955000, to: 955999, title: 'Fremdes Steuerprogramm (Web Shell)', explain: 'Die Antwort sieht aus wie ein Steuerprogramm, das jemand auf dem Server abgelegt hat.' },
  { from: 959000, to: 959999, title: 'Auswertung: Sperrschwelle der Antwort', explain: 'Diese Regel sucht nicht selbst nach etwas. Sie zählt die Punkte der Regeln zusammen, die bei der Antwort deiner Website angeschlagen haben. Erreicht die Summe die Sperrschwelle, hält Schild die Antwort zurück, wenn OWASP CRS auf „Sperren“ steht.', links: [CRS_SCORING_DOC] },
  { from: 950000, to: 959999, title: 'Datenleck in der Antwort', explain: 'Die Antwort deiner Website enthielt etwas, das nicht nach außen gehört (z. B. Fehlermeldungen mit Pfaden).' },
  { from: 980000, to: 980999, title: 'Auswertung: Zusammenfassung', explain: 'Diese Regel sucht nicht selbst nach etwas. Sie fasst die Treffer einer Anfrage für das Protokoll zusammen.', links: [CRS_SCORING_DOC] },
]

/** Single rules whose attack type differs from their family: 930130 asks for hidden files (.env, .git) by name. */
const RULE_OWN_LINKS: Record<number, RuleLink[]> = {
  930130: [owasp('Forced Browsing', 'attacks/Forced_browsing')],
}

const ruleNumber = (id: string | number): number => typeof id === 'number' ? id : /^\d+$/.test(id) ? Number(id) : Number.NaN

/**
 * CRS evaluation rules (949 request, 959 response, 980 correlation): they find nothing themselves, they add up the
 * points of the other rules and decide. Shown as the decision, never as a finding of its own.
 */
export function isEvaluationRule(id: string | number): boolean {
  const n = ruleNumber(id)
  return (n >= 949000 && n <= 949999) || (n >= 959000 && n <= 959999) || (n >= 980000 && n <= 980999)
}

/**
 * Public references for a CRS rule: the OWASP page of the attack type where one fits, then the CRS docs.
 * Local, network and hub rules have none (hub rules carry their CVE). docs: false leaves out the CRS docs.
 */
export function ruleLinks(id: string | number, opts: { docs?: boolean } = {}): RuleLink[] {
  const n = ruleNumber(id)
  const fam = Number.isNaN(n) ? undefined : CRS_FAMILIES.find(f => n >= f.from && n <= f.to)
  if (!fam) return []
  const own = RULE_OWN_LINKS[n] ?? fam.links ?? []
  if (opts.docs === false) return own.filter(l => l !== CRS_SCORING_DOC)
  return own.includes(CRS_SCORING_DOC) ? own : [...own, CRS_RULES_DOC]
}

export interface RuleExplanation {
  title: string
  explain: string
}

/** Explanation for a rule id (CRS, CrowdSec Hub or local number) with an optional rule message. */
export function explainRule(id: string | number, msg?: string | null): RuleExplanation {
  const n = ruleNumber(id)
  if (!Number.isNaN(n)) {
    const fam = CRS_FAMILIES.find(f => n >= f.from && n <= f.to)
    if (fam) return { title: fam.title, explain: fam.explain }
    if (isHubId(n) && (!msg || msg.startsWith('crowdsec hub '))) return { title: msg ? msg.replace('crowdsec hub crowdsecurity/', '') : `Regel ${id}`, explain: HUB_LABEL }
  }
  return { title: msg ? humanizeMsg(msg) : `Regel ${id}`, explain: 'Eigene Regel aus rules.d.' }
}

const MSG_DE: Record<string, string> = {
  'sql injection in arguments': 'SQL-Injection-Versuch in Formularfeldern',
  'scanner user agent': 'Bekannter Scanner',
  'os file access attempt': 'Versuchter Dateizugriff',
  'nuclei scanner templates': 'Scanner „Nuclei“',
  'gallery plugin upload bypass': 'Versuch, die Upload-Lücke im Galerie-Plugin auszunutzen',
  'wp-login burst from hosting networks': 'Login-Versuche aus Rechenzentren',
  'xmlrpc.php not used on this site': 'XML-RPC abgeschaltet (wird hier nicht genutzt)',
}

function humanizeMsg(msg: string): string {
  return MSG_DE[msg.toLowerCase()] ?? msg.charAt(0).toUpperCase() + msg.slice(1)
}

const CATEGORY_WORDS: Record<string, string> = {
  wordpress: 'WordPress',
  login: 'Login',
  bruteforce: 'Passwort-Raten',
  sqli: 'SQL-Injection-Versuch',
  xss: 'Versuchte Skript-Einschleusung',
  rce: 'Versuchte Befehlsausführung',
  lfi: 'Versuchter Dateizugriff',
  rfi: 'Versuch, fremden Code nachzuladen',
  protocol: 'Fehlerhafte Anfrage',
  'reputation-scanner': 'Bekannter Scanner',
  'injection-php': 'Versuch, PHP-Code einzuschleusen',
  'injection-generic': 'Versuch, Code einzuschleusen',
  fixation: 'Versuch, eine Sitzung zu übernehmen',
  java: 'Versuchter Angriff auf Java-Anwendungen',
  ssrf: 'Versuchte Anfragen über den Server (SSRF)',
  disclosure: 'Datenleck in der Antwort',
  generic: 'Allgemeiner Angriffsversuch',
  'multipart-header': 'Manipulierter Upload-Versuch',
  'local-rule': 'Eigene Regel',
  anomaly: 'Sperrschwelle erreicht',
  scanner: 'Scanner',
  burst: 'viele Versuche',
  'rest-api': 'REST-API',
  'wp-admin': 'wp-admin',
  'upload': 'Datei-Upload',
  'xmlrpc': 'XML-RPC',
  'multicall': 'Mehrfachaufruf',
  'dotfile': 'versteckte Dateien',
  'query': 'in der Adresse',
  'search': 'Suche',
  'cgi': 'CGI',
  'scan': 'Scan',
  'wp-plugin': 'WordPress-Plugin',
}

/** "wordpress-login-bruteforce" -> "WordPress Login Passwort-Raten", "login-burst/wp-admin" -> "Login viele Versuche · wp-admin". */
export function humanizeToken(token: string | undefined | null): string {
  if (!token) return '–'
  return token
    .split('/')
    .map(seg => CATEGORY_WORDS[seg] ?? seg.split('-').map(w => CATEGORY_WORDS[w] ?? w).join(' '))
    .join(' · ')
}

const LOCATIONS: Record<string, string> = {
  ARGS: 'in einem Formular- oder URL-Feld',
  ARGS_GET: 'in einem URL-Parameter',
  ARGS_POST: 'in einem Formularfeld',
  REQUEST_HEADERS: 'in einer Kopfzeile der Anfrage',
  REQUEST_URI: 'in der Adresse',
  REQUEST_FILENAME: 'im Dateinamen der Adresse',
  REQUEST_BODY: 'im Inhalt der Anfrage',
  REQUEST_COOKIES: 'in einem Cookie',
  FILES: 'in einem Datei-Upload',
}

/** "ARGS:log" -> "im Feld „log“". */
export function explainLocation(location: string | undefined): string {
  if (!location) return ''
  const [base, name] = location.split(':')
  if (name && (base === 'ARGS' || base === 'ARGS_POST' || base === 'ARGS_GET')) return `im Feld „${name}“`
  if (name && base === 'REQUEST_HEADERS') return `in der Kopfzeile „${name}“`
  return LOCATIONS[base ?? ''] ?? location
}

/**
 * Score 0..100 of a request (events.schema.json): the CRS points scaled so that 40 is exactly the blocking
 * threshold (schild.yaml waf.crs.inbound_anomaly_threshold); a blocking own rule lifts it to
 * at least 40. CrowdSec Hub rules add nothing. So "40" means "enough for a block", not "40 % dangerous".
 */
export const SCORE_THRESHOLD = 40

/** Score in words, relative to the blocking threshold. */
export function explainScore(score: number | undefined): string {
  if (score === undefined) return ''
  if (score > SCORE_THRESHOLD) return `über der Sperrschwelle von ${SCORE_THRESHOLD}`
  if (score === SCORE_THRESHOLD) return 'Sperrschwelle erreicht'
  if (score > 0) return `unter der Sperrschwelle von ${SCORE_THRESHOLD}`
  return 'keine Punkte'
}

/** How the score comes about, in one calm paragraph. */
export const SCORE_HOW = `Jede Regel, die anschlägt, gibt der Anfrage Punkte, je schwerer der Fund, desto mehr. Die Sperrschwelle liegt bei ${SCORE_THRESHOLD}.`

/** query: also look in the query string ("?file=../../etc/passwd"); only for targets that are paths there too. */
interface Target { re: RegExp, text: string, query?: boolean }

/**
 * Well-known files and folders scanners ask for. Matched against the inspected path and the (already redacted)
 * query, so the explanation can say what was asked for instead of only the rule family.
 */
const TARGETS: Target[] = [
  { re: /(^|\/)\.git(\/|$)/, query: true, text: 'Gesucht war der Ordner .git. Er enthält die Versionsgeschichte des Quellcodes. Ist er öffentlich abrufbar, lässt sich daraus der Code nachbauen, oft mit Passwörtern oder Schlüsseln darin.' },
  { re: /(^|\/)\.(svn|hg|bzr)(\/|$)/, query: true, text: 'Gesucht war ein Ordner der Versionsverwaltung. Ist er öffentlich abrufbar, lässt sich daraus der Quellcode nachbauen, oft mit Passwörtern oder Schlüsseln darin.' },
  { re: /(^|\/)\.env([./]|$)/, query: true, text: 'Gesucht war eine .env-Datei. Darin stehen oft Zugangsdaten, z. B. das Passwort der Datenbank oder Schlüssel für andere Dienste.' },
  { re: /wp-config\.php/, query: true, text: 'Gesucht war wp-config.php, die Konfiguration von WordPress. Sie enthält das Passwort der Datenbank.' },
  { re: /\/etc\/(passwd|shadow)/, query: true, text: 'Gesucht war eine Systemdatei wie /etc/passwd, die Liste der Benutzerkonten des Servers. Damit wird getestet, ob sich beliebige Dateien vom Server lesen lassen.' },
  { re: /(^|\/)\.ht(access|passwd)$/, text: 'Gesucht war eine Einstellungsdatei des Webservers (.htaccess oder .htpasswd). Darin stehen manchmal Passwörter für Bereiche mit Passwortabfrage.' },
  { re: /(^|\/)(\.ssh\/|id_(rsa|dsa|ecdsa|ed25519)$)/, query: true, text: 'Gesucht war ein privater SSH-Schlüssel. Mit ihm könnte man sich am Server anmelden.' },
  { re: /(^|\/)\.ds_store$/, text: 'Gesucht war .DS_Store. Die Datei verrät, welche Dateien in einem Ordner liegen.' },
  { re: /\.(sql|bak|old|backup|swp)(\.(gz|zip|tar))?$/, text: 'Gesucht war eine Sicherungskopie, z. B. ein Export der Datenbank. Solche Dateien landen manchmal versehentlich im öffentlichen Ordner.' },
]

function decode(s: string): string {
  try {
    return decodeURIComponent(s)
  }
  catch {
    return s
  }
}

/** What a request asked for, when it is a well-known sensitive file ("/.git/HEAD" -> the .git folder); else null. */
export function explainTarget(path: string | undefined, query?: string): string | null {
  if (!path) return null
  const p = decode(path).toLowerCase()
  const q = query ? decode(query).toLowerCase() : ''
  return TARGETS.find(t => t.re.test(p) || (t.query && q && t.re.test(q)))?.text ?? null
}

/** What the website answered, as far as it tells whether the file exists. */
export function targetAnswer(outcome: string | undefined, status: number | undefined): string {
  if (outcome === 'blocked') return 'Schild hat die Anfrage gesperrt. Ausgeliefert wurde nichts.'
  if (status === 404 || status === 410) return `Deine Website antwortete mit HTTP ${status}: Die Datei gibt es dort nicht.`
  if (status !== undefined && status >= 200 && status < 300) return `Die Anfrage kam durch, und deine Website antwortete mit HTTP ${status}. Prüf, ob die Datei wirklich öffentlich abrufbar ist.`
  return 'Ob es die Datei bei dir gibt, zeigt dieser Treffer nicht.'
}
