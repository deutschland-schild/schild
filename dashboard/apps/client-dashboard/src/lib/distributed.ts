import type { StatusTone } from '@schild/ui'
import type { DetectorId, DetectorSetting, DetectorThresholds, DistributedMode, DistributedSettings, Wave } from '@/api/distributed'
import { formatNumber } from '@schild/ui'
import { formatClock, formatDuration, routeText } from '@/lib/behaviour'

/**
 * Plain German for the "Wellen" tab (MVP-18): every distributed attack as one sentence
 * ("Verteilte Login-Versuche auf wp-login.php: 380 Adressen, gleicher Fingerabdruck, 41 verschiedene
 * Browser-Angaben"), the response that runs or would have run, detector thresholds in words.
 * Waves are address-free: they never name a single address or a user name. Pure functions only.
 */

function n(count: number, one: string, many: string) {
  return `${formatNumber(count)} ${count === 1 ? one : many}`
}

const dayFmt = new Intl.DateTimeFormat('de-DE', { day: 'numeric', month: 'long' })
/** "3. November" in the browser's time zone. */
export function formatDay(value: string | number | Date): string {
  return dayFmt.format(new Date(value))
}

// ------------------------------------------------------------------ detectors

export interface DetectorMeta {
  name: string
  description: string
}

export const DETECTORS: Record<DetectorId, DetectorMeta> = {
  route_wave: {
    name: 'Ansturm auf eine Route',
    description: 'Viel mehr Fehlversuche an einer Anmeldung oder einer anderen wichtigen Route als sonst, auch wenn jede Adresse nur selten fragt.',
  },
  account_wave: {
    name: 'Ein Konto, viele Adressen',
    description: 'Viele Adressen probieren dasselbe Konto aus. Benutzernamen speichert Schild nicht, es zählt nur ein paar Minuten im Speicher.',
  },
  shape_wave: {
    name: 'Gleiche Anfrage, viele Adressen',
    description: 'Dieselbe auffällige Anfrage kommt in kurzer Zeit von vielen verschiedenen Adressen.',
  },
  fingerprint_cluster: {
    name: 'Gleicher Fingerabdruck',
    description: 'Viele Adressen haben denselben technischen Fingerabdruck, obwohl Adresse und Browser-Angabe ständig wechseln.',
  },
  inconsistency: {
    name: 'Widersprüchliche Browser-Angaben',
    description: 'Anfragen, deren Browser-Angaben nicht zusammenpassen, oder eine Anmeldung ohne vorher geladenes Formular.',
  },
}

export const DETECTOR_ORDER: DetectorId[] = ['route_wave', 'account_wave', 'shape_wave', 'fingerprint_cluster', 'inconsistency']

export const DISTRIBUTED_MODES: Record<DistributedMode, { label: string, explain: string }> = {
  off: { label: 'Aus', explain: 'Diese Erkennung zählt nichts.' },
  observe: { label: 'Beobachten', explain: 'Schild erkennt Wellen und zeigt, wie es reagiert hätte. Geändert wird nichts.' },
  respond: { label: 'Reagieren', explain: 'Bei einer Welle schränkt Schild die betroffene Route oder das Konto für kurze Zeit ein. Einzelne Adressen sperrt es nie.' },
}

/** "mindestens 30 Fehlversuche in 1 Minute und mindestens das 5-Fache des Üblichen". */
export function detectorThresholdsText(id: DetectorId, t: DetectorThresholds): string {
  const within = `in ${formatDuration(t.window_s)}`
  switch (id) {
    case 'route_wave': {
      const base = `mindestens ${n(t.count, 'Fehlversuch', 'Fehlversuche')} ${within}`
      return t.factor ? `${base} und mindestens das ${formatNumber(t.factor)}-Fache des Üblichen` : base
    }
    case 'account_wave':
      return `mindestens ${n(t.count, 'Fehlversuch', 'Fehlversuche')} für ein Konto ${within}, von verschiedenen Adressen`
    case 'shape_wave':
      return `dieselbe Anfrage von mindestens ${n(t.count, 'Adresse', 'Adressen')} ${within}`
    case 'fingerprint_cluster':
      return `ein Fingerabdruck an mindestens ${n(t.count, 'Adresse', 'Adressen')} ${within}`
    case 'inconsistency':
      return `mindestens ${n(t.count, 'widersprüchliche Anfrage', 'widersprüchliche Anfragen')} ${within}`
  }
}

/** What a detector counts, as it stands between the number and the time span in the thresholds form (D97). */
export const DETECTOR_COUNTED: Record<DetectorId, string> = {
  route_wave: 'Fehlversuche an einer Route',
  account_wave: 'Fehlversuche für ein Konto',
  shape_wave: 'Adressen mit derselben Anfrage',
  fingerprint_cluster: 'Adressen mit demselben Fingerabdruck',
  inconsistency: 'widersprüchliche Anfragen',
}

/** Whether the thresholds of a detector differ from the built-in ones. */
export function detectorThresholdsChanged(d: { thresholds: DetectorThresholds, defaults: DetectorThresholds }): boolean {
  return (['count', 'window_s', 'factor'] as const).some(f => (d.thresholds[f] ?? 0) !== (d.defaults[f] ?? 0))
}

/** "keine Welle", "1 Welle", "3 Wellen" (last 24 h). */
export function wavesCountText(count: number): string {
  return count ? n(count, 'Welle', 'Wellen') : 'keine Welle'
}

/** Why a detector set to "Reagieren" only observes right now; null when it runs as set. */
export function effectiveNote(d: Pick<DetectorSetting, 'mode' | 'effective_mode'>, s: Pick<DistributedSettings, 'gateway_observe' | 'learning_until'>): string | null {
  if (d.mode !== 'respond' || d.effective_mode !== 'observe') return null
  if (s.gateway_observe) return 'Reagieren ist eingestellt. Das Gateway läuft im Testprofil, darum beobachtet diese Erkennung im Moment nur.'
  return `Reagieren ist eingestellt. Schild lernt noch${s.learning_until ? ` bis ${formatDay(s.learning_until)}` : ''} den Normalzustand dieser Website, darum beobachtet diese Erkennung bis dahin nur.`
}

// ------------------------------------------------------------------ one wave in one sentence

/** A login is attacked (the contract flags it with suggest_second_factor). */
export function isLoginWave(w: Pick<Wave, 'route' | 'suggest_second_factor'>): boolean {
  return w.suggest_second_factor === true || /login|signin|anmeld/i.test(w.route)
}

/**
 * "Verteilte Login-Versuche auf wp-login.php: 380 Adressen, gleicher Fingerabdruck, 41 verschiedene Browser-Angaben",
 * "Ungewöhnlich viele Fehlversuche an /user/login: 145 in 1 Minute, sonst etwa 2,5, von 212 Adressen".
 */
export function explainWave(w: Wave): string {
  const route = routeText(w.route)
  const senders = n(w.senders, 'Adresse', 'Adressen')
  const within = `in ${formatDuration(w.window_s)}`
  switch (w.detector) {
    case 'fingerprint_cluster': {
      const head = isLoginWave(w) ? `Verteilte Login-Versuche auf ${route}` : `Verteilte Anfragen an ${route}`
      const agents = w.user_agents !== undefined ? `, ${w.user_agents === 1 ? '1 Browser-Angabe' : `${formatNumber(w.user_agents)} verschiedene Browser-Angaben`}` : ''
      return `${head}: ${senders}, gleicher Fingerabdruck${agents}`
    }
    case 'route_wave': {
      const usual = w.baseline !== undefined ? `, sonst etwa ${formatNumber(w.baseline)}` : ''
      return `Ungewöhnlich viele Fehlversuche an ${w.route}: ${formatNumber(w.count)} ${within}${usual}, von ${senders}`
    }
    case 'account_wave':
      return `Ein Konto wird von ${senders} aus ausprobiert: ${n(w.count, 'Fehlversuch', 'Fehlversuche')} ${within} an ${route}`
    case 'shape_wave':
      return `Dieselbe auffällige Anfrage von ${senders} ${within} an ${w.route}`
    case 'inconsistency':
      return `Anfragen, deren Browser-Angaben nicht zusammenpassen: ${formatNumber(w.count)} ${within} an ${route}, von ${senders}`
  }
}

export function waveTitle(w: Pick<Wave, 'detector'>): string {
  return DETECTORS[w.detector].name
}

// ------------------------------------------------------------------ responses

export const RESPONSES: Record<Wave['response'], string> = {
  route_tighten: 'Route eingeschränkt',
  account_slowdown: 'Wartezeit für betroffene Konten',
  shape_block: 'Anfrageform abgelehnt',
}

type ResponseSettings = Partial<Pick<DistributedSettings, 'route_tighten' | 'account_slowdown'>>

/**
 * What the response does, in the present tense:
 * "Anmeldung bis 09:32 nur eingeschränkt: ohne Sitzungs-Cookie höchstens 10 Versuche pro Minute für alle zusammen".
 */
export function responseText(w: Pick<Wave, 'response' | 'route' | 'until' | 'suggest_second_factor'>, s: ResponseSettings = {}): string {
  const until = w.until ? ` bis ${formatClock(w.until)}` : ''
  switch (w.response) {
    case 'route_tighten': {
      const login = isLoginWave(w)
      const what = login ? 'Anmeldung' : `Zugriff auf ${w.route}`
      const unit = login ? ['Versuch', 'Versuche'] as const : ['Anfrage', 'Anfragen'] as const
      const limit = s.route_tighten
        ? `höchstens ${n(s.route_tighten.limit_per_minute, unit[0], unit[1])} pro Minute`
        : `nur wenige ${unit[1]} pro Minute`
      return `${what}${until} nur eingeschränkt: ohne Sitzungs-Cookie ${limit} für alle zusammen`
    }
    case 'account_slowdown': {
      const a = s.account_slowdown ?? { start_s: 5, max_s: 60 }
      return `Betroffene Konten: kurze Wartezeit vor dem nächsten Versuch (${formatNumber(a.start_s)} s bis höchstens ${formatNumber(a.max_s)} s), nie gesperrt; wer eingeloggt war, kommt durch`
    }
    case 'shape_block':
      return `Diese Anfrageform wird${until} von jeder Adresse abgelehnt`
  }
}

/** "noch 12 Minuten", "noch 1 Stunde und 5 Minuten", "endet gleich". */
export function remainingText(until: string, now: number = Date.now()): string {
  const ms = Date.parse(until) - now
  if (ms <= 30_000) return 'endet gleich'
  const min = Math.ceil(ms / 60_000)
  if (min < 60) return `noch ${n(min, 'Minute', 'Minuten')}`
  const h = Math.floor(min / 60)
  const m = min % 60
  return `noch ${n(h, 'Stunde', 'Stunden')}${m ? ` und ${n(m, 'Minute', 'Minuten')}` : ''}`
}

/** "1.830 Anfragen gebremst", "1 Anfrage gebremst", "keine Anfrage gebremst". */
export function stoppedText(count: number | undefined): string {
  return count ? `${n(count, 'Anfrage', 'Anfragen')} gebremst` : 'keine Anfrage gebremst'
}

/** Why a detector only observed this wave. */
export function observeReasonText(reason: Wave['reason'], learningUntil?: string | null): string | null {
  if (reason === 'learning') return `Schild lernt noch den Normalzustand dieser Website${learningUntil ? ` (bis ${formatDay(learningUntil)})` : ''}`
  if (reason === 'gateway_observe') return 'Das Gateway läuft im Testprofil'
  return null
}

export interface WaveOutcome {
  label: string
  tone: StatusTone
  /** Why it only observed, in words. */
  reason: string | null
}

/** What happened (or would have happened) with this wave. */
export function waveOutcome(w: Wave, learningUntil?: string | null): WaveOutcome {
  if (w.action === 'observe') {
    return { label: 'Erkannt (Probelauf)', tone: 'warning', reason: observeReasonText(w.reason, learningUntil) }
  }
  if (w.active) return { label: w.until ? `Läuft bis ${formatClock(w.until)}` : 'Läuft', tone: 'signal', reason: null }
  if (w.end_reason === 'operator') return { label: 'Vorzeitig beendet', tone: 'neutral', reason: null }
  return { label: 'Abgelaufen', tone: 'neutral', reason: null }
}

// ------------------------------------------------------------------ cluster

export const FINGERPRINT_KINDS: Record<'ja4' | 'headers', { label: string, explain: string }> = {
  ja4: {
    label: 'TLS-Fingerabdruck (JA4)',
    explain: 'Kommt von deinem vorgeschalteten TLS-Proxy und beschreibt, wie ein Programm die verschlüsselte Verbindung aufbaut.',
  },
  headers: {
    label: 'Header-Merkmale',
    explain: 'Welche Angaben eine Anfrage mitschickt und in welcher Form, etwa Sprache und unterstützte Formate. Gröber als ein TLS-Fingerabdruck.',
  },
}

/** "sha256:abab…" -> "abababababab" (the first 12 hex digits, enough to tell shapes apart). */
export function shortSig(sig: string): string {
  return sig.replace(/^sha256:/, '').slice(0, 12)
}
