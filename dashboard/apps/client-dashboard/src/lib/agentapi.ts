import type { StatusTone } from '@schild/ui'
import type { AgentAPIState, AgentTokenInfo, AgentTokenScope } from '@/api/agentapi'

/**
 * Copy of the Agent-API card on Einstellungen › Allgemein (D103). German, du-form, calm; the texts name the
 * mechanism (the listener, its address, the token), never an unqualified "geschützt" or "sicher".
 * Humanizer pass applied.
 */
export const AGENT_API_COPY = {
  title: 'Agent-API',
  lead: 'Über die Agent-API liest dein KI-Agent, was die Firewall sieht, testet Anfragen gegen die Regeln und setzt Ausnahmen.',
  on: 'An',
  off: 'Aus',
  notOpen: 'Nicht offen',
  switchOn: 'Einschalten',
  switchOff: 'Ausschalten',
  switchOnLabel: 'Agent-API einschalten',
  switchOffLabel: 'Agent-API ausschalten',
  offText: 'Die Agent-API ist aus. Schild nimmt keine Aufrufe von Agenten an, auch nicht mit Token.',
  notOpenText: 'Die Agent-API ist eingeschaltet, aber ihr Listener ist nicht offen. Der Port ist belegt, oder die Adresse ist außerhalb eines Containers nicht erlaubt.',
  lockedText: 'Die Agent-API ist in schild.yaml ausgeschaltet (agent_api.enabled: false). Einschalten kannst du sie nur dort, danach startest du Schild neu.',
  withoutToken: 'Ohne Token lehnt Schild jeden Aufruf ab.',
  confirmTitle: 'Agent-API ausschalten?',
  confirmText: 'Der Firewall-Container holt seine Sperren über die Agent-API. Ist sie aus, kommen keine neuen Sperren mehr in der Firewall an. Die laufenden enden von selbst.',
  tokens: 'Tokens',
  noToken: 'Es gibt noch kein gültiges Token. Leg eines auf dem Server an:',
  commandCaption: 'Paket oder Binary mit systemd',
  commandCaptionDocker: 'Docker Compose',
  commandCopy: 'Befehl zum Anlegen eines Tokens kopieren',
  commandCopyDocker: 'Befehl für Docker Compose kopieren',
  tokenOnce: 'Schild zeigt das Token nur dieses eine Mal an. Es gilt 90 Tage, mit --expires bis zu 365.',
  tokensManaged: 'Tokens legst du nur auf dem Server an und widerrufst sie auch nur dort:',
  tokensFailed: 'Die Tokens lassen sich gerade nicht laden.',
  neverUsed: 'noch nie benutzt',
  reset: 'Wert aus schild.yaml einsetzen',
  docs: 'Einrichtung in der Doku',
  docsNewTab: '(öffnet in neuem Tab)',
  savedOn: 'Agent-API eingeschaltet',
  savedOff: 'Agent-API ausgeschaltet',
  savedReset: 'Agent-API: wieder wie in schild.yaml',
  failed: 'Umschalten hat nicht geklappt',
  loadFailed: 'Die Agent-API lässt sich gerade nicht laden',
} as const

/** Where the setup is described (docs/gateway/02-betrieb.md, rendered by the website). */
export const AGENT_API_DOCS = 'https://deutschland-schild.de/doku/gateway/02-betrieb#agent-api-einrichten'

/** The commands of the docs for a first token: the package or binary, and Docker Compose. */
export const TOKEN_ADD_COMMAND = 'sudo schild token add --scope exceptions:write --label coding-agent'
export const TOKEN_ADD_COMMAND_DOCKER = `docker compose exec schild ${TOKEN_ADD_COMMAND.replace('sudo ', '')}`

export type AgentApiStatusKind = 'on' | 'off' | 'not_open'

/** What the pill says: on, off, or switched on with a listener that did not open. */
export function agentApiStatus(s: Pick<AgentAPIState, 'enabled' | 'listening'>): { kind: AgentApiStatusKind, tone: StatusTone, label: string } {
  if (!s.enabled) return { kind: 'off', tone: 'neutral', label: AGENT_API_COPY.off }
  if (!s.listening) return { kind: 'not_open', tone: 'warning', label: AGENT_API_COPY.notOpen }
  return { kind: 'on', tone: 'success', label: AGENT_API_COPY.on }
}

/** The listener is bound to this machine alone: 127.x.x.x, [::1] or localhost. */
export function isLoopback(listen: string): boolean {
  const host = listen.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase()
  return host === 'localhost' || host === '::1' || /^127(\.\d{1,3}){3}$/.test(host)
}

/** Where the open listener can be reached from. Only a loopback address is reachable on the server alone. */
export function listenText(listen: string): string {
  return isLoopback(listen)
    ? `Sie lauscht auf ${listen} und ist nur vom Server selbst erreichbar. Von einem anderen Rechner kommst du über einen SSH-Tunnel dorthin.`
    : `Sie lauscht auf ${listen}, also auf allen Schnittstellen. Das ist für Container gedacht: Erreichbar ist sie dort, wo Docker den Port veröffentlicht, in den Vorlagen nur auf 127.0.0.1 des Servers. Von einem anderen Rechner kommst du über einen SSH-Tunnel dorthin.`
}

/** Whether this change switches the API off while the firewall container depends on it: ask first. */
export function needsConfirm(s: Pick<AgentAPIState, 'enabled' | 'config_enabled' | 'firewall_tokens'>, input: { enabled?: boolean, reset?: boolean }): boolean {
  const next = input.reset ? s.config_enabled : input.enabled
  return s.enabled && next === false && s.firewall_tokens > 0
}

/** "in schild.yaml steht an" for the line below a value set in the dashboard. */
export function configText(configEnabled: boolean): string {
  return `In schild.yaml steht ${configEnabled ? 'an' : 'aus'}.`
}

export type TokenState = 'valid' | 'expired' | 'revoked'

export const TOKEN_STATE: Record<TokenState, { label: string, tone: StatusTone }> = {
  valid: { label: 'gültig', tone: 'success' },
  expired: { label: 'abgelaufen', tone: 'neutral' },
  revoked: { label: 'widerrufen', tone: 'neutral' },
}

/** Revoked wins over expired: a revoked token stays revoked after its date. */
export function tokenState(t: Pick<AgentTokenInfo, 'expires_at' | 'revoked_at'>, now: number = Date.now()): TokenState {
  if (t.revoked_at) return 'revoked'
  return Date.parse(t.expires_at) <= now ? 'expired' : 'valid'
}

/** What a token may do, in the words of the dashboard. */
export const SCOPE_LABEL: Record<AgentTokenScope, string> = {
  'agent:read': 'Lesen',
  'export:read': 'Export lesen',
  'rules:write': 'Regeln schalten',
  'blocks:write': 'Adressen sperren',
  'exceptions:write': 'Ausnahmen setzen',
  'crawlers:write': 'KI-Crawler einstellen',
  'firewall:sync': 'Sperren an die Firewall geben',
}

/** A scope this dashboard does not know yet reads as its name. */
export function scopeLabel(scope: string): string {
  return (SCOPE_LABEL as Record<string, string>)[scope] ?? scope
}

/** The label of a token, or its id when it has none. */
export function tokenName(t: Pick<AgentTokenInfo, 'id' | 'label'>): string {
  return t.label?.trim() || t.id
}

/** Valid tokens first, then by creation, newest first. The input is not changed. */
export function sortTokens<T extends Pick<AgentTokenInfo, 'created_at' | 'expires_at' | 'revoked_at'>>(tokens: readonly T[], now: number = Date.now()): T[] {
  const rank = (t: T) => tokenState(t, now) === 'valid' ? 0 : 1
  return [...tokens].sort((a, b) => rank(a) - rank(b) || Date.parse(b.created_at) - Date.parse(a.created_at))
}
