import type { components } from './generated/schema'

/** Schema aliases of the client dashboard API (contracts/api/client-dashboard.openapi.yaml). */
type S = components['schemas']

export type Session = S['Session']
export type Overview = S['Overview']
export type Health = S['Health']
export type Mode = S['Mode']
export type Outcome = S['Outcome']
export type WouldBlockReason = S['WouldBlockReason']
export type Geo = S['Geo']
export type EventSummary = S['EventSummary']
export type EventPage = S['EventPage']
export type Incident = S['Incident']
export type UnblockRequest = S['UnblockRequest']
export type RuleRepositoryId = S['RuleRepositoryId']
export type RuleRepositoryState = S['RuleRepositoryState']
export type RuleRepository = S['RuleRepository']
export type RuleEffect = S['RuleEffect']
export type RuleLimitedBy = S['RuleLimitedBy']
export type RuleStatus = S['RuleStatus']
export type RuleOrigin = S['RuleOrigin']
export type Rule = S['Rule']
export type RuleDetail = S['RuleDetail']
export type RuleDecision = S['RuleDecision']
export type RuleException = S['RuleException']
export type RulePage = S['RulePage']
export type CrowdsecRule = S['CrowdsecRule']
export type CrowdsecSkipCode = S['CrowdsecHubSkipCode']
export type AllowlistEntry = S['AllowlistEntry']
export type AllowlistInput = S['AllowlistInput']
export type AllowlistPage = S['AllowlistPage']
export type MyIP = S['MyIP']
export type Settings = S['Settings']
export type SettingsPatch = S['SettingsPatch']
export type Problem = S['Problem']
export type Ttl = '24h' | '7d' | '30d' | 'never'
export type BaselineReason = Overview['baseline']['reasons'][number]['code']

/**
 * Local event as stored by schild (contracts/events.schema.json). The generated type leaves `data`
 * open, so the shapes the dashboard reads are spelled out here (all fields optional on purpose:
 * the UI must render whatever event type arrives).
 */
export interface LocalEvent {
  id: string
  type: string
  time: string
  source: string
  data: LocalEventData
}

/** v0.6 (D73): one rule that matched, with its repository (events.schema.json matchedRule). */
export interface MatchedRule {
  /** The SecRule id; for crowdsec the id of the AND-group that matched (hubBaseId gives the rule). */
  id: number
  repository: RuleRepositoryId
  /** Only with repository crowdsec. Third-party text: render as text. */
  crowdsec?: { name: string, version: string, label?: string, cves?: string[] }
  msg?: string
  severity?: 'critical' | 'error' | 'warning' | 'notice'
  match_shape?: { location?: string, content_type?: string, len_bucket?: string }
}

export interface LocalEventData {
  request_id?: string
  incident?: string
  client?: { ip: string, port?: number, attribution: string, geo: Geo, allowlisted?: boolean }
  method?: string
  host?: string
  path?: string
  /**
   * D33 amendment (contracts v0.5): only when schild evaluated the request more than once (e.g. again in
   * handle_errors after handle_path stripped a prefix): every inspected path in order, 2..4 items; the last
   * equals path.
   */
  checked_paths?: string[]
  query?: string
  protocol?: string
  status?: number
  user_agent?: string
  session_id?: string
  rules?: MatchedRule[]
  score?: number
  outcome?: Outcome
  /** v0.5 (D36 open items): why a would_block was let through. */
  would_block_reason?: WouldBlockReason
  mode?: Mode
  duration_ms?: number
  waf_ms?: number
  // session flagged
  requests?: number
  window_s?: number
  // unblocked
  by?: string
  false_positive?: boolean
  [key: string]: unknown
}
