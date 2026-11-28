/**
 * Mock of the audit log (MVP-36, listAudit): entries of every class and way, newest first, with the
 * filters and the cursor of the contract. The entries name objects the mock holds (an own IP, a rule
 * exception, a token, an event, an incident) and some that are gone, so both kinds of link can be seen.
 * Documentation addresses and example names only. Mock mode and tests only.
 */
import type { HttpHandler } from 'msw'
import type { AuditEntry } from '@/api/audit'
import type { MockState } from './data'
import type { WebsiteHandlerTools } from './websites'
import { http, HttpResponse } from 'msw'

const isoS = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
const MIN = 60_000
const HOUR = 3600_000
const DAY = 86400_000

/** The log of this gateway and the one of a second node of a group. */
const LOG = '0a1b2c3d4e5f6071'
const LOG_OTHER = '9f8e7d6c5b4a3021'
const SESSION_NOW = '5e1f0a9c'
const SESSION_BEFORE = '0a1b2c3d'
const OFFICE = '198.51.100.20'
/** An event the mock no longer holds: past retention.events_days. */
export const MOCK_GONE_EVENT = '6f1d2c3b-4a59-4e68-9a7b-8c9d0e1f2a3b'
/** An own IP that expired and is gone; its history stays. */
export const MOCK_GONE_ALLOW = 'al-7c2e'

type Draft = Omit<AuditEntry, 'schema' | 'id' | 'node' | 'result' | '$defs'> & { result?: AuditEntry['result'], node?: string }

export function createAuditState(st: Pick<MockState, 'scenario' | 'events' | 'incidents' | 'allowlist'>, t0: number): AuditEntry[] {
  if (st.scenario === 'empty') return []
  const admin = (session: string) => ({ kind: 'dashboard' as const, user: 'admin', session })
  const agent = { kind: 'agent' as const, id: 'tok_000000000001', label: 'coding-agent' }
  const fromEvent = st.events.find(e => e.summary.outcome === 'blocked' && e.summary.site)?.summary
  const incident = [...st.incidents.values()].find(i => i.status === 'blocked')
  const office = st.allowlist.find(a => a.id === 'al-2')

  const drafts: Draft[] = [
    {
      time: isoS(t0 - 12 * MIN), class: 'refused', action: 'agent_api.call', operation: 'agent:any', result: 'refused',
      actor: { kind: 'agent' }, address: '203.0.113.77', subject: { kind: 'agent_api' }, count: 48, last: isoS(t0 - 12 * MIN + 50_000),
    },
    {
      time: isoS(t0 - 28 * MIN), class: 'change', action: 'settings.set', operation: 'dashboard:updateSettings',
      actor: admin(SESSION_NOW), address: OFFICE, subject: { kind: 'setting', id: 'retention' },
      change: { fields: [{ field: '/retention/events_days', change: 'changed', before: 30, after: 14 }] },
    },
    {
      time: isoS(t0 - 30 * MIN), class: 'access', action: 'session.start', operation: 'dashboard:login',
      actor: admin(SESSION_NOW), address: OFFICE, subject: { kind: 'user' },
    },
    {
      time: isoS(t0 - 2 * HOUR), class: 'change', action: 'crawlers.set', operation: 'agent:setAgentCrawlers',
      actor: agent, address: '192.0.2.10', subject: { kind: 'website', id: 'shop.example' }, website: 'shop.example',
      change: { fields: [{ field: '/categories/ai_training', change: 'changed', before: 'allow', after: 'block' }, { field: '/preset', change: 'changed', before: 'open', after: 'custom' }] },
      reason: 'Der Shop soll nicht in Trainingsdaten landen.',
    },
    ...(incident
      ? [{
          time: isoS(t0 - 3 * HOUR), class: 'change' as const, action: 'block.set', operation: 'dashboard:createBlock',
          actor: admin(SESSION_BEFORE), address: OFFICE, subject: { kind: 'block', id: incident.incident },
          ...(incident.request.site ? { website: incident.request.site } : {}),
          cause: { incident: incident.incident },
          change: { fields: [{ field: '/client', change: 'added' as const, after: incident.request.ip ?? '203.0.113.42' }, { field: '/duration_s', change: 'added' as const, after: 86400 }, { field: '/until', change: 'added' as const, after: isoS(t0 + 21 * HOUR) }] },
          reason: 'Sucht seit Tagen nach Konfigurationsdateien.',
        }]
      : []),
    ...(fromEvent
      ? [{
          time: isoS(t0 - 5 * HOUR), class: 'change' as const, action: 'rule_exception.set', operation: 'dashboard:createRuleException',
          actor: admin(SESSION_BEFORE), address: OFFICE, subject: { kind: 'rule_exception', id: '1900004' }, website: fromEvent.site!,
          cause: { event: fromEvent.id },
          change: { fields: [
            { field: '/path', change: 'added' as const, after: fromEvent.path ?? '/kontakt' },
            { field: '/repository', change: 'added' as const, after: 'crs' },
            { field: '/rules', change: 'added' as const, added: ['941100', '941160', '942100'], more: 4 },
            { field: '/target', change: 'added' as const, after: 'ARGS:nachricht' },
          ] },
          reason: 'Kontaktformular: Besucher schreiben Wörter, die wie SQL aussehen.',
        }]
      : []),
    {
      time: isoS(t0 - 5 * HOUR - 4 * MIN), class: 'access', action: 'session.start', operation: 'dashboard:login',
      actor: admin(SESSION_BEFORE), address: OFFICE, subject: { kind: 'user' },
    },
    {
      time: isoS(t0 - 6 * HOUR), class: 'refused', action: 'session.start', operation: 'dashboard:login', result: 'refused',
      actor: { kind: 'dashboard' }, address: '203.0.113.150', subject: { kind: 'user' }, count: 12, last: isoS(t0 - 6 * HOUR + 40_000),
    },
    {
      time: isoS(t0 - DAY), class: 'change', action: 'config.apply', operation: 'config:schild_yaml',
      actor: { kind: 'config' }, subject: { kind: 'config' },
      change: {
        fields: [
          { field: '/digest', change: 'changed', before: '1f2e3d4c5b6a', after: '6a5b4c3d2e1f' },
          { field: '/geo/ipinfo_key', change: 'changed', hidden: 'secret' },
          { field: '/ingress/trusted_proxies', change: 'changed', hidden: 'unlisted' },
          { field: '/retention/max_size_mb', change: 'changed', hidden: 'unlisted' },
        ],
        more_fields: 3,
      },
    },
    {
      time: isoS(t0 - 2 * DAY + 20 * MIN), class: 'change', action: 'allowlist.remove', operation: 'system:expiry',
      actor: { kind: 'system' }, subject: { kind: 'allowlist_entry', id: MOCK_GONE_ALLOW },
      change: { fields: [{ field: '/expires', change: 'removed', before: isoS(t0 - 2 * DAY + 20 * MIN) }, { field: '/ip', change: 'removed', before: '192.0.2.70' }, { field: '/label', change: 'removed', before: 'Meine IP' }, { field: '/level', change: 'removed', before: 'no_block' }] },
    },
    {
      time: isoS(t0 - 3 * DAY + 20 * MIN), class: 'change', action: 'allowlist.add', operation: 'dashboard:allowMyIP',
      actor: admin('7b3c9d1e'), address: '192.0.2.70', subject: { kind: 'allowlist_entry', id: MOCK_GONE_ALLOW },
      change: { fields: [{ field: '/expires', change: 'added', after: isoS(t0 - 2 * DAY + 20 * MIN) }, { field: '/ip', change: 'added', after: '192.0.2.70' }, { field: '/label', change: 'added', after: 'Meine IP' }, { field: '/level', change: 'added', after: 'no_block' }] },
    },
    {
      time: office?.created_at ?? isoS(t0 - 5 * DAY), class: 'change', action: 'allowlist.add', operation: 'dashboard:addAllowlistEntry',
      actor: admin('2c4e6a8b'), address: OFFICE, subject: { kind: 'allowlist_entry', id: 'al-2' },
      change: { fields: [{ field: '/cidr', change: 'added', after: '198.51.100.0/24' }, { field: '/label', change: 'added', after: 'Agentur' }, { field: '/level', change: 'added', after: 'no_block' }] },
    },
    {
      time: isoS(t0 - 6 * DAY), class: 'credential', action: 'token.add', operation: 'cli:token add',
      actor: { kind: 'cli', account: 'deploy' }, subject: { kind: 'token', id: 'tok_000000000003' },
      change: { fields: [{ field: '/expires', change: 'added', after: isoS(t0 + 345 * DAY) }, { field: '/label', change: 'added', after: 'firewall' }, { field: '/scope', change: 'added', after: 'firewall:sync' }] },
    },
    {
      time: isoS(t0 - 8 * DAY), class: 'privacy', action: 'privacy.erase', operation: 'dashboard:privacyDelete',
      actor: admin('4d5e6f7a'), address: OFFICE, subject: { kind: 'address' },
      change: { fields: [{ field: '/blocks', change: 'added', after: 1 }, { field: '/events', change: 'added', after: 37 }, { field: '/incidents', change: 'added', after: 2 }, { field: '/keep_incidents', change: 'added', after: false }, { field: '/requests', change: 'added', after: 120 }] },
      reason: 'Auskunft und Löschung auf Anfrage.',
    },
    {
      time: isoS(t0 - 9 * DAY), class: 'change', action: 'access_lock.set', operation: 'cli:lock on',
      actor: { kind: 'cli', account: 'deploy' }, subject: { kind: 'website', id: 'verein.example' }, website: 'verein.example',
      change: { fields: [
        { field: '/message', change: 'added', after: 'Dieser Bereich ist nur für Mitglieder des Vereins. Das Passwort steht im letzten Rundbrief', cut: true },
        { field: '/password', change: 'added', hidden: 'secret' },
        { field: '/paths', change: 'added', added: ['/intern'] },
        { field: '/scope', change: 'added', after: 'paths' },
      ] },
    },
    {
      time: isoS(t0 - 12 * DAY), class: 'change', action: 'rule_exception.set', operation: 'agent:createAgentException',
      actor: agent, address: '192.0.2.10', subject: { kind: 'rule_exception', id: '1900000' }, website: 'verein.example',
      cause: { event: MOCK_GONE_EVENT },
      change: { fields: [
        { field: '/path', change: 'added', after: '/livewire/update' },
        { field: '/repository', change: 'added', after: 'crs' },
        { field: '/rules', change: 'added', added: ['932160', '933160'] },
        { field: '/target', change: 'added', after: 'ARGS:json.components.*.updates.body' },
      ] },
      reason: 'Text field of the editor: code samples in normal text were blocked.',
    },
    {
      time: isoS(t0 - 20 * DAY), node: 'web-2', class: 'change', action: 'rule_repository.sync', operation: 'system:hub_update',
      actor: { kind: 'system' }, subject: { kind: 'rule_repository', id: 'crowdsec' },
      change: { fields: [{ field: '/rules_loaded', change: 'changed', before: 212, after: 218 }, { field: '/set', change: 'changed', before: '3c1a9e07', after: '8d2b4f61' }] },
    },
  ]

  // Ids as the gateway counts them: per log and letter from 1, the oldest entry first.
  const counters = new Map<string, number>()
  const letter = (d: Draft) => d.class === 'refused' ? 'r' : d.class === 'access' ? 'a' : 'k'
  const byAge = [...drafts].sort((a, b) => Date.parse(a.time) - Date.parse(b.time))
  const entries = byAge.map((d): AuditEntry => {
    const node = d.node ?? 'web-1'
    const key = `${node === 'web-1' ? LOG : LOG_OTHER}-${letter(d)}`
    const n = (counters.get(key) ?? 0) + 1
    counters.set(key, n)
    const { node: _n, result, ...rest } = d
    return { schema: 'schild.audit/0.1', id: `${key}-${n}`, node, result: result ?? 'done', ...rest } as AuditEntry
  })
  return entries.reverse()
}

const PATTERNS: Record<string, RegExp> = {
  website: /^[a-z0-9_][a-z0-9_.-]*$/,
  class: /^(change|credential|privacy|access|refused)$/,
  action: /^[a-z][a-z_]*\.[a-z][a-z_]*$/,
  way: /^(dashboard|agent|integration|cli|config|system)$/,
  actor: /^(tok|pk)_[0-9a-f]{12}$/,
  subject: /^[a-z][a-z_]{0,31}$/,
  subject_id: /^.{1,253}$/,
  session: /^[0-9a-f]{8}$/,
  event: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  incident: /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/,
}

/** The filters of listAudit over the stored entries; time in [from, to). */
export function filterAudit(entries: AuditEntry[], q: URLSearchParams): AuditEntry[] {
  const from = q.get('from') ? Date.parse(q.get('from')!) : null
  const to = q.get('to') ? Date.parse(q.get('to')!) : null
  const get = (k: string) => q.get(k)
  return entries.filter((e) => {
    const t = Date.parse(e.time)
    if (from !== null && t < from) return false
    if (to !== null && t >= to) return false
    if (get('website') && e.website !== get('website')) return false
    if (get('class') && e.class !== get('class')) return false
    if (get('action') && e.action !== get('action')) return false
    if (get('way') && !e.operation.startsWith(`${get('way')}:`)) return false
    if (get('actor') && (e.actor as { id?: string }).id !== get('actor')) return false
    if (get('subject') && e.subject.kind !== get('subject')) return false
    if (get('subject_id') && e.subject.id !== get('subject_id')) return false
    if (get('session') && (e.actor as { session?: string }).session !== get('session')) return false
    if (get('event') && (e.cause as { event?: string } | undefined)?.event !== get('event')) return false
    // Cause or subject: the block of an incident, its release, the own IP set from it.
    if (get('incident') && (e.cause as { incident?: string } | undefined)?.incident !== get('incident') && !((e.subject.kind === 'block' || e.subject.kind === 'incident') && e.subject.id === get('incident'))) return false
    return true
  })
}

export function auditHandlers(t: WebsiteHandlerTools & { page: <T>(items: T[], url: URL, defLimit?: number) => { items: T[], next_cursor: string | null } }): HttpHandler[] {
  const { base, guard, problem } = t
  return [
    http.get(`${base}/audit`, guard('read', ({ request }) => {
      const url = new URL(request.url)
      const errors: { pointer: string, detail: string }[] = []
      for (const [k, re] of Object.entries(PATTERNS)) {
        const v = url.searchParams.get(k)
        if (v !== null && !re.test(v)) errors.push({ pointer: `#/query/${k}`, detail: 'does not match the pattern of the contract' })
      }
      for (const k of ['from', 'to']) {
        const v = url.searchParams.get(k)
        if (v !== null && Number.isNaN(Date.parse(v))) errors.push({ pointer: `#/query/${k}`, detail: 'not a timestamp' })
      }
      if (errors.length) return problem(400, 'invalid', 'Ungültiger Filter', errors)
      return HttpResponse.json(t.page(filterAudit(t.state().audit, url.searchParams), url))
    })),
  ]
}
