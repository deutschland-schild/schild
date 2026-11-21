/**
 * Mock of the rule repositories (D73, contracts v0.6): OWASP CRS, CrowdSec Hub and the operator's own rules
 * with status and effect computed like contract/rules (vectors rule-effect) from the test profile, the
 * repository state, the origin and the settling time (D89: no approvals). Mock mode and tests only.
 *
 * Examples in every scenario: rules disabled in schild.yaml, in the dashboard and through an agent, and
 * updates that settle. Scenario standalone: no hub, only the rules of the image.
 */
import type { HttpHandler } from 'msw'
import type { MockState, Scenario } from './data'
import type { WebsiteHandlerTools } from './websites'
import type {
  CrowdsecRule,
  Mode,
  Rule,
  RuleDecision,
  RuleDetail,
  RuleException,
  RuleEffect,
  RuleLimitedBy,
  RuleOrigin,
  RuleRepository,
  RuleRepositoryId,
  RuleRepositoryState,
  RuleStatus,
} from '@/api/types'
import { http, HttpResponse } from 'msw'
import exceptionsFixture from '../../../../../contracts/api/fixtures/client/listRuleExceptions.json'
import { gatewayMode } from './data'

const isoS = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
const H = 3600_000
const D = 24 * H

type By = 'config' | 'dashboard' | 'agent'
interface Token { token_id: string, label: string }
interface DecisionRecord { by: By, at?: number, note?: string, token?: Token }

export interface MockRule {
  repository: RuleRepositoryId
  id: string
  name?: string
  msg?: string
  version: string
  origin: RuleOrigin
  paranoia_level?: number
  /** Third-party text of the hub, without settling_until (computed). */
  crowdsec?: Omit<CrowdsecRule, 'settling_until'>
  seclang?: string
  file?: string
  disabled?: DecisionRecord
  /** Unix ms an update has settled (mode autoblock). */
  settlingUntil?: number
  hits_24h: number
  match_share_24h: number
}

export interface MockRepository {
  id: RuleRepositoryId
  state: RuleRepositoryState
  config_state: RuleRepositoryState
  /** default or config: what reset_state goes back to. */
  config_source: 'default' | 'config'
  state_source: RuleRepository['state_source']
  state_set_at?: number
  state_set_by?: Token
  last_change_at: number | null
  crs?: NonNullable<RuleRepository['crs']>
  crowdsec?: NonNullable<RuleRepository['crowdsec']>
  local?: Omit<NonNullable<RuleRepository['local']>, 'files'>
  /** Tests: the next sync of local is refused with this error. */
  failNextSync?: string
}

export interface RulesMock {
  repositories: Record<RuleRepositoryId, MockRepository>
  rules: MockRule[]
  /** Exceptions set through the agent API (D83). */
  exceptions: RuleException[]
}

// ------------------------------------------------------------------ status and effect (contract/rules)

/** One rule at one moment, as contract/rules computes it (vectors rule-effect, op effect). */
export function ruleEffect(r: Pick<MockRule, 'origin' | 'disabled' | 'settlingUntil' | 'version'>, mode: Mode, state: RuleRepositoryState, now: number): { status: RuleStatus, effect: RuleEffect, limited_by?: RuleLimitedBy, disabled_by?: By } {
  if (r.disabled) return { status: 'disabled', effect: 'off', disabled_by: r.disabled.by }
  const status: RuleStatus = r.origin === 'update' && mode !== 'observe' && r.settlingUntil && now < r.settlingUntil ? 'settling' : 'active'
  if (state === 'off') return { status, effect: 'off' }
  if (state === 'detect') return { status, effect: 'detect', limited_by: 'repository_detect' }
  if (status === 'settling') return { status, effect: 'detect', limited_by: 'settling' }
  if (mode === 'observe') return { status, effect: 'would_block', limited_by: 'gateway_observe' }
  return { status, effect: 'block' }
}

/** What a repository does (op repository); the test profile holds Sperren back. */
export function repositoryEffect(state: RuleRepositoryState, mode: Mode): { effect: RuleEffect, limited_by?: 'gateway_observe' } {
  if (state !== 'block') return { effect: state }
  return mode === 'observe' ? { effect: 'would_block', limited_by: 'gateway_observe' } : { effect: 'block' }
}

// ------------------------------------------------------------------ views of the state

function ruleView(st: MockState, r: MockRule): Rule {
  const repo = st.ruleRepos.repositories[r.repository]
  const e = ruleEffect(r, gatewayMode(st.settings), repo.state, st.now())
  const settling = r.crowdsec && r.origin === 'update' && r.settlingUntil && e.status === 'settling'
  return {
    repository: r.repository,
    id: r.id,
    ...(r.name ? { name: r.name } : {}),
    ...(r.msg ? { msg: r.msg } : {}),
    version: r.version,
    origin: r.origin,
    status: e.status,
    effect: e.effect,
    ...(e.limited_by ? { limited_by: e.limited_by } : {}),
    ...(e.disabled_by ? { disabled_by: e.disabled_by } : {}),
    hits_24h: r.hits_24h,
    match_share_24h: r.match_share_24h,
    ...(r.paranoia_level ? { paranoia_level: r.paranoia_level } : {}),
    ...(r.crowdsec ? { crowdsec: { ...r.crowdsec, ...(settling ? { settling_until: isoS(r.settlingUntil!) } : {}) } } : {}),
  }
}

function decision(kind: RuleDecision['kind'], rec: DecisionRecord): RuleDecision {
  return {
    kind,
    by: rec.by,
    ...(rec.token ? { token: rec.token } : {}),
    ...(rec.note ? { note: rec.note } : {}),
    ...(rec.at !== undefined && rec.by !== 'config' ? { at: isoS(rec.at) } : {}),
  }
}

export function ruleDetail(st: MockState, r: MockRule): RuleDetail {
  const decisions: RuleDecision[] = []
  if (r.disabled) decisions.push(decision('disabled', r.disabled))
  return {
    ...ruleView(st, r),
    ...(r.seclang ? { seclang: r.seclang } : {}),
    ...(r.file ? { file: r.file } : {}),
    ...(decisions.length ? { decisions } : {}),
  }
}

const NAMES: Record<RuleRepositoryId, string> = { crs: 'OWASP CRS', crowdsec: 'CrowdSec Hub', local: 'Eigene Regeln' }

export function repositoryView(st: MockState, id: RuleRepositoryId): RuleRepository {
  const repo = st.ruleRepos.repositories[id]
  const rules = st.ruleRepos.rules.filter(r => r.repository === id).map(r => ruleView(st, r))
  const count = (s: RuleStatus) => rules.filter(r => r.status === s).length
  const overlay = repo.state_source === 'dashboard' || repo.state_source === 'agent'
  const out: RuleRepository = {
    id,
    name: NAMES[id],
    state: repo.state,
    config_state: repo.config_state,
    state_source: repo.state_source,
    ...(overlay && repo.state_set_at ? { state_set_at: isoS(repo.state_set_at) } : {}),
    ...(repo.state_source === 'agent' && repo.state_set_by ? { state_set_by: repo.state_set_by } : {}),
    differs: overlay && repo.state !== repo.config_state,
    ...repositoryEffect(repo.state, gatewayMode(st.settings)),
    origin: id === 'crs' ? 'built_in' : id === 'crowdsec' ? 'remote' : 'operator',
    counts: { rules: rules.length, disabled: count('disabled'), settling: count('settling'), skipped: repo.crowdsec?.skipped.length ?? 0 },
    last_change_at: repo.last_change_at === null ? null : isoS(repo.last_change_at),
    ...(id === 'crs' ? { licence: 'Apache-2.0' } : id === 'crowdsec' ? { licence: 'MIT' } : {}),
  }
  if (repo.crs) out.crs = repo.crs
  if (repo.crowdsec) out.crowdsec = { ...repo.crowdsec, update_state: repo.state === 'off' ? 'off' : repo.crowdsec.update_state, set_source: repo.state === 'off' ? 'none' : repo.crowdsec.set_source }
  if (repo.local) {
    const files = new Map<string, number>()
    for (const r of st.ruleRepos.rules) if (r.repository === 'local' && r.file) files.set(r.file, (files.get(r.file) ?? 0) + 1)
    out.local = { ...repo.local, files: [...files].map(([name, n]) => ({ name, rules: n })) }
  }
  return out
}

// ------------------------------------------------------------------ seed

const CRS_VERSION = '4.30.0'
const CRS: { id: string, msg: string, pl?: number }[] = [
  { id: '913100', msg: 'Found User-Agent associated with security scanner' },
  { id: '920350', msg: 'Host header is a numeric IP address' },
  { id: '930120', msg: 'OS File Access Attempt' },
  { id: '930130', msg: 'Restricted File Access Attempt' },
  { id: '932160', msg: 'Remote Command Execution: Unix Shell Code Found' },
  { id: '933160', msg: 'PHP Injection Attack: High-Risk PHP Function Call Found' },
  { id: '941100', msg: 'XSS Attack Detected via libinjection' },
  { id: '942100', msg: 'SQL Injection Attack Detected via libinjection' },
  { id: '949110', msg: 'Inbound Anomaly Score Exceeded' },
]

interface HubSeed {
  id: string
  cve: string
  label: string
  description: string
  cwe: string
  version: string
  origin: RuleOrigin
  /** Hours since the hub changed it (updates) or since it was first seen (release). */
  age: number
  path: string
  extra?: Partial<MockRule>
  notes?: CrowdsecRule['notes']
}

function hubRule(s: HubSeed, t0: number): MockRule {
  const name = `crowdsecurity/vpatch-${s.cve}`
  return {
    repository: 'crowdsec',
    id: s.id,
    name,
    msg: `crowdsec hub ${name}`,
    version: s.version,
    origin: s.origin,
    crowdsec: {
      name,
      version: s.version,
      licence: 'MIT',
      label: s.label,
      description: s.description,
      cves: [s.cve],
      cwes: [s.cwe],
      attack: ['T1190'],
      ...(s.notes ? { notes: s.notes } : {}),
      first_seen: isoS(t0 - (s.origin === 'update' ? s.age * H : 40 * D)),
      changed_at: isoS(t0 - s.age * H),
    },
    seclang: `SecRule REQUEST_FILENAME "@rx ^${s.path}" "id:${s.id},phase:2,pass,t:none,severity:CRITICAL,msg:'crowdsec hub ${name}',tag:crowdsec_hub,chain"\n    SecRule ARGS "@rx (?:\\.\\./|<script|union\\s+select)" "t:none,t:lowercase,t:urlDecodeUni"`,
    hits_24h: 0,
    match_share_24h: 0,
    ...(s.origin === 'update' ? { settlingUntil: t0 - s.age * H + D } : {}),
    ...s.extra,
  }
}

function seedHub(t0: number, standalone: boolean): MockRule[] {
  const agent: Token = { token_id: 'tok_000000000001', label: 'coding-agent' }
  const seeds: HubSeed[] = [
    // The fixture rule: an update that still settles (getRule.json).
    { id: '62846312', cve: 'CVE-2026-1207', label: 'Django - SQL Injection', description: 'Detects SQL injection through the raster lookup of a GIS API.', cwe: 'CWE-89', version: '0.3', origin: 'update', age: 4, path: '/api/gis/raster' },
    { id: '60000008', cve: 'CVE-2025-29927', label: 'Next.js - Middleware Bypass', description: 'Detects requests that set the internal middleware subrequest header.', cwe: 'CWE-285', version: '0.1', origin: 'update', age: 9, path: '/' },
    { id: '60000016', cve: 'CVE-2024-27198', label: 'JetBrains TeamCity - Authentication Bypass', description: 'Detects the alternative path that skips the login of TeamCity.', cwe: 'CWE-288', version: '0.2', origin: 'update', age: 30, path: '/app/rest' },
    { id: '60000024', cve: 'CVE-2023-22515', label: 'Atlassian Confluence - Privilege Escalation', description: 'Detects calls to the setup endpoints of Confluence after installation.', cwe: 'CWE-284', version: '0.2', origin: 'update', age: 50, path: '/setup', extra: { disabled: { by: 'agent', token: agent, note: 'matches the setup page of our wiki', at: t0 - 2 * D } } },
    { id: '60000040', cve: 'CVE-2023-46805', label: 'Ivanti Connect Secure - Authentication Bypass', description: 'Detects path traversal into the REST API of Ivanti Connect Secure.', cwe: 'CWE-287', version: '0.4', origin: 'update', age: 60, path: '/api/v1/totp' },
    { id: '71204448', cve: 'CVE-2025-24813', label: 'Apache Tomcat - RCE', description: 'Detects a request body that writes a session file.', cwe: 'CWE-502', version: '0.2', origin: 'release', age: 40 * 24, path: '/', notes: ['raw_body_partial'] },
    { id: '84512096', cve: 'CVE-2024-4577', label: 'PHP CGI - Argument Injection', description: 'Detects an argument injection in PHP CGI.', cwe: 'CWE-78', version: '0.1', origin: 'release', age: 40 * 24, path: '/', extra: { disabled: { by: 'config' } } },
    { id: '60000032', cve: 'CVE-2024-4040', label: 'CrushFTP - Arbitrary File Read', description: 'Detects template injection that reads files outside the virtual file system.', cwe: 'CWE-1336', version: '0.1', origin: 'release', age: 40 * 24, path: '/WebInterface' },
    { id: '60000048', cve: 'CVE-2024-1061', label: 'WordPress HTML5 Video Player - SQL Injection', description: 'Detects SQL injection in the id parameter of the plugin.', cwe: 'CWE-89', version: '0.1', origin: 'release', age: 40 * 24, path: '/wp-admin/admin-ajax.php', extra: { disabled: { by: 'dashboard', note: 'plugin not in use, hits on our own form', at: t0 - 3 * D } } },
  ]
  // Without the hub only the rules of the image run.
  return seeds.filter(s => !standalone || s.origin === 'release').map(s => hubRule(s, t0))
}

function seedLocal(t0: number): MockRule[] {
  const agent: Token = { token_id: 'tok_000000000002', label: 'shop-deploy' }
  const local = (id: string, version: string, file: string, msg: string, seclang: string, extra: Partial<MockRule> = {}): MockRule => ({
    repository: 'local',
    id,
    msg,
    version,
    origin: 'operator',
    file,
    seclang,
    hits_24h: 0,
    match_share_24h: 0,
    ...extra,
  })
  return [
    local('1000010', '3f2a9c01be44', '10-admin.conf', 'xmlrpc.php not used on this site', 'SecRule REQUEST_FILENAME "@endsWith /xmlrpc.php" "id:1000010,phase:1,deny,status:403,log,msg:\'xmlrpc.php not used on this site\',severity:WARNING"'),
    local('1000020', '9b07d4e2a1c3', '10-admin.conf', 'block the old admin path', 'SecRule REQUEST_FILENAME "@beginsWith /admin-alt/" "id:1000020,phase:1,deny,status:403,log,msg:\'block the old admin path\'"'),
    local('1000030', 'c41e88f0d2a7', '20-shop.conf', 'no PUT on the shop API', 'SecRule REQUEST_METHOD "@streq PUT" "id:1000030,phase:1,deny,status:405,log,msg:\'no PUT on the shop API\',chain"\n    SecRule REQUEST_HEADERS:Host "@streq shop.example"', { disabled: { by: 'agent', token: agent, note: 'checkout test until Friday', at: t0 - 5 * H } }),
  ]
}

export function createRulesState(scenario: Scenario, t0: number): RulesMock {
  const standalone = scenario === 'standalone'
  const crs: MockRule[] = CRS.map(r => ({
    repository: 'crs',
    id: r.id,
    msg: r.msg,
    version: CRS_VERSION,
    origin: 'release',
    paranoia_level: r.pl ?? 1,
    hits_24h: 0,
    match_share_24h: 0,
    file: `REQUEST-${r.id.slice(0, 3)}-EXAMPLE.conf`,
    seclang: `SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS|XML:/* "@rx example" \\\n    "id:${r.id},\\\n    phase:2,\\\n    block,\\\n    t:none,\\\n    msg:'${r.msg}',\\\n    tag:'paranoia-level/${r.pl ?? 1}',\\\n    severity:'CRITICAL',\\\n    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`,
  }))
  // rules.crs.disabled_rules in schild.yaml.
  crs.find(r => r.id === '920350')!.disabled = { by: 'config' }
  const hub = seedHub(t0, standalone)
  return {
    exceptions: standalone ? [] : structuredClone(exceptionsFixture.items) as RuleException[],
    repositories: {
      crs: {
        id: 'crs',
        state: 'block',
        config_state: 'block',
        config_source: 'default',
        state_source: 'default',
        last_change_at: null,
        crs: { paranoia_level: 1, inbound_anomaly_threshold: 5, config_paranoia_level: 1, config_inbound_anomaly_threshold: 5, livewire_exception: false, version: CRS_VERSION },
      },
      crowdsec: standalone
        ? {
            id: 'crowdsec',
            state: 'detect',
            config_state: 'detect',
            config_source: 'default',
            state_source: 'default',
            last_change_at: null,
            crowdsec: { update_state: 'unreachable', auto_update: true, interval_s: 3600, settling_s: 86400, set_source: 'image', skipped: [], last_check_at: isoS(t0 - 10 * 60_000), snapshot_at: isoS(t0 - 5 * D), snapshot_age_days: 5, hub_commit: '4b1f0c9e2d7a6b5c8e3f1a0d9c8b7a6f5e4d3c2b' },
          }
        : {
            id: 'crowdsec',
            state: 'block',
            config_state: 'detect',
            config_source: 'default',
            state_source: 'agent',
            state_set_at: t0 - 26 * H,
            state_set_by: { token_id: 'tok_000000000001', label: 'coding-agent' },
            last_change_at: t0 - 4 * H,
            crowdsec: {
              update_state: 'current',
              auto_update: true,
              interval_s: 3600,
              settling_s: 86400,
              set_source: 'stored',
              skipped: [
                { name: 'crowdsecurity/vpatch-CVE-2026-109618', version: '0.3', code: 'raw_seclang' },
                { name: 'crowdsecurity/vpatch-CVE-2024-2862', version: '0.1', code: 'forbidden_header' },
              ],
              index_sha256: '86f5b58056aee781d9fd5e4d208211de9c0eea482e84ce70a5fb81293d7888d6',
              last_check_at: isoS(t0 - 28 * 60_000),
              last_change: { added: 2, changed: 1, removed: 0 },
              snapshot_at: isoS(t0 - 5 * D),
              snapshot_age_days: 5,
            },
          },
      local: {
        id: 'local',
        state: 'block',
        config_state: 'block',
        config_source: 'default',
        state_source: 'default',
        last_change_at: t0 - 20 * H,
        local: { dir: '/etc/schild/rules.d', last_reload_at: isoS(t0 - 20 * H) },
      },
    },
    rules: [...crs, ...hub, ...seedLocal(t0)],
  }
}

// ------------------------------------------------------------------ handlers

const ORDER: Record<RuleRepositoryId, number> = { crs: 0, crowdsec: 1, local: 2 }
const STATES: RuleRepositoryState[] = ['off', 'detect', 'block']

export function ruleHandlers(t: WebsiteHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object, status = 200) => HttpResponse.json(body as Record<string, unknown>, { status })
  const read = async (req: Request) => {
    try {
      return await req.json() as Record<string, unknown>
    }
    catch {
      return {}
    }
  }
  const repoOf = (id: unknown) => typeof id === 'string' && id in ORDER ? t.state().ruleRepos.repositories[id as RuleRepositoryId] : undefined
  const ruleOf = (repo: unknown, id: unknown) => t.state().ruleRepos.rules.find(r => r.repository === repo && r.id === id)
  const notFound = () => problem(404, 'not_found', 'Nicht gefunden')
  const notSupported = () => problem(409, 'not_supported', 'Das geht bei dieser Regelquelle nicht.')
  const note = (v: unknown) => typeof v === 'string' && v.trim() ? v.trim().slice(0, 500) : undefined

  return [
    http.get(`${base}/rule-exceptions`, guard('read', () => json({ items: t.state().ruleRepos.exceptions, max: exceptionsFixture.max }))),
    // D84: the checks of the gateway in short, enough for the form.
    http.post(`${base}/rule-exceptions`, guard('write', async ({ request }) => {
      const body = await read(request)
      const list = t.state().ruleRepos.exceptions
      const str = (v: unknown) => typeof v === 'string' ? v : ''
      const website = str(body.website)
      const path = str(body.path)
      const target = str(body.target)
      const repository = str(body.repository)
      const reason = str(body.reason).trim()
      const rules = Array.isArray(body.rules) ? body.rules.map(String) : []
      if (repository === 'local') return notSupported()
      const errors: { pointer: string, detail: string }[] = []
      if (!website) errors.push({ pointer: '/website', detail: 'fehlt' })
      if (!/^\/[^\s?#]*$/.test(path)) errors.push({ pointer: '/path', detail: 'beginnt mit /' })
      if (!/^(?:ARGS|REQUEST_COOKIES|REQUEST_HEADERS):[\w.*-]*\w[\w.*-]*$/.test(target)) errors.push({ pointer: '/target', detail: 'ein benanntes Feld' })
      if (repository !== 'crs' && repository !== 'crowdsec') errors.push({ pointer: '/repository', detail: 'crs oder crowdsec' })
      else if (!rules.length || rules.length > 16 || new Set(rules).size !== rules.length || rules.some(r => !/^[1-9]\d{0,8}$/.test(r))) errors.push({ pointer: '/rules', detail: '1 bis 16 Regelnummern' })
      if (!reason || reason.length > 300) errors.push({ pointer: '/reason', detail: 'eine Zeile' })
      if (errors.length) return problem(400, 'invalid', 'So lässt sich die Ausnahme nicht anlegen.', errors)
      if (rules.some(r => !ruleOf(repository, r) && !t.state().ruleRepos.rules.some(x => x.repository === repository && x.id.startsWith(r)))) return problem(400, 'unknown_rule', 'Mindestens eine dieser Regeln läuft auf diesem Gateway nicht. Prüf die Nummern unter Regeln.')
      const same = list.find(x => x.website === website && x.path === path && x.target === target && x.repository === repository && x.rules.join() === [...rules].sort().join())
      if (same) return json(same)
      if (list.length >= exceptionsFixture.max) return problem(409, 'exception_cap', `Mehr als ${exceptionsFixture.max} Ausnahmen hält ein Gateway nicht. Entfern zuerst eine, die du nicht mehr brauchst.`)
      const made: RuleException = {
        id: Math.max(1_900_000, ...list.map(x => x.id)) + 1,
        website,
        hosts: [website],
        path,
        target,
        repository: repository as RuleException['repository'],
        rules: [...rules].sort(),
        reason,
        created: isoS(t.now()),
        set_by: 'dashboard',
        token_id: '',
        token_label: '',
      }
      list.push(made)
      return json(made)
    })),
    http.delete(`${base}/rule-exceptions/:id`, guard('write', ({ params }) => {
      const st = t.state().ruleRepos
      const at = st.exceptions.findIndex(x => String(x.id) === params.id)
      if (at < 0) return problem(404, 'not_found', 'Diese Ausnahme gibt es nicht mehr.')
      st.exceptions.splice(at, 1)
      return json({ items: st.exceptions, max: exceptionsFixture.max })
    })),
    // D86: one rule out; the last one out removes the exception.
    http.delete(`${base}/rule-exceptions/:id/rules/:rule`, guard('write', ({ params }) => {
      const st = t.state().ruleRepos
      const at = st.exceptions.findIndex(x => String(x.id) === params.id)
      const x = st.exceptions[at]
      if (!x || !x.rules.includes(String(params.rule))) return problem(404, 'not_found', 'Diese Regel ist in der Ausnahme nicht mehr enthalten.')
      const left = x.rules.filter(r => r !== params.rule)
      if (left.length) st.exceptions[at] = { ...x, rules: left }
      else st.exceptions.splice(at, 1)
      return json({ items: st.exceptions, max: exceptionsFixture.max })
    })),
    http.get(`${base}/rule-repositories`, guard('read', () => {
      const st = t.state()
      return json({ items: (['crs', 'crowdsec', 'local'] as const).map(id => repositoryView(st, id)) })
    })),
    http.get(`${base}/rule-repositories/:repository`, guard('read', ({ params }) => {
      const repo = repoOf(params.repository)
      return repo ? json(repositoryView(t.state(), repo.id)) : notFound()
    })),
    // D73: session and CSRF, no password; the overlay wins over schild.yaml until reset_state.
    http.patch(`${base}/rule-repositories/:repository`, guard('write', async ({ params, request }) => {
      const repo = repoOf(params.repository)
      if (!repo) return notFound()
      const body = await read(request)
      const both = 'state' in body && 'reset_state' in body
      if (both || (!('state' in body) && body.reset_state !== true)) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/state', detail: 'exactly one of state and reset_state' }])
      const now = t.now()
      if (body.reset_state === true) {
        Object.assign(repo, { state: repo.config_state, state_source: repo.config_source, state_set_at: undefined, state_set_by: undefined })
      }
      else {
        if (!STATES.includes(body.state as RuleRepositoryState)) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/state', detail: 'off, detect or block' }])
        Object.assign(repo, { state: body.state, state_source: 'dashboard', state_set_at: now, state_set_by: undefined })
      }
      return json(repositoryView(t.state(), repo.id))
    })),
    // D101: the body replaces what the dashboard set; a field left out falls back to schild.yaml.
    http.patch(`${base}/rule-repositories/:repository/settings`, guard('write', async ({ params, request }) => {
      const repo = repoOf(params.repository)
      if (!repo) return notFound()
      if (!repo.crs) return notSupported()
      const body = await read(request)
      const whole = (v: unknown, max: number) => v === undefined || (Number.isInteger(v) && (v as number) >= 1 && (v as number) <= max)
      if (!whole(body.paranoia_level, 4)) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/paranoia_level', detail: 'eine ganze Zahl von 1 bis 4' }])
      if (!whole(body.inbound_anomaly_threshold, 100)) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/inbound_anomaly_threshold', detail: 'eine ganze Zahl von 1 bis 100' }])
      repo.crs.paranoia_level = (body.paranoia_level as number | undefined) ?? repo.crs.config_paranoia_level
      repo.crs.inbound_anomaly_threshold = (body.inbound_anomaly_threshold as number | undefined) ?? repo.crs.config_inbound_anomaly_threshold
      return json(repositoryView(t.state(), repo.id))
    })),
    http.post(`${base}/rule-repositories/:repository/sync`, guard('write', ({ params }) => {
      const repo = repoOf(params.repository)
      if (!repo) return notFound()
      const st = t.state()
      const now = t.now()
      if (repo.id === 'crs') return notSupported()
      if (repo.id === 'local') {
        if (repo.failNextSync) {
          repo.local!.last_error = repo.failNextSync
          repo.failNextSync = undefined
          return problem(409, 'sync_refused', 'Die Dateien in rules.d ließen sich nicht laden. Es laufen weiter die Regeln von vorher.')
        }
        delete repo.local!.last_error
        repo.local!.last_reload_at = isoS(now)
        return json(repositoryView(st, 'local'))
      }
      const c = repo.crowdsec!
      c.last_check_at = isoS(now)
      if (st.scenario !== 'standalone' && c.update_state === 'unreachable') c.update_state = 'current'
      return json(repositoryView(st, 'crowdsec'))
    })),
    http.post(`${base}/rule-repositories/:repository/reset`, guard('write', ({ params }) => {
      const repo = repoOf(params.repository)
      if (!repo) return notFound()
      if (repo.id !== 'crowdsec') return notSupported()
      const st = t.state()
      // Back to the image snapshot: the rules fetched since are gone, the state stays.
      st.ruleRepos.rules = st.ruleRepos.rules.filter(r => r.repository !== 'crowdsec' || r.origin !== 'update')
      Object.assign(repo.crowdsec!, { set_source: 'image', update_state: st.scenario === 'standalone' ? 'unreachable' : 'current' })
      delete repo.crowdsec!.last_change
      repo.last_change_at = t.now()
      return json(repositoryView(st, 'crowdsec'))
    })),

    http.get(`${base}/rules`, guard('read', ({ request }) => {
      const st = t.state()
      const url = new URL(request.url)
      const repository = url.searchParams.get('repository')
      const status = url.searchParams.get('status')
      const items = st.ruleRepos.rules
        .filter(r => !repository || r.repository === repository)
        .map(r => ruleView(st, r))
        .filter(r => !status || r.status === status)
        .sort((a, b) => b.hits_24h - a.hits_24h || ORDER[a.repository] - ORDER[b.repository] || Number(a.id) - Number(b.id))
      const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit') ?? 50) || 50))
      const offset = Number(url.searchParams.get('cursor') || 0) || 0
      return json({ items: items.slice(offset, offset + limit), next_cursor: offset + limit < items.length ? String(offset + limit) : null })
    })),
    http.get(`${base}/rules/:repository/:rule`, guard('read', ({ params }) => {
      const r = ruleOf(params.repository, params.rule)
      return r ? json(ruleDetail(t.state(), r)) : notFound()
    })),
    http.patch(`${base}/rules/:repository/:rule`, guard('write', async ({ params, request }) => {
      const r = ruleOf(params.repository, params.rule)
      if (!r) return notFound()
      const body = await read(request)
      if (typeof body.disabled !== 'boolean') return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/disabled', detail: 'required' }])
      if (r.disabled?.by === 'config') return problem(409, 'config_limit', 'Diese Regel ist in schild.yaml ausgeschaltet und lässt sich nur dort wieder einschalten.')
      r.disabled = body.disabled ? { by: 'dashboard', at: t.now(), note: note(body.note) } : undefined
      return json(ruleDetail(t.state(), r))
    })),
  ]
}
