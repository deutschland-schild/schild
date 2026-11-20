import type {
  Bundle,
  Client,
  Issuer,
  LabHealth,
  LabSettings,
  LogEntry,
  PatternDetail,
  PatternSummary,
  Peer,
  Proposal,
  ReceivedSignal,
  Relay,
  Withdrawal,
} from '@/api/types'
import bundlePage from '../../../../../contracts/api/fixtures/lab/listBundles.json'
import clientPage from '../../../../../contracts/api/fixtures/lab/listClients.json'
import issuerList from '../../../../../contracts/api/fixtures/lab/listIssuers.json'
import labHealth from '../../../../../contracts/api/fixtures/lab/getHealth.json'
import labSettings from '../../../../../contracts/api/fixtures/lab/getSettings.json'
import patternDetail from '../../../../../contracts/api/fixtures/lab/getPattern.json'
import patternPage from '../../../../../contracts/api/fixtures/lab/listPatterns.json'
import peerList from '../../../../../contracts/api/fixtures/lab/listPeers.json'
import proposalPage from '../../../../../contracts/api/fixtures/lab/listProposals.json'
import signalPage from '../../../../../contracts/api/fixtures/lab/listSignals.json'
import relayList from '../../../../../contracts/api/fixtures/lab/listRelays.json'
import withdrawalPage from '../../../../../contracts/api/fixtures/lab/listWithdrawals.json'

/**
 * Seed data for mock mode: the contract fixtures (contracts/api/fixtures/lab) plus a few
 * deterministic extras so every screen has something realistic to show. Documentation ASNs only
 * (64496-64511), never an IP address: labs have none.
 */

const clone = <T>(v: unknown): T => JSON.parse(JSON.stringify(v)) as T

export interface Seed {
  now: Date
  health: LabHealth
  patterns: PatternSummary[]
  details: Record<string, PatternDetail>
  signals: ReceivedSignal[]
  proposals: Proposal[]
  bundles: Bundle[]
  withdrawals: Withdrawal[]
  relays: Relay[]
  peers: Peer[]
  issuers: Issuer[]
  clients: Client[]
  settings: LabSettings
  log: Omit<LogEntry, 'digest'>[]
}

/** Small deterministic PRNG so the seed looks the same on every load (and in tests). */
export function rng(seed: number) {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s / 2 ** 32
  }
}

const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

const EXTRA: { sig: string, cat: string, issuers: number, share: number, signals: number, status: PatternSummary['status'], ageH: number }[] = [
  { sig: 'xmlrpc-multicall/xmlrpc.php', cat: 'wordpress-xmlrpc-abuse', issuers: 6, share: 0.22, signals: 5120, status: 'watching', ageH: 70 },
  { sig: 'path-traversal/wp-content', cat: 'path-traversal', issuers: 5, share: 0.29, signals: 640, status: 'new', ageH: 3 },
  { sig: 'scanner-burst/.env', cat: 'sensitive-file-probe', issuers: 9, share: 0.18, signals: 12210, status: 'watching', ageH: 160 },
  { sig: 'rce/gallery-upload', cat: 'remote-code-execution', issuers: 2, share: 0.62, signals: 88, status: 'new', ageH: 1 },
  { sig: 'credential-stuffing/my-account', cat: 'credential-stuffing', issuers: 4, share: 0.41, signals: 2304, status: 'new', ageH: 9 },
  { sig: 'xss/search-param', cat: 'cross-site-scripting', issuers: 3, share: 0.34, signals: 190, status: 'watching', ageH: 30 },
  { sig: 'sqli/woocommerce-orderby', cat: 'sql-injection', issuers: 1, share: 1, signals: 51, status: 'new', ageH: 0.5 },
  { sig: 'log4shell/user-agent', cat: 'remote-code-execution', issuers: 7, share: 0.2, signals: 930, status: 'ignored', ageH: 400 },
  { sig: 'admin-ajax-flood/admin-ajax.php', cat: 'resource-exhaustion', issuers: 3, share: 0.3, signals: 4400, status: 'published', ageH: 220 },
]

const COUNTRIES = ['NL', 'US', 'DE', 'FR', 'SG', 'BR', 'RU', 'CN', 'VN', 'IN']
const ASNS = [64496, 64497, 64500, 64501, 64505, 64510, 64511]
const ISSUERS = ['issuer-test-1', 'issuer-test-2', 'issuer-test-3', 'issuer-test-4', 'issuer-test-5', 'issuer-test-6', 'issuer-test-7', 'issuer-test-8', 'issuer-test-9']

function split(total: number, parts: number, firstShare: number, rand: () => number): number[] {
  const first = Math.round(total * firstShare)
  const rest = total - first
  if (parts <= 1) return [total]
  const weights = Array.from({ length: parts - 1 }, () => 0.5 + rand())
  const sum = weights.reduce((a, b) => a + b, 0)
  const out = [first, ...weights.map(w => Math.min(first, Math.round((rest * w) / sum)))]
  return out.sort((a, b) => b - a)
}

function hexId(rand: () => number, n = 16): string {
  return Array.from({ length: n }, () => Math.floor(rand() * 16).toString(16)).join('')
}

function detailFor(p: PatternSummary, rand: () => number, now: Date): PatternDetail {
  const byIssuer = split(p.signals, Math.max(1, p.issuers), p.max_issuer_share, rand).map((count, i) => ({ key: ISSUERS[i % ISSUERS.length]!, count }))
  const countries = split(p.signals, 4, 0.45, rand).map((count, i) => ({ key: COUNTRIES[(i * 3 + p.signals) % COUNTRIES.length]!, count }))
  const asns = split(p.signals, 3, 0.5, rand).map((count, i) => ({ key: ASNS[(i + p.issuers) % ASNS.length]!, count }))
  const timeline = Array.from({ length: 24 }, (_, i) => {
    const bucket = new Date(now.getTime() - (23 - i) * 3600_000)
    bucket.setUTCMinutes(0, 0, 0)
    const base = p.signals / 24
    const signals = Math.max(0, Math.round(base * (0.4 + rand() * 1.2) * (i > 18 ? 1.6 : 1)))
    return { bucket: iso(bucket), signals, issuers: Math.max(1, Math.min(p.issuers, Math.round(p.issuers * (0.5 + rand() / 2)))) }
  })
  return {
    pattern: p,
    by_issuer: byIssuer,
    by_operator: [],
    countries,
    asns,
    net_classes: [{ key: 'hosting', count: Math.round(p.signals * 0.7) }, { key: 'residential', count: Math.round(p.signals * 0.3) }],
    agents: [{ key: 'python-requests/2', count: Math.round(p.signals * 0.6) }, { key: 'curl/8', count: Math.round(p.signals * 0.4) }],
    waf_rules: [{ key: 942100, count: p.signals }],
    timeline,
    samples: [],
  }
}

export function buildSeed(now = new Date()): Seed {
  const rand = rng(42)
  const health = clone<LabHealth>(labHealth)
  health.generated_at = iso(now)

  const patterns = clone<PatternSummary[]>(patternPage.items)
  for (const [i, x] of EXTRA.entries()) {
    const first = new Date(now.getTime() - x.ageH * 3600_000)
    patterns.push({
      pattern_id: `p_${hexId(rand)}`,
      action_sig: x.sig,
      categories: [x.cat],
      status: x.status,
      signals: x.signals,
      issuers: x.issuers,
      clients: x.issuers * 3 + i,
      max_issuer_share: x.share,
      request_sigs: 1 + (i % 5),
      score_avg: 40 + Math.round(rand() * 55),
      top_countries: [{ key: COUNTRIES[i % COUNTRIES.length]!, count: Math.round(x.signals * 0.5) }, { key: 'US', count: Math.round(x.signals * 0.2) }],
      top_asns: [{ key: ASNS[i % ASNS.length]!, count: Math.round(x.signals * 0.4) }],
      first_seen: iso(first),
      last_seen: iso(new Date(now.getTime() - Math.round(rand() * 30) * 60_000)),
      proposal_id: null,
    })
  }
  // Fixture times are fixed; move them close to "now" so relative times read naturally.
  for (const p of patterns.slice(0, 2)) {
    p.last_seen = iso(new Date(now.getTime() - 5 * 60_000))
    p.first_seen = iso(new Date(now.getTime() - 33 * 3600_000))
  }

  const details: Record<string, PatternDetail> = {}
  for (const p of patterns) details[p.pattern_id] = detailFor(p, rand, now)
  const fixtureDetail = clone<PatternDetail>(patternDetail)
  fixtureDetail.pattern = patterns[0]!
  details[fixtureDetail.pattern.pattern_id] = { ...details[fixtureDetail.pattern.pattern_id]!, ...fixtureDetail, timeline: details[fixtureDetail.pattern.pattern_id]!.timeline }

  const signals = clone<ReceivedSignal[]>(signalPage.items)
  for (const d of Object.values(details)) {
    if (!d.samples?.length) d.samples = signals.filter(s => s.payload.action_sig === d.pattern.action_sig)
  }

  const proposals = clone<Proposal[]>(proposalPage.items)
  // Fixture times are absolute; anchor them to `now` so the review order (newest first:
  // prop-0007, then the extra prop-0008 from 8 h ago) does not depend on the time of day.
  proposals.forEach((p, i) => {
    p.created_at = iso(new Date(now.getTime() - (3 + 24 * i) * 3600_000))
    p.updated_at = iso(new Date(now.getTime() - (1 + 24 * i) * 3600_000))
  })
  proposals.push(
    {
      ...clone<Proposal>(proposalPage.items[0]),
      id: 'prop-0008',
      rule_id: 'schild-2026-0414',
      status: 'review',
      pattern_id: patterns.find(p => p.action_sig === 'credential-stuffing/my-account')!.pattern_id,
      class: 'behavioral',
      seclang: 'SecRule REQUEST_URI "@beginsWith /my-account/" "id:7700014,phase:1,pass,log,msg:\'Credential stuffing on my-account\',tag:\'schild-remote\',t:none,chain"\n  SecRule &ARGS_POST:password "@gt 0" "t:none"',
      target: { software: 'woocommerce', versions: '*' },
      evidence: { reproduced_operators: 0, sensor_operators: 1, tip_issuers: 4, max_issuer_share: 0.41, human_approval_orgs: 0, reproductions: [] },
      allowed_max_action: 'observe',
      requested_max_action: 'challenge',
      approvals: [],
      created_at: iso(new Date(now.getTime() - 8 * 3600_000)),
      updated_at: iso(new Date(now.getTime() - 2 * 3600_000)),
    },
    {
      ...clone<Proposal>(proposalPage.items[0]),
      id: 'prop-0009',
      rule_id: 'schild-2026-0415',
      status: 'draft',
      pattern_id: patterns.find(p => p.action_sig === 'path-traversal/wp-content')!.pattern_id,
      class: 'heuristic',
      seclang: 'SecRule REQUEST_URI "@contains ../wp-config" "id:7700015,phase:1,pass,log,msg:\'Path traversal to wp-config\',tag:\'schild-remote\',t:none,t:urlDecodeUni"',
      target: { software: 'wordpress', versions: '*' },
      evidence: { reproduced_operators: 0, sensor_operators: 0, tip_issuers: 5, max_issuer_share: 0.29, human_approval_orgs: 0, reproductions: [] },
      allowed_max_action: 'observe',
      requested_max_action: 'observe',
      approvals: [],
      created_at: iso(new Date(now.getTime() - 40 * 60_000)),
      updated_at: iso(new Date(now.getTime() - 40 * 60_000)),
    },
  )

  const bundles = clone<Bundle[]>(bundlePage.items)
  const withdrawals = clone<Withdrawal[]>(withdrawalPage.items)
  // Start calm: no emergency stop pending. Instead a rule withdrawal proposed by another operator, waiting for our co-signature.
  withdrawals[0] = {
    seq: 4,
    channel: 'schild-main',
    scope: 'rules',
    rule_ids: ['schild-2026-0413'],
    reason: 'false_positives',
    note: 'Fehlalarme bei Login über Single Sign-on',
    up_to_version: 42,
    status: 'collecting',
    signatures: [{ keyid: 'test-lab-b', lab: 'lab-b', operator: 'op-test-b', at: iso(new Date(now.getTime() - 25 * 60_000)) }],
    threshold: 2,
    proposed_by: 'lab-b',
    created_at: iso(new Date(now.getTime() - 25 * 60_000)),
    effective_at: null,
  }

  const relays = clone<Relay[]>(relayList.items)
  relays.push({ id: 'relay-3', kind: 'relay', url: 'http://relay-3.schild.test:7480', status: 'lagging', connected_since: iso(new Date(now.getTime() - 3 * 3600_000)), last_event_id: 'k3x9-1031', lag_events: 11 })
  const peers = clone<Peer[]>(peerList.items)
  peers.push({ lab: 'lab-b', operator: 'op-test-b', endpoint: 'https://lab-b.schild.test:7444', accept_from: true, share_with: true, trust_weight: 1, observe_only: false, status: 'ok', last_seen: iso(new Date(now.getTime() - 20_000)), independent: true })
  peers.push({ lab: 'lab-c', operator: 'op-test-c', endpoint: 'https://lab-c.schild.test:7444', accept_from: true, share_with: false, trust_weight: 0.5, observe_only: true, status: 'slow', last_seen: iso(new Date(now.getTime() - 4 * 60_000)), independent: true })

  const issuers = clone<Issuer[]>(issuerList.items)
  // The usability task L5 asks to revoke issuer-test-evil: start with it active (it is revoked in the fixture).
  const evil = issuers.find(i => i.id === 'issuer-test-evil')!
  Object.assign(evil, { revoked: false, revoked_at: null, quota_per_day: 100000, used_24h: 40211, signals_24h: 40211, rejected_24h: 40211, patterns_24h: 31 })
  issuers.push({ id: 'issuer-test-3', quota_per_day: 20000, used_24h: 1730, clients: 4, signals_24h: 1730, rejected_24h: 1, patterns_24h: 6, revoked: false, revoked_at: null })

  const clients = clone<Client[]>(clientPage.items)
  for (let i = 0; i < 6; i++) {
    clients.push({ keyid: `test-site-evil-${i + 1}`, issuer: 'issuer-test-evil', quota_per_day: 500, used_24h: 480 - i * 7, last_seen_bucket: iso(new Date(now.getTime() - i * 300_000)), revoked: false, test_key: true })
  }

  const settings = clone<LabSettings>(labSettings)

  const log: Omit<LogEntry, 'digest'>[] = []
  let index = 0
  const start = now.getTime() - 41 * 3600_000
  for (let i = 0; i < 40; i++) {
    const t = new Date(start + i * 3600_000)
    const kind: LogEntry['kind'] = i % 5 === 0 ? 'proposal' : i % 7 === 0 ? 'bundle' : i % 11 === 0 ? 'withdrawal' : 'checkpoint'
    const ref = kind === 'checkpoint' ? String(i) : kind === 'bundle' ? '42' : kind === 'withdrawal' ? '3' : ['prop-0006', 'prop-0007', 'prop-0008', 'prop-0009'][i % 4]!
    const summary = kind === 'checkpoint' ? `checkpoint ${ref}` : kind === 'bundle' ? `bundle ${ref} published` : kind === 'withdrawal' ? `withdrawal ${ref} effective` : `proposal ${ref}`
    log.push({ index: index++, time: iso(t), kind, ref, summary, envelope: null })
  }

  return { now, health, patterns, details, signals, proposals, bundles, withdrawals, relays, peers, issuers, clients, settings, log }
}
