import type {
  ApproveProposal,
  AssembleBundle,
  Bundle,
  Confirm,
  EmergencyStopInput,
  EvidenceInput,
  LabHealth,
  LabSettingsPatch,
  LogEntry,
  Proposal,
  ProposalInput,
  Session,
  Signature,
  Withdrawal,
  WithdrawalInput,
} from '@/api/types'
import type { Seed } from './seed'
import { actionRank, evidenceLevel, levelWithApproval } from '@/lib/evidence'
import { bytesToBase64, digestOf } from '@/lib/digest'
import { WITHDRAW_ALL_PHRASE, WITHDRAW_ALL_WIRE_CONFIRM } from '@/lib/labels'
import { treeRoot } from '@/lib/logverify'
import { buildSeed, rng } from './seed'

/**
 * In-memory lab for mock mode. Mirrors the server rules that matter for the UI:
 * withdrawing all network rules needs the typed phrase (wire: confirm_text NOT-AUS until contracts v0.4) + password, approvals never above the evidence (G2), human approval with person and org,
 * k-of-n signatures by distinct operators, revocations need the password.
 * Not a security boundary: the real checks live in schild-lab.
 */
export interface MockResult { status: number, body?: unknown }

export const MOCK_WRONG_PASSWORD = 'falsch'
const SELF = { lab: 'lab-a', operator: 'op-test-a', keyid: 'test-lab-a' }
const PEER = { lab: 'lab-b', operator: 'op-test-b', keyid: 'test-lab-b' }

const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

function problem(status: number, code: string, title: string, errors?: { pointer: string, detail: string }[], detail?: string): MockResult {
  return { status, body: { type: `https://schild.example/problems/${code}`, title, status, code, ...(detail ? { detail } : {}), ...(errors ? { errors } : {}) } }
}

const ok = (body: unknown, status = 200): MockResult => ({ status, body })

function page<T>(items: T[], cursor: string | null | undefined, limit = 50): { items: T[], next_cursor: string | null } {
  const start = cursor ? Number(atob(cursor)) || 0 : 0
  const end = start + Math.min(500, Math.max(1, limit))
  return { items: items.slice(start, end), next_cursor: end < items.length ? btoa(String(end)) : null }
}

function distinctOperators(sigs: Signature[]): number {
  return new Set(sigs.map(s => s.operator)).size
}

export interface SessionStore {
  get: () => Session
  set: (s: Session) => void
}

export function memorySessionStore(initial: Session = { authenticated: false, first_run: false }): SessionStore {
  let s = initial
  return { get: () => s, set: (v) => { s = v } }
}

export class LabMock {
  state: Seed
  private rand = rng(7)
  private started = Date.now()
  private timers: ReturnType<typeof setTimeout>[] = []
  /** Delay until the simulated peer lab co-signs (ms). 0 disables the simulation. */
  peerDelayMs: number
  logEntries: LogEntry[] = []
  private ready: Promise<void>

  constructor(private session: SessionStore, opts: { now?: Date, peerDelayMs?: number } = {}) {
    this.state = buildSeed(opts.now)
    this.peerDelayMs = opts.peerDelayMs ?? 15_000
    this.ready = this.buildLog()
  }

  whenReady(): Promise<void> {
    return this.ready
  }

  dispose(): void {
    for (const t of this.timers) clearTimeout(t)
  }

  private now(): Date {
    return new Date()
  }

  // ---------- public log with real digests ----------

  private async envelopeFor(kind: string, ref: string, summary: string, time: string) {
    const payload = JSON.stringify({ schema: `schild.log.${kind}/0`, ref, summary, time })
    const bytes = new TextEncoder().encode(payload)
    // Proposal entries carry no envelope (the digest covers the rule text), as in the lab.
    if (kind === 'proposal') return { envelope: null, envelope_sha256: null, digest: await digestOf(bytes) }
    const envelope = { payloadType: `application/vnd.schild.${kind}.v0+json`, payload: bytesToBase64(bytes), signatures: [{ keyid: SELF.keyid, sig: bytesToBase64(new TextEncoder().encode(`test-only-${ref}`)) }] }
    return { envelope: envelope as unknown as LogEntry['envelope'], envelope_sha256: await digestOf(JSON.stringify(envelope)), digest: await digestOf(bytes) }
  }

  private async buildLog() {
    const out: LogEntry[] = []
    for (const e of this.state.log) {
      const { envelope, envelope_sha256, digest } = await this.envelopeFor(e.kind, e.ref, e.summary, e.time)
      out.push({ ...e, digest, envelope, envelope_sha256 })
    }
    this.logEntries = out.reverse() // newest first
  }

  private async appendLog(kind: LogEntry['kind'], ref: string, summary: string) {
    await this.ready
    const time = iso(this.now())
    const index = (this.logEntries[0]?.index ?? -1) + 1
    const { envelope, envelope_sha256, digest } = await this.envelopeFor(kind, ref, summary, time)
    this.logEntries.unshift({ index, time, kind, ref, summary, digest, envelope, envelope_sha256 })
  }

  private later(fn: () => void) {
    if (this.peerDelayMs <= 0) return
    this.timers.push(setTimeout(fn, this.peerDelayMs))
  }

  // ---------- auth ----------

  getSession(): MockResult {
    return ok(this.session.get())
  }

  private openSession(user: string, via: Session['via']): Session {
    const s: Session = { authenticated: true, first_run: false, user, role: 'admin', csrf_token: `mock-csrf-${Math.floor(this.rand() * 1e12).toString(16).padStart(12, '0')}`, expires_at: iso(new Date(this.now().getTime() + 8 * 3600_000)), via }
    this.session.set(s)
    return s
  }

  login(body: { user?: string, password?: string }): MockResult {
    if (!body.password) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/password', detail: 'Bitte gib dein Passwort ein.' }])
    if (body.password === MOCK_WRONG_PASSWORD) return problem(401, 'unauthenticated', 'Anmeldung fehlgeschlagen', undefined, 'Benutzer oder Passwort stimmen nicht.')
    return ok(this.openSession(body.user || 'admin', 'password'))
  }

  setup(body: { password?: string }): MockResult {
    if (!this.session.get().first_run) return problem(409, 'conflict', 'Schon eingerichtet')
    if (!body.password || body.password.length < 12) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/password', detail: 'Mindestens 12 Zeichen.' }])
    return ok(this.openSession('admin', 'password'))
  }

  logout(): MockResult {
    this.session.set({ authenticated: false, first_run: false })
    return { status: 204 }
  }

  /** null when the request may proceed; else the problem response. */
  guard(method: string, csrf: string | null): MockResult | null {
    const s = this.session.get()
    if (!s.authenticated) return problem(401, 'unauthenticated', 'Nicht angemeldet')
    if (method !== 'GET' && csrf !== s.csrf_token) return problem(403, 'csrf', 'CSRF-Token fehlt oder passt nicht')
    return null
  }

  private checkPassword(password: string | undefined, pointer = '/password'): MockResult | null {
    if (!password) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer, detail: 'Bitte gib dein Passwort ein.' }])
    if (password === MOCK_WRONG_PASSWORD) return problem(403, 'forbidden', 'Passwort falsch', [{ pointer, detail: 'Das Passwort stimmt nicht.' }])
    return null
  }

  // ---------- health ----------

  health(): MockResult {
    const h = this.state.health
    const jitter = (v: number, f = 0.08) => Math.max(0, Math.round(v * (1 + (this.rand() - 0.5) * 2 * f) * 10) / 10)
    const next: LabHealth = {
      ...h,
      generated_at: iso(this.now()),
      ingest: { ...h.ingest, rate_per_s: jitter(184.2), accepted_24h: h.ingest.accepted_24h + Math.round(this.rand() * 900) },
      ack_ms: { ...h.ack_ms, p50: jitter(3.1, 0.2), p99: jitter(18.7, 0.25), max: jitter(41, 0.15) },
      queue: { ...h.queue, depth: { new_pattern: Math.round(jitter(12, 0.5)), repeat: Math.round(jitter(2210, 0.2)), baseline: Math.round(jitter(40112, 0.1)) }, oldest_age_s: jitter(41, 0.3) },
      workers: h.workers.map(w => (w.status === 'running' ? { ...w, processed_per_s: jitter(w.processed_per_s ?? 0), lag_s: jitter(w.lag_s ?? 0, 0.4) } : w)),
      feed: { ...h.feed, checkpoint_seq: 10 + Math.floor((Date.now() - this.started) / 60_000), last_checkpoint_at: iso(new Date(Date.now() - ((Date.now() - this.started) % 60_000))), bundle_version: this.publishedVersion(), withdrawal_seq: Math.max(0, ...this.state.withdrawals.filter(w => w.status === 'effective').map(w => w.seq)) },
    }
    this.state.health = { ...next, ingest: { ...next.ingest } }
    return ok(next)
  }

  private publishedVersion(): number {
    return Math.max(0, ...this.state.bundles.filter(b => b.status === 'published').map(b => b.version))
  }

  // ---------- patterns ----------

  listPatterns(q: URLSearchParams): MockResult {
    let items = [...this.state.patterns]
    const text = q.get('q')?.toLowerCase()
    if (text) items = items.filter(p => p.action_sig.toLowerCase().includes(text) || p.categories?.some(c => c.toLowerCase().includes(text)))
    const category = q.get('category')
    if (category) items = items.filter(p => p.categories?.includes(category))
    const country = q.get('country')
    if (country) items = items.filter(p => p.top_countries?.some(c => c.key === country))
    const asn = q.get('asn')
    if (asn) items = items.filter(p => p.top_asns?.some(c => String(c.key) === asn))
    const minIssuers = q.get('min_issuers')
    if (minIssuers) items = items.filter(p => p.issuers >= Number(minIssuers))
    const status = q.get('status')
    if (status) items = items.filter(p => p.status === status)
    const sort = q.get('sort') ?? 'last_seen'
    const by: Record<string, (p: typeof items[number]) => number> = {
      last_seen: p => Date.parse(p.last_seen),
      first_seen: p => Date.parse(p.first_seen),
      signals: p => p.signals,
      issuers: p => p.issuers,
    }
    const f = by[sort] ?? by.last_seen!
    items.sort((a, b) => f(b) - f(a))
    return ok(page(items, q.get('cursor'), Number(q.get('limit') ?? 50)))
  }

  getPattern(id: string): MockResult {
    const d = this.state.details[id]
    if (!d) return problem(404, 'not_found', 'Muster nicht gefunden')
    return ok({ ...d, pattern: this.state.patterns.find(p => p.pattern_id === id) })
  }

  listSignals(q: URLSearchParams): MockResult {
    let items = [...this.state.signals]
    const pid = q.get('pattern_id')
    if (pid) {
      const sig = this.state.patterns.find(p => p.pattern_id === pid)?.action_sig
      items = items.filter(s => s.pattern_id === pid || s.payload.action_sig === sig)
    }
    const issuer = q.get('issuer')
    if (issuer) items = items.filter(s => s.issuer === issuer)
    return ok(page(items, q.get('cursor'), Number(q.get('limit') ?? 50)))
  }

  // ---------- proposals ----------

  listProposals(q: URLSearchParams): MockResult {
    const status = q.get('status')
    const items = this.state.proposals.filter(p => !status || p.status === status).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
    return ok(page(items, q.get('cursor'), Number(q.get('limit') ?? 50)))
  }

  getProposal(id: string): MockResult {
    const p = this.state.proposals.find(x => x.id === id)
    return p ? ok(p) : problem(404, 'not_found', 'Vorschlag nicht gefunden')
  }

  private seclangCheck(text: string): Proposal['seclang_check'] {
    if (/\bctl:|REMOTE_ADDR|@ipMatch|\ballow\b|%\{/.test(text)) return { valid: false, error: 'outside the SecLang subset (ctl, REMOTE_ADDR, @ipMatch, allow and macros are not allowed)' }
    if (!/id:77\d{5}/.test(text)) return { valid: false, error: 'rule id must be in 7700000..7799999' }
    return { valid: true }
  }

  private recompute(p: Proposal) {
    const reproducedOps = new Set(p.evidence.reproductions.filter(r => r.status === 'reproduced').map(r => r.operator))
    p.evidence.reproduced_operators = reproducedOps.size
    p.evidence.human_approval_orgs = new Set(p.approvals.map(a => a.org)).size
    p.allowed_max_action = evidenceLevel(p.class, p.evidence)
    p.updated_at = iso(this.now())
  }

  createProposal(body: ProposalInput): MockResult {
    const errors: { pointer: string, detail: string }[] = []
    if (!body.seclang?.trim()) errors.push({ pointer: '/seclang', detail: 'Bitte gib die Regel ein.' })
    if (!body.class) errors.push({ pointer: '/class', detail: 'Bitte wähle eine Klasse.' })
    const target = (body.target ?? {}) as { software?: string, versions?: string, cve?: string[] }
    if (!target.software) errors.push({ pointer: '/target/software', detail: 'Bitte nenne die betroffene Software.' })
    if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
    const pattern = this.state.patterns.find(x => x.pattern_id === body.pattern_id)
    const next = Math.max(...this.state.proposals.map(p => Number(p.id.slice(5)))) + 1
    const ruleNo = Math.max(...this.state.proposals.map(p => Number(p.rule_id.slice(12)))) + 1
    const p: Proposal = {
      id: `prop-${String(next).padStart(4, '0')}`,
      rule_id: `schild-2026-${String(ruleNo).padStart(4, '0')}`,
      status: 'review',
      pattern_id: body.pattern_id ?? null,
      class: body.class!,
      stage: body.stage ?? 'shadow',
      seclang: body.seclang!,
      seclang_check: this.seclangCheck(body.seclang!),
      target: { software: target.software!, versions: target.versions || '*', ...(target.cve?.length ? { cve: target.cve } : {}) },
      evidence: { reproduced_operators: 0, sensor_operators: 0, tip_issuers: pattern?.issuers ?? 0, max_issuer_share: pattern?.max_issuer_share ?? 1, human_approval_orgs: 0, reproductions: [] },
      allowed_max_action: null,
      requested_max_action: body.requested_max_action ?? 'observe',
      max_action_until: null,
      approvals: [],
      rejected_reason: null,
      bundle_version: null,
      created_by: this.session.get().user ?? null,
      created_at: iso(this.now()),
      updated_at: iso(this.now()),
    }
    this.recompute(p)
    this.state.proposals.unshift(p)
    if (pattern) {
      pattern.status = 'proposed'
      pattern.proposal_id = p.id
    }
    void this.appendLog('proposal', p.id, `proposal ${p.rule_id} (${p.class}, ${p.target.software} ${p.target.versions})`)
    return ok(p, 201)
  }

  updateProposal(id: string, body: ProposalInput): MockResult {
    const p = this.state.proposals.find(x => x.id === id)
    if (!p) return problem(404, 'not_found', 'Vorschlag nicht gefunden')
    if (p.status !== 'draft' && p.status !== 'review') return problem(409, 'conflict', 'Nur Entwürfe und Vorschläge in Prüfung lassen sich ändern')
    if (body.seclang !== undefined) {
      p.seclang = body.seclang
      p.seclang_check = this.seclangCheck(body.seclang)
    }
    if (body.class) p.class = body.class
    if (body.requested_max_action) p.requested_max_action = body.requested_max_action
    if (body.stage) p.stage = body.stage
    if (body.target) p.target = { ...p.target, ...(body.target as object) }
    // Edits invalidate earlier approvals: they referred to another text.
    p.approvals = []
    this.recompute(p)
    return ok(p)
  }

  addEvidence(id: string, body: EvidenceInput): MockResult {
    const p = this.state.proposals.find(x => x.id === id)
    if (!p) return problem(404, 'not_found', 'Vorschlag nicht gefunden')
    if (body.kind === 'reproduction') {
      const errors: { pointer: string, detail: string }[] = []
      if (!body.image) errors.push({ pointer: '/image', detail: 'Bitte nenne das Container-Image.' })
      if (!body.version) errors.push({ pointer: '/version', detail: 'Bitte nenne die Version.' })
      if (!body.request?.trim()) errors.push({ pointer: '/request', detail: 'Bitte füge die reproduzierende Anfrage ein.' })
      if (!body.result) errors.push({ pointer: '/result', detail: 'Bitte wähle das Ergebnis.' })
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      const existing = p.evidence.reproductions.find(r => r.lab === SELF.lab)
      const repro = { lab: SELF.lab, operator: SELF.operator, status: body.result!, image: body.image!, version: body.version!, request_digest: `sha256:${'0'.repeat(64)}`, at: iso(this.now()) }
      void digestOf(body.request!).then((d) => { repro.request_digest = d })
      if (existing) Object.assign(existing, repro)
      else p.evidence.reproductions.push(repro)
    }
    else if (body.kind === 'sensor') {
      p.evidence.sensor_operators = Math.max(p.evidence.sensor_operators, 1)
    }
    else if (body.kind === 'negative_corpus') {
      p.evidence.negative_corpus = { version: body.corpus_version ?? 'corpus-2026.10', matches: body.corpus_matches ?? 0 }
    }
    this.recompute(p)
    return ok(p)
  }

  approve(id: string, body: ApproveProposal): MockResult {
    const p = this.state.proposals.find(x => x.id === id)
    if (!p) return problem(404, 'not_found', 'Vorschlag nicht gefunden')
    if (!['review', 'approved'].includes(p.status)) return problem(409, 'conflict', 'Dieser Vorschlag lässt sich nicht freigeben')
    if (!body.org?.trim()) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/org', detail: 'Bitte nenne deine Organisation.' }])
    if (!p.seclang_check.valid) return problem(409, 'seclang', 'Regel ungültig', undefined, p.seclang_check.error)
    const user = this.session.get().user ?? 'admin'
    if (p.created_by && p.created_by === user) return problem(403, 'self_approval', 'Eigener Vorschlag', undefined, `${user} hat den Vorschlag angelegt; eine andere Person muss freigeben.`)
    if (p.approvals.some(a => a.by === user)) return problem(409, 'conflict', 'Du hast diesen Vorschlag schon freigegeben')
    const allowed = levelWithApproval(p.class, p.evidence, body.org, p.approvals.map(a => a.org), p.allowed_max_action)
    if (actionRank(body.max_action) > actionRank(allowed)) {
      return problem(409, 'evidence', 'Belege reichen nicht', [{ pointer: '/max_action', detail: `Die Belege erlauben höchstens ${allowed ?? 'nichts'}.` }])
    }
    if (body.max_action !== 'observe' && !body.max_action_until) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/max_action_until', detail: 'Challenge und Sperren brauchen ein Enddatum.' }])
    p.approvals.push({ by: user, org: body.org, at: iso(this.now()), max_action: body.max_action })
    p.max_action_until = body.max_action_until ?? null
    p.status = 'approved'
    this.recompute(p)
    void this.appendLog('proposal', p.id, `proposal ${p.rule_id} approved by ${body.org} (${body.max_action})`)
    return ok(p)
  }

  reject(id: string, body: { reason?: string }): MockResult {
    const p = this.state.proposals.find(x => x.id === id)
    if (!p) return problem(404, 'not_found', 'Vorschlag nicht gefunden')
    if (!body.reason?.trim()) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/reason', detail: 'Bitte nenne einen Grund.' }])
    if (!['draft', 'review', 'approved'].includes(p.status)) return problem(409, 'conflict', 'Dieser Vorschlag lässt sich nicht ablehnen')
    p.status = 'rejected'
    p.rejected_reason = body.reason
    p.updated_at = iso(this.now())
    const pattern = this.state.patterns.find(x => x.proposal_id === p.id)
    if (pattern) pattern.status = 'watching'
    void this.appendLog('proposal', p.id, `proposal ${p.rule_id} rejected`)
    return ok(p)
  }

  // ---------- bundles ----------

  listBundles(q: URLSearchParams): MockResult {
    return ok(page([...this.state.bundles].sort((a, b) => b.version - a.version), q.get('cursor'), Number(q.get('limit') ?? 50)))
  }

  getBundle(version: number): MockResult {
    const b = this.state.bundles.find(x => x.version === version)
    return b ? ok(b) : problem(404, 'not_found', 'Bündel nicht gefunden')
  }

  cosignBundle(version: number, body: Confirm): MockResult {
    const b = this.state.bundles.find(x => x.version === version)
    if (!b) return problem(404, 'not_found', 'Bündel nicht gefunden')
    const pw = this.checkPassword(body.password)
    if (pw) return pw
    if (b.status !== 'collecting') return problem(409, 'conflict', 'Dieses Bündel sammelt keine Signaturen mehr')
    if (b.signatures.some(s => s.lab === SELF.lab)) return problem(409, 'conflict', 'Dieses Lab hat schon signiert')
    b.signatures.push({ ...SELF, at: iso(this.now()) })
    if (distinctOperators(b.signatures) >= b.threshold) {
      for (const x of this.state.bundles) if (x.status === 'published') x.status = 'superseded'
      b.status = 'published'
      b.digest = `sha256:${version.toString(16).padStart(64, 'b')}`
      void this.appendLog('bundle', String(version), `bundle ${version} published (${b.rules.length} rules, ${distinctOperators(b.signatures)} operators)`)
    }
    return ok(b)
  }

  assembleBundle(body: AssembleBundle): MockResult {
    const errors: { pointer: string, detail: string }[] = []
    body.add.forEach((id, i) => {
      const p = this.state.proposals.find(x => x.id === id)
      if (!p || p.status !== 'approved') errors.push({ pointer: `/add/${i}`, detail: `${id} ist nicht freigegeben.` })
    })
    if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
    if (!body.add.length && !body.remove.length) return problem(400, 'invalid', 'Nichts zu ändern', [{ pointer: '/add', detail: 'Wähle mindestens einen freigegebenen Vorschlag.' }])
    const current = this.state.bundles.find(b => b.status === 'published')
    const version = Math.max(...this.state.bundles.map(b => b.version)) + 1
    const rules: Bundle['rules'] = (current?.rules ?? []).filter(r => !body.remove.includes(r.rule_id)).map(r => ({ ...r, change: 'unchanged' as const }))
    for (const id of body.add) {
      const p = this.state.proposals.find(x => x.id === id)!
      const action = p.approvals.at(-1)?.max_action ?? 'observe'
      const idx = rules.findIndex(r => r.rule_id === p.rule_id)
      const rule = { rule_id: p.rule_id, class: p.class, max_action: action, stage: p.stage ?? 'shadow', change: idx >= 0 ? 'changed' as const : 'added' as const }
      if (idx >= 0) rules[idx] = rule
      else rules.push(rule)
      p.bundle_version = version
    }
    const now = this.now()
    const hours = body.validity_hours ?? this.state.settings.publish.bundle_validity_hours
    const bundle: Bundle = {
      channel: this.state.settings.channel ?? 'schild-main',
      version,
      status: 'collecting',
      issued_at: iso(now),
      expires: iso(new Date(now.getTime() + hours * 3600_000)),
      rules,
      signatures: [{ ...SELF, at: iso(now) }],
      threshold: 2,
      proposed_by: SELF.lab,
      envelope: null,
    }
    this.state.bundles.unshift(bundle)
    this.later(() => {
      bundle.signatures.push({ ...PEER, at: iso(this.now()) })
      if (distinctOperators(bundle.signatures) >= bundle.threshold) {
        for (const b of this.state.bundles) if (b.status === 'published') b.status = 'superseded'
        bundle.status = 'published'
        bundle.digest = `sha256:${version.toString(16).padStart(64, 'b')}`
        for (const id of body.add) {
          const p = this.state.proposals.find(x => x.id === id)
          if (p) p.status = 'published'
        }
        void this.appendLog('bundle', String(version), `bundle ${version} published (${rules.length} rules, ${distinctOperators(bundle.signatures)} operators)`)
      }
    })
    return ok(bundle, 201)
  }

  // ---------- withdrawals ----------

  listWithdrawals(q: URLSearchParams): MockResult {
    return ok(page([...this.state.withdrawals].sort((a, b) => b.seq - a.seq), q.get('cursor'), Number(q.get('limit') ?? 50)))
  }

  private newWithdrawal(w: Omit<Withdrawal, 'seq' | 'channel' | 'up_to_version' | 'status' | 'signatures' | 'threshold' | 'proposed_by' | 'created_at' | 'effective_at'>): Withdrawal {
    const now = iso(this.now())
    const out: Withdrawal = {
      seq: Math.max(0, ...this.state.withdrawals.map(x => x.seq)) + 1,
      channel: this.state.settings.channel ?? 'schild-main',
      up_to_version: Math.max(1, this.publishedVersion()),
      status: 'collecting',
      signatures: [{ ...SELF, at: now }],
      threshold: 2,
      proposed_by: SELF.lab,
      created_at: now,
      effective_at: null,
      ...w,
    }
    this.state.withdrawals.unshift(out)
    this.later(() => this.addSignature(out, PEER))
    return out
  }

  private addSignature(w: Withdrawal, who: typeof SELF) {
    if (w.signatures.some(s => s.lab === who.lab) || w.status !== 'collecting') return
    w.signatures.push({ ...who, at: iso(this.now()) })
    if (distinctOperators(w.signatures) >= w.threshold) {
      w.status = 'effective'
      w.effective_at = iso(this.now())
      void this.appendLog('withdrawal', String(w.seq), `withdrawal ${w.seq} effective (${w.scope})`)
    }
  }

  createWithdrawal(body: WithdrawalInput): MockResult {
    const errors: { pointer: string, detail: string }[] = []
    if (!body.rule_ids?.length) errors.push({ pointer: '/rule_ids', detail: 'Wähle mindestens eine Regel.' })
    if (!body.reason) errors.push({ pointer: '/reason', detail: 'Bitte wähle einen Grund.' })
    if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
    const pw = this.checkPassword(body.confirm?.password, '/confirm/password')
    if (pw) return pw
    return ok(this.newWithdrawal({ scope: 'rules', rule_ids: body.rule_ids, reason: body.reason, ...(body.note ? { note: body.note } : {}) }), 201)
  }

  emergencyStop(body: Partial<EmergencyStopInput>): MockResult {
    if (body.confirm_text !== WITHDRAW_ALL_WIRE_CONFIRM) return problem(400, 'invalid', 'Bestätigung fehlt', [{ pointer: '/confirm_text', detail: `Bitte tippe genau ${WITHDRAW_ALL_PHRASE}.` }])
    if (!body.reason) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/reason', detail: 'Bitte wähle einen Grund.' }])
    const pw = this.checkPassword(body.password)
    if (pw) return pw
    const open = this.state.withdrawals.find(w => w.scope === 'all' && w.status === 'collecting')
    if (open) return problem(409, 'conflict', 'Ein Rückzug aller Netzregeln sammelt schon Mitzeichnungen', undefined, `Rückzug ${open.seq}`)
    return ok(this.newWithdrawal({ scope: 'all', reason: body.reason, ...(body.note ? { note: body.note } : {}) }), 201)
  }

  cosign(seq: number, body: Confirm): MockResult {
    const w = this.state.withdrawals.find(x => x.seq === seq)
    if (!w) return problem(404, 'not_found', 'Rückzug nicht gefunden')
    const pw = this.checkPassword(body.password)
    if (pw) return pw
    if (w.status !== 'collecting') return problem(409, 'conflict', 'Dieser Rückzug sammelt keine Signaturen mehr')
    if (w.signatures.some(s => s.lab === SELF.lab)) return problem(409, 'conflict', 'Dieses Lab hat schon signiert')
    this.addSignature(w, SELF)
    return ok(w)
  }

  // ---------- network ----------

  relays(): MockResult {
    // relay-1 and the peer lab lab-a2 follow the feed (one event every 20 s); relay-3 stands still and shows up as frozen after a few minutes.
    const moving = `k3x9-${1042 + Math.floor((Date.now() - this.started) / 20_000)}`
    for (const r of this.state.relays) if (r.id === 'relay-1' || r.kind === 'peer_lab') r.last_event_id = moving
    return ok({ items: this.state.relays })
  }

  peers(): MockResult {
    return ok({ items: this.state.peers })
  }

  // ---------- log ----------

  async listLog(q: URLSearchParams): Promise<MockResult> {
    await this.ready
    const kind = q.get('kind')
    const items = this.logEntries.filter(e => !kind || e.kind === kind).map(e => ({ ...e, envelope: null }))
    // RFC 6962 root over the whole mock log, as the lab computes it (contracts v0.1).
    const head = { size: this.logEntries.length, root: await treeRoot([...this.logEntries].sort((a, b) => a.index - b.index)) }
    return ok({ ...page(items, q.get('cursor'), Number(q.get('limit') ?? 50)), head })
  }

  async getLogEntry(index: number): Promise<MockResult> {
    await this.ready
    const e = this.logEntries.find(x => x.index === index)
    return e ? ok(e) : problem(404, 'not_found', 'Eintrag nicht gefunden')
  }

  // ---------- issuers and clients ----------

  issuers(): MockResult {
    return ok({ items: this.state.issuers })
  }

  updateIssuer(id: string, body: { quota_per_day?: number }): MockResult {
    const i = this.state.issuers.find(x => x.id === id)
    if (!i) return problem(404, 'not_found', 'Bürge nicht gefunden')
    if (body.quota_per_day === undefined || body.quota_per_day < 0 || !Number.isInteger(body.quota_per_day)) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/quota_per_day', detail: 'Bitte eine ganze Zahl ab 0.' }])
    i.quota_per_day = body.quota_per_day
    return ok(i)
  }

  revokeIssuer(id: string, body: Confirm): MockResult {
    const i = this.state.issuers.find(x => x.id === id)
    if (!i) return problem(404, 'not_found', 'Bürge nicht gefunden')
    const pw = this.checkPassword(body.password)
    if (pw) return pw
    i.revoked = true
    i.revoked_at = iso(this.now())
    for (const c of this.state.clients) if (c.issuer === id) c.revoked = true
    return ok(i)
  }

  listClients(q: URLSearchParams): MockResult {
    const issuer = q.get('issuer')
    return ok(page(this.state.clients.filter(c => !issuer || c.issuer === issuer), q.get('cursor'), Number(q.get('limit') ?? 50)))
  }

  updateClient(keyid: string, body: { quota_per_day?: number }): MockResult {
    const c = this.state.clients.find(x => x.keyid === keyid)
    if (!c) return problem(404, 'not_found', 'Client nicht gefunden')
    if (body.quota_per_day === undefined || body.quota_per_day < 0) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/quota_per_day', detail: 'Bitte eine ganze Zahl ab 0.' }])
    c.quota_per_day = body.quota_per_day
    return ok(c)
  }

  revokeClient(keyid: string, body: Confirm): MockResult {
    const c = this.state.clients.find(x => x.keyid === keyid)
    if (!c) return problem(404, 'not_found', 'Client nicht gefunden')
    const pw = this.checkPassword(body.password)
    if (pw) return pw
    c.revoked = true
    return ok(c)
  }

  // ---------- settings ----------

  settings(): MockResult {
    return ok(this.state.settings)
  }

  updateSettings(body: LabSettingsPatch): MockResult {
    const pw = this.checkPassword(body.confirm?.password, '/confirm/password')
    if (pw) return pw
    const errors: { pointer: string, detail: string }[] = []
    const s = body.scoring ?? {}
    if (s.min_issuers !== undefined && s.min_issuers < 3) errors.push({ pointer: '/scoring/min_issuers', detail: 'Mindestens 3.' })
    if (s.max_issuer_share !== undefined && (s.max_issuer_share <= 0 || s.max_issuer_share > 0.34)) errors.push({ pointer: '/scoring/max_issuer_share', detail: 'Höchstens 0,34.' })
    if (s.window_minutes !== undefined && s.window_minutes < 5) errors.push({ pointer: '/scoring/window_minutes', detail: 'Mindestens 5 Minuten.' })
    if (s.min_score !== undefined && (s.min_score < 0 || s.min_score > 100)) errors.push({ pointer: '/scoring/min_score', detail: 'Zwischen 0 und 100.' })
    const r = body.retention ?? {}
    if (r.signals_days !== undefined && (r.signals_days < 1 || r.signals_days > 30)) errors.push({ pointer: '/retention/signals_days', detail: 'Zwischen 1 und 30 Tagen.' })
    const ing = body.ingest ?? {}
    if (ing.rate_per_client_per_min !== undefined && ing.rate_per_client_per_min < 1) errors.push({ pointer: '/ingest/rate_per_client_per_min', detail: 'Mindestens 1.' })
    if (ing.retry_after_ms !== undefined && ing.retry_after_ms < 1) errors.push({ pointer: '/ingest/retry_after_ms', detail: 'Mindestens 1.' })
    if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
    const st = this.state.settings
    this.state.settings = {
      ...st,
      scoring: { ...st.scoring, ...s },
      ingest: { ...st.ingest, ...ing },
      retention: { ...st.retention, ...r },
    }
    return ok(this.state.settings)
  }
}
