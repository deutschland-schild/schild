/**
 * Mock backend of the "Server" section (contracts v0.3, MVP-11): hosts with read-only host reports,
 * "Jetzt prüfen" for the gateway, agent enrolment with one-time codes, confirmation and revocation.
 * Seeded from the contract fixtures plus one end-of-life host. Example host names (*.example) and
 * documentation addresses (RFC 5737) only. Mock mode and tests only.
 */
import type { HttpHandler } from 'msw'
import type { Scenario } from './data'
import type { Agent, Enrolment, HostDetail, HostReport, HostSummary, ServersSummary, SeverityCounts } from '@/api/hosts'
import { http, HttpResponse } from 'msw'
import agentFixture from '../../../../../contracts/api/fixtures/client/getHost.agent.json'
import localFixture from '../../../../../contracts/api/fixtures/client/getHost.json'
import silentFixture from '../../../../../contracts/api/fixtures/client/getHost.silent.json'
import waitingFixture from '../../../../../contracts/api/fixtures/client/getHost.waiting.json'
import agentsFixture from '../../../../../contracts/api/fixtures/client/listAgents.json'
import logsVector from '../../../../../contracts/vectors/host-report/valid/007-logs-area.json'

const FIXTURE_NOW = Date.parse('2026-10-26T12:00:00Z')
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

interface PendingEnrolment {
  code: string
  label: string | null
  created_at: number
  expires_at: number
  /** When the simulated app VM runs the command and its enrolment request arrives. */
  arrives_at: number
  used: boolean
}

export interface HostMock {
  /** false: host_check is not configured (no hosts, no Overview.servers). */
  configured: boolean
  /** Host details by id; the summary inside is recomputed on every read. */
  hosts: Map<string, HostDetail>
  agents: Agent[]
  enrolments: PendingEnrolment[]
  localRun: { requested_at: number, done_at: number } | null
  /** No way to start the check from the dashboard (503 check_unavailable). */
  checkUnavailable: boolean
  /** Simulated delays (ms): the local run and the app VM running the enrolment command. */
  checkRunMs: number
  enrolDelayMs: number
  seq: number
}

function iso(ms: number) {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z')
}

/** Deep-shift every RFC 3339 timestamp (not the calendar EOL dates) by `delta` ms. */
function shiftTimes<T>(value: T, delta: number): T {
  return JSON.parse(JSON.stringify(value), (_k, v) => {
    if (typeof v === 'string' && /^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(v)) return iso(Date.parse(v) + delta)
    return v
  }) as T
}

const zero = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 })

export function countsOf(report: HostReport | null): SeverityCounts {
  const c = zero()
  for (const f of report?.findings ?? []) if (f.status === 'finding') c[f.severity]++
  return c
}

/** An app VM on a system without any support left: Debian 10 with PHP 7.3, MariaDB 10.3 and TYPO3 9. */
function eolHost(t0: number): HostDetail {
  const started = t0 - 5 * 3600_000 - 14 * 60_000
  const report: HostReport = {
    schema: 'schild.host_report/0.1',
    report_id: '6c1d2e3f-4a5b-4c6d-8e7f-90a1b2c3d4e5',
    host: {
      hostname: 'verein-alt.example',
      role: 'agent',
      agent_key_id: 'verein-alt/agent/2026-10',
      os: { id: 'debian', version_id: '10', name: 'Debian GNU/Linux 10 (buster)', kernel: '4.19.0-21-amd64', arch: 'x86_64', eol: '2022-09-10', extended_support_until: '2024-06-30' },
    },
    run: { started_at: iso(started), duration_ms: 3870, schild_version: '0.3.0', eol_table: '2026-10-01', as_root: false },
    findings: [
      {
        id: 'distribution.eol', area: 'distribution', severity: 'critical', status: 'finding',
        title: 'Debian 10 bekommt keine Sicherheitsupdates mehr',
        explanation: 'Auch der Langzeit-Support endete am 30.06.2024. Neue Lücken werden nicht mehr geschlossen. Plane den Umzug auf Debian 12 oder 13, am besten auf eine neue VM.',
        fix_command: null, evidence: { source: 'eol_table', date: '2024-06-30' },
      },
      {
        id: 'distribution.kernel_outdated', area: 'distribution', severity: 'medium', status: 'finding',
        title: 'Der laufende Kernel ist älter als der installierte',
        explanation: 'Ein neuerer Kernel ist installiert, aber erst nach einem Neustart aktiv.',
        fix_command: 'sudo systemctl reboot', evidence: { source: 'uname', installed_version: '4.19.0-27-amd64', package: 'linux-image-amd64' },
      },
      {
        id: 'updates.security_pending', area: 'updates', severity: 'info', status: 'unreadable',
        title: 'Sicherheitsupdates nicht lesbar',
        explanation: 'Die Paketquellen von Debian 10 gibt es nicht mehr. Ohne aktuelle Paketlisten lässt sich nicht sagen, was fehlt.',
        fix_command: null, evidence: { source: 'apt' }, unreadable: { reason: 'not_supported' },
      },
      {
        id: 'updates.automatic', area: 'updates', severity: 'info', status: 'ok',
        title: 'Automatische Updates sind an',
        explanation: 'unattended-upgrades ist eingerichtet. Für Debian 10 kommen aber keine Updates mehr.',
        fix_command: null, evidence: { source: 'unattended_upgrades', enabled: true },
      },
      {
        id: 'ports.docker_api', area: 'ports', subject: 'tcp/2375', severity: 'critical', status: 'finding',
        title: 'Die Docker-API ist ohne Anmeldung aus dem Netz erreichbar',
        explanation: 'Wer Port 2375 erreicht, kann Container starten und damit den ganzen Server übernehmen. Die API gehört an den lokalen Socket, nicht ins Netz.',
        fix_command: 'sudo ufw deny 2375/tcp', evidence: { source: 'ss', port: 2375, protocol: 'tcp', address: '198.51.100.25', process: 'dockerd' },
      },
      {
        id: 'ports.public_service', area: 'ports', subject: 'tcp/80', severity: 'info', status: 'ok',
        title: 'HTTP ist für das Gateway erreichbar',
        explanation: 'Apache nimmt Anfragen vom Gateway entgegen. So soll es sein.',
        fix_command: null, evidence: { source: 'ss', port: 80, protocol: 'tcp', address: '198.51.100.25', process: 'apache2' },
      },
      {
        id: 'firewall.active', area: 'firewall', severity: 'high', status: 'finding',
        title: 'Keine Firewall aktiv',
        explanation: 'Jeder Dienst, der lauscht, ist direkt erreichbar. Erlaube zuerst SSH, dann schalte ufw ein.',
        fix_command: 'sudo ufw allow OpenSSH && sudo ufw enable', evidence: { source: 'ufw', enabled: false },
      },
      {
        id: 'ssh.permit_root_login', area: 'ssh', severity: 'medium', status: 'finding',
        title: 'root darf sich mit Passwort anmelden',
        explanation: 'Der Name root ist bekannt, es bleibt nur das Passwort zu erraten. Mit prohibit-password geht root nur noch mit Schlüssel.',
        fix_command: 'sudo sed -i \'s/^#\\?PermitRootLogin .*/PermitRootLogin prohibit-password/\' /etc/ssh/sshd_config && sudo systemctl reload ssh',
        evidence: { source: 'sshd_config', setting: 'PermitRootLogin', value: 'yes', expected: 'prohibit-password', path: '/etc/ssh/sshd_config' },
      },
      {
        id: 'ssh.failed_logins', area: 'ssh', severity: 'info', status: 'unreadable',
        title: 'Anmeldeversuche nicht lesbar',
        explanation: 'Der Check läuft ohne root und darf /var/log/auth.log nicht lesen.',
        fix_command: null, evidence: { source: 'auth_log', path: '/var/log/auth.log' }, unreadable: { reason: 'permission_denied', needs: 'group:adm' },
      },
      {
        id: 'software.runtime_eol', area: 'software', subject: 'php', severity: 'high', status: 'finding',
        title: 'PHP 7.3 bekommt keine Updates mehr',
        explanation: 'PHP 7.3 ist seit Dezember 2021 ohne Sicherheitsupdates. Viele Angriffe auf Websites zielen genau auf solche alten Versionen.',
        fix_command: null, evidence: { source: 'dpkg', package: 'php7.3', installed_version: '7.3.31-1~deb10u7', date: '2021-12-06' },
      },
      {
        id: 'software.database_eol', area: 'software', subject: 'mariadb', severity: 'medium', status: 'finding',
        title: 'MariaDB 10.3 bekommt keine Updates mehr',
        explanation: 'Der Support endete im Mai 2023. Die Datenbank lauscht nur auf localhost, das begrenzt das Risiko.',
        fix_command: null, evidence: { source: 'dpkg', package: 'mariadb-server', installed_version: '1:10.3.39-0+deb10u2', date: '2023-05-25' },
      },
      {
        id: 'software.app_outdated', area: 'software', subject: 'typo3', severity: 'medium', status: 'finding',
        title: 'TYPO3 9.5 ist veraltet',
        explanation: 'Für TYPO3 9 gibt es nur noch kostenpflichtigen Langzeit-Support. Ein Update auf eine aktuelle LTS-Version braucht etwas Planung.',
        fix_command: null, evidence: { source: 'app_path', installed_version: '9.5.31', path: '/var/www/verein' },
      },
    ],
    inventory: [
      { kind: 'runtime', name: 'php7.3', version: '7.3.31-1~deb10u7', eol: '2021-12-06', source: 'dpkg' },
      { kind: 'server', name: 'apache2', version: '2.4.38-3+deb10u10', eol: null, source: 'dpkg' },
      { kind: 'server', name: 'docker.io', version: '18.09.1+dfsg1-7.1+deb10u3', eol: null, source: 'dpkg' },
      { kind: 'database', name: 'mariadb-server', version: '1:10.3.39-0+deb10u2', eol: '2023-05-25', source: 'dpkg' },
      { kind: 'os_package', name: 'openssl', version: '1.1.1n-0+deb10u6', eol: null, source: 'dpkg' },
      { kind: 'app', name: 'typo3', version: '9.5.31', eol: '2021-09-30', source: 'app_path', path: '/var/www/verein' },
    ],
  }
  return {
    host: summaryStub('verein-alt', 'verein-alt.example', 1440, report),
    report: report as HostDetail['report'],
    history: [
      { report_id: report.report_id, started_at: report.run.started_at, received_at: iso(started + 6000), counts: countsOf(report) },
      { report_id: '0b1c2d3e-4f5a-4b6c-9d7e-8f9a0b1c2d3e', started_at: iso(started - 24 * 3600_000), received_at: iso(started - 24 * 3600_000 + 5000), counts: countsOf(report) },
    ],
    last_rejected: null,
  }
}

function summaryStub(id: string, hostname: string, interval: number, report: HostReport | null): HostSummary {
  return {
    id, hostname, role: id === 'local' ? 'gateway' : 'agent', agent_id: id === 'local' ? null : id,
    status: report ? 'findings' : 'waiting', silent: false,
    last_report_at: report?.run.started_at ?? null,
    received_at: report ? iso(Date.parse(report.run.started_at) + 6000) : null,
    interval_minutes: interval, duration_ms: report?.run.duration_ms ?? null,
    counts: countsOf(report), unreadable: report?.findings.filter(f => f.status === 'unreadable').length ?? 0,
    os: report ? { name: report.host.os.name, eol: report.host.os.eol } : null,
  }
}

export function createHostState(scenario: Scenario, t0: number): HostMock {
  const delta = t0 - FIXTURE_NOW
  const hosts = new Map<string, HostDetail>()
  const local = shiftTimes(localFixture as unknown as HostDetail, delta)
  if (scenario === 'empty') {
    // Fresh install: the gateway's timer has not run yet, no agents.
    hosts.set('local', { host: summaryStub('local', local.host.hostname, 1440, null), report: null, history: [], last_rejected: null })
    return { configured: true, hosts, agents: [], enrolments: [], localRun: null, checkUnavailable: false, checkRunMs: 4000, enrolDelayMs: 4000, seq: 6 }
  }
  if (local.report) {
    // v0.5 (D38): the log-hygiene findings of the contract vector (area logs, fix_config from the
    // gateway templates) on the gateway's own report.
    const logs = (JSON.parse(logsVector.input_raw) as HostReport).findings.filter(f => f.area === 'logs')
    local.report.findings.push(...(logs as typeof local.report.findings))
    local.host = { ...local.host, counts: countsOf(local.report as HostReport) }
  }
  hosts.set('local', local)
  for (const f of [agentFixture, silentFixture, waitingFixture]) {
    const d = shiftTimes(f as unknown as HostDetail, delta)
    hosts.set(d.host.id, d)
  }
  const old = eolHost(t0)
  hosts.set(old.host.id, old)
  const agents = shiftTimes(agentsFixture.items as unknown as Agent[], delta)
  agents.push({
    id: 'verein-alt', hostname: 'verein-alt.example', label: 'Vereinsseite (alt)', keyid: 'verein-alt/agent/2026-10',
    fingerprint: 'sha256:a17c4e9b02d5f3688a17c4e9b02d5f3688a17c4e9b02d5f3688a17c4e9b02d5f3', status: 'enrolled', source: 'config',
    created_at: iso(t0 - 9 * 24 * 3600_000), confirmed_at: iso(t0 - 9 * 24 * 3600_000), revoked_at: null,
    last_report_at: old.report!.run.started_at, silent: false,
  })
  return { configured: true, hosts, agents, enrolments: [], localRun: null, checkUnavailable: false, checkRunMs: 4000, enrolDelayMs: 4000, seq: 6 }
}

// ------------------------------------------------------------------ derived state

/** Apply what happened in the meantime: a finished local run, enrolment requests that arrived. */
export function tick(h: HostMock, now: number, hex: (n: number) => string, uuid: () => string) {
  if (h.localRun && now >= h.localRun.done_at) {
    const d = h.hosts.get('local')
    const base = d?.report
    if (d && base) {
      const report = structuredClone(base)
      report.report_id = uuid()
      report.run.started_at = iso(h.localRun.done_at - 3000)
      report.run.duration_ms = 2950
      d.report = report
      d.history = [{ report_id: report.report_id, started_at: report.run.started_at, received_at: iso(h.localRun.done_at), counts: countsOf(report) }, ...d.history].slice(0, 30)
      d.host.received_at = iso(h.localRun.done_at)
    }
    h.localRun = null
  }
  for (const e of h.enrolments) {
    if (e.used || now < e.arrives_at || now > e.expires_at) continue
    e.used = true
    const id = nextAgentId(h, e.label)
    const fp = `sha256:${hex(64)}`
    h.agents.push({
      id, hostname: `${id}.example`, label: e.label, keyid: `${id}/agent/${new Date(now).toISOString().slice(0, 7)}`,
      fingerprint: fp, status: 'pending', source: 'code', created_at: iso(now), confirmed_at: null, revoked_at: null, last_report_at: null, silent: false,
    })
  }
}

function nextAgentId(h: HostMock, label: string | null): string {
  const slug = (label ?? '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40)
  let id = slug && /^[a-z0-9]/.test(slug) ? slug : `app-${h.seq}`
  while (h.agents.some(a => a.id === id) || h.hosts.has(id)) id = `app-${++h.seq}`
  return id
}

/** The host summary as the server derives it: counts from the newest report, silent after twice the interval. */
export function summarize(d: HostDetail, h: HostMock, now: number): HostSummary {
  const agent = h.agents.find(a => a.id === d.host.agent_id)
  const s: HostSummary = { ...d.host }
  s.counts = countsOf(d.report)
  s.unreadable = d.report?.findings.filter(f => f.status === 'unreadable').length ?? 0
  s.last_report_at = d.report?.run.started_at ?? null
  s.duration_ms = d.report?.run.duration_ms ?? null
  s.os = d.report ? { name: d.report.host.os.name, eol: d.report.host.os.eol } : null
  const interval = (s.interval_minutes ?? 1440) * 60_000
  s.silent = s.role === 'agent' && agent?.status !== 'revoked' && !!s.last_report_at && now - Date.parse(s.last_report_at) > 2 * interval
  const open = s.counts.critical + s.counts.high + s.counts.medium + s.counts.low
  s.status = agent?.status === 'revoked' ? 'revoked' : s.silent ? 'silent' : !d.report ? 'waiting' : open ? 'findings' : 'ok'
  return s
}

export function serversSummary(h: HostMock, now: number): ServersSummary | undefined {
  if (!h.configured) return undefined
  const all = [...h.hosts.values()].map(d => summarize(d, h, now)).filter(s => s.status !== 'revoked')
  const findings = zero()
  for (const s of all) for (const k of Object.keys(findings) as (keyof SeverityCounts)[]) findings[k] += s.counts[k]
  return {
    hosts: all.length,
    findings,
    silent: all.filter(s => s.silent).length,
    unreadable: all.reduce((n, s) => n + s.unreadable, 0),
    pending_agents: h.agents.filter(a => a.status === 'pending').length,
  }
}

function sortedHosts(h: HostMock, now: number): HostSummary[] {
  const all = [...h.hosts.values()].map(d => summarize(d, h, now))
  return [...all.filter(s => s.role === 'gateway'), ...all.filter(s => s.role === 'agent').sort((a, b) => a.hostname.localeCompare(b.hostname))]
}

// ------------------------------------------------------------------ handlers

type Params = Record<string, string | readonly string[] | undefined>
type Fn = (args: { request: Request, params: Params }) => Promise<Response> | Response
export interface HostHandlerTools {
  base: string
  hosts: () => HostMock
  scenario: () => Scenario
  now: () => number
  hex: (n: number) => string
  uuid: () => string
  guard: (kind: 'read' | 'write', fn: Fn) => (args: { request: Request, params: Params }) => Promise<Response>
  problem: (status: number, code: string, title: string, errors?: { pointer: string, detail: string }[]) => Response
  page: <T>(items: T[], url: URL, defLimit?: number) => { items: T[], next_cursor: string | null }
  read: (req: Request) => Promise<Record<string, unknown>>
}

export function hostHandlers(t: HostHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object, status = 200) => HttpResponse.json(body as Record<string, unknown>, { status })
  const unavailable = () => t.scenario() === 'error' ? problem(503, 'internal', 'Interner Fehler') : null
  const state = () => {
    const h = t.hosts()
    tick(h, t.now(), t.hex, t.uuid)
    return h
  }

  return [
    http.get(`${base}/hosts`, guard('read', ({ request }) => {
      const err = unavailable()
      if (err) return err
      const h = state()
      if (!h.configured) return json({ items: [], next_cursor: null })
      const url = new URL(request.url)
      const status = url.searchParams.get('status')
      return json(t.page(sortedHosts(h, t.now()).filter(s => !status || s.status === status), url, 100))
    })),
    http.post(`${base}/hosts/local/check`, guard('write', () => {
      const h = state()
      if (h.checkUnavailable || !h.configured) return problem(503, 'check_unavailable', 'Prüfung lässt sich hier nicht starten')
      if (h.localRun) return problem(409, 'check_running', 'Prüfung läuft bereits')
      const now = t.now()
      h.localRun = { requested_at: now, done_at: now + h.checkRunMs }
      return json({ requested_at: iso(now), state: 'queued' }, 202)
    })),
    http.get(`${base}/hosts/:id`, guard('read', ({ params }) => {
      const err = unavailable()
      if (err) return err
      const h = state()
      const d = h.hosts.get(String(params.id))
      if (!d) return problem(404, 'not_found', 'Server nicht gefunden')
      return json({ ...d, host: summarize(d, h, t.now()) })
    })),

    http.get(`${base}/agents`, guard('read', ({ request }) => {
      const err = unavailable()
      if (err) return err
      const h = state()
      const url = new URL(request.url)
      const status = url.searchParams.get('status')
      const now = t.now()
      const items = h.agents
        .filter(a => !status || a.status === status)
        .map((a) => {
          const d = h.hosts.get(a.id)
          return d ? { ...a, last_report_at: d.report?.run.started_at ?? a.last_report_at ?? null, silent: summarize(d, h, now).silent } : a
        })
      return json(t.page(items, url, 100))
    })),
    http.post(`${base}/agents/enrolments`, guard('write', async ({ request }) => {
      const h = state()
      const body = await t.read(request)
      const errors: { pointer: string, detail: string }[] = []
      const label = typeof body.label === 'string' ? body.label.trim() : undefined
      if (body.label !== undefined && (!label || label.length > 64)) errors.push({ pointer: '/label', detail: '1 to 64 characters' })
      const ttl = body.ttl_minutes === undefined ? 30 : Number(body.ttl_minutes)
      if (!Number.isInteger(ttl) || ttl < 5 || ttl > 1440) errors.push({ pointer: '/ttl_minutes', detail: 'between 5 and 1440' })
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      const now = t.now()
      const part = () => Array.from({ length: 4 }, () => CODE_ALPHABET[Number.parseInt(t.hex(2), 16) % CODE_ALPHABET.length]).join('')
      const code = `${part()}-${part()}-${part()}-${part()}`
      h.enrolments.push({ code, label: label ?? null, created_at: now, expires_at: now + ttl * 60_000, arrives_at: now + h.enrolDelayMs, used: false })
      const pin = 'sha256:9e4c1a7b3d5f20869e4c1a7b3d5f20869e4c1a7b3d5f20869e4c1a7b3d5f2086'
      const gateway = 'https://gw-1.example:8790'
      const out: Enrolment = {
        code, expires_at: iso(now + ttl * 60_000), label: label ?? null, gateway_url: gateway, gateway_name: 'gw-1', gateway_pin: pin,
        command: `sudo schild-agent enrol --gateway ${gateway} --gateway-name gw-1 --pin ${pin} --code ${code}`,
      }
      return json(out, 201)
    })),
    http.post(`${base}/agents/:id/confirm`, guard('write', async ({ request, params }) => {
      const h = state()
      const a = h.agents.find(x => x.id === params.id)
      if (!a) return problem(404, 'not_found', 'Agent nicht gefunden')
      if (a.status !== 'pending') return problem(409, 'conflict', 'Nicht mehr wartend')
      const body = await t.read(request)
      if (typeof body.fingerprint !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(body.fingerprint)) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/fingerprint', detail: 'sha256:<64 hex>' }])
      if (body.fingerprint !== a.fingerprint) return problem(409, 'fingerprint_mismatch', 'Fingerabdruck stimmt nicht', [{ pointer: '/fingerprint', detail: 'differs' }])
      const now = t.now()
      a.status = 'enrolled'
      a.confirmed_at = iso(now)
      if (typeof body.label === 'string' && body.label.trim()) a.label = body.label.trim()
      h.hosts.set(a.id, { host: summaryStub(a.id, a.hostname, 1440, null), report: null, history: [], last_rejected: null })
      return json(a)
    })),
    http.post(`${base}/agents/:id/revoke`, guard('write', async ({ params }) => {
      const h = state()
      const a = h.agents.find(x => x.id === params.id)
      if (!a) return problem(404, 'not_found', 'Agent nicht gefunden')
      if (a.source === 'config') return problem(409, 'config_agent', 'Agent steht in schild.yaml')
      if (a.status === 'revoked') return problem(409, 'conflict', 'Schon zurückgezogen')
      a.status = 'revoked'
      a.revoked_at = iso(t.now())
      return json(a)
    })),
  ]
}
