import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import type { AuditEntry } from '../src/api/audit'
import catalogue from '../../../../contracts/audit-actions.json'
import {
  ACTIONS,
  actionLabel,
  actorName,
  AUDIT_COPY,
  AUDIT_PATH,
  auditChips,
  auditLink,
  CLASSES,
  dayIso,
  entryTitle,
  HIDDEN,
  hiddenText,
  lastChangedText,
  objectLink,
  parseAuditFilters,
  SUBJECTS,
  toAuditQuery,
  WAYS,
} from '../src/lib/audit'
import { buildNav } from '../src/lib/nav'
import { MOCK_GONE_ALLOW, MOCK_GONE_EVENT } from '../src/mock/audit'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, waitFor } from './helpers'

const mock = mockServer()
const requests: string[] = []
beforeAll(() => {
  mock.server.listen({ onUnhandledRequest: 'error' })
  mock.server.events.on('request:start', ({ request }) => {
    if (new URL(request.url).pathname.endsWith('/audit')) requests.push(request.url)
  })
})
afterEach(() => {
  cleanup()
  mock.reset()
  requests.length = 0
})
afterAll(() => mock.server.close())

const BASE = 'http://dashboard.schild.test/api/v0'
const list = async (query = '') => await (await fetch(`${BASE}/audit${query}`)).json() as { items: AuditEntry[], next_cursor: string | null }
const entries = () => mock.state.audit
const find = (pred: (e: AuditEntry) => boolean) => entries().find(pred)!
const row = (id: string) => document.querySelector<HTMLElement>(`tr[data-row-id="${id}"]`)
const rowIds = () => [...document.querySelectorAll<HTMLElement>('tr[data-row-id]')].map(r => r.dataset.rowId!)
const href = (testid: string) => byTestId(testid)?.getAttribute('href') ?? ''
/** The audit calls the page made, as their query parameters. */
const queries = () => requests.map(u => new URL(u).searchParams)

/** An entry a test adds on top of the mock's: valid against the contract, newest of all. */
function entry(over: Partial<AuditEntry>): AuditEntry {
  return {
    schema: 'schild.audit/0.1',
    id: `0a1b2c3d4e5f6071-k-${900 + entries().length}`,
    time: new Date(mock.state.now() - 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    node: 'web-1',
    class: 'change',
    action: 'allowlist.add',
    operation: 'dashboard:addAllowlistEntry',
    result: 'done',
    actor: { kind: 'dashboard', user: 'admin', session: 'aaaa0000' },
    subject: { kind: 'allowlist_entry', id: 'al-test' },
    ...over,
  } as AuditEntry
}

describe('wording of the audit log', () => {
  it('names every action, class and way of the contract in German', () => {
    const actions = catalogue.actions.map(a => a.action)
    expect(actions.length).toBeGreaterThan(40)
    for (const a of actions) {
      expect(ACTIONS[a], a).toBeTruthy()
      expect(actionLabel(a), a).not.toBe(a)
    }
    // Nothing is named that the catalogue does not hold.
    expect(Object.keys(ACTIONS).sort()).toEqual([...actions].sort())
    expect(Object.keys(CLASSES).sort()).toEqual(['access', 'change', 'credential', 'privacy', 'refused'])
    expect(Object.keys(WAYS).sort()).toEqual(['agent', 'cli', 'config', 'dashboard', 'integration', 'system'])
    for (const a of catalogue.actions) expect(SUBJECTS[a.subject], a.subject).toBeTruthy()
    for (const op of catalogue.actions.flatMap(a => a.operations)) expect(WAYS[op.split(':')[0] as keyof typeof WAYS], op).toBeTruthy()
    expect(Object.keys(HIDDEN).sort()).toEqual(['list', 'operator', 'order', 'secret', 'size', 'unlisted'])
  })

  it('shows an action of a later build by its raw name, and a refused call as refused', () => {
    expect(actionLabel('portal_key.add')).toBe('portal_key.add')
    expect(entryTitle({ action: 'portal_key.add', result: 'done' })).toBe('portal_key.add')
    expect(entryTitle({ action: 'session.start', result: 'done' })).toBe('Angemeldet')
    expect(entryTitle({ action: 'session.start', result: 'refused' })).toBe('Anmeldung abgelehnt')
    expect(entryTitle({ action: 'allowlist.add', result: 'refused' })).toBe('Abgelehnt: Eigene IP eingetragen')
    expect(hiddenText('later_reason')).toContain('later_reason')
  })

  it('names who by the kind of actor', () => {
    expect(actorName({ kind: 'dashboard', user: 'admin' })).toBe('admin')
    expect(actorName({ kind: 'agent', id: 'tok_0123456789ab', label: 'coding-agent' })).toBe('coding-agent')
    expect(actorName({ kind: 'agent', id: 'tok_0123456789ab' })).toBe('tok_0123456789ab')
    expect(actorName({ kind: 'cli', account: 'deploy' })).toBe('deploy')
    expect(actorName({ kind: 'config' })).toBe('Konfigurationsdatei')
    expect(actorName({ kind: 'system' })).toBe('Schild selbst')
    expect(lastChangedText({ kind: 'dashboard', user: 'admin' })).toBe('Zuletzt geändert von admin')
    expect(lastChangedText({ kind: 'system' })).toBe('Zuletzt geändert von Schild selbst')
    expect(lastChangedText({ kind: 'config' })).toBe('Zuletzt geändert über die Konfigurationsdatei')
  })

  it('says what the log keeps and for how long, in the required wording', () => {
    expect(AUDIT_COPY.keep).toContain('ein Jahr')
    expect(AUDIT_COPY.keep).toContain('audit.keep_days')
    expect(AUDIT_COPY.keep).toContain('90 Tage')
    expect(AUDIT_COPY.addresses).toContain('IP-Adressen')
    expect(AUDIT_COPY.older).toBe('Älter als die Aufbewahrung des Protokolls')
    const all = [...Object.values(AUDIT_COPY), ...Object.values(ACTIONS), ...Object.values(HIDDEN), ...Object.values(SUBJECTS), ...Object.values(WAYS), ...Object.values(CLASSES).map(c => c.label)].join(' ')
    expect(all).not.toMatch(/anonym/i)
    expect(all).not.toMatch(/\b(geschützt|sicher|gefährlich|dringend)\b/i)
    expect(all).not.toMatch(/\bSie\b|\bIhr(e|en)?\b/)
    expect(all).not.toMatch(/[—–]/)
  })

  it('keeps only filters the API accepts, and turns days into the range [from, to)', () => {
    const f = parseAuditFilters({
      website: 'shop.example', class: 'nope', way: 'agent', action: 'allowlist.add', actor: 'TOK_0123456789AB', subject: 'token', subject_id: 'tok_000000000003',
      session: 'zzzz', event: 'not-a-uuid', incident: 'k7qm-4xwd', from: '2026-11-01', to: '24.11.2026',
    })
    expect(f).toEqual({ website: 'shop.example', way: 'agent', action: 'allowlist.add', actor: 'tok_0123456789ab', subject: 'token', subject_id: 'tok_000000000003', incident: 'K7QM-4XWD', from: '2026-11-01' })
    // An id without its kind names nothing.
    expect(parseAuditFilters({ subject_id: 'al-2' })).toEqual({})
    const q = toAuditQuery({ ...f, to: '2026-11-24' })
    expect(q).toMatchObject({ website: 'shop.example', way: 'agent', action: 'allowlist.add', actor: 'tok_0123456789ab', subject: 'token', subject_id: 'tok_000000000003', incident: 'K7QM-4XWD' })
    expect(q.from).toBe(dayIso('2026-11-01'))
    // "Bis" is the last day shown: the API gets the first instant after it.
    expect(q.to).toBe(dayIso('2026-11-24', 1))
    expect(Date.parse(q.to!) - Date.parse(dayIso('2026-11-24')!)).toBe(86400_000)
  })

  it('builds chips and links from the filters', () => {
    expect(auditChips({ subject: 'allowlist_entry', subject_id: 'al-2', class: 'refused', from: '2026-11-01' }).map(c => `${c.label}: ${c.value}`)).toEqual(['Art: Abgelehnt', 'Objekt: Eigene IP al-2', 'Von: 01.11.2026'])
    expect(auditChips({ website: 'shop.example', actor: 'tok_000000000001' }, { website: () => 'Shop', token: () => 'coding-agent' }).map(c => c.value)).toEqual(['Shop', 'coding-agent'])
    expect(auditLink({ session: '5e1f0a9c' }, 'x-k-1')).toEqual({ path: AUDIT_PATH, query: { session: '5e1f0a9c', entry: 'x-k-1' } })
  })

  it('knows the page of an object', () => {
    const at = (action: string, kind: string, id?: string, website?: string) => objectLink({ action, subject: { kind, ...(id ? { id } : {}) }, ...(website ? { website } : {}) })?.to
    expect(at('allowlist.add', 'allowlist_entry', 'al-2')).toBe('/own-ips')
    expect(at('rule_exception.set', 'rule_exception', '1900000')).toBe('/settings/rules/local?view=exceptions')
    expect(at('token.add', 'token', 'tok_000000000003')).toBe('/settings#agent-api')
    expect(at('settings.set', 'setting', 'retention')).toBe('/settings#retention')
    expect(at('agent_api.set', 'setting')).toBe('/settings#agent-api')
    expect(at('crawlers.set', 'website', 'shop.example')).toBe('/w/shop.example/ai-crawlers')
    expect(at('access_lock.set', 'website', 'verein.example')).toBe('/w/verein.example/access')
    expect(at('block.set', 'block', 'K7QM-4XWD')).toBe('/incidents/K7QM-4XWD')
    expect(at('rule_repository.sync', 'rule_repository', 'crowdsec')).toBe('/settings/rules/crowdsec')
    // A subject id is text of another system: only a well-formed incident number becomes a path.
    expect(at('block.set', 'block', '../settings')).toBeUndefined()
    expect(at('privacy.erase', 'address')).toBeUndefined()
  })

  it('is found under Einstellungen in the sidebar', () => {
    const item = buildNav({ site: '' }).flatMap(g => g.items).find(i => i.to === AUDIT_PATH)!
    expect(item.label).toBe('Protokoll')
    expect(item.keywords).toEqual(expect.arrayContaining(['audit', 'änderungen']))
  })
})

describe('the mock serves listAudit like the contract', () => {
  it('holds entries of every class and way, with hidden fields, causes and two websites', async () => {
    const { items, next_cursor } = await list()
    expect(next_cursor).toBeNull()
    expect(new Set(items.map(e => e.class))).toEqual(new Set(['change', 'credential', 'privacy', 'access', 'refused']))
    expect(new Set(items.map(e => e.operation.split(':')[0]))).toEqual(new Set(['dashboard', 'agent', 'cli', 'config', 'system']))
    expect(new Set(items.map(e => e.actor.kind))).toEqual(new Set(['dashboard', 'agent', 'cli', 'config', 'system']))
    expect(new Set(items.map(e => e.website).filter(Boolean)).size).toBeGreaterThanOrEqual(2)
    expect(items.some(e => e.cause && 'event' in e.cause)).toBe(true)
    expect(items.some(e => e.cause && 'incident' in e.cause)).toBe(true)
    expect(items.some(e => e.change?.more_fields)).toBe(true)
    const hidden = new Set(items.flatMap(e => e.change?.fields ?? []).map(f => f.hidden).filter(Boolean))
    expect(hidden).toEqual(new Set(['secret', 'unlisted']))
    expect(items.filter(e => e.result === 'refused').every(e => e.class === 'refused' && e.count! > 0 && !!e.last)).toBe(true)
    // Newest first, ids and pairs as the contract writes them.
    const times = items.map(e => Date.parse(e.time))
    expect([...times].sort((a, b) => b - a)).toEqual(times)
    const pairs = new Map(catalogue.actions.map(a => [a.action, a]))
    for (const e of items) {
      expect(e.id, e.id).toMatch(/^[0-9a-f]{16}-[kar]-[1-9][0-9]{0,15}$/)
      const spec = pairs.get(e.action)!
      expect(spec, e.action).toBeTruthy()
      expect(spec.operations, `${e.action} ${e.operation}`).toContain(e.operation)
      expect(e.subject.kind).toBe(spec.subject)
      if (e.class !== 'refused') expect(e.class).toBe(spec.class)
      if (spec.website === 'required') expect(e.website, e.action).toBeTruthy()
      if (spec.website === 'none') expect(e.website, e.action).toBeUndefined()
      // No secret value, no address as a subject, documentation addresses only.
      expect(e.subject.id ?? '').not.toMatch(/^\d+\.\d+\.\d+\.\d+$/)
      if (e.address) expect(e.address).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./)
      for (const f of e.change?.fields ?? []) {
        if (/(password|secret|token|key)$/.test(f.field)) expect(f, f.field).toMatchObject({ hidden: 'secret' })
      }
    }
    expect(new Set(items.map(e => e.id)).size).toBe(items.length)
  })

  it('filters by way, class, action, website, token, object, session, cause and time', async () => {
    const all = entries()
    const ids = (r: { items: AuditEntry[] }) => r.items.map(e => e.id)
    const where = (pred: (e: AuditEntry) => boolean) => all.filter(pred).map(e => e.id)
    expect(ids(await list('?way=cli'))).toEqual(where(e => e.operation.startsWith('cli:')))
    expect(ids(await list('?class=refused'))).toEqual(where(e => e.class === 'refused'))
    expect(ids(await list('?action=allowlist.add'))).toEqual(where(e => e.action === 'allowlist.add'))
    expect(ids(await list('?website=shop.example'))).toEqual(where(e => e.website === 'shop.example'))
    expect(ids(await list('?actor=tok_000000000001'))).toEqual(where(e => e.actor.kind === 'agent' && e.actor.id === 'tok_000000000001'))
    expect(ids(await list(`?subject=allowlist_entry&subject_id=${MOCK_GONE_ALLOW}`))).toHaveLength(2)
    expect((await list('?subject=allowlist_entry&subject_id=al-2&limit=1')).items[0]).toMatchObject({ action: 'allowlist.add', actor: { user: 'admin' } })
    const session = (find(e => e.action === 'settings.set').actor as { session: string }).session
    expect(ids(await list(`?session=${session}`))).toEqual(where(e => (e.actor as { session?: string }).session === session))
    expect(ids(await list(`?session=${session}`)).length).toBeGreaterThanOrEqual(2)
    expect(ids(await list(`?event=${MOCK_GONE_EVENT}`))).toEqual(where(e => e.action === 'rule_exception.set' && e.subject.id === '1900000'))
    const block = find(e => e.action === 'block.set')
    expect(ids(await list(`?incident=${block.subject.id}`))).toEqual([block.id])
    // [from, to): the entry at `from` is in, the one at `to` is not.
    const a = all[3]!
    const b = all[1]!
    expect(ids(await list(`?from=${a.time}&to=${b.time}`))).toEqual(where(e => Date.parse(e.time) >= Date.parse(a.time) && Date.parse(e.time) < Date.parse(b.time)))
  })

  it('refuses a filter that does not fit, and pages with a cursor', async () => {
    for (const q of ['?actor=admin', '?session=xyz', '?event=1', '?incident=abc', '?class=other', '?way=ssh', '?from=gestern']) {
      const res = await fetch(`${BASE}/audit${q}`)
      expect(res.status, q).toBe(400)
      expect((await res.json()).code).toBe('invalid')
    }
    const seen: string[] = []
    let cursor: string | null = ''
    while (cursor !== null) {
      const page: { items: AuditEntry[], next_cursor: string | null } = await list(`?limit=4${cursor ? `&cursor=${cursor}` : ''}`)
      expect(page.items.length).toBeLessThanOrEqual(4)
      seen.push(...page.items.map(e => e.id))
      cursor = page.next_cursor
    }
    expect(seen).toEqual(entries().map(e => e.id))
  })

  it('needs a session and keeps nothing in the empty scenario', async () => {
    mock.reset({ scenario: 'login' })
    expect((await fetch(`${BASE}/audit`)).status).toBe(401)
    mock.reset({ scenario: 'empty' })
    expect((await list()).items).toEqual([])
  })
})

const openPage = async (query = '') => {
  const app = await mountApp(`${AUDIT_PATH}${query}`)
  await waitFor(() => !!document.querySelector('table[aria-label="Protokoll"]') && !document.querySelector('table[aria-busy="true"]'))
  return app
}
const openEntry = async (e: AuditEntry, query = '') => {
  const app = await openPage(query)
  await click(row(e.id))
  await waitFor(() => byTestId('audit-entry')?.dataset.entry === e.id)
  return app
}

describe('Einstellungen > Protokoll', () => {
  it('lists the entries, newest first, with action, who and way, and says what the log keeps', async () => {
    await openPage()
    expect(rowIds()).toEqual(entries().map(e => e.id))
    expect(byTestId('audit-keep')!.textContent).toContain(AUDIT_COPY.keep)
    expect(byTestId('audit-keep')!.textContent).toContain(AUDIT_COPY.addresses)
    const crawl = find(e => e.action === 'crawlers.set')
    expect(row(crawl.id)!.textContent).toContain('Vorgaben für KI-Crawler geändert')
    expect(row(crawl.id)!.textContent).toContain('coding-agent')
    expect(row(crawl.id)!.textContent).toContain('Agent-API')
    expect(row(crawl.id)!.textContent).toContain('shop.example')
    const refused = find(e => e.class === 'refused' && e.action === 'session.start')
    expect(row(refused.id)!.textContent).toContain('Anmeldung abgelehnt')
    expect(row(refused.id)!.textContent).toContain('12 Versuche')
    expect(row(refused.id)!.textContent).toContain('Ohne Namen')
    // No raw action name stands alone in the list.
    for (const e of entries()) expect(row(e.id)!.textContent, e.action).not.toContain(e.action)
  })

  it('sends the filters of the URL to listAudit and shows them as chips', async () => {
    await openPage(`?subject=allowlist_entry&subject_id=${MOCK_GONE_ALLOW}&way=system&class=change&from=2020-01-01`)
    const q = queries().at(-1)!
    expect(q.get('subject')).toBe('allowlist_entry')
    expect(q.get('subject_id')).toBe(MOCK_GONE_ALLOW)
    expect(q.get('way')).toBe('system')
    expect(q.get('class')).toBe('change')
    expect(q.get('from')).toBe(dayIso('2020-01-01'))
    expect(q.get('limit')).toBe('100')
    expect(rowIds()).toEqual(entries().filter(e => e.subject.id === MOCK_GONE_ALLOW && e.operation === 'system:expiry').map(e => e.id))
    const chips = [...document.querySelectorAll('[data-testid="filter-chip"]')].map(c => c.textContent!.replace(/\s+/g, ' ').trim())
    expect(chips).toEqual(['Art:Änderung', 'Weg:Schild selbst', `Objekt:Eigene IP ${MOCK_GONE_ALLOW}`, 'Von:01.01.2020'])
  })

  it('passes every link filter on: token, session, event and incident', async () => {
    const block = find(e => e.action === 'block.set')
    for (const [query, key, value] of [
      ['?actor=tok_000000000001', 'actor', 'tok_000000000001'],
      ['?session=5e1f0a9c', 'session', '5e1f0a9c'],
      [`?event=${MOCK_GONE_EVENT}`, 'event', MOCK_GONE_EVENT],
      [`?incident=${block.subject.id}`, 'incident', block.subject.id!],
      ['?website=verein.example&action=access_lock.set', 'action', 'access_lock.set'],
    ] as const) {
      requests.length = 0
      await openPage(query)
      expect(queries().some(q => q.get(key) === value), query).toBe(true)
      expect(rowIds().length, query).toBeGreaterThan(0)
      cleanup()
    }
  })

  it('filters with the selects, and a removed chip takes its filter out again', async () => {
    const { router } = await openPage()
    const set = async (testid: string, value: string) => {
      const el = byTestId<HTMLSelectElement>(testid)!
      el.value = value
      el.dispatchEvent(new Event('change', { bubbles: true }))
      await waitFor(() => !document.querySelector('table[aria-busy="true"]'))
    }
    await set('audit-filter-way', 'cli')
    await waitFor(() => router.currentRoute.value.query.way === 'cli')
    await waitFor(() => rowIds().length === entries().filter(e => e.operation.startsWith('cli:')).length)
    expect(queries().at(-1)!.get('way')).toBe('cli')

    await set('audit-filter-class', 'credential')
    await waitFor(() => rowIds().length === 1)
    expect(queries().at(-1)!.get('class')).toBe('credential')
    expect(row(find(e => e.action === 'token.add').id)).not.toBeNull()

    await click(document.querySelector('[aria-label="Filter Weg: Kommandozeile entfernen"]'))
    await waitFor(() => router.currentRoute.value.query.way === undefined)
    expect(router.currentRoute.value.query.class).toBe('credential')

    await set('audit-filter-class', 'privacy')
    await waitFor(() => router.currentRoute.value.query.class === 'privacy')
    await set('audit-filter-action', 'privacy.erase')
    await waitFor(() => router.currentRoute.value.query.action === 'privacy.erase')
    await waitFor(() => queries().at(-1)!.get('action') === 'privacy.erase')
    await waitFor(() => rowIds().length === 1)

    await set('audit-filter-action', 'token.add')
    await waitFor(() => router.currentRoute.value.query.action === 'token.add')
    await waitFor(() => bodyText().includes(AUDIT_COPY.emptyFilteredTitle))
  })

  it('shows who, when, the way, where from, what and before and after of an entry', async () => {
    const e = find(x => x.action === 'settings.set')
    const { router } = await openEntry(e)
    expect(router.currentRoute.value.query.entry).toBe(e.id)
    expect(byTestId('audit-title')!.textContent).toContain('Aufbewahrung geändert')
    expect(byTestId('audit-actor')!.textContent).toContain('admin')
    expect(byTestId('audit-actor')!.textContent).toContain('5e1f0a9c')
    expect(byTestId('audit-way')!.textContent).toContain('Dashboard')
    expect(byTestId('audit-way')!.textContent).toContain('updateSettings')
    expect(byTestId('audit-address')!.textContent).toContain('198.51.100.20')
    expect(byTestId('audit-subject')!.textContent).toContain('Einstellung')
    expect(byTestId('audit-entry')!.querySelector('time')!.getAttribute('datetime')).toBe(e.time)
    const field = document.querySelector('[data-field="/retention/events_days"]')!
    expect(field.textContent).toContain('geändert')
    expect(field.querySelector('[data-testid="audit-before"]')!.textContent!.trim()).toBe('30')
    expect(field.querySelector('[data-testid="audit-after"]')!.textContent!.trim()).toBe('14')
    expect(byTestId('audit-id')!.textContent).toBe(e.id)
  })

  it('shows every kind of actor in its own words', async () => {
    const check = async (e: AuditEntry, ...texts: string[]) => {
      await openEntry(e)
      expect(byTestId('audit-actor')!.dataset.actorKind).toBe(e.actor.kind)
      for (const t of texts) expect(byTestId('audit-actor')!.textContent, t).toContain(t)
      cleanup()
    }
    await check(find(e => e.action === 'crawlers.set'), 'coding-agent', 'tok_000000000001', 'Agent mit Token')
    await check(find(e => e.action === 'token.add'), 'deploy', 'Konto auf dem Server', AUDIT_COPY.cliHint)
    await check(find(e => e.action === 'config.apply'), 'Konfigurationsdatei')
    await check(find(e => e.operation === 'system:expiry'), 'Schild selbst')
    await check(find(e => e.class === 'refused' && e.action === 'session.start'), AUDIT_COPY.noName)
    await openEntry(find(e => e.action === 'config.apply'))
    expect(byTestId('audit-address')!.textContent).toContain(AUDIT_COPY.onHost)
  })

  it('says why a field has no value, and how many fields the entry leaves out', async () => {
    await openEntry(find(e => e.action === 'config.apply'))
    const hidden = (field: string) => document.querySelector(`[data-field="${field}"] [data-testid="audit-hidden"]`) as HTMLElement
    expect(hidden('/geo/ipinfo_key').dataset.hidden).toBe('secret')
    expect(hidden('/geo/ipinfo_key').textContent).toContain(HIDDEN.secret)
    expect(hidden('/ingress/trusted_proxies').textContent).toContain(HIDDEN.unlisted)
    expect(document.querySelector('[data-field="/geo/ipinfo_key"] [data-testid="audit-after"]')).toBeNull()
    expect(byTestId('audit-more-fields')!.textContent).toContain('3 weitere Felder')
    expect(document.querySelector('[data-field="/digest"] [data-testid="audit-before"]')!.textContent!.trim()).toBe('1f2e3d4c5b6a')
  })

  it('shows every other reason a value is hidden, lists, what was cut and what was left out', async () => {
    const e = entry({
      action: 'access_lock.set', operation: 'dashboard:setAccessProtection', subject: { kind: 'website', id: 'verein.example' }, website: 'verein.example',
      change: { fields: [
        { field: '/addresses', change: 'changed', hidden: 'list' },
        { field: '/except', change: 'changed', hidden: 'order' },
        { field: '/message', change: 'changed', hidden: 'size' },
        { field: '/own_networks', change: 'changed', hidden: 'operator' },
        { field: '/paths', change: 'changed', added: ['/intern', '/vorstand'], removed: ['/alt'], more: 7 },
        { field: '/scope', change: 'removed', before: 'site', cut: true },
      ] },
    })
    entries().unshift(e)
    await openEntry(e)
    for (const [field, reason] of [['/addresses', 'list'], ['/except', 'order'], ['/message', 'size'], ['/own_networks', 'operator']] as const) {
      expect(document.querySelector(`[data-field="${field}"] [data-testid="audit-hidden"]`)!.textContent, field).toContain(HIDDEN[reason])
    }
    const paths = document.querySelector('[data-field="/paths"]')!
    expect(paths.querySelector('[data-testid="audit-added"]')!.textContent).toContain('/intern, /vorstand')
    expect(paths.querySelector('[data-testid="audit-removed"]')!.textContent).toContain('/alt')
    expect(paths.querySelector('[data-testid="audit-more"]')!.textContent).toContain('7 weitere')
    const scope = document.querySelector('[data-field="/scope"]')!
    expect(scope.textContent).toContain('entfernt')
    expect(scope.querySelector('[data-testid="audit-cut"]')).not.toBeNull()
  })

  it('shows count and last of refused calls', async () => {
    const e = find(x => x.action === 'agent_api.call')
    await openEntry(e)
    expect(byTestId('audit-title')!.textContent).toContain('Aufruf der Agent-API abgelehnt')
    expect(byTestId('audit-count')!.textContent).toContain('48 Versuche')
    expect(byTestId('audit-count')!.querySelector('time')!.getAttribute('datetime')).toBe(e.last)
  })

  it('leads from an entry to its object while it exists, and to every entry of that object', async () => {
    const e = find(x => x.subject.id === 'al-2')
    const { router } = await openEntry(e)
    await waitFor(() => !!byTestId('audit-object-link'))
    expect(href('audit-object-link')).toBe('/own-ips')
    expect(byTestId('audit-object-gone')).toBeNull()
    expect(href('audit-history-link')).toBe(`${AUDIT_PATH}?subject=allowlist_entry&subject_id=al-2`)
    await click(byTestId('audit-history-link'))
    await waitFor(() => router.currentRoute.value.query.subject_id === 'al-2')
    await waitFor(() => rowIds().length === 1)
    expect(rowIds()).toEqual([e.id])
  })

  it('says that an object is gone and keeps its history', async () => {
    const e = find(x => x.subject.id === MOCK_GONE_ALLOW && x.action === 'allowlist.add')
    const { router } = await openEntry(e)
    await waitFor(() => !!byTestId('audit-object-gone'))
    expect(byTestId('audit-object-gone')!.textContent).toContain(AUDIT_COPY.objectGone)
    expect(byTestId('audit-object-link')).toBeNull()
    await click(byTestId('audit-history-link'))
    await waitFor(() => router.currentRoute.value.query.subject_id === MOCK_GONE_ALLOW)
    await waitFor(() => rowIds().length === 2)
    expect(rowIds().map(id => entries().find(x => x.id === id)!.action)).toEqual(['allowlist.remove', 'allowlist.add'])
  })

  it('finds the other objects too: an exception, a token, a website, a block', async () => {
    const check = async (e: AuditEntry, to: string) => {
      await openEntry(e)
      await waitFor(() => !!byTestId('audit-object-link') || !!byTestId('audit-object-gone'))
      expect(href('audit-object-link'), e.action).toBe(to)
      cleanup()
    }
    await check(find(e => e.subject.id === '1900000'), '/settings/rules/local?view=exceptions')
    await check(find(e => e.action === 'token.add'), '/settings#agent-api')
    await check(find(e => e.action === 'crawlers.set'), '/w/shop.example/ai-crawlers')
    const block = find(e => e.action === 'block.set')
    await check(block, `/incidents/${block.subject.id}`)
    // The exception made in the dashboard is not in force any more.
    await openEntry(find(e => e.subject.id === '1900004'))
    await waitFor(() => !!byTestId('audit-object-gone'))
    cleanup()
    // A token leads to what it did.
    await openEntry(find(e => e.action === 'token.add'))
    expect(href('audit-token-did-link')).toBe(`${AUDIT_PATH}?actor=tok_000000000003`)
  })

  it('leads from an entry to its cause, and says when the event is gone', async () => {
    const made = find(e => e.subject.id === '1900004')
    const event = (made.cause as { event: string }).event
    await openEntry(made)
    await waitFor(() => !!byTestId('audit-cause-link'))
    expect(href('audit-cause-link')).toBe(`/events?event=${event}&time=all`)
    expect(href('audit-cause-entries')).toBe(`${AUDIT_PATH}?event=${event}`)
    expect(byTestId('audit-cause-gone')).toBeNull()
    cleanup()

    await openEntry(find(e => e.subject.id === '1900000'))
    await waitFor(() => !!byTestId('audit-cause-gone'))
    expect(byTestId('audit-cause-gone')!.textContent).toContain(AUDIT_COPY.eventGone)
    expect(byTestId('audit-cause-link')).toBeNull()
    // The entries made because of it are still found.
    expect(href('audit-cause-entries')).toBe(`${AUDIT_PATH}?event=${MOCK_GONE_EVENT}`)
    cleanup()

    const block = find(e => e.action === 'block.set')
    await openEntry(block)
    await waitFor(() => !!byTestId('audit-cause-link'))
    expect(href('audit-cause-link')).toBe(`/incidents/${block.subject.id}`)
    expect(href('audit-cause-entries')).toBe(`${AUDIT_PATH}?incident=${block.subject.id}`)
  })

  it('leads from a sign-in to everything its session did, and from a token to its entries', async () => {
    const login = find(e => e.action === 'session.start' && e.result === 'done')
    const session = (login.actor as { session: string }).session
    const { router } = await openEntry(login)
    expect(byTestId('audit-session-link')!.textContent).toContain('Was diese Anmeldung getan hat')
    await click(byTestId('audit-session-link'))
    await waitFor(() => router.currentRoute.value.query.session === session)
    const mine = entries().filter(e => (e.actor as { session?: string }).session === session).map(e => e.id)
    await waitFor(() => rowIds().length === mine.length)
    expect(rowIds()).toEqual(mine)
    expect(mine.length).toBeGreaterThanOrEqual(2)
    cleanup()

    const { router: r2 } = await openEntry(find(e => e.action === 'crawlers.set'))
    expect(href('audit-token-link')).toBe(`${AUDIT_PATH}?actor=tok_000000000001`)
    expect(href('audit-website-link')).toBe('/w/shop.example')
    expect(href('audit-website-entries')).toBe(`${AUDIT_PATH}?website=shop.example`)
    await click(byTestId('audit-token-link'))
    await waitFor(() => r2.currentRoute.value.query.actor === 'tok_000000000001')
    await waitFor(() => rowIds().length === 2)
    // The chip names the token by its label.
    expect(bodyText()).toContain('coding-agent (tok_000000000001)')
  })

  it('renders text from outside as text: no markup, no link target', async () => {
    const evil = '<img src=x onerror="window.__pwned=1"><a href="https://evil.invalid">klick</a>'
    const e = entry({
      action: 'rule_exception.set', operation: 'agent:createAgentException', class: 'change',
      actor: { kind: 'agent', id: 'tok_000000000001', label: `<b id="evil-label">agent</b>` },
      subject: { kind: 'rule_exception', id: '<i id="evil-id">7</i>' }, website: 'verein.example',
      reason: evil,
      change: { fields: [{ field: '/path', change: 'added', after: `<script id="evil-value">1</script>` }, { field: '/rules', change: 'added', added: ['<u id="evil-item">942100</u>'] }] },
    })
    entries().unshift(e)
    await openPage()
    expect(row(e.id)!.textContent).toContain('<b id="evil-label">agent</b>')
    await click(row(e.id))
    await waitFor(() => !!byTestId('audit-entry'))
    expect(byTestId('audit-reason')!.textContent).toBe(evil)
    expect(byTestId('audit-reason')!.children).toHaveLength(0)
    expect(byTestId('audit-actor')!.textContent).toContain('<b id="evil-label">agent</b>')
    expect(document.querySelector('[data-testid="audit-after"]')!.textContent!.trim()).toBe('<script id="evil-value">1</script>')
    for (const id of ['evil-label', 'evil-id', 'evil-value', 'evil-item']) expect(document.getElementById(id), id).toBeNull()
    expect(document.querySelector('img[src="x"]')).toBeNull()
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined()
    // No link of the page points anywhere but into the app.
    for (const a of document.querySelectorAll('[data-testid="audit-sheet"] a')) expect(a.getAttribute('href'), a.textContent ?? '').toMatch(/^\//)
    expect([...document.querySelectorAll('a')].some(a => a.getAttribute('href')?.includes('evil.invalid'))).toBe(false)
  })

  it('shows an entry of a later build by its raw names instead of failing', async () => {
    const e = entry({
      action: 'portal_key.add', operation: 'integration:createPortalKey', class: 'credential',
      actor: { kind: 'integration', id: 'pk_0123456789ab', label: 'Kundenportal', session: 'bbbb1111', on_behalf_of: 'kunde@example.org' },
      subject: { kind: 'portal_key', id: 'pk_0123456789ab' },
    })
    entries().unshift(e)
    await openEntry(e)
    expect(byTestId('audit-title')!.textContent).toContain('portal_key.add')
    expect(byTestId('audit-subject')!.textContent).toContain('portal_key')
    expect(byTestId('audit-way')!.textContent).toContain('Portal')
    expect(byTestId('audit-actor')!.textContent).toContain('kunde@example.org')
    expect(byTestId('audit-object-link')).toBeNull()
  })

  it('opens an entry from a link and says when it is not in the selection', async () => {
    const e = find(x => x.subject.id === 'al-2')
    await openPage(`?subject=allowlist_entry&subject_id=al-2&entry=${e.id}`)
    await waitFor(() => byTestId('audit-entry')?.dataset.entry === e.id)
    cleanup()
    await openPage(`?class=refused&entry=${e.id}`)
    await waitFor(() => !!byTestId('audit-entry-missing'))
    expect(byTestId('audit-entry')).toBeNull()
  })

  it('loads more with the cursor', async () => {
    const old = Date.parse(entries().at(-1)!.time)
    for (let i = 0; i < 130; i++) entries().push(entry({ id: `0a1b2c3d4e5f6071-k-${2000 + i}`, time: new Date(old - (i + 1) * 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z') }))
    const total = entries().length
    await openPage()
    expect(rowIds()).toHaveLength(100)
    expect(queries().at(-1)!.get('cursor')).toBeNull()
    await click(byTestId('load-more'))
    await waitFor(() => rowIds().length === total)
    expect(queries().at(-1)!.get('cursor')).toBeTruthy()
    expect(byTestId('load-more')).toBeNull()
  })

  it('says so when the log is empty or cannot be loaded', async () => {
    mock.reset({ scenario: 'empty' })
    await openPage()
    expect(bodyText()).toContain(AUDIT_COPY.emptyTitle)
    expect(bodyText()).not.toContain(AUDIT_COPY.emptyFilteredTitle)
  })
})

describe('"Zuletzt geändert von …" and the way back from an event or incident', () => {
  it('names who changed an own IP last, with a link to that entry, and says when the log is too young', async () => {
    await mountApp('/own-ips')
    await waitFor(() => !!byTestId('last-change') && !!byTestId('last-change-older'))
    const e = find(x => x.subject.id === 'al-2')
    const cell = byTestId('last-change')!
    expect(cell.dataset.entry).toBe(e.id)
    expect(cell.textContent).toContain('Zuletzt geändert von admin')
    expect(href('last-change-link')).toBe(`${AUDIT_PATH}?subject=allowlist_entry&subject_id=al-2&entry=${e.id}`)
    // al-3 came from the command line before the log began; al-1 is an entry of schild.yaml and has no line.
    expect(document.querySelectorAll('[data-testid="last-change-older"]')).toHaveLength(1)
    expect(byTestId('last-change-older')!.textContent).toContain(AUDIT_COPY.older)
    // One call for the whole list.
    expect(queries().filter(q => q.get('subject') === 'allowlist_entry')).toHaveLength(1)
    expect(queries().find(q => q.get('subject') === 'allowlist_entry')!.get('subject_id')).toBeNull()
  })

  it('opens that entry on the page of the log', async () => {
    const { router } = await mountApp('/own-ips')
    await waitFor(() => !!byTestId('last-change-link'))
    await click(byTestId('last-change-link'))
    await waitFor(() => router.currentRoute.value.path === AUDIT_PATH)
    await waitFor(() => byTestId('audit-entry')?.dataset.entry === find(x => x.subject.id === 'al-2').id)
    expect(rowIds()).toHaveLength(1)
  })

  it('names who set a rule exception last', async () => {
    await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => !!byTestId('rule-exception') && !!byTestId('last-change'))
    const e = find(x => x.subject.id === '1900000')
    expect(byTestId('rule-exception')!.querySelector('[data-testid="last-change"]')!.textContent).toContain('Zuletzt geändert von coding-agent')
    expect(href('last-change-link')).toBe(`${AUDIT_PATH}?subject=rule_exception&subject_id=1900000&entry=${e.id}`)
    cleanup()

    mock.state.audit = entries().filter(x => x.subject.kind !== 'rule_exception')
    await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => !!byTestId('rule-exception') && !!byTestId('last-change-older'))
    expect(byTestId('last-change-older')!.textContent).toContain(AUDIT_COPY.older)
  })

  it('names the last change of the retention on Einstellungen, asked with limit 1', async () => {
    await mountApp('/settings')
    await waitFor(() => !!document.querySelector('#retention [data-testid="last-change"]'))
    const e = find(x => x.action === 'settings.set')
    const line = document.querySelector('#retention [data-testid="last-change"]')!
    expect(line.textContent).toContain('Zuletzt geändert von admin')
    expect(line.querySelector('a')!.getAttribute('href')).toBe(`${AUDIT_PATH}?action=settings.set&entry=${e.id}`)
    const q = queries().find(x => x.get('action') === 'settings.set')!
    expect(q.get('limit')).toBe('1')
    // Nobody switched the agent API in this log: the card says that this can mean two things.
    await waitFor(() => !!document.querySelector('#agent-api [data-testid="last-change-older"]'))
    expect(document.querySelector('#agent-api [data-testid="last-change-older"]')!.textContent).toContain(AUDIT_COPY.noChange)
    // A token leads to its entries.
    await waitFor(() => !!byTestId('agent-api-token-audit'))
    expect(document.querySelector('[data-token="tok_000000000001"] [data-testid="agent-api-token-audit"]')!.getAttribute('href')).toBe(`${AUDIT_PATH}?actor=tok_000000000001`)
  })

  it('leads from an event to what was changed because of it', async () => {
    const made = find(e => e.subject.id === '1900004')
    const event = (made.cause as { event: string }).event
    await mountApp(`/events?event=${event}&time=all`)
    await waitFor(() => !!byTestId('audit-trail'))
    const item = byTestId('audit-trail-item')!
    expect(item.textContent).toContain('Ausnahme für Regeln gesetzt')
    expect(item.textContent).toContain('admin')
    expect(item.querySelector('a')!.getAttribute('href')).toBe(`${AUDIT_PATH}?event=${event}&entry=${made.id}`)
    expect(queries().some(q => q.get('event') === event)).toBe(true)
    cleanup()

    // An event nothing was made from shows no such section.
    const other = mock.state.events.find(e => e.summary.id !== event)!.summary.id
    await mountApp(`/events?event=${other}&time=all`)
    await waitFor(() => !!byTestId('event-sheet') && queries().some(q => q.get('event') === other))
    expect(byTestId('audit-trail')).toBeNull()
  })

  it('leads from an incident to what was changed because of it', async () => {
    const block = find(e => e.action === 'block.set')
    await mountApp(`/incidents/${block.subject.id}`)
    await waitFor(() => !!byTestId('audit-trail'))
    expect(byTestId('audit-trail-item')!.textContent).toContain('Adresse gesperrt')
    expect(byTestId('audit-trail-item')!.querySelector('a')!.getAttribute('href')).toBe(`${AUDIT_PATH}?incident=${block.subject.id}&entry=${block.id}`)
  })
})
