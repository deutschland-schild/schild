import type { BehaviourHit, BehaviourSettings, RateLimit } from '../src/api/behaviour'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import {
  behaviourStatus,
  limitRecommendationChanges,
  dryRunText,
  explainHit,
  formatClock,
  formatDuration,
  formatPer,
  hitOutcome,
  isSiteWide,
  LEARNING_REASON,
  ladderText,
  isIdlePreset,
  limitUsageText,
  limitText,
  networkOf,
  recommendationChanges,
  scenarioCountsText,
  thresholdsText,
  validPer,
} from '../src/lib/behaviour'
import hitsFixture from '../../../../contracts/api/fixtures/client/listBehaviourHits.json'
import settingsFixture from '../../../../contracts/api/fixtures/client/getBehaviourSettings.json'
import limitsFixture from '../../../../contracts/api/fixtures/client/listRateLimits.json'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, toastAction, type, waitFor } from './helpers'

const hits = hitsFixture.items as BehaviourHit[]
const byScenario = (s: string) => hits.find(h => h.scenario === s)!
const base: BehaviourHit = { id: 'x', time: '2026-10-28T09:00:00Z', kind: 'scenario', scope: 'client', count: 1, threshold: 1, window_s: 60, mode: 'block', action: 'observe', active: false, released: false }

describe('behaviour explanations', () => {
  it('formats durations naturally, singular and plural', () => {
    expect(formatDuration(1)).toBe('1 Sekunde')
    expect(formatDuration(30)).toBe('30 Sekunden')
    expect(formatDuration(60)).toBe('1 Minute')
    expect(formatDuration(90)).toBe('90 Sekunden')
    expect(formatDuration(120)).toBe('2 Minuten')
    expect(formatDuration(3600)).toBe('1 Stunde')
    expect(formatDuration(86400)).toBe('24 Stunden')
    expect(formatDuration(172800)).toBe('2 Tagen')
    expect(formatPer(60)).toBe('pro Minute')
    expect(formatPer(600)).toBe('pro 10 Minuten')
    expect(formatPer(3600)).toBe('pro Stunde')
  })

  it('explains every scenario from the fixture in one sentence', () => {
    expect(explainHit(byScenario('login_bruteforce'))).toBe('37 falsche Anmeldungen in 2 Minuten an wp-login.php von 198.51.100.7')
    expect(explainHit(byScenario('path_probing'))).toBe('24 verschiedene nicht vorhandene Adressen in 1 Minute von 203.0.113.45, z. B. /.env')
    expect(explainHit(byScenario('waf_repeat'))).toBe('3 verschiedene WAF-Regeln in 1 Minute von 203.0.113.9')
    expect(explainHit(byScenario('credential_stuffing'))).toBe('412 verschiedene Benutzernamen in 10 Minuten an wp-login.php von vielen Adressen')
    expect(explainHit({ ...base, scenario: 'credential_stuffing', ip: '192.0.2.150', key_bits: 32, route: '/wp-login.php', count: 1, window_s: 600 }))
      .toBe('1 verschiedener Benutzername in 10 Minuten an wp-login.php von 192.0.2.150')
    expect(explainHit({ ...base, scenario: 'aggressive_crawl', ip: '203.0.113.77', host: 'verein.example', count: 1, window_s: 60 }))
      .toBe('1 Anfrage in 1 Minute an verein.example von 203.0.113.77, weit mehr als üblich')
  })

  it('names the /64 network for IPv6 client keys', () => {
    expect(explainHit(hits[2]!)).toBe('7 falsche Anmeldungen in 1 Minute an wp-login.php aus dem Netz 2001:db8:4:7::/64')
    expect(networkOf('2001:db8::17', 64)).toBe('2001:db8::/64')
    expect(networkOf('198.51.100.7', 24)).toBe('198.51.100.0/24')
    expect(networkOf('198.51.100.7', 32)).toBeNull()
  })

  it('explains rate limit records with the limit', () => {
    const rl = hits.find(h => h.kind === 'rate_limit')!
    expect(explainHit(rl)).toBe('48 Anfragen über dem Limit von 10 pro Minute an /xmlrpc.php von 192.0.2.150')
    expect(hitOutcome(rl).label).toBe('Erkannt (Probelauf)')
  })

  it('says what happened or would have happened, with the reason', () => {
    // The gateway says whether the block still runs (active); the UI never compares until with its clock.
    const blocked = hitOutcome(byScenario('login_bruteforce'))
    expect(blocked.label).toBe(`Gesperrt bis ${formatClock('2026-10-28T09:29:02Z')} (Stufe 1)`)
    expect(blocked.tone).toBe('warning') // calm, as on the incident page
    expect(hitOutcome({ ...byScenario('login_bruteforce'), active: false }).tone).toBe('neutral')
    expect(hitOutcome(byScenario('path_probing')).label).toBe('Erkannt (Probelauf)')
    const mobile = hitOutcome(hits[2]!)
    expect(mobile.label).toBe('Nur beobachtet')
    expect(mobile.reason).toBe('Mobilfunk-, CGNAT- oder Tor-Adresse: viele Menschen teilen sie, deshalb nie gesperrt')
    expect(hitOutcome(byScenario('credential_stuffing')).reason).toBe('über viele Adressen verteilt, keine einzelne Adresse zum Sperren')
    expect(hitOutcome(byScenario('waf_repeat')).reason).toBe('freigegeben')
    expect(hitOutcome({ ...base, reason: 'allowlisted' }).reason).toBe('eigene Adresse, nie gesperrt')
    expect(hitOutcome({ ...base, reason: 'unverified_bot' }).reason).toBe('gibt sich als Suchmaschine aus, wird nur gezählt')
    // Learning period: block configured, observed, no other reason (MVP-19 measurement).
    expect(hitOutcome({ ...base, mode: 'block', action: 'observe', would_action: 'block', reason: undefined, released: false }).reason).toBe(LEARNING_REASON)
    expect(hitOutcome({ ...base, mode: 'block', action: 'observe', would_action: 'block', reason: 'learning', released: false }).reason).toBe(LEARNING_REASON)
    expect(hitOutcome({ ...base, mode: 'observe', action: 'observe', would_action: 'block', reason: undefined, released: false }).reason).toBeNull()
  })

  it('puts thresholds, counts and the ladder into words', () => {
    const s = settingsFixture as BehaviourSettings
    const login = s.scenarios.find(x => x.id === 'login_bruteforce')!
    expect(thresholdsText('login_bruteforce', login.thresholds)).toBe('mindestens 5 falsche Anmeldungen in 1 Minute oder 30 in 1 Stunde')
    expect(thresholdsText('waf_repeat', { count: 2, window_s: 60 })).toBe('2 oder mehr verschiedene WAF-Regeln in 1 Minute')
    expect(thresholdsText('aggressive_crawl', { count: 120, window_s: 60, baseline_factor: 10 })).toBe('mindestens 120 Anfragen in 1 Minute und mindestens das 10-Fache des Üblichen')
    expect(scenarioCountsText(login)).toBe('4 Treffer, 0 erkannt')
    expect(scenarioCountsText({ hits_24h: 1, would_block_24h: 1 })).toBe('1 Treffer, 1 erkannt')
    expect(ladderText(s.block_steps_s, s.block_cap_s)).toBe('15 Min, 1 Std, 4 Std, höchstens 24 Std')
  })

  it('lists the switches that differ from the recommendation, scenarios first (D92)', () => {
    const settings = structuredClone(settingsFixture) as BehaviourSettings
    expect(recommendationChanges(settings).map(c => [c.name, c.from, c.to, c.mode])).toEqual([
      ['Ausprobieren von Zugangsdaten', 'Beobachten', 'Sperren', 'block'],
      ['Suche nach Schwachstellen', 'Beobachten', 'Sperren', 'block'],
    ])
    for (const sc of settings.scenarios) sc.mode = sc.recommended
    expect(recommendationChanges(settings)).toEqual([])
    // Preset limits have their own list (D95); own limits have no recommendation.
    const limits = structuredClone(limitsFixture.items) as RateLimit[]
    expect(limitRecommendationChanges(limits).map(c => [c.id, c.name, c.from, c.to])).toEqual([
      ['preset-wordpress-login', 'WordPress Anmeldung', 'Beobachten', 'Begrenzen'],
      ['preset-wordpress-xmlrpc', 'WordPress XML-RPC', 'Beobachten', 'Begrenzen'],
    ])
  })

  it('describes rate limits, dry runs and site-wide routes', () => {
    const [login, , , contact] = limitsFixture.items as RateLimit[]
    expect(limitText(login!)).toBe('10 pro Minute, kurzzeitig 10')
    expect(limitText(contact!)).toBe('3 pro 10 Minuten, kurzzeitig 3')
    expect(limitUsageText(login!)).toBe('222 Anfragen, 37 über dem Limit, 1 Adresse')
    expect(limitUsageText({ mode: 'block', matched_24h: 12, exceeded_24h: 0, clients_24h: 0 })).toBe('12 Anfragen, nichts über dem Limit')
    expect(limitUsageText({ mode: 'block', matched_24h: 0, exceeded_24h: 0, clients_24h: 0 })).toBe('keine Anfragen')
    expect(limitUsageText({ mode: 'off', matched_24h: 0, exceeded_24h: 0, clients_24h: 0 })).toBe('zählt nicht')
    // Idle: a preset limit on its recommendation whose route nobody requested (D96).
    const idle = { source: 'preset' as const, mode: 'block' as const, recommended: 'block' as const, matched_24h: 0, exceeded_24h: 0 }
    expect(isIdlePreset(idle)).toBe(true)
    expect(isIdlePreset({ ...idle, matched_24h: 1 })).toBe(false)
    expect(isIdlePreset({ ...idle, mode: 'observe' })).toBe(false)
    expect(isIdlePreset({ ...idle, source: 'dashboard', recommended: undefined, mode: 'block' })).toBe(false)
    expect(dryRunText({ window_h: 24, requests: 214, would_limit: 12, clients: 2, sampled: false })).toBe('In den letzten 24 Stunden hätte dieses Limit 12 Anfragen von 2 Adressen begrenzt.')
    expect(dryRunText({ window_h: 24, requests: 214, would_limit: 1, clients: 1, sampled: true })).toBe('In den letzten 24 Stunden hätte dieses Limit mindestens 1 Anfrage von 1 Adresse begrenzt.')
    expect(dryRunText({ window_h: 24, requests: 3, would_limit: 0, clients: 0, sampled: true })).toBe('In den letzten 24 Stunden hätte dieses Limit keine Anfrage begrenzt.')
    for (const r of ['/', '/*', '/**', '*']) expect(isSiteWide(r)).toBe(true)
    for (const r of ['/wp-login.php', '/api/*', '']) expect(isSiteWide(r)).toBe(false)
    expect(validPer('1m')).toBe(true)
    expect(validPer('24h')).toBe(true)
    expect(validPer('60m')).toBe(false)
    expect(validPer('25h')).toBe(false)
  })
})

// ------------------------------------------------------------------ mock backend and the view

const BASE = 'http://dashboard.schild.test/api/v0'
const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
})
afterAll(() => mock.server.close())

const all = <T extends Element = HTMLElement>(sel: string) => [...document.querySelectorAll<T>(sel)]

describe('mock backend: behaviour and rate limits', () => {
  const h = () => ({ 'Content-Type': 'application/json', 'X-CSRF-Token': mock.state.session.csrf_token! })

  it('filters hits and changes settings without a password', async () => {
    const page = await (await fetch(`${BASE}/behaviour/hits?kind=rate_limit`)).json() as { items: BehaviourHit[] }
    expect(page.items.map(x => x.kind)).toEqual(['rate_limit'])
    const active = await (await fetch(`${BASE}/behaviour/hits?active=true`)).json() as { items: BehaviourHit[] }
    expect(active.items.map(x => x.ip)).toEqual(['198.51.100.7'])
    // D92: there is no browser check, so no mode challenge.
    let res = await fetch(`${BASE}/behaviour/settings`, { method: 'PATCH', headers: h(), body: JSON.stringify({ scenarios: { path_probing: 'challenge' } }) })
    expect(res.status).toBe(400)
    res = await fetch(`${BASE}/behaviour/settings`, { method: 'PATCH', headers: h(), body: JSON.stringify({ scenarios: { path_probing: 'block' } }) })
    const s = await res.json() as BehaviourSettings
    expect(s.scenarios.find(x => x.id === 'path_probing')).toMatchObject({ mode: 'block', effective_mode: 'block', recommended: 'block' })
  })

  it('creates, refuses site-wide without confirmation, and keeps preset limits read-only', async () => {
    let res = await fetch(`${BASE}/behaviour/rate-limits`, { method: 'POST', headers: h(), body: JSON.stringify({ route: '/**', limit: 100, per: '1m' }) })
    expect((await res.json()).errors[0].pointer).toBe('/confirm_site_wide')
    res = await fetch(`${BASE}/behaviour/rate-limits`, { method: 'POST', headers: h(), body: JSON.stringify({ route: '/suche', limit: 20, per: '1m' }) })
    expect(res.status).toBe(201)
    const created = await res.json() as RateLimit
    expect(created).toMatchObject({ source: 'dashboard', mode: 'observe', burst: 20 })
    res = await fetch(`${BASE}/behaviour/rate-limits/preset-wordpress-login`, { method: 'DELETE', headers: h() })
    expect((await res.json()).code).toBe('config_limit')
    res = await fetch(`${BASE}/behaviour/rate-limits/${created.id}`, { method: 'DELETE', headers: h() })
    expect(res.status).toBe(204)
  })

  it('releases a client and allows it permanently via Eigene IPs', async () => {
    const res = await fetch(`${BASE}/behaviour/release`, { method: 'POST', headers: h(), body: JSON.stringify({ ip: '198.51.100.7', allow: 'permanent' }) })
    const r = await res.json()
    expect(r.blocks_ended).toBe(1)
    expect(mock.state.allowlist.find(a => a.id === r.allowlist_entry)).toMatchObject({ ip: '198.51.100.7', level: 'no_block', expires: 'never' })
    expect(mock.state.behaviour.hits.some(x => x.active)).toBe(false)
  })
})

describe('Verhalten & Limits', () => {
  it('is reachable from the navigation and lists hits in plain German', async () => {
    // The old address leads to the hits, the tab Verlauf of Sperren (2026-11-18).
    const { wrapper, router } = await mountApp('/behaviour')
    expect(wrapper.get('h1').text()).toBe('Sperren')
    expect(router.currentRoute.value.fullPath).toBe('/blocks?view=hits')
    await waitFor(() => all('[data-testid="hit-item"]').length === hits.length)
    const texts = all('[data-testid="hit-explain"]').map(e => e.textContent)
    expect(texts).toContain('37 falsche Anmeldungen in 2 Minuten an wp-login.php von 198.51.100.7')
    expect(texts).toContain('412 verschiedene Benutzernamen in 10 Minuten an wp-login.php von vielen Adressen')
    expect(bodyText()).toContain('Erkannt (Probelauf)')
    expect(bodyText()).toContain('Mobilfunk-, CGNAT- oder Tor-Adresse')
    expect(bodyText()).not.toMatch(/geschützt|anonym|sicher\b/)
    await click(byTestId('hits-filter-running'))
    await waitFor(() => all('[data-testid="hit-item"]').length === 1)
  })

  it('releases a blocked client from the detail', async () => {
    const { router } = await mountApp('/behaviour')
    await waitFor(() => all('[data-testid="hit-item"]').length > 0)
    await click(all('[data-testid="hit-item"]')[0]!)
    expect(router.currentRoute.value.query.hit).toBe(hits[0]!.id)
    await waitFor(() => !!byTestId('hit-actions'))
    expect(byTestId('hit-blocks')!.textContent).toContain('Passwort-Raten')
    expect(all('[data-testid="hit-requests"] li')).toHaveLength(4)
    await click(byTestId('hit-exception'))
    await waitFor(() => !!byTestId('confirm-submit'))
    expect(bodyText()).toContain('das Szenario „Passwort-Raten“')
    await click(byTestId('confirm-submit'))
    await waitFor(() => bodyText().includes('Ausnahme für 198.51.100.7 angelegt'))
    expect(mock.state.behaviour.exceptions[0]).toMatchObject({ ip: '198.51.100.7', sources: ['behaviour:login_bruteforce'] })
    expect(mock.state.behaviour.hits[0]!.active).toBe(false)
  })

  it('says why a scenario on Beobachten blocked nothing and switches it to Sperren from the hit', async () => {
    const probing = byScenario('path_probing')
    Object.assign(mock.state.behaviour.settings.scenarios.find(s => s.id === 'path_probing')!, { mode: 'observe', effective_mode: 'observe' })
    await mountApp(`/behaviour?hit=${probing.id}`)
    await waitFor(() => !!byTestId('hit-observed-block'))
    expect(byTestId('hit-observed-now')).toBeNull()
    expect(byTestId('hit-observed')!.textContent).toContain('Das Szenario „Suche nach Schwachstellen“ stand auf „Beobachten“')
    expect(byTestId('hit-observed')!.textContent).toContain('Jedes Szenario hat seinen eigenen Schalter.')
    expect(bodyText()).toContain('Szenario: Beobachten')
    expect(bodyText()).not.toContain('Modus: Beobachten')
    await click(byTestId('hit-observed-block'))
    await waitFor(() => !!byTestId('confirm-submit'))
    await click(byTestId('confirm-submit'))
    await waitFor(() => !!byTestId('hit-observed-now'))
    expect(byTestId('hit-observed-now')!.textContent).toContain('Inzwischen steht es auf „Sperren“')
    expect(byTestId('hit-observed-block')).toBeNull()
    expect(mock.state.behaviour.settings.scenarios.find(s => s.id === 'path_probing')!.mode).toBe('block')
  })

  it('shows no such notice for a hit that blocked or has its own reason', async () => {
    await mountApp(`/behaviour?hit=${hits[0]!.id}`)
    await waitFor(() => !!byTestId('hit-actions'))
    expect(byTestId('hit-observed')).toBeNull()
    expect(byTestId('hit-requests-hint')!.textContent).toContain('diese eine Anfrage')
  })

  it('offers no release for hits spread over many addresses', async () => {
    const site = hits.find(x => x.scope === 'site')!
    await mountApp(`/behaviour?hit=${site.id}`)
    await waitFor(() => !!byTestId('hit-site-scope'))
    expect(byTestId('hit-actions')).toBeNull()
  })

  it('says that no address is blocked while every scenario only observes', async () => {
    for (const s of mock.state.behaviour.settings.scenarios) Object.assign(s, { mode: 'observe', effective_mode: 'observe' })
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => !!byTestId('scenarios-none-blocking'))
    expect(byTestId('scenarios-none-blocking')!.textContent).toContain('Gerade sperrt kein Szenario eine Adresse.')
    await click(byTestId('scenario-waf_repeat-block'))
    await waitFor(() => !!byTestId('confirm-submit'))
    await click(byTestId('confirm-submit'))
    await waitFor(() => byTestId('scenarios-none-blocking') === null)
  })

  it('asks before switching a scenario, without a password', async () => {
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => all('[data-testid="scenario-row"]').length === 5)
    expect(byTestId('scenario-path_probing-challenge')).toBeNull()
    expect(byTestId('ladder')!.textContent).toContain('15 Min, 1 Std, 4 Std, höchstens 24 Std')
    expect(bodyText()).toContain('mindestens 5 falsche Anmeldungen in 1 Minute oder 30 in 1 Stunde')
    await click(byTestId('scenario-path_probing-block'))
    await waitFor(() => !!byTestId('confirm-submit'))
    expect(bodyText()).toContain('„Suche nach Schwachstellen“ auf „Sperren“ stellen?')
    expect(mock.state.behaviour.settings.scenarios.find(x => x.id === 'path_probing')!.mode).toBe('observe')
    await click(byTestId('confirm-submit'))
    await waitFor(() => mock.state.behaviour.settings.scenarios.find(x => x.id === 'path_probing')!.mode === 'block')
  })

  it('sums scenarios and limits up as one status, honest about the learning period (D94)', async () => {
    const base = settingsFixture as BehaviourSettings
    const now = Date.parse('2026-10-28T09:20:00Z')
    const all = (mode: 'off' | 'observe' | 'block') => base.scenarios.map(x => ({ ...x, mode, effective_mode: mode }))
    const lim = (...m: RateLimit['mode'][]) => m.map(mode => ({ mode }))
    expect(behaviourStatus(base, lim('observe', 'block'), now)).toEqual({ effect: 'block', facts: ['2 von 5 Szenarien sperren', '1 von 2 Limits begrenzen'] })
    expect(behaviourStatus(base, null, now).facts).toEqual(['2 von 5 Szenarien sperren'])
    expect(behaviourStatus({ ...base, learning_until: '2026-11-03T10:00:00Z' }, lim('observe'), now)).toEqual({
      effect: 'would_block',
      facts: ['2 von 5 Szenarien stehen auf „Sperren“, Schild lernt noch bis 3. November und beobachtet bis dahin nur', '0 von 1 Limits begrenzen'],
    })
    expect(behaviourStatus({ ...base, learning_until: null }, [], now).effect).toBe('would_block')
    // Limits act from the first day, also while scenarios still learn.
    expect(behaviourStatus({ ...base, learning_until: null }, lim('block'), now).effect).toBe('block')
    expect(behaviourStatus({ ...base, scenarios: all('observe') }, lim('observe'), now)).toEqual({ effect: 'observe', facts: ['Kein Szenario sperrt, alle beobachten nur', '0 von 1 Limits begrenzen'] })
    expect(behaviourStatus({ ...base, scenarios: all('off') }, lim('off'), now)).toEqual({ effect: 'off', facts: ['Alle Szenarien sind aus', '0 von 1 Limits begrenzen'] })
    expect(behaviourStatus({ ...base, scenarios: all('off') }, [], now).facts).toEqual(['Alle Szenarien sind aus', 'Keine Limits'])
    expect(behaviourStatus({ ...base, scenarios: base.scenarios.map(x => ({ ...x, mode: 'block' as const, effective_mode: 'observe' as const })) }, [], now).facts[0])
      .toBe('5 von 5 Szenarien stehen auf „Sperren“, im Testprofil beobachten sie nur')

    const rules = await mountApp('/settings/rules')
    await waitFor(() => !!byTestId('rules-behaviour-status'))
    expect(byTestId('rules-behaviour-status')!.textContent).toContain('Sperrt')
    expect(byTestId('rules-behaviour-facts')!.textContent).toContain('2 von 5 Szenarien sperren')
    expect(byTestId('rules-behaviour-facts')!.textContent).toContain('2 von 4 Limits begrenzen')
    // The wave detectors are part of the card and its status (D97).
    await waitFor(() => !!byTestId('rules-behaviour-facts')?.textContent?.includes('Wellen-Erkennungen reagieren'))
    expect(byTestId('rules-behaviour-waves')!.getAttribute('href')).toBe('/settings/rules/behaviour?view=detectors')
    const det = (mode: string, effective_mode: string) => [{ mode, effective_mode }, { mode: 'observe', effective_mode: 'observe' }]
    expect(behaviourStatus({ ...base, scenarios: all('observe') }, [], now, det('respond', 'respond'))).toEqual({ effect: 'block', facts: ['Kein Szenario sperrt, alle beobachten nur', 'Keine Limits', '1 von 2 Wellen-Erkennungen reagieren'] })
    expect(behaviourStatus({ ...base, scenarios: all('observe') }, [], now, det('respond', 'observe')).effect).toBe('would_block')
    expect(behaviourStatus({ ...base, scenarios: all('off') }, [], now, det('observe', 'observe')).effect).toBe('observe')
    rules.wrapper.unmount()
    mock.state.behaviour.settings.learning_until = null
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => !!byTestId('scenarios-learning'))
    expect(byTestId('scenarios-learning')!.textContent).toContain('Bis dahin sperrt kein Szenario')
  })

  it('sets the threshold of a scenario and puts the built-in value back (D93)', async () => {
    const probing = () => mock.state.behaviour.settings.scenarios.find(x => x.id === 'path_probing')!
    const meta = () => document.querySelector('[data-scenario="path_probing"] [data-testid="scenario-meta"]')!.textContent
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => all('[data-testid="scenario-row"]').length === 5)
    await click(byTestId('scenario-path_probing-thresholds'))
    await waitFor(() => !!byTestId('thresholds-form'))
    expect(byTestId('thresholds-defaults')!.textContent).toContain('Ab Werk: mindestens 20 verschiedene nicht vorhandene Adressen in 1 Minute')
    expect(byTestId('thresholds-reset')).toBeNull()
    expect(byTestId('thresholds-slow-count')).toBeNull()
    expect(byTestId('thresholds-factor')).toBeNull()
    await type(byTestId('thresholds-count') as HTMLInputElement, '1')
    await click(byTestId('thresholds-submit'))
    expect(bodyText()).toContain('Eine ganze Zahl zwischen 2 und 100.000.')
    expect(probing().thresholds.count).toBe(20)
    await type(byTestId('thresholds-count') as HTMLInputElement, '8')
    await type(byTestId('thresholds-window-n') as HTMLInputElement, '2')
    await click(byTestId('thresholds-submit'))
    await waitFor(() => probing().thresholds.count === 8)
    expect(probing().thresholds.window_s).toBe(120)
    await waitFor(() => !!meta()?.includes('mindestens 8 verschiedene nicht vorhandene Adressen in 2 Minuten (angepasst)'))

    await click(byTestId('scenario-path_probing-thresholds'))
    await waitFor(() => !!byTestId('thresholds-reset'))
    await click(byTestId('thresholds-reset'))
    await click(byTestId('thresholds-submit'))
    await waitFor(() => probing().thresholds.count === 20)
    await waitFor(() => !meta()?.includes('angepasst'))
  })

  it('offers the slow variant for Passwort-Raten and the factor for Aggressives Abrufen (D93)', async () => {
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => all('[data-testid="scenario-row"]').length === 5)
    await click(byTestId('scenario-login_bruteforce-thresholds'))
    await waitFor(() => !!byTestId('thresholds-slow-count'))
    expect((byTestId('thresholds-slow-count') as HTMLInputElement).value).toBe('30')
    expect(byTestId('thresholds-factor')).toBeNull()
  })

  it('marks the recommended mode of every switch and says why where it is not Sperren (D92)', async () => {
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => all('[data-testid="scenario-row"]').length === 5)
    expect(byTestId('scenario-path_probing-block')!.textContent).toContain('empfohlen')
    expect(byTestId('scenario-path_probing-observe')!.textContent).not.toContain('empfohlen')
    expect(byTestId('scenario-aggressive_crawl-observe')!.textContent).toContain('empfohlen')
    expect(all('[data-testid="scenario-recommended-why"]').map(x => x.textContent)).toEqual([expect.stringContaining('Empfohlen: Beobachten. Suchmaschinen-Tools')])
  })

  it('takes over the recommendation in one change, after listing every switch it changes', async () => {
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => !!byTestId('apply-recommendation'))
    expect(byTestId('recommendation-text')!.textContent).toContain('Empfehlung: 4 von 5 Szenarien sperren.')
    expect(byTestId('recommendation-text')!.textContent).toContain('2 Schalter weichen davon ab.')
    await click(byTestId('apply-recommendation'))
    await waitFor(() => !!byTestId('bulk-changes'))
    expect(byTestId('bulk-changes')!.textContent).toContain('Ausprobieren von Zugangsdaten: Beobachten → Sperren')
    expect(byTestId('bulk-changes')!.textContent).toContain('Suche nach Schwachstellen: Beobachten → Sperren')
    expect(byTestId('confirm-submit')!.textContent).toContain('2 Schalter ändern')
    await click(byTestId('confirm-submit'))
    await waitFor(() => byTestId('apply-recommendation') === null)
    expect(byTestId('recommendation-text')!.textContent).toContain('Alle Schalter stehen auf der Empfehlung.')
    const modes = Object.fromEntries(mock.state.behaviour.settings.scenarios.map(x => [x.id, x.mode]))
    expect(modes).toEqual({ login_bruteforce: 'block', credential_stuffing: 'block', path_probing: 'block', aggressive_crawl: 'observe', waf_repeat: 'block' })
  })

  it('switches every scenario to Sperren from the menu', async () => {
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => !!byTestId('scenarios-more'))
    await click(byTestId('scenarios-more'))
    await waitFor(() => !!byTestId('scenarios-block-all'))
    await click(byTestId('scenarios-block-all'))
    await waitFor(() => !!byTestId('bulk-changes'))
    expect(bodyText()).toContain('Alle Szenarien auf „Sperren“ stellen?')
    expect(all('[data-testid="bulk-changes"] li')).toHaveLength(3)
    await click(byTestId('confirm-submit'))
    await waitFor(() => mock.state.behaviour.settings.scenarios.every(x => x.mode === 'block'))
  })

  it('switches preset limits one by one and takes over their recommendation (D95)', async () => {
    const mode = (id: string) => mock.state.behaviour.limits.find(l => l.id === id)!.mode
    const first = await mountApp('/behaviour?view=limits')
    await waitFor(() => !!byTestId('limit-mode-preset-wordpress-login'))
    const login = byTestId('limit-mode-preset-wordpress-login') as HTMLSelectElement
    expect(login.value).toBe('observe')
    expect([...login.options].map(o => o.textContent?.trim())).toEqual(['Aus', 'Beobachten', 'Begrenzen (empfohlen)'])
    expect(byTestId('limit-mode-contact-form')).toBeNull()
    expect(byTestId('limit-recommendation')!.textContent).toContain('2 voreingestellte Limits stehen nicht auf der Empfehlung.')
    login.value = 'block'
    login.dispatchEvent(new Event('change'))
    await waitFor(() => mode('preset-wordpress-login') === 'block')
    expect(mode('preset-wordpress-xmlrpc')).toBe('observe')
    await waitFor(() => !!byTestId('limit-recommendation')?.textContent?.includes('1 voreingestelltes Limit steht nicht auf der Empfehlung.'))
    await click(byTestId('limit-apply-recommendation'))
    await waitFor(() => !!byTestId('limit-bulk-changes'))
    expect(byTestId('limit-bulk-changes')!.textContent).toContain('WordPress XML-RPC: Beobachten → Begrenzen')
    await click(byTestId('confirm-submit'))
    await waitFor(() => mode('preset-wordpress-xmlrpc') === 'block')
    await waitFor(() => byTestId('limit-recommendation') === null)

    // A preset limit on its recommendation without requests leaves the list until asked for (D96).
    expect(byTestId('limits-idle')).toBeNull()
    Object.assign(mock.state.behaviour.limits.find(l => l.id === 'preset-wordpress-xmlrpc')!, { matched_24h: 0, exceeded_24h: 0, clients_24h: 0 })
    first.wrapper.unmount()
    const again = await mountApp('/behaviour?view=limits')
    await waitFor(() => !!byTestId('limits-idle'))
    expect(byTestId('limits-idle')!.textContent).toContain('1 voreingestelltes Limit ist ausgeblendet')
    expect(byTestId('limit-mode-preset-wordpress-xmlrpc')).toBeNull()
    expect(byTestId('limit-mode-preset-wordpress-login')).not.toBeNull()
    await click(byTestId('limits-idle-toggle'))
    await waitFor(() => !!byTestId('limit-mode-preset-wordpress-xmlrpc'))
    expect(again.router.currentRoute.value.query.all).toBe('1')
  })

  it('adds a rate limit after a Probelauf, with the site-wide checkbox', async () => {
    await mountApp('/behaviour?view=limits')
    await waitFor(() => all('[data-testid="limit-text"]').length === 4)
    expect(all('[data-testid="limit-edit"]')).toHaveLength(1)
    await click(byTestId('limit-add'))
    await waitFor(() => !!byTestId('limit-form'))
    await type(byTestId('limit-route'), '/**')
    expect(byTestId('limit-site-wide')).not.toBeNull()
    await type(byTestId('limit-route'), '/kontakt')
    expect(byTestId('limit-site-wide')).toBeNull()
    await click(byTestId('limit-dry-run'))
    await waitFor(() => !!byTestId('limit-dry-run-result'))
    expect(byTestId('limit-dry-run-result')!.textContent).toContain('In den letzten 24 Stunden hätte dieses Limit mindestens 12 Anfragen von 2 Adressen begrenzt.')
    expect(byTestId('limit-dry-run-result')!.textContent).toContain('Stichprobe')
    await click(byTestId('limit-submit'))
    await waitFor(() => bodyText().includes('Limit hinzugefügt'))
    expect(mock.state.behaviour.limits.at(-1)).toMatchObject({ route: '/kontakt', limit: 10, per: '1m', mode: 'observe', source: 'dashboard' })
    await waitFor(() => all('[data-testid="limit-text"]').length === 5)
  })
})

describe('Sperren (D87)', () => {
  it('lists every blocked address, says whether the firewall holds it, and lifts it', async () => {
    const running = mock.state.behaviour.hits.filter(h => h.kind === 'scenario' && h.active && h.ip && h.until && Date.parse(h.until) > Date.now())
    expect(running.length).toBeGreaterThan(0)
    const ip = running[0]!.ip!
    // The gateway keeps an incident for every block: the mock gets one for this block.
    const any = [...mock.state.incidents.values()][0]!
    mock.state.incidents.set(running[0]!.incident!, { ...any, incident: running[0]!.incident!, status: 'blocked', unblocked_at: null, request: { ...any.request, ip } })
    await mountApp('/blocks')
    await waitFor(() => all('[data-testid="block-row"]').length === running.length, 5000)
    expect(byTestId('firewall-state')!.dataset.state).toBe('off')
    expect(byTestId('firewall-state')!.textContent).toContain('Die Firewall ist nicht angebunden')
    expect(byTestId('block-firewall')!.textContent).toContain('nur Schild')
    cleanup()
    // The host's sync put the address into the firewall.
    mock.state.firewall = { state: 'ok', banned: [ip] }
    await mountApp('/blocks')
    await waitFor(() => !!document.querySelector(`[data-client="${ip}"] [data-testid="block-firewall"]`))
    expect(document.querySelector(`[data-client="${ip}"] [data-testid="block-firewall"]`)!.textContent).toContain('in der Firewall')
    expect(byTestId('firewall-state')!.textContent).toContain('1 Adresse kommt nicht mehr')
    await click(document.querySelector<HTMLElement>(`[data-client="${ip}"] [data-testid="block-lift"]`)!)
    // The unblock of the incident, as on the incident page: false positive or not, the address as an own IP.
    await waitFor(() => !!byTestId('unblock-submit'), 4000)
    await click(byTestId('unblock-fp-no'))
    await click(byTestId('unblock-allow-ip'))
    await click(byTestId('unblock-submit'))
    await waitFor(() => mock.state.incidents.get(running[0]!.incident!)!.status === 'unblocked')
    await waitFor(() => !document.querySelector(`[data-client="${ip}"]`), 4000)
    expect(mock.state.allowlist.some(e => e.ip === ip)).toBe(true)
  })

  it('lists the stopped requests of every website in the second tab', async () => {
    await mountApp('/blocks?view=requests')
    await waitFor(() => all('[data-testid="stopped-row"]').length > 0)
    expect(document.querySelector('[data-testid="stopped-row"] a')!.getAttribute('href')).toMatch(/\/incidents\/[A-Z0-9]{4}-[A-Z0-9]{4}$/)
  })

  it('keeps scenarios and limits below Regeln', async () => {
    const { wrapper, router } = await mountApp('/behaviour?view=scenarios')
    expect(router.currentRoute.value.path).toBe('/settings/rules/behaviour')
    expect(wrapper.get('h1').text()).toBe('Szenarien und Limits')
    await waitFor(() => all('[data-testid="scenario-row"]').length === 5, 5000)
    expect(byTestId('tab-hits')).toBeNull()
    expect(byTestId('tab-limits')).not.toBeNull()
  })
})

describe('Adresse sperren (D88)', () => {
  it('blocks an address by hand, asks before a shared one, and lists it', async () => {
    await mountApp('/blocks')
    await waitFor(() => !!byTestId('block-add'), 5000)
    await click(byTestId('block-add'))
    await waitFor(() => !!byTestId('block-dialog'))
    // Nothing typed: the form says so and sends nothing.
    await click(byTestId('block-submit'))
    expect(bodyText()).toContain('Bitte ausfüllen.')
    await type(byTestId('block-address'), '198.51.100.0/24')
    await type(byTestId('block-reason'), 'Scanner')
    await click(byTestId('block-submit'))
    expect(bodyText()).toContain('keine einzelne IP-Adresse')
    // A shared address needs the confirmation.
    await type(byTestId('block-address'), '198.51.100.23')
    await click(byTestId('block-submit'))
    await waitFor(() => !!byTestId('block-shared'))
    expect(byTestId<HTMLButtonElement>('block-submit')!.disabled).toBe(true)
    await click(byTestId('block-shared-ok'))
    await click(byTestId('block-submit'))
    await waitFor(() => mock.state.manualBlocks.length === 1)
    expect(mock.state.manualBlocks[0]).toMatchObject({ client: '198.51.100.23', source: 'dashboard', duration_s: 86400 })
    await waitFor(() => !!document.querySelector('[data-client="198.51.100.23"]'), 4000)
    expect(document.querySelector('[data-client="198.51.100.23"]')!.textContent).toContain('Im Dashboard gesperrt')
  })

  it('blocks the client of an event with one click and takes it back from the toast', async () => {
    const own = new Set(mock.state.allowlist.map(e => e.ip))
    const ip = (x: (typeof mock.state.events)[number]) => String(x.detail.data?.client?.ip ?? '')
    const e = mock.state.events.find(x => x.summary.type.startsWith('schild.request.') && !x.detail.data?.incident
      && ip(x) && !own.has(ip(x)) && !ip(x).startsWith('198.51.100.2'))!
    expect(e).toBeTruthy()
    await mountApp(`/events?event=${e.summary.id}`)
    await waitFor(() => !!byTestId('event-block-ip'), 5000)
    await click(byTestId('event-block-ip'))
    await waitFor(() => mock.state.manualBlocks.length === 1)
    // 7 days for a data-centre address, 24 hours for every other one; the button says which.
    const hosting = e.detail.data?.client?.geo?.net_class === 'hosting'
    expect(mock.state.manualBlocks[0]).toMatchObject({ source: 'dashboard', duration_s: hosting ? 604800 : 86400 })
    expect(byTestId('block-dialog')).toBeNull()
    const inc = mock.state.incidents.get(mock.state.manualBlocks[0]!.incident)!
    expect(inc.reason).toContain(`Ereignis ${e.summary.id}`)
    const said = hosting ? 'für 7 Tage gesperrt' : 'für 24 Stunden gesperrt'
    await waitFor(() => !!toastAction(said))
    await click(toastAction(said))
    await waitFor(() => mock.state.incidents.get(inc.incident)!.status === 'unblocked')
  })

  it('opens the dialog with the reason of the event for another duration from the menu', async () => {
    const e = mock.state.events.find(x => x.summary.type.startsWith('schild.request.') && !x.detail.data?.incident && x.detail.data?.client?.ip)!
    await mountApp(`/events?event=${e.summary.id}`)
    await waitFor(() => !!byTestId('event-more'), 5000)
    // The rare actions sit in the menu: another duration and Eigene IPs.
    await click(byTestId('event-more'))
    await waitFor(() => !!byTestId('event-block-other'))
    expect(byTestId('event-allow-ip')).not.toBeNull()
    await click(byTestId('event-block-other'))
    await waitFor(() => !!byTestId('block-dialog'))
    expect(byTestId<HTMLInputElement>('block-reason')!.value).toContain(`Ereignis ${e.summary.id}`)
    expect(mock.state.manualBlocks).toHaveLength(0)
  })

  it('blocks from a row of Ereignisse without opening the event', async () => {
    const own = new Set(mock.state.allowlist.map(e => e.ip))
    const { router } = await mountApp('/events')
    await waitFor(() => !!byTestId('row-more'), 5000)
    const row = [...document.querySelectorAll<HTMLElement>('tbody tr[data-row]')].find((r) => {
      const ip = r.querySelector('.font-mono')?.textContent?.trim() ?? ''
      return r.querySelector('[data-testid="row-more"]') && !own.has(ip) && !ip.startsWith('198.51.100.2')
    })!
    expect(row).toBeTruthy()
    await click(row.querySelector<HTMLElement>('[data-testid="row-more"]'))
    await waitFor(() => !!byTestId('row-block-ip'))
    await click(byTestId('row-block-ip'))
    await waitFor(() => mock.state.manualBlocks.length === 1, 4000)
    expect(router.currentRoute.value.query.event).toBeUndefined()
    expect(mock.state.incidents.get(mock.state.manualBlocks[0]!.incident)!.reason).toMatch(/Ereignis [0-9a-f-]{36}: /)
  })

  it('refuses an own address in the words of the gateway', async () => {
    const own = mock.state.allowlist.find(e => e.ip && !e.ip.includes('/'))?.ip
    expect(own).toBeTruthy()
    await mountApp('/blocks')
    await waitFor(() => !!byTestId('block-add'), 5000)
    await click(byTestId('block-add'))
    await waitFor(() => !!byTestId('block-dialog'))
    await type(byTestId('block-address'), own!)
    await type(byTestId('block-reason'), 'Test')
    await click(byTestId('block-submit'))
    await waitFor(() => !!byTestId('block-refused'))
    expect(byTestId('block-refused')!.textContent).toContain('Eigene IPs')
    expect(mock.state.manualBlocks).toHaveLength(0)
  })
})
