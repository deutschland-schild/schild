import type { DistributedSettings, Wave } from '../src/api/distributed'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { formatClock } from '../src/lib/behaviour'
import {
  detectorThresholdsText,
  effectiveNote,
  explainWave,
  formatDay,
  observeReasonText,
  remainingText,
  responseText,
  shortSig,
  stoppedText,
  waveOutcome,
  wavesCountText,
} from '../src/lib/distributed'
import settingsFixture from '../../../../contracts/api/fixtures/client/getDistributedSettings.json'
import wavesFixture from '../../../../contracts/api/fixtures/client/listWaves.json'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, type, waitFor } from './helpers'

const waves = wavesFixture.items as Wave[]
const settings = settingsFixture as DistributedSettings
const byDetector = (d: string) => waves.find(w => w.detector === d)!
const base: Wave = { id: 'x', time: '2026-10-28T09:00:00Z', detector: 'inconsistency', route: '/wp-login.php', senders: 1, count: 1, threshold: 1, window_s: 60, response: 'route_tighten', mode: 'respond', action: 'respond', active: false }

describe('wave explanations', () => {
  it('explains every detector in one sentence, without addresses or user names', () => {
    expect(explainWave(byDetector('fingerprint_cluster'))).toBe('Verteilte Login-Versuche auf wp-login.php: 380 Adressen, gleicher Fingerabdruck, 41 verschiedene Browser-Angaben')
    expect(explainWave(byDetector('route_wave'))).toBe('Ungewöhnlich viele Fehlversuche an /user/login: 145 in 1 Minute, sonst etwa 2,5, von 212 Adressen')
    expect(explainWave(byDetector('account_wave'))).toBe('Ein Konto wird von 57 Adressen aus ausprobiert: 64 Fehlversuche in 10 Minuten an wp-login.php')
    expect(explainWave(byDetector('shape_wave'))).toBe('Dieselbe auffällige Anfrage von 120 Adressen in 1 Minute an /wp-json/gallery/v1/upload')
    expect(explainWave({ ...base, senders: 30, count: 25, window_s: 300 }))
      .toBe('Anfragen, deren Browser-Angaben nicht zusammenpassen: 25 in 5 Minuten an wp-login.php, von 30 Adressen')
  })

  it('uses singular forms and leaves out what the wave does not carry', () => {
    expect(explainWave({ ...base, detector: 'fingerprint_cluster', route: '/api/search', senders: 1, user_agents: 1 }))
      .toBe('Verteilte Anfragen an /api/search: 1 Adresse, gleicher Fingerabdruck, 1 Browser-Angabe')
    expect(explainWave({ ...base, detector: 'fingerprint_cluster', route: '/api/search', senders: 2 }))
      .toBe('Verteilte Anfragen an /api/search: 2 Adressen, gleicher Fingerabdruck')
    expect(explainWave({ ...base, detector: 'route_wave', route: '/user/login', count: 40, senders: 1 }))
      .toBe('Ungewöhnlich viele Fehlversuche an /user/login: 40 in 1 Minute, von 1 Adresse')
    expect(explainWave({ ...base, detector: 'account_wave', count: 1, senders: 1, window_s: 600 }))
      .toBe('Ein Konto wird von 1 Adresse aus ausprobiert: 1 Fehlversuch in 10 Minuten an wp-login.php')
  })

  it('describes each response with the settings', () => {
    expect(responseText(byDetector('fingerprint_cluster'), settings))
      .toBe(`Anmeldung bis ${formatClock('2026-10-28T09:32:00Z')} nur eingeschränkt: ohne Sitzungs-Cookie höchstens 10 Versuche pro Minute für alle zusammen`)
    expect(responseText({ ...base, route: '/checkout/pay', until: null }, { route_tighten: { minutes: 20, max_minutes: 120, limit_per_minute: 1 } }))
      .toBe('Zugriff auf /checkout/pay nur eingeschränkt: ohne Sitzungs-Cookie höchstens 1 Anfrage pro Minute für alle zusammen')
    expect(responseText(byDetector('account_wave'), settings))
      .toBe('Betroffene Konten: kurze Wartezeit vor dem nächsten Versuch (5 s bis höchstens 60 s), nie gesperrt; wer eingeloggt war, kommt durch')
    expect(responseText(byDetector('shape_wave'), settings))
      .toBe(`Diese Anfrageform wird bis ${formatClock('2026-10-27T19:50:00Z')} von jeder Adresse abgelehnt`)
  })

  it('says whether a response runs, ran out, was ended or was only a dry run', () => {
    expect(waveOutcome(byDetector('fingerprint_cluster'))).toMatchObject({ label: `Läuft bis ${formatClock('2026-10-28T09:32:00Z')}`, reason: null })
    expect(waveOutcome(byDetector('account_wave')).label).toBe('Abgelaufen')
    expect(waveOutcome(byDetector('shape_wave')).label).toBe('Vorzeitig beendet')
    const learning = waveOutcome(byDetector('route_wave'), settings.learning_until)
    expect(learning.label).toBe('Erkannt (Probelauf)')
    expect(learning.reason).toBe(`Schild lernt noch den Normalzustand dieser Website (bis ${formatDay('2026-10-14T10:00:00Z')})`)
    expect(observeReasonText('learning', null)).toBe('Schild lernt noch den Normalzustand dieser Website')
    expect(observeReasonText('gateway_observe')).toBe('Das Gateway läuft im Testprofil')
    expect(waveOutcome({ ...base, action: 'observe', reason: 'gateway_observe' }).reason).toBe('Das Gateway läuft im Testprofil')
  })

  it('counts remaining time and stopped requests with plurals', () => {
    const now = Date.parse('2026-10-28T09:20:00Z')
    expect(remainingText('2026-10-28T09:32:00Z', now)).toBe('noch 12 Minuten')
    expect(remainingText('2026-10-28T09:21:00Z', now)).toBe('noch 1 Minute')
    expect(remainingText('2026-10-28T10:25:00Z', now)).toBe('noch 1 Stunde und 5 Minuten')
    expect(remainingText('2026-10-28T11:20:00Z', now)).toBe('noch 2 Stunden')
    expect(remainingText('2026-10-28T09:20:10Z', now)).toBe('endet gleich')
    expect(stoppedText(1830)).toBe('1.830 Anfragen gebremst')
    expect(stoppedText(1)).toBe('1 Anfrage gebremst')
    expect(stoppedText(0)).toBe('keine Anfrage gebremst')
    expect(wavesCountText(0)).toBe('keine Welle')
    expect(wavesCountText(1)).toBe('1 Welle')
    expect(wavesCountText(3)).toBe('3 Wellen')
    expect(shortSig('sha256:abababababababababab')).toBe('abababababab')
  })

  it('puts detector thresholds and the effective mode into words', () => {
    const t = (id: string) => settings.detectors.find(d => d.id === id)!
    expect(detectorThresholdsText('route_wave', t('route_wave').thresholds)).toBe('mindestens 30 Fehlversuche in 1 Minute und mindestens das 5-Fache des Üblichen')
    expect(detectorThresholdsText('account_wave', t('account_wave').thresholds)).toBe('mindestens 10 Fehlversuche für ein Konto in 10 Minuten, von verschiedenen Adressen')
    expect(detectorThresholdsText('shape_wave', t('shape_wave').thresholds)).toBe('dieselbe Anfrage von mindestens 20 Adressen in 1 Minute')
    expect(detectorThresholdsText('fingerprint_cluster', t('fingerprint_cluster').thresholds)).toBe('ein Fingerabdruck an mindestens 20 Adressen in 5 Minuten')
    expect(detectorThresholdsText('inconsistency', { count: 1, window_s: 300 })).toBe('mindestens 1 widersprüchliche Anfrage in 5 Minuten')
    expect(effectiveNote({ mode: 'respond', effective_mode: 'respond' }, settings)).toBeNull()
    expect(effectiveNote({ mode: 'respond', effective_mode: 'observe' }, { gateway_observe: true, learning_until: null })).toContain('Testprofil')
    expect(effectiveNote({ mode: 'respond', effective_mode: 'observe' }, { gateway_observe: false, learning_until: '2026-11-03T10:00:00Z' }))
      .toBe(`Reagieren ist eingestellt. Schild lernt noch bis ${formatDay('2026-11-03T10:00:00Z')} den Normalzustand dieser Website, darum beobachtet diese Erkennung bis dahin nur.`)
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
const running = waves.find(w => w.active)!

describe('mock backend: waves', () => {
  const h = () => ({ 'Content-Type': 'application/json', 'X-CSRF-Token': mock.state.session.csrf_token! })

  it('filters waves and answers 409 for a wave that already ended', async () => {
    const active = await (await fetch(`${BASE}/distributed/waves?active=true`)).json() as { items: Wave[] }
    expect(active.items.map(w => w.id)).toEqual([running.id])
    const byDet = await (await fetch(`${BASE}/distributed/waves?detector=shape_wave`)).json() as { items: Wave[] }
    expect(byDet.items.map(w => w.detector)).toEqual(['shape_wave'])
    let res = await fetch(`${BASE}/distributed/waves/${running.id}/end`, { method: 'POST', headers: h() })
    expect(await res.json()).toMatchObject({ active: false, end_reason: 'operator' })
    res = await fetch(`${BASE}/distributed/waves/${running.id}/end`, { method: 'POST', headers: h() })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('not_active')
  })

  it('switches detectors and rejects unknown modes', async () => {
    let res = await fetch(`${BASE}/distributed/settings`, { method: 'PATCH', headers: h(), body: JSON.stringify({ detectors: { shape_wave: 'block' } }) })
    expect(res.status).toBe(400)
    res = await fetch(`${BASE}/distributed/settings`, { method: 'PATCH', headers: h(), body: JSON.stringify({ detectors: { shape_wave: 'respond' } }) })
    const s = await res.json() as DistributedSettings
    expect(s.detectors.find(d => d.id === 'shape_wave')).toMatchObject({ mode: 'respond', effective_mode: 'respond' })
  })

  it('observes only while the gateway observes', async () => {
    mock.reset({ scenario: 'observe' })
    const s = await (await fetch(`${BASE}/distributed/settings`)).json() as DistributedSettings
    expect(s.gateway_observe).toBe(true)
    expect(s.detectors.find(d => d.id === 'route_wave')!.effective_mode).toBe('observe')
    const page = await (await fetch(`${BASE}/distributed/waves`)).json() as { items: Wave[] }
    expect(page.items.every(w => w.action === 'observe' && !w.active)).toBe(true)
  })
})

describe('Verhalten & Limits: Wellen', () => {
  it('lists waves in plain German with response, remaining time and reasons', async () => {
    const { wrapper } = await mountApp('/behaviour?view=waves')
    // The waves stand next to their detectors below Regeln (D97); the old address leads there.
    expect(wrapper.get('h1').text()).toBe('Szenarien und Limits')
    await waitFor(() => all('[data-testid="wave-item"]').length === waves.length)
    const texts = all('[data-testid="wave-explain"]').map(e => e.textContent)
    expect(texts).toContain('Verteilte Login-Versuche auf wp-login.php: 380 Adressen, gleicher Fingerabdruck, 41 verschiedene Browser-Angaben')
    expect(texts).toContain('Ein Konto wird von 57 Adressen aus ausprobiert: 64 Fehlversuche in 10 Minuten an wp-login.php')
    await waitFor(() => bodyText().includes('höchstens 10 Versuche pro Minute für alle zusammen'))
    expect(byTestId('wave-remaining')!.textContent).toMatch(/^noch 1[12] Minuten$/)
    expect(bodyText()).toContain('Erkannt (Probelauf)')
    expect(bodyText()).toContain('Schild lernt noch den Normalzustand dieser Website (bis ')
    expect(bodyText()).toContain('Vorzeitig beendet')
    expect(bodyText()).toContain('Abgelaufen')
    await waitFor(() => all('[data-testid="detector-row"]').length === 5)
    expect(bodyText()).not.toMatch(/geschützt|anonym|sicher\b/)
    await click(byTestId('waves-filter-running'))
    await waitFor(() => all('[data-testid="wave-item"]').length === 1)
  })

  it('ends a running response early after asking', async () => {
    const { router } = await mountApp('/behaviour?view=waves')
    await waitFor(() => all('[data-testid="wave-item"]').length > 0)
    await click(all('[data-testid="wave-item"]')[0]!)
    expect(router.currentRoute.value.query.wave).toBe(running.id)
    await waitFor(() => !!byTestId('wave-end'))
    expect(byTestId('wave-fingerprint')!.textContent).toContain('3f9a0c11b2d4')
    expect(byTestId('wave-second-factor')!.textContent).toContain('Passkeys oder ein zweiter Faktor')
    expect(all('[data-testid="wave-requests"] li')).toHaveLength(4)
    expect(bodyText()).toContain('sperrt Schild keine Adressen')
    await click(byTestId('wave-end'))
    await waitFor(() => !!byTestId('confirm-submit'))
    expect(bodyText()).toContain('Reaktion vorzeitig beenden?')
    expect(mock.state.behaviour.distributed.waves[0]!.active).toBe(true)
    await click(byTestId('confirm-submit'))
    await waitFor(() => bodyText().includes('Reaktion beendet'))
    expect(mock.state.behaviour.distributed.waves[0]).toMatchObject({ active: false, end_reason: 'operator' })
    await waitFor(() => byTestId('wave-end') === null)
  })

  it('asks before switching a detector, without a password', async () => {
    const { wrapper } = await mountApp('/behaviour?view=detectors')
    await waitFor(() => all('[data-testid="detector-row"]').length === 5)
    expect(wrapper.get('h1').text()).toBe('Szenarien und Limits')
    expect(byTestId('fingerprint-kind')!.textContent).toContain('Header-Merkmale')
    expect(bodyText()).toContain('mindestens 30 Fehlversuche in 1 Minute und mindestens das 5-Fache des Üblichen')
    expect(byTestId('detectors-learning')).toBeNull() // learning ended (fixture)
    await click(byTestId('detector-shape_wave-respond'))
    await waitFor(() => !!byTestId('confirm-submit'))
    expect(bodyText()).toContain('„Gleiche Anfrage, viele Adressen“ auf „Reagieren“ stellen?')
    expect(mock.state.behaviour.distributed.settings.detectors.find(d => d.id === 'shape_wave')!.mode).toBe('observe')
    await click(byTestId('confirm-submit'))
    await waitFor(() => mock.state.behaviour.distributed.settings.detectors.find(d => d.id === 'shape_wave')!.mode === 'respond')
  })

  it('shows an empty list on a fresh install, with every detector still learning', async () => {
    mock.reset({ scenario: 'empty' })
    const { router } = await mountApp('/blocks?view=waves')
    expect(router.currentRoute.value.fullPath).toBe('/settings/rules/behaviour?view=detectors')
    await waitFor(() => !!byTestId('waves-empty'))
    await waitFor(() => all('[data-testid="detector-effective"]').length === 3)
  })

  it('sets the threshold of a detector and puts the built-in value back (D97)', async () => {
    const route = () => mock.state.behaviour.distributed.settings.detectors.find(d => d.id === 'route_wave')!
    const meta = () => document.querySelector('[data-detector="route_wave"] [data-testid="detector-meta"]')!.textContent
    await mountApp('/behaviour?view=detectors')
    await waitFor(() => all('[data-testid="detector-row"]').length === 5)
    await click(byTestId('detector-route_wave-thresholds'))
    await waitFor(() => !!byTestId('detector-thresholds-form'))
    expect(byTestId('detector-thresholds-defaults')!.textContent).toContain('Ab Werk: mindestens 30 Fehlversuche in 1 Minute und mindestens das 5-Fache des Üblichen')
    expect(byTestId('detector-thresholds-reset')).toBeNull()
    expect((byTestId('detector-thresholds-factor') as HTMLInputElement).value).toBe('5')
    await type(byTestId('detector-thresholds-count') as HTMLInputElement, '2')
    await click(byTestId('detector-thresholds-submit'))
    expect(bodyText()).toContain('Eine ganze Zahl zwischen 3 und 100.000.')
    expect(route().thresholds.count).toBe(30)
    await type(byTestId('detector-thresholds-count') as HTMLInputElement, '50')
    await type(byTestId('detector-thresholds-window-n') as HTMLInputElement, '2')
    await click(byTestId('detector-thresholds-submit'))
    await waitFor(() => route().thresholds.count === 50)
    expect(route().thresholds.window_s).toBe(120)
    await waitFor(() => !!meta()?.includes('mindestens 50 Fehlversuche in 2 Minuten und mindestens das 5-Fache des Üblichen (angepasst)'))

    await click(byTestId('detector-route_wave-thresholds'))
    await waitFor(() => !!byTestId('detector-thresholds-reset'))
    await click(byTestId('detector-thresholds-reset'))
    await click(byTestId('detector-thresholds-submit'))
    await waitFor(() => route().thresholds.count === 30)
    await waitFor(() => !meta()?.includes('angepasst'))
  })
})
