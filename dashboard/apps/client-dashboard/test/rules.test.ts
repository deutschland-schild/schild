import type { Mode, RuleOrigin, RuleRepository, RuleRepositoryState } from '../src/api/types'
import type { CrowdsecRepository } from '../src/lib/crowdsec'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { HUB_LABEL, hubBaseId, hubRuleText, isHubId, skipText, updateText } from '../src/lib/crowdsec'
import { buildNav } from '../src/lib/nav'
import { decisionText, effectText, exceptionField, exceptionTarget, exceptionTargetOf, ownerText, parseExceptionRules, parseExceptionTarget, REPOSITORIES, REPOSITORY_STATES, RULE_STATUS, ruleFileName, stateExplain } from '../src/lib/rules'
import { annotationLabel, annotationLink } from '../src/lib/websites'
import { repositoryEffect, ruleEffect } from '../src/mock/rules'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, settle, type, waitFor } from './helpers'

const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
})
afterAll(() => mock.server.close())

const BASE = 'http://dashboard.schild.test/api/v0'
const repos = () => mock.state.ruleRepos.repositories
async function select(el: Element | null, value: string) {
  const s = el as HTMLSelectElement
  s.value = value
  s.dispatchEvent(new Event('change', { bubbles: true }))
  await settle()
}
const rule = (repository: string, id: string) => mock.state.ruleRepos.rules.find(r => r.repository === repository && r.id === id)!

function segment(label: string): HTMLElement {
  const el = [...byTestId('repository-switch')!.querySelectorAll<HTMLElement>('[role="radio"]')].find(x => x.textContent?.includes(label))
  if (!el) throw new Error(`no segment ${label}`)
  return el
}

describe('rule copy', () => {
  it('keeps the required wording', () => {
    const crowdsec: CrowdsecRepository = { update_state: 'unreachable', auto_update: true, settling_s: 0, set_source: 'image', skipped: [] }
    const all = [
      HUB_LABEL,
      ...Object.values(REPOSITORIES).flatMap(r => [r.name, r.lead]),
      ...Object.values(REPOSITORY_STATES).map(s => s.explain),
      ...Object.values(RULE_STATUS).map(s => s.explain),
      effectText({ id: 'crs', state: 'block', effect: 'would_block', limited_by: 'gateway_observe' }),
      updateText(crowdsec),
      skipText('raw_seclang'),
    ].join(' ')
    expect(HUB_LABEL).toBe('Regel aus dem CrowdSec Hub, MIT')
    expect(all).not.toMatch(/anonym/i)
    expect(all).not.toMatch(/\b(geschützt|sicher|gefährlich|dringend)\b/i)
    expect(all).not.toMatch(/\bSie\b(?! sperren| erkennen)|\bIhr(e|en)?\b/)
    expect(all).not.toMatch(/Freigabe|freigeben|Modus/)
  })

  it('finds the base id of any hub group', () => {
    expect(isHubId('62846312')).toBe(true)
    expect(isHubId(942100)).toBe(false)
    expect(hubBaseId(62846319)).toBe(62846312)
  })

  it('says calmly that the running rules stay', () => {
    const base: Omit<CrowdsecRepository, 'update_state'> = { auto_update: true, settling_s: 0, set_source: 'stored', skipped: [] }
    expect(updateText({ ...base, update_state: 'unreachable' })).toContain('laufen weiter')
    expect(updateText({ ...base, update_state: 'refused', last_refusal: { at: '2026-10-30T08:00:00Z', code: 'set_too_costly' } })).toContain('gebremst')
  })

  it('names who set a switch and who decided on a rule', () => {
    expect(ownerText({ state_source: 'agent', state_set_by: { token_id: 'tok_000000000000', label: 'coding-agent' } })).toContain('Agent „coding-agent“')
    expect(ownerText({ state_source: 'config' })).toBeNull()
    expect(decisionText({ kind: 'disabled', by: 'config' })).toBe('Ausgeschaltet in schild.yaml')
  })

  it('says how the test profile holds Sperren back and how updates settle', () => {
    expect(effectText({ id: 'crowdsec', state: 'block', effect: 'would_block', limited_by: 'gateway_observe' })).toContain('Im Testprofil sperrt Schild nichts')
    expect(effectText({ id: 'crowdsec', state: 'block', effect: 'block', crowdsec: { settling_s: 86400 } as RuleRepository['crowdsec'] })).toContain('24 Stunden lang nur')
    expect(effectText({ id: 'crowdsec', state: 'detect', effect: 'detect', crowdsec: { settling_s: 86400 } as RuleRepository['crowdsec'] })).toBeNull()
    expect(effectText({ id: 'crs', state: 'block', effect: 'block' })).toBeNull()
    expect(stateExplain({ id: 'crs', state: 'block', crs: { paranoia_level: 1, inbound_anomaly_threshold: 5, config_paranoia_level: 1, config_inbound_anomaly_threshold: 5, livewire_exception: false, version: '4.30.0' } })).toContain('Ab 5 Punkten')
  })

  it('labels and links the annotation of a switch', () => {
    const a = { t: '2026-10-30T08:00:00Z', kind: 'rule_repository_changed', repository: 'crowdsec', state_to: 'block', actor: 'agent', token_label: 'coding-agent' } as const
    expect(annotationLabel(a)).toBe('CrowdSec Hub: Sperren, über Agent coding-agent')
    expect(annotationLabel({ ...a, actor: 'dashboard', token_label: undefined })).toBe('CrowdSec Hub: Sperren')
    expect(annotationLink(a)).toBe('/settings/rules/crowdsec')
  })

})

describe('the mock computes status and effect like contract/rules', () => {
  const files = import.meta.glob<{ default: { input_decoded: Record<string, never>, expect: { result: unknown } } }>('../../../../contracts/vectors/rule-effect/valid/*.json', { eager: true })
  const vectors = Object.entries(files).map(([path, m]) => ({ f: path.split('/').pop()!, v: m.default }))
  interface In { op: string, mode: Mode, state: RuleRepositoryState, origin: RuleOrigin, now: number, disabled?: boolean, disabled_by?: 'config' | 'dashboard' | 'agent', settling_until?: number }
  for (const { f, v } of vectors.filter(x => x.v.input_decoded.op === 'effect')) {
    it(f, () => {
      const i = v.input_decoded as unknown as In
      const got = ruleEffect({
        origin: i.origin,
        version: '1',
        disabled: i.disabled ? { by: i.disabled_by ?? 'dashboard' } : undefined,
        settlingUntil: i.settling_until ? i.settling_until * 1000 : undefined,
      }, i.mode, i.state, i.now * 1000)
      expect(got).toEqual(v.expect.result)
    })
  }
  for (const { f, v } of vectors.filter(x => x.v.input_decoded.op === 'repository')) {
    it(f, () => expect(repositoryEffect(v.input_decoded.state, v.input_decoded.mode)).toEqual(v.expect.result))
  }
})

describe('Regeln in the navigation', () => {
  it('shows once under Schutz, with the three sources below it on a rule page', () => {
    const items = buildNav({ site: '' }).flatMap(g => g.items)
    expect(items.filter(i => i.to === '/settings/rules')).toHaveLength(1)
    expect(items.find(i => i.to === '/settings/rules')!.children).toBeUndefined()
    const open = buildNav({ site: '', path: '/settings/rules/crowdsec' }).flatMap(g => g.items).find(i => i.to === '/settings/rules')!
    expect(open.children!.map(c => [c.to, c.label])).toEqual([
      ['/settings/rules/crs', 'OWASP CRS'],
      ['/settings/rules/crowdsec', 'CrowdSec Hub'],
      ['/settings/rules/local', 'Eigene & Ausnahmen'],
      ['/settings/rules/behaviour', 'Szenarien und Limits'],
    ])
  })
})

describe('the overview of the sources', () => {
  it('lists the three sources with what they do', async () => {
    const { wrapper } = await mountApp('/settings/rules')
    await waitFor(() => !!byTestId('rules-local'))
    expect(byTestId('rules-crs')!.textContent).toContain('Sperrt')
    expect(byTestId('rules-crowdsec')!.textContent).toContain('CrowdSec Hub')
    expect(byTestId('rules-pending')).toBeNull()
    wrapper.unmount()
  })
})

describe('the exceptions in force (D83)', () => {
  it('names the field of a target', () => {
    expect(exceptionField('ARGS:json.components.*.updates.body')).toEqual({ kind: 'Feld', name: 'components.*.updates.body' })
    expect(exceptionField('REQUEST_COOKIES:session')).toEqual({ kind: 'Cookie', name: 'session' })
  })

  it('shows them under Eigene Regeln, with reason, field and the rules left out', async () => {
    const { wrapper } = await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => !!byTestId('rule-exception'))
    const card = byTestId('rule-exceptions')!
    expect(card.textContent).toContain('/livewire/update')
    expect(card.textContent).toContain('components.*.updates.body')
    expect(card.textContent).toContain('2 Regeln ausgenommen')
    expect(card.textContent).toContain('maintenance-agent')
    expect(byTestId('rule-exception-reason')!.textContent).toContain(mock.state.ruleRepos.exceptions[0]!.reason)
    const links = [...card.querySelectorAll('a')].map(a => a.getAttribute('href'))
    expect(links.some(h => h?.includes('/settings/rules/crs') && h.includes('932160'))).toBe(true)
    wrapper.unmount()
  })

  it('says so under Eigene Regeln when there is none, and counts them on the overview', async () => {
    mock.state.ruleRepos.exceptions = []
    const local = await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => !!byTestId('rule-exceptions-empty'))
    local.wrapper.unmount()
    cleanup()
    document.body.innerHTML = ''
    const { wrapper } = await mountApp('/settings/rules')
    await waitFor(() => !!byTestId('rules-local-facts')?.textContent?.includes('0 Ausnahmen'))
    expect(byTestId('rule-exceptions')).toBeNull()
    expect(byTestId('rules-local')!.textContent).toContain('Eigene Regeln und Ausnahmen')
    wrapper.unmount()
  })

  it('lists on a repository only its own', async () => {
    const { wrapper } = await mountApp('/settings/rules/crowdsec')
    await waitFor(() => !!byTestId('repository-switch'))
    expect(byTestId('rule-exception')).toBeNull()
    wrapper.unmount()
  })
})

describe('exceptions set and removed in the dashboard (D84)', () => {
  it('builds and reads a target', () => {
    expect(exceptionTarget('json', ' updates.body ')).toBe('ARGS:json.updates.body')
    expect(exceptionTarget('header', 'X-Signature')).toBe('REQUEST_HEADERS:X-Signature')
    expect(parseExceptionTarget('ARGS:json.updates.body')).toEqual({ kind: 'json', name: 'updates.body' })
    expect(parseExceptionTarget('ARGS:message')).toEqual({ kind: 'form', name: 'message' })
    expect(parseExceptionTarget('REQUEST_COOKIES:session')).toEqual({ kind: 'cookie', name: 'session' })
    expect(parseExceptionTarget('')).toEqual({ kind: 'form', name: '' })
    expect(exceptionTargetOf('ARGS_POST:message')).toBe('ARGS:message')
    expect(exceptionTargetOf('REQUEST_HEADERS:User-Agent')).toBe('REQUEST_HEADERS:User-Agent')
    expect(exceptionTargetOf('REQUEST_URI')).toBe('')
    expect(parseExceptionRules('942100, 942110  942100;941100')).toEqual(['942100', '942110', '941100'])
  })

  it('has a tab each: the own rules first, the exceptions with their count behind the second', async () => {
    const { wrapper } = await mountApp('/settings/rules/local')
    await waitFor(() => !!byTestId('repository-local') && !!byTestId('rule-table'))
    expect(byTestId('rule-exceptions')).toBeNull()
    const tabs = [...document.querySelectorAll('[role="tab"]')].map(t => t.textContent!.replace(/\s+/g, ' ').trim())
    await waitFor(() => byTestId('tab-exceptions')!.textContent!.includes(`(${mock.state.ruleRepos.exceptions.length})`))
    expect(tabs[0]).toBe('Eigene Regeln')
    expect(tabs[1]).toContain('Ausnahmen')
    wrapper.unmount()
    cleanup()
    document.body.innerHTML = ''
    const again = await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => !!byTestId('rule-exception'))
    expect(byTestId('rule-table')).toBeNull()
    expect(byTestId('repository-local')).toBeNull()
    again.wrapper.unmount()
  })

  it('sets one with the form: checks the fields first, then it is in force and in the list', async () => {
    mock.state.ruleRepos.exceptions = []
    const site = mock.state.monitoring.sites[0]!.id
    const { wrapper } = await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => !!byTestId('rule-exception-add'))
    await click(byTestId('rule-exception-add'))
    await waitFor(() => !!byTestId('exception-dialog'))
    await click(byTestId('exception-submit'))
    await waitFor(() => document.querySelectorAll('[data-testid="exception-dialog"] [role="alert"]').length >= 4)
    expect(mock.state.ruleRepos.exceptions).toHaveLength(0)
    await select(byTestId('exception-website'), site)
    await type(byTestId('exception-path'), '/kontakt')
    await type(byTestId('exception-name'), 'nachricht')
    await type(byTestId('exception-rules'), '942100, 942100')
    await type(byTestId('exception-reason'), 'Das Kontaktformular nimmt freien Text an')
    await click(byTestId('exception-submit'))
    await waitFor(() => mock.state.ruleRepos.exceptions.length === 1)
    expect(mock.state.ruleRepos.exceptions[0]).toMatchObject({ website: site, path: '/kontakt', target: 'ARGS:nachricht', repository: 'crs', rules: ['942100'], set_by: 'dashboard', token_id: '' })
    await waitFor(() => !!byTestId('rule-exception') && !byTestId('exception-dialog'))
    expect(byTestId('rule-exception')!.textContent).toContain('im Dashboard gesetzt')
    expect(byTestId('rule-exception-reason')!.textContent).toContain('Kontaktformular')
    wrapper.unmount()
  })

  it('shows what the gateway refuses in its words and keeps the form open', async () => {
    const site = mock.state.monitoring.sites[0]!.id
    const { wrapper } = await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => !!byTestId('rule-exception-add'))
    await click(byTestId('rule-exception-add'))
    await waitFor(() => !!byTestId('exception-dialog'))
    await select(byTestId('exception-website'), site)
    await type(byTestId('exception-path'), '/kontakt')
    await type(byTestId('exception-name'), 'nachricht')
    await type(byTestId('exception-rules'), '999999')
    await type(byTestId('exception-reason'), 'Test')
    const before = mock.state.ruleRepos.exceptions.length
    await click(byTestId('exception-submit'))
    await waitFor(() => !!byTestId('exception-refused'))
    expect(byTestId('exception-refused')!.textContent).toContain('läuft auf diesem Gateway nicht')
    expect(mock.state.ruleRepos.exceptions).toHaveLength(before)
    wrapper.unmount()
  })

  it('removes one after a confirmation, whoever set it', async () => {
    const { wrapper } = await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => !!byTestId('rule-exception-remove'))
    const before = mock.state.ruleRepos.exceptions.length
    const first = mock.state.ruleRepos.exceptions[0]!
    await click(byTestId('rule-exception-remove'))
    await waitFor(() => !!byTestId('confirm-submit'))
    expect(bodyText()).toContain('Ausnahme entfernen?')
    expect(mock.state.ruleRepos.exceptions).toHaveLength(before)
    await click(byTestId('confirm-submit'))
    await waitFor(() => mock.state.ruleRepos.exceptions.length === before - 1)
    expect(mock.state.ruleRepos.exceptions.some(x => x.id === first.id)).toBe(false)
    await waitFor(() => !document.querySelector(`[data-exception="${first.id}"]`))
    wrapper.unmount()
  })

  it('shows exceptions for the same field as one entry, the rules folded by kind, and removes all parts at once', async () => {
    // What an agent sets for a free-text field: more rules than one exception holds (16), so several parts.
    const base = mock.state.ruleRepos.exceptions[0]!
    const ids = [930100, 930110, 930120, 932120, 932125, 932130, 932140, 932160, 932170, 932171, 932175, 932180, 933100, 933110, 941100, 941110, 941120, 942100, 942140, 942151].map(String)
    const part = (n: number, rules: string[], reason: string) => ({ ...base, id: 1900100 + n, path: '/converter', target: 'ARGS:json.text', rules, reason, created: `2026-11-02T12:40:2${n}Z` })
    mock.state.ruleRepos.exceptions = [base, part(1, ids.slice(0, 16), 'Freitext mit Code, Teil 1'), part(2, ids.slice(16), 'Freitext mit Code, Teil 2')]
    const { wrapper } = await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => document.querySelectorAll('[data-testid="rule-exception"]').length === 2)
    expect(byTestId('tab-exceptions')!.textContent).toContain('(2)')
    const entry = document.querySelector<HTMLElement>('[data-exception="1900101"]')!
    expect(entry.textContent).toContain('20 Regeln ausgenommen')
    expect(entry.textContent).toContain('Freitext mit Code, Teil 1')
    expect(entry.querySelector('[data-testid="rule-exception-more-reasons"]')!.textContent).toContain('Eine weitere Begründung')
    const families = entry.querySelector('[data-testid="rule-exception-families"] summary')!.textContent!
    expect(families).toContain('Versuchter Dateizugriff (3)')
    expect(families).toContain('Versuchter Datenbank-Angriff (SQL-Injection) (3)')
    expect(entry.querySelectorAll('[data-testid="rule-exception-families"] a')).toHaveLength(20)
    await click(entry.querySelector<HTMLElement>('[data-testid="rule-exception-remove"]')!)
    await waitFor(() => bodyText().includes('allen 20 Regeln'))
    await click(byTestId('confirm-submit'))
    await waitFor(() => mock.state.ruleRepos.exceptions.length === 1)
    expect(mock.state.ruleRepos.exceptions[0]!.id).toBe(base.id)
    await waitFor(() => document.querySelectorAll('[data-testid="rule-exception"]').length === 1)
    wrapper.unmount()
  })

  it('takes one rule out of an exception, the others stay', async () => {
    const base = mock.state.ruleRepos.exceptions[0]!
    mock.state.ruleRepos.exceptions = [{ ...base, rules: ['932235', '942100'] }]
    const { wrapper } = await mountApp('/settings/rules/local?view=exceptions')
    await waitFor(() => document.querySelectorAll('[data-testid="rule-exception-rule"]').length === 2)
    await click(document.querySelector<HTMLElement>('[data-rule="942100"] [data-testid="rule-exception-rule-remove"]')!)
    await waitFor(() => !!byTestId('confirm-submit'))
    expect(bodyText()).toContain('Regel aus der Ausnahme nehmen?')
    expect(bodyText()).toContain('Die andere Regel bleibt ausgenommen.')
    await click(byTestId('confirm-submit'))
    await waitFor(() => mock.state.ruleRepos.exceptions[0]!.rules.length === 1)
    expect(mock.state.ruleRepos.exceptions[0]).toMatchObject({ id: base.id, rules: ['932235'], reason: base.reason })
    await waitFor(() => document.querySelectorAll('[data-testid="rule-exception-rule"]').length === 1)
    // The last rule out: the dialog says the exception goes.
    await click(byTestId('rule-exception-rule-remove'))
    await waitFor(() => bodyText().includes('damit ist die Ausnahme weg'))
    await click(byTestId('confirm-submit'))
    await waitFor(() => mock.state.ruleRepos.exceptions.length === 0)
    await waitFor(() => !!byTestId('rule-exceptions-empty'))
    wrapper.unmount()
  })

  it('fills the form from a possible false positive, listed for all websites in the tab Ausnahmen', async () => {
    const hintSite = 'verein.example'
    mock.state.monitoring.requestRing = true
    // The page a website had for this is gone: its old address leads here.
    const { wrapper, router } = await mountApp(`/w/${hintSite}/exceptions`)
    await waitFor(() => router.currentRoute.value.path === '/settings/rules/local' && router.currentRoute.value.query.view === 'exceptions')
    await waitFor(() => !!byTestId('fp-hint-add'))
    await click(byTestId('fp-hint-add'))
    await waitFor(() => !!byTestId('exception-dialog'))
    expect(byTestId<HTMLSelectElement>('exception-website')!.value).toBe(hintSite)
    expect(byTestId<HTMLInputElement>('exception-path')!.value).toBe('/mitglied-werden')
    expect(byTestId<HTMLInputElement>('exception-name')!.value).toBe('nachricht')
    expect(byTestId<HTMLInputElement>('exception-rules')!.value).toBe('942100')
    wrapper.unmount()
  })
})

describe('the switch of a repository', () => {
  it('shows Aus, Erkennen, Sperren and switches with one click, without a password', async () => {
    const { wrapper } = await mountApp('/settings/rules/crowdsec')
    await waitFor(() => !!byTestId('repository-counts'))
    expect(byTestId('repository-switch')!.textContent).toMatch(/Aus.*Erkennen.*Sperren/)
    expect(segment('Sperren').getAttribute('aria-checked')).toBe('true')
    // Set by an agent, schild.yaml says detect: the card says so and offers the way back.
    expect(byTestId('repository-owner')!.textContent).toContain('Agent „coding-agent“')
    expect(byTestId('repository-owner')!.textContent).toContain('In schild.yaml steht „Erkennen“')
    await click(segment('Aus'))
    await waitFor(() => repos().crowdsec.state === 'off')
    expect(repos().crowdsec.state_source).toBe('dashboard')
    expect(document.querySelector('[role="dialog"]')).toBeNull()
    await waitFor(() => !!byTestId('repository-restore'))
    await click(byTestId('repository-restore'))
    await waitFor(() => repos().crowdsec.state === 'detect' && repos().crowdsec.state_source === 'default')
    await waitFor(() => !byTestId('repository-restore'))
    wrapper.unmount()
  })

  it('says that the test profile holds Sperren back', async () => {
    mock.reset({ scenario: 'observe' })
    const { wrapper } = await mountApp('/settings/rules/crs')
    await waitFor(() => !!byTestId('repository-effect'))
    expect(segment('Sperren').getAttribute('aria-checked')).toBe('true')
    expect(byTestId('repository-effect')!.textContent).toContain('Im Testprofil sperrt Schild nichts')
    wrapper.unmount()
  })

  it('CRS: strictness and threshold are set in a dialog and go back to schild.yaml (D101)', async () => {
    const { wrapper } = await mountApp('/settings/rules/crs')
    await waitFor(() => !!byTestId('crs-settings-open'))
    expect(byTestId('repository-threshold-hint')).toBeNull()
    await click(byTestId('crs-settings-open'))
    await waitFor(() => !!byTestId('crs-settings-form'))
    expect(byTestId('crs-settings-config')!.textContent).toContain('In schild.yaml: Stufe 1, sperrt ab 5 Punkten')
    expect(byTestId('crs-settings-reset')).toBeNull()
    expect(byTestId('crs-settings-threshold-hint')).toBeNull()

    // Out of bounds: said in the form, nothing sent.
    await type(byTestId('crs-settings-threshold') as HTMLInputElement, '0')
    await click(byTestId('crs-settings-submit'))
    expect(bodyText()).toContain('Eine ganze Zahl zwischen 1 und 100.')
    expect(repos().crs.crs!.inbound_anomaly_threshold).toBe(5)

    await type(byTestId('crs-settings-threshold') as HTMLInputElement, '12')
    await waitFor(() => !!byTestId('crs-settings-threshold-hint'))
    await select(byTestId('crs-settings-level'), '2')
    await waitFor(() => !!byTestId('crs-settings-level-hint')?.textContent?.includes('Ab Stufe 2'))
    await click(byTestId('crs-settings-submit'))
    await waitFor(() => repos().crs.crs!.inbound_anomaly_threshold === 12 && repos().crs.crs!.paranoia_level === 2)
    await waitFor(() => !!byTestId('crs-threshold')?.textContent?.includes('angepasst'))
    expect(byTestId('crs-level')!.textContent).toContain('Stufe 2 von 4')
    expect(byTestId('crs-level')!.textContent).toContain('in schild.yaml: 1')
    expect(byTestId('repository-threshold-hint')!.textContent).toContain('Schwelle von 12 Punkten')
    expect(byTestId('repository-explain')!.textContent).toContain('Ab 12 Punkten')

    await click(byTestId('crs-settings-open'))
    await waitFor(() => !!byTestId('crs-settings-reset'))
    await click(byTestId('crs-settings-reset'))
    await click(byTestId('crs-settings-submit'))
    await waitFor(() => repos().crs.crs!.inbound_anomaly_threshold === 5 && repos().crs.crs!.paranoia_level === 1)
    await waitFor(() => !byTestId('crs-threshold')?.textContent?.includes('angepasst'))
    expect(byTestId('repository-threshold-hint')).toBeNull()
    wrapper.unmount()
  })

  it('CRS: shows its values and what off means for the Grundschutz', async () => {
    const { wrapper } = await mountApp('/settings/rules/crs')
    await waitFor(() => !!byTestId('repository-crs'))
    expect(byTestId('repository-crs')!.textContent).toContain('Stufe 1 von 4')
    expect(byTestId('repository-crs')!.textContent).toContain('4.30.0')
    expect(byTestId('repository-sync')).toBeNull()
    await click(segment('Aus'))
    await waitFor(() => !!byTestId('repository-baseline'))
    expect(byTestId('repository-baseline')!.textContent).toContain('Grundschutz aus')
    wrapper.unmount()
  })

  it('CrowdSec: checks now and goes back to the image with one click', async () => {
    const { wrapper } = await mountApp('/settings/rules/crowdsec')
    await waitFor(() => !!byTestId('repository-reset'))
    expect(byTestId('crowdsec-skipped')!.textContent).toContain('2 Regeln aus dem Hub nicht geladen')
    const before = repos().crowdsec.crowdsec!.last_check_at
    await click(byTestId('repository-sync'))
    await waitFor(() => repos().crowdsec.crowdsec!.last_check_at !== before)
    await click(byTestId('repository-reset'))
    await waitFor(() => repos().crowdsec.crowdsec!.set_source === 'image')
    expect(mock.state.ruleRepos.rules.some(r => r.origin === 'update')).toBe(false)
    expect(document.querySelector('[role="dialog"]')).toBeNull()
    await waitFor(() => !byTestId('repository-reset'))
    wrapper.unmount()
  })

  it('Eigene Regeln: reloads rules.d and keeps the running rules when a file does not load', async () => {
    repos().local.failNextSync = '20-shop.conf line 3: unknown operator @rxx'
    const { wrapper } = await mountApp('/settings/rules/local')
    await waitFor(() => !!byTestId('repository-local'))
    expect(byTestId('repository-local')!.textContent).toContain('/etc/schild/rules.d')
    expect(byTestId('repository-local')!.textContent).toContain('10-admin.conf')
    await click(byTestId('repository-sync'))
    await waitFor(() => !!byTestId('local-error'))
    expect(byTestId('local-error')!.textContent).toContain('Es laufen weiter die Regeln von vorher')
    expect(byTestId('local-error')!.textContent).toContain('unknown operator')
    await click(byTestId('repository-sync'))
    await waitFor(() => !byTestId('local-error'))
    wrapper.unmount()
  })

  it('without a connection to the hub the switch works and says so calmly', async () => {
    mock.reset({ scenario: 'standalone' })
    const { wrapper } = await mountApp('/settings/rules/crowdsec')
    await waitFor(() => !!byTestId('crowdsec-update'))
    expect(byTestId('crowdsec-update')!.textContent).toContain('laufen weiter')
    await click(segment('Sperren'))
    await waitFor(() => repos().crowdsec.state === 'block')
    wrapper.unmount()
  })
})

describe('one rule', () => {
  it('switches a rule off with a reason and on again, without a password', async () => {
    const { wrapper } = await mountApp('/settings/rules/crowdsec?rule=71204448')
    await waitFor(() => !!byTestId('rule-disable'))
    expect(byTestId('rule-hub')!.textContent).toContain('CVE-2025-24813')
    expect(byTestId('rule-hub-partial')!.textContent).toContain('XML')
    await click(byTestId('rule-disable'))
    await waitFor(() => !!byTestId('rule-disable-confirm'))
    expect(bodyText()).not.toMatch(/Passwort/)
    await type(document.querySelector<HTMLTextAreaElement>('#rule-off-note')!, 'stört den Upload')
    await click(byTestId('rule-disable-confirm'))
    await waitFor(() => rule('crowdsec', '71204448').disabled?.by === 'dashboard')
    expect(rule('crowdsec', '71204448').disabled!.note).toBe('stört den Upload')
    await waitFor(() => !!byTestId('rule-enable'))
    await click(byTestId('rule-enable'))
    await waitFor(() => !rule('crowdsec', '71204448').disabled)
    wrapper.unmount()
  })

  it('works for CRS and own rules too', async () => {
    const { wrapper } = await mountApp('/settings/rules/crs?rule=930120')
    await waitFor(() => !!byTestId('rule-disable'))
    expect(byTestId('rule-source')!.textContent).toContain('OWASP CRS 4.30.0')
    expect(byTestId('rule-references')).not.toBeNull()
    // D82: the rule as it runs, open, with the file it comes from.
    expect(byTestId('rule-seclang')!.textContent).toMatch(/SecRule[\s\S]*id:930120/)
    expect(byTestId('rule-source')!.textContent).toMatch(/REQUEST-930-\S+\.conf/)
    expect(byTestId('rule-seclang-copy')).not.toBeNull()
    expect(byTestId('rule-seclang-download')).not.toBeNull()
    expect(ruleFileName({ id: '930120', repository: 'crs' })).toBe('schild-crs-930120.conf')
    expect(ruleFileName({ id: 'a/b c', repository: 'local' })).toBe('schild-local-a-b-c.conf')
    wrapper.unmount()
  })

  it('steps to the next and the previous rule from the panel, with the buttons and with J and K', async () => {
    const { wrapper, router } = await mountApp('/settings/rules/crs')
    await waitFor(() => !!document.querySelector('[data-testid="rule-sheet"]') || document.querySelectorAll('tbody tr').length > 1)
    await click(document.querySelector('tbody tr'))
    await waitFor(() => !!byTestId('sheet-stepper'))
    const first = router.currentRoute.value.query.rule
    expect(byTestId('sheet-stepper-position')!.textContent).toMatch(/^1 von \d+$/)
    expect(byTestId<HTMLButtonElement>('sheet-stepper-prev')!.disabled).toBe(true)
    await click(byTestId('sheet-stepper-next'))
    await waitFor(() => router.currentRoute.value.query.rule !== first)
    const second = router.currentRoute.value.query.rule
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k' }))
    await waitFor(() => router.currentRoute.value.query.rule === first)
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'j' }))
    await waitFor(() => router.currentRoute.value.query.rule === second)
    wrapper.unmount()
  })

  it('a rule disabled in schild.yaml says where to change it, and the API refuses (config_limit)', async () => {
    const { wrapper } = await mountApp('/settings/rules/crs?rule=920350')
    await waitFor(() => !!byTestId('rule-switch'))
    expect(byTestId('rule-switch')!.textContent).toContain('In schild.yaml ausgeschaltet')
    const sw = byTestId('rule-enable')!
    expect(sw.hasAttribute('disabled') || sw.getAttribute('data-disabled') !== null).toBe(true)
    const res = await fetch(`${BASE}/rules/crs/920350`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': mock.state.session.csrf_token! }, body: JSON.stringify({ disabled: false }) })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('config_limit')
    wrapper.unmount()
  })

  it('an update settles and then blocks on its own (D89: no approvals)', async () => {
    const { wrapper } = await mountApp('/settings/rules/crowdsec?rule=62846312')
    await waitFor(() => !!byTestId('rule-settling'))
    expect(byTestId('rule-settling')!.textContent).toContain('sperrt')
    expect(document.querySelector('[data-testid="rule-approve"], [data-testid="rule-reject"]')).toBeNull()
    const res = await fetch(`${BASE}/rules/crowdsec/62846312/approve`, { method: 'POST', headers: { 'X-CSRF-Token': 'x' }, body: '{}' })
    expect(res.status).toBe(404)
    wrapper.unmount()
  })
})

describe('a hub rule in plain German', () => {
  const hub = (label?: string) => ({ name: 'crowdsecurity/vpatch-CVE-2026-1', label, cves: ['CVE-2026-1'] })
  it('names the attack by the type in its label', () => {
    expect(hubRuleText(hub('Apache Tomcat - RCE'))).toEqual({
      title: 'Apache Tomcat: Versuch, Code auf dem Server auszuführen',
      explain: 'Erkennt Versuche, über eine bekannte Lücke in Apache Tomcat eigenen Code auf dem Server auszuführen (CVE-2026-1).',
    })
  })
  it('stays calm with a type it does not know', () => {
    expect(hubRuleText(hub('Foo - Something New')).explain).toBe('Erkennt Versuche, eine bekannte Lücke in Foo auszunutzen (CVE-2026-1).')
  })
  it('falls back to the name without a label', () => {
    expect(hubRuleText(hub()).title).toBe('vpatch-CVE-2026-1')
  })
})
