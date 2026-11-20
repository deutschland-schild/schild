import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import type { CrawlerPolicy } from '../src/api/crawlers'
import getFixture from '../../../../contracts/api/fixtures/client/getCrawlerPolicy.json'
import {
  applyPreset,
  blockedText,
  categoryAction,
  CRAWLER_CATEGORIES,
  CRAWLERS_COPY,
  effectiveAction,
  isPresetApplied,
  ownRule,
  policyInput,
  presetInput,
  rangesNote,
  withBot,
  withCategory,
  withImpersonators,
} from '../src/lib/crawlers'
import { OUTCOME_FILTER_LABELS, REQUEST_OUTCOMES } from '../src/lib/requests'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, waitFor } from './helpers'

const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  mock.reset()
})
afterAll(() => mock.server.close())

const fixture = getFixture.policy as CrawlerPolicy

describe('KI-Crawler copy and helpers', () => {
  it('says when the impersonator check cannot work', () => {
    const r = (stale: boolean) => ({ id: 'googlebot', operator: 'Google', fetched_at: '2026-10-29T19:20:29Z', stale, source: 'release' as const })
    const v = (ranges: boolean) => ({ ranges, fcrdns: false, ranges_fetch: false })
    expect(rangesNote(undefined)).toBeNull()
    expect(rangesNote({ verification: v(true), ranges: [r(false), r(true)] })).toBeNull()
    expect(rangesNote({ verification: v(true), ranges: [r(true), r(true)] })).toBe(CRAWLERS_COPY.rangesStale)
    expect(rangesNote({ verification: v(false), ranges: [r(false)] })).toBe(CRAWLERS_COPY.rangesOff)
    expect(CRAWLERS_COPY.rangesStale).toMatch(/^Adressbereiche veraltet/)
  })

  it('keeps the required wording', () => {
    const all = Object.values(CRAWLERS_COPY).join(' ')
    expect(all).not.toMatch(/anonym/i)
    expect(all).not.toMatch(/\b(geschützt|sicher|gefährlich|dringend)\b/i)
    expect(all).not.toMatch(/\bSie\b|\bIhr(e|en)?\b/)
    expect(all).toContain('User-Agent')
    expect(all).toContain('robots.txt')
  })

  it('lists the eleven catalogue categories, never the two that are no crawlers', () => {
    expect(CRAWLER_CATEGORIES).toHaveLength(11)
    expect(CRAWLER_CATEGORIES).not.toContain('likely_automated')
    expect(CRAWLER_CATEGORIES).not.toContain('likely_browser')
  })

  it('lets the own rule of a crawler override its category', () => {
    expect(effectiveAction(fixture, { id: 'gptbot', category: 'ai_training' })).toBe('block')
    expect(effectiveAction(fixture, { id: 'ccbot', category: 'ai_training' })).toBe('allow')
    expect(effectiveAction(fixture, { id: 'googlebot', category: 'search_engine' })).toBe('allow')
    const p = withBot(withCategory(fixture, 'search_engine', 'block'), 'googlebot', 'allow')
    expect(effectiveAction(p, { id: 'googlebot', category: 'search_engine' })).toBe('allow')
    expect(effectiveAction(p, { id: 'bingbot', category: 'search_engine' })).toBe('block')
    expect(effectiveAction({ ...p, bots: { x: 'block' } }, { id: 'x', category: 'likely_automated' })).toBe('allow')
    expect(ownRule(fixture, 'ccbot')).toBe('allow')
    expect(ownRule(fixture, 'gptbot')).toBe('inherit')
  })

  it('stores allow as an absent key and drops an own rule with inherit', () => {
    const p = withCategory(fixture, 'ai_training', 'allow')
    expect(p.categories).toEqual({})
    expect(categoryAction(p, 'ai_training')).toBe('allow')
    expect(withBot(fixture, 'ccbot', 'inherit').bots).toEqual({})
    expect(withBot(fixture, 'gptbot', 'block').bots).toEqual({ ccbot: 'allow', gptbot: 'block' })
    // The input is never changed in place.
    expect(fixture.categories).toEqual({ ai_training: 'block' })
  })

  it('builds the PUT body: the whole policy, or the preset alone', () => {
    expect(policyInput(withImpersonators(fixture, 'allow'))).toEqual({ categories: { ai_training: 'block' }, bots: { ccbot: 'allow' }, impersonators: 'allow' })
    expect(presetInput()).toEqual({ preset: 'block_ai_training' })
  })

  it('knows what the preset leaves behind', () => {
    expect(isPresetApplied(fixture)).toBe(false)
    const p = applyPreset(fixture)
    expect(p).toEqual({ categories: { ai_training: 'block' }, bots: {}, impersonators: 'block' })
    expect(isPresetApplied(p)).toBe(true)
    expect(isPresetApplied({ ...p, categories: { ai_training: 'block', search_engine: 'allow' } })).toBe(true)
    expect(isPresetApplied(withCategory(p, 'ai_search', 'block'))).toBe(false)
  })

  it('says what a crawler rule did', () => {
    expect(blockedText(undefined)).toBe('–')
    expect(blockedText({ blocked: 12 })).toBe('12')
    expect(blockedText({ would_block: 3 })).toBe('hätte 3 blockiert')
    expect(REQUEST_OUTCOMES.blocked_crawler.label).toBe('Gesperrt')
    expect(OUTCOME_FILTER_LABELS.blocked_crawler).toBe('Gesperrt: Crawler-Regel')
  })
})

const radio = (testid: string, value: string) => byTestId(testid)?.querySelector<HTMLElement>(`[role="radio"][data-value="${value}"]`) ?? null

describe('KI-Crawler page', () => {
  it('blocks AI training in one click, takes single crawlers back and blocks impersonators', async () => {
    mock.reset({ requestRing: true })
    await mountApp('/w/verein.example/ai-crawlers')
    await waitFor(() => !!byTestId('crawlers-preset'))
    expect(bodyText()).toContain(CRAWLERS_COPY.scope)
    expect(document.querySelectorAll('[data-crawler-category]')).toHaveLength(11)

    await click(byTestId('crawlers-preset'))
    await waitFor(() => !!mock.state.crawlers['verein.example'])
    expect(mock.state.crawlers['verein.example']!.policy).toEqual({ categories: { ai_training: 'block' }, bots: {}, impersonators: 'allow' })
    await waitFor(() => byTestId('crawlers-preset-text')!.textContent!.includes(CRAWLERS_COPY.presetActive))
    // The button undoes itself (initiator 2026-11-02: "kann ich den Block nicht mehr aufheben").
    expect(byTestId('crawlers-preset')!.textContent).toContain(CRAWLERS_COPY.presetUndo)
    await click(byTestId('crawlers-preset'))
    await waitFor(() => byTestId('crawlers-preset')!.textContent!.includes(CRAWLERS_COPY.preset))
    expect(byTestId('crawlers-preset-text')!.textContent).toContain(CRAWLERS_COPY.presetExplain)
    await waitFor(() => mock.state.crawlers['verein.example']!.policy.categories.ai_training !== 'block')
    await click(byTestId('crawlers-preset'))
    await waitFor(() => byTestId('crawlers-preset-text')!.textContent!.includes(CRAWLERS_COPY.presetActive))

    // Open KI-Training: GPTBot follows its category; an own rule lets CCBot back in.
    await click(byTestId('crawlers-open-ai_training'))
    await waitFor(() => !!document.querySelector('[data-crawler="ccbot"]'))
    expect(document.querySelector('[data-crawler="gptbot"]')!.getAttribute('data-effective')).toBe('block')
    await click(radio('crawlers-bot-ccbot', 'allow'))
    await waitFor(() => mock.state.crawlers['verein.example']!.policy.bots.ccbot === 'allow')
    await waitFor(() => document.querySelector('[data-crawler="ccbot"]')!.getAttribute('data-effective') === 'allow')

    await click(byTestId('crawlers-impersonators'))
    await waitFor(() => mock.state.crawlers['verein.example']!.policy.impersonators === 'block')

    await click(radio('crawlers-category-search_engine', 'block'))
    await waitFor(() => mock.state.crawlers['verein.example']!.policy.categories.search_engine === 'block')
    expect(mock.state.crawlers['verein.example']!.policy).toEqual({ categories: { ai_training: 'block', search_engine: 'block' }, bots: { ccbot: 'allow' }, impersonators: 'block' })
    await waitFor(() => !!byTestId('crawlers-updated'))
  })

  it('says that observe mode only records', async () => {
    mock.reset({ scenario: 'observe', requestRing: true })
    mock.state.crawlers['verein.example'] = { policy: { categories: { ai_training: 'block' }, bots: { claudebot: 'allow' }, impersonators: 'allow' }, updated_at: null, actor: null }
    await mountApp('/w/verein.example/ai-crawlers')
    await waitFor(() => !!byTestId('crawlers-observe'))
    expect(byTestId('crawlers-observe')!.textContent).toContain(CRAWLERS_COPY.observe)
    await click(byTestId('crawlers-open-ai_training'))
    await waitFor(() => /^hätte .* blockiert$/.test(document.querySelector('[data-blocked="gptbot"]')?.textContent?.trim() ?? ''))
    expect(document.querySelector('[data-blocked="claudebot"]')!.textContent!.trim()).toBe('–')
  })

  it('shows per crawler what the rule blocked, also in the bots tab, with a link to the rules', async () => {
    mock.reset({ requestRing: true })
    mock.state.crawlers['verein.example'] = { policy: { categories: { ai_training: 'block' }, bots: {}, impersonators: 'allow' }, updated_at: null, actor: null }
    await mountApp('/w/verein.example/ai-crawlers')
    await waitFor(() => !!byTestId('crawlers-open-ai_training'))
    expect(byTestId('crawlers-observe')).toBeNull()
    await click(byTestId('crawlers-open-ai_training'))
    await waitFor(() => /^[\d.]+$/.test(document.querySelector('[data-blocked="gptbot"]')?.textContent?.trim() ?? ''))
    expect(byTestId('crawlers-window')!.textContent).toContain(CRAWLERS_COPY.window)

    cleanup()
    await mountApp('/w/verein.example?view=bots')
    await waitFor(() => !!document.querySelector('[data-crawler-blocked="gptbot"]'))
    expect(document.querySelector('[data-crawler-blocked="gptbot"]')!.textContent).toMatch(/^geblockt: [\d.]+$/)
    expect(document.querySelector('[data-crawler-blocked="googlebot"]')).toBeNull()
    expect(byTestId('bots-crawler-control')!.querySelector('a')!.getAttribute('href')).toMatch(/\/w\/verein\.example\/ai-crawlers$/)
  })
})
