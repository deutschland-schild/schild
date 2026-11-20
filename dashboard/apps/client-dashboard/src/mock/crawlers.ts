/**
 * Mock of the KI-Crawler endpoints (D57, MVP-29): the crawler policy per website, with the catalogue of the
 * made-up bots of mock/requests.ts. Validation as the gateway does it (unknown categories and crawler ids are
 * refused with a pointer). The bot overview reads the same policy for blocked / would_block per bot.
 * Mock mode and tests only.
 */
import type { HttpHandler } from 'msw'
import type { CrawlerCatalogueEntry, CrawlerPolicy, CrawlerPolicyInput, CrawlerPolicyState } from '@/api/crawlers'
import type { MockState } from './data'
import type { WebsiteHandlerTools } from './websites'
import { http, HttpResponse } from 'msw'
import { applyPreset, CRAWLER_CATEGORIES } from '@/lib/crawlers'
import { MOCK_BOTS } from './requests'

const isoS = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
export const MOCK_CATALOGUE_VERSION = '2026-10-20.1'

/** The crawlers a policy can name: every made-up catalogue bot (verifiable when its operator publishes ranges). */
export function mockCrawlers(): CrawlerCatalogueEntry[] {
  return MOCK_BOTS.map(b => ({ id: b.id, name: b.name, operator: b.operator, category: b.category as CrawlerCatalogueEntry['category'], verifiable: b.ranges !== 'none' }))
}

function stateOf(st: MockState, site: string): CrawlerPolicyState {
  const p = st.crawlers[site]
  return {
    website: site,
    policy: p?.policy ?? { categories: {}, bots: {}, impersonators: 'allow' },
    updated_at: p?.updated_at ?? null,
    actor: p?.actor ?? null,
    catalogue_version: MOCK_CATALOGUE_VERSION,
    crawlers: mockCrawlers(),
    presets: ['block_ai_training'],
  }
}

const ACTIONS = new Set(['allow', 'block'])

export function crawlerHandlers(t: WebsiteHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object, status = 200) => HttpResponse.json(body as Record<string, unknown>, { status })
  const findSite = (id: unknown) => t.state().monitoring.sites.find(s => s.id === id)
  return [
    http.get(`${base}/websites/:website/crawlers`, guard('read', ({ params }) => {
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      return json(stateOf(t.state(), s.id))
    })),
    http.put(`${base}/websites/:website/crawlers`, guard('write', async ({ request, params }) => {
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const b = await request.json() as CrawlerPolicyInput
      const st = t.state()
      const bad = (pointer: string, detail: string) => problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer, detail }])
      const ids = new Set(MOCK_BOTS.map(x => x.id))
      for (const [k, v] of Object.entries(b.categories ?? {})) {
        if (!(CRAWLER_CATEGORIES as readonly string[]).includes(k)) return bad(`/categories/${k}`, 'unknown category')
        if (!ACTIONS.has(v)) return bad(`/categories/${k}`, 'allow or block')
      }
      for (const [k, v] of Object.entries(b.bots ?? {})) {
        if (!ids.has(k)) return bad(`/bots/${k}`, 'unknown bot')
        if (!ACTIONS.has(v)) return bad(`/bots/${k}`, 'allow or block')
      }
      if (b.impersonators !== undefined && !ACTIONS.has(b.impersonators)) return bad('/impersonators', 'allow or block')
      const old = stateOf(st, s.id).policy
      let policy: CrawlerPolicy
      if (b.preset !== undefined) {
        if (b.preset !== 'block_ai_training') return bad('/preset', 'unknown preset')
        if (b.categories || b.bots) return bad('/preset', 'a preset comes alone or with impersonators')
        policy = applyPreset({ ...old, impersonators: b.impersonators ?? old.impersonators })
      }
      else {
        policy = { categories: { ...b.categories }, bots: { ...b.bots }, impersonators: b.impersonators ?? 'allow' }
      }
      st.crawlers[s.id] = { policy, updated_at: isoS(t.now()), actor: 'dashboard' }
      return json(stateOf(st, s.id))
    })),
  ]
}
