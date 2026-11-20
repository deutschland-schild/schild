/**
 * KI-Crawler of a website (D57, MVP-29): per catalogue category and per crawler allow or block, and whether
 * requests that only pretend to be a crawler are blocked. Only crawlers that name themselves in the
 * User-Agent are covered; robots.txt stays as it is.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api, csrf } from './client'

type S = components['schemas']
export type CrawlerAction = S['CrawlerAction']
export type CrawlerCategory = S['CrawlerCategory']
export type CrawlerPolicy = S['CrawlerPolicy']
export type CrawlerPolicyState = S['CrawlerPolicyState']
export type CrawlerPolicyInput = S['CrawlerPolicyInput']
export type CrawlerCatalogueEntry = S['CrawlerCatalogueEntry']

export const crawlersKey = (site: string) => ['crawlers', site] as const

export function useCrawlerPolicy(site: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => crawlersKey(toValue(site))),
    queryFn: () => unwrap(api.GET('/websites/{website}/crawlers', { params: { path: { website: toValue(site) } } })),
    enabled: computed(() => !!toValue(site)),
    refetchInterval: 60_000,
  })
}

export function useSetCrawlerPolicy(site: MaybeRefOrGetter<string>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: CrawlerPolicyInput) =>
      unwrap(api.PUT('/websites/{website}/crawlers', { params: { path: { website: toValue(site) }, header: csrf() }, body })),
    onSuccess: st => qc.setQueryData(crawlersKey(st.website), st),
  })
}
