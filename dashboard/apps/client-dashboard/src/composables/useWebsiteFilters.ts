import type { ComputedRef } from 'vue'
import type { WebsiteRangeKey } from '@/api/websites'
import { computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { DEFAULT_RANGE, ringCovers, websiteRangeOf } from '@/api/websites'
import { filterChip, filtersFromQuery, parseFilter } from '@/lib/websites'

/**
 * Click-to-filter state of a website page in the URL (`filter`, repeated; `time`), as on the website
 * overview (D36): with the request ring several filters combine and breakdowns follow them within 48 h;
 * without it one filter at a time. Shared by the Zugriffe page (MVP-22).
 */
export function useWebsiteFilters(ring: ComputedRef<boolean>, ringKnown: ComputedRef<boolean>) {
  const route = useRoute()
  const router = useRouter()

  function setQuery(patch: Record<string, string | string[] | undefined>) {
    const query = { ...route.query }
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined || v === '' || (Array.isArray(v) && !v.length)) delete query[k]
      else query[k] = v
    }
    void router.replace({ query })
  }

  const range = computed({
    get: () => websiteRangeOf(route.query.time).key,
    set: (v: WebsiteRangeKey) => setQuery({ time: v === DEFAULT_RANGE ? undefined : v }),
  })
  const urlFilters = computed(() => filtersFromQuery(route.query.filter))
  // Links from before D64 carry ip and ua as keys of their own; they become filters.
  watch(() => [route.query.ip, route.query.ua] as const, ([ip, ua]) => {
    if (ip === undefined && ua === undefined) return
    const add = [typeof ip === 'string' ? `ip:${ip}` : '', typeof ua === 'string' ? `user_agent:${ua}` : ''].filter(f => parseFilter(f) !== null)
    const dims = add.map(f => f.slice(0, f.indexOf(':') + 1))
    const kept = urlFilters.value.filter(f => !dims.some(d => f.startsWith(d)))
    setQuery({ ip: undefined, ua: undefined, filter: [...kept, ...add].slice(-4) })
  }, { immediate: true })
  const filters = computed(() => ring.value ? urlFilters.value : urlFilters.value.slice(-1))
  watch([urlFilters, ringKnown], ([f, known]) => {
    if (known && !ring.value && f.length > 1) setQuery({ filter: f.slice(-1) })
  }, { immediate: true })

  function addFilter(expr: string) {
    const p = parseFilter(expr)
    if (!p) return
    if (!ring.value) {
      setQuery({ filter: filters.value.includes(expr) ? [] : [expr] })
      return
    }
    // One value per dimension: a second click on the same dimension replaces it, on the same value removes it.
    const rest = filters.value.filter(f => !f.startsWith(`${p.dimension}:`))
    setQuery({ filter: filters.value.includes(expr) ? rest : [...rest, expr].slice(-4) })
  }
  function removeFilter(expr: string) {
    setQuery({ filter: filters.value.filter(f => f !== expr) })
  }
  const chips = computed(() => filters.value.map(filterChip).filter(c => c !== null))
  const inRingRange = computed(() => ringCovers(range.value))
  /** Breakdowns under a filter come from the request ring within its window; else the tables stay unfiltered. */
  const panelFilters = computed(() => ring.value && inRingRange.value ? filters.value : [])
  const panelsUnfiltered = computed(() => filters.value.length > 0 && panelFilters.value.length === 0)
  /** The value of one dimension among the filters (e.g. country). */
  const valueOf = (dimension: string) => {
    const f = filters.value.find(x => x.startsWith(`${dimension}:`))
    return f ? f.slice(dimension.length + 1) : null
  }

  return { setQuery, range, filters, addFilter, removeFilter, chips, inRingRange, panelFilters, panelsUnfiltered, valueOf }
}
