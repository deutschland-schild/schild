import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { subpageOf } from '@/lib/nav'

/** Last website whose pages were open; shortcuts go back to it. */
export const lastWebsite = ref('')

/**
 * The website in the URL (/w/<id>/...), '' on the server and settings pages. Only that website
 * expands in the sidebar; `last` keeps the most recent one for shortcuts.
 */
export function useCurrentWebsite() {
  const route = useRoute()
  watch(() => route.params.site, (p) => {
    if (typeof p === 'string' && p) lastWebsite.value = p
  }, { immediate: true })
  const site = computed(() => {
    const p = route.params.site
    return typeof p === 'string' && p ? p : ''
  })
  /** Sub-page to keep when switching websites ('' = Zugriffe); null outside the website pages. */
  const subpage = computed(() => subpageOf(route.path))
  return { site, subpage, last: lastWebsite }
}
