import type { Ref } from 'vue'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

/**
 * Two-way binding of one URL query parameter, so filters are deep-linkable and survive reloads.
 * Empty values remove the parameter. Uses router.replace (filters do not flood the history).
 */
export function useRouteQuery(name: string): Ref<string> {
  const route = useRoute()
  const router = useRouter()
  return computed({
    get: () => {
      const v = route.query[name]
      return (Array.isArray(v) ? v[0] : v) ?? ''
    },
    set: (value: string) => {
      const query = { ...route.query }
      if (value === '' || value === undefined || value === null) delete query[name]
      else query[name] = value
      void router.replace({ query })
    },
  })
}

/** Numeric variant; '' when unset. */
export function useRouteQueryNumber(name: string): Ref<number | undefined> {
  const raw = useRouteQuery(name)
  return computed({
    get: () => (raw.value === '' || Number.isNaN(Number(raw.value)) ? undefined : Number(raw.value)),
    set: (v) => {
      raw.value = v === undefined || Number.isNaN(v) ? '' : String(v)
    },
  })
}
