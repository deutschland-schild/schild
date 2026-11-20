import type { App } from 'vue'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { ApiError } from './api'

/** Query defaults: calm refetching, no retry on 4xx. */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: false,
        retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
      },
      mutations: { retry: false },
    },
  })
}

export function installQuery(app: App, client: QueryClient = createQueryClient()): QueryClient {
  app.use(VueQueryPlugin, { queryClient: client })
  return client
}
