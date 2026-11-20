import type { Session } from '@/api/types'
import { unwrap } from '@schild/app-kit'
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed } from 'vue'
import { csrf } from '@/api/auth-state'
import { api } from '@/api/client'
import { keys } from '@/api/queries'

export const LOGGED_OUT: Session = { authenticated: false, first_run: false }

export function useSessionQuery() {
  return useQuery({
    queryKey: keys.session,
    queryFn: () => unwrap(api.GET('/auth/session')),
    staleTime: Number.POSITIVE_INFINITY,
    retry: 1,
  })
}

/** Current session plus derived flags. Read-only users see everything but cannot change anything. */
export function useSession() {
  const q = useSessionQuery()
  const session = computed(() => q.data.value)
  return {
    session,
    user: computed(() => session.value?.user ?? 'admin'),
    canEdit: computed(() => (session.value?.role ?? 'admin') === 'admin'),
  }
}

export function useLogin() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { user: string, password: string }) => unwrap(api.POST('/auth/login', { body })),
    onSuccess: s => qc.setQueryData(keys.session, s),
  })
}

export function useSetup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { password: string, setup_code: string }) => unwrap(api.POST('/auth/setup', { body })),
    onSuccess: s => qc.setQueryData(keys.session, s),
  })
}

export function useLogout() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST('/auth/logout', { params: { header: csrf() } })),
    onSettled: () => {
      qc.removeQueries({ predicate: q => q.queryKey[0] !== 'session' })
      qc.setQueryData(keys.session, LOGGED_OUT)
    },
  })
}
