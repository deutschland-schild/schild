/** The address blocks that run (D87), with the state of the handoff to the host's firewall. */
import type { components } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { api, csrf } from './client'

type S = components['schemas']
export type RunningBlock = S['RunningBlock']
export type BlockList = S['BlockList']

export const blockKeys = { all: ['blocks'] as const }

export function useBlocks() {
  return useQuery({
    queryKey: blockKeys.all,
    queryFn: () => unwrap(api.GET('/blocks')),
    refetchInterval: 15_000,
  })
}

export type BlockRequest = S['BlockRequest']

/** Block one address by hand (D88); the list and the incidents load again. */
export function useCreateBlock() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: BlockRequest) => unwrap(api.POST('/blocks', { params: { header: csrf() }, body })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: blockKeys.all })
      void qc.invalidateQueries({ queryKey: ['incidents'] })
      void qc.invalidateQueries({ queryKey: ['events'] })
    },
  })
}
