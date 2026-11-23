/**
 * The filter "Server" of a cluster (MVP-27, contracts/cluster.md section 9a): whose numbers the counters and
 * charts show. "all" is every gateway of the cluster added up, the default; a node id is one gateway alone.
 * One choice for the whole dashboard, kept for the browser tab. Lists of events and requests are not filtered:
 * they always show the cluster.
 */
import type { components } from '@/api/generated/schema'
import { formatDateTime } from '@schild/ui'
import { ref } from 'vue'

export type ClusterScope = components['schemas']['ClusterScope']

export const ALL_NODES = 'all'
const KEY = 'schild-node-filter'
const NODE_ID = /^n-[0-9a-f]{32}$/

function stored(): string {
  try {
    const v = sessionStorage.getItem(KEY)
    return v && NODE_ID.test(v) ? v : ALL_NODES
  }
  catch {
    return ALL_NODES
  }
}

/** The node the counters and charts show: "all" or a node id. */
export const selectedNode = ref<string>(stored())

export function selectNode(id: string) {
  const v = NODE_ID.test(id) ? id : ALL_NODES
  selectedNode.value = v
  try {
    if (v === ALL_NODES) sessionStorage.removeItem(KEY)
    else sessionStorage.setItem(KEY, v)
  }
  catch { /* the choice then holds until the page is reloaded */ }
}

/** The operations that take `node`: the counters and charts read from the metric rings. */
const NODE_PATHS = /\/(?:monitoring\/(?:now|series|traffic\/breakdown)|websites\/[^/]+\/(?:kpis|realtime))$/

/** The request with `node` set when one gateway is chosen; the same request otherwise. */
export function withNode(req: Request): Request {
  const node = selectedNode.value
  if (node === ALL_NODES || req.method !== 'GET') return req
  const url = new URL(req.url)
  if (!NODE_PATHS.test(url.pathname) || url.searchParams.has('node')) return req
  url.searchParams.set('node', node)
  return new Request(url, req)
}

const list = (names: string[]) => names.length <= 1 ? names.join('') : `${names.slice(0, -1).join(', ')} und ${names.at(-1)}`

/** What an answer lacks, in one calm sentence; '' when it lacks nothing. */
export function partialNodesText(scope: ClusterScope | undefined): string {
  const partial = scope?.partial_nodes ?? []
  if (!partial.length) return ''
  const names = list(partial.map(p => p.name))
  const untils = partial.map(p => p.until).filter((u): u is string => !!u).sort()
  const verb = partial.length === 1 ? 'fehlen' : 'fehlen'
  if (!untils.length) return `Daten von ${names} ${verb} noch. Die Summen und Diagramme zeigen bis dahin nur die anderen Server.`
  return `Daten von ${names} ${verb} seit ${formatDateTime(untils[0]!)}. Die Summen und Diagramme sind ab da ohne ${partial.length === 1 ? 'diesen Server' : 'diese Server'}.`
}
