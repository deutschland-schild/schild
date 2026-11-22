import { afterEach, describe, expect, it } from 'vitest'
import { ALL_NODES, partialNodesText, selectedNode, selectNode, withNode } from '../src/lib/node-filter'

const WEB2 = 'n-1b2c3d4e5f60718293a4b5c6d7e8f90a'
const get = (path: string) => new Request(`http://dashboard.schild.test/api/v0${path}`)

afterEach(() => selectNode(ALL_NODES))

describe('filter "Server" of a cluster (MVP-27)', () => {
  it('asks for every gateway by default and leaves the request alone', () => {
    const req = get('/monitoring/now')
    expect(selectedNode.value).toBe(ALL_NODES)
    expect(withNode(req)).toBe(req)
  })

  it('adds the chosen gateway to the counters and charts only', () => {
    selectNode(WEB2)
    for (const path of ['/monitoring/now', '/monitoring/series?metric=traffic.requests', '/monitoring/traffic/breakdown?by=path', '/websites/shop.example/kpis?from=a', '/websites/shop.example/realtime'])
      expect(new URL(withNode(get(path)).url).searchParams.get('node'), path).toBe(WEB2)
    // Lists show the whole cluster, and so does everything that is no number of the rings.
    for (const path of ['/events', '/requests', '/group', '/monitoring/server', '/websites'])
      expect(new URL(withNode(get(path)).url).searchParams.has('node'), path).toBe(false)
    const post = new Request('http://dashboard.schild.test/api/v0/monitoring/now', { method: 'POST' })
    expect(withNode(post)).toBe(post)
  })

  it('takes nothing but a node id as a choice', () => {
    selectNode('web-2')
    expect(selectedNode.value).toBe(ALL_NODES)
    selectNode(WEB2)
    expect(selectedNode.value).toBe(WEB2)
  })

  it('says which gateway is missing from the numbers, and since when', () => {
    expect(partialNodesText(undefined)).toBe('')
    expect(partialNodesText({ node: 'all', nodes: [], partial_nodes: [], clients_at_least: true })).toBe('')
    const one = partialNodesText({ node: 'all', nodes: [], partial_nodes: [{ node: WEB2, name: 'web-2', until: '2026-11-21T13:58:00Z' }], clients_at_least: true })
    expect(one).toContain('Daten von web-2 fehlen seit')
    expect(one).toContain('ohne diesen Server')
    const none = partialNodesText({ node: 'all', nodes: [], partial_nodes: [{ node: WEB2, name: 'web-2' }], clients_at_least: true })
    expect(none).toContain('Daten von web-2 fehlen noch')
  })
})
