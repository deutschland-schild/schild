import { describe, expect, it } from 'vitest'
import { bytesToBase64, digestOf } from '../src/lib/digest'
import type { TreeEntry } from '../src/lib/logverify'
import { checkEntry, checkRoot, checkSequence, treeRoot } from '../src/lib/logverify'

describe('public log checks', () => {
  it('accepts a contiguous, newest-first sequence matching the head', () => {
    const items = [{ index: 9, time: '2026-10-26T12:00:00Z' }, { index: 8, time: '2026-10-26T11:00:00Z' }, { index: 7, time: '2026-10-26T11:00:00Z' }]
    expect(checkSequence(items, 10)).toEqual([])
  })

  it('reports gaps, time going backwards and a head mismatch', () => {
    const items = [{ index: 9, time: '2026-10-26T10:00:00Z' }, { index: 7, time: '2026-10-26T11:00:00Z' }]
    const issues = checkSequence(items, 12).map(i => i.text)
    expect(issues).toHaveLength(3)
    expect(issues[0]).toContain('Kopf')
    expect(issues[1]).toContain('Lücke')
    expect(issues[2]).toContain('jünger')
  })

  it('verifies the digest over the DSSE payload bytes', async () => {
    const bytes = new TextEncoder().encode('{"schema":"schild.log.bundle/0","ref":"42"}')
    const envelope = { payloadType: 'x', payload: bytesToBase64(bytes), signatures: [] }
    const digest = await digestOf(bytes)
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(await checkEntry({ digest, envelope: envelope as never })).toBe('ok')
    expect(await checkEntry({ digest: `sha256:${'0'.repeat(64)}`, envelope: envelope as never })).toBe('mismatch')
    expect(await checkEntry({ digest, envelope: null })).toBe('no_envelope')
  })
})

// The RFC 6962 tree hash must agree with the golden vectors of contracts v0.1,
// which Go (contract/logtree) and Python (crosscheck.py) check as well.
const vectors = import.meta.glob<{ input_raw: string, expect: { valid: boolean, error?: string } }>('../../../../contracts/vectors/log-tree/*/*.json', { eager: true, import: 'default' })

describe('public log tree (RFC 6962)', () => {
  it('has golden vectors', () => {
    expect(Object.keys(vectors).length).toBeGreaterThanOrEqual(15)
  })
  for (const [file, v] of Object.entries(vectors)) {
    const doc = (() => {
      try {
        return JSON.parse(v.input_raw) as { entries?: TreeEntry[], head?: { size: number, root: string } }
      }
      catch {
        return null
      }
    })()
    // Only vectors whose verdict depends on the root (shape errors are the schema's job).
    if (!(v.expect.valid || v.expect.error === 'log_root') || !doc?.entries || !doc.head) continue
    it(`${file.split('/').slice(-2).join('/')}: root ${v.expect.valid ? 'matches' : 'differs'}`, async () => {
      expect(await checkRoot(doc!.entries!, doc!.head!.size, doc!.head!.root)).toBe(v.expect.valid ? 'ok' : 'mismatch')
    })
  }

  it('reports an incomplete copy instead of a wrong root', async () => {
    const e = { index: 1, time: '2026-10-26T12:00:00Z', kind: 'proposal' as const, ref: 'prop-0001', digest: `sha256:${'0'.repeat(64)}`, summary: 'x', envelope_sha256: null }
    expect(await checkRoot([e], 2, `sha256:${'0'.repeat(64)}`)).toBe('incomplete')
  })

  it('matches the RFC 6962 root of the empty tree', async () => {
    expect(await treeRoot([])).toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })
})
