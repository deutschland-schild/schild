import type { LogEntry } from '@/api/types'
import { base64ToBytes, digestOf } from './digest'

/**
 * Checks of the public log that the browser can do on its own:
 *  - sequence: indices contiguous and newest first, times not going backwards, newest index = head.size - 1
 *  - digest: sha256 over the DSSE payload bytes equals the entry digest (as contract/msg.Digest)
 *  - envelope: sha256 over the envelope bytes equals envelope_sha256 (contracts v0.1)
 *  - root: the RFC 6962 Merkle tree hash over all entries equals the head root and the root
 *    the newest checkpoint signs (contracts v0.1, contracts/cosign.md; same algorithm as
 *    contract/logtree in Go and contracts/tools/crosscheck.py in Python).
 */
export type EntryCheck = 'ok' | 'mismatch' | 'no_envelope' | 'error'

export interface SequenceIssue { index: number, text: string }

export function checkSequence(items: Pick<LogEntry, 'index' | 'time'>[], headSize?: number): SequenceIssue[] {
  const issues: SequenceIssue[] = []
  if (items.length && headSize !== undefined && items[0]!.index !== headSize - 1) {
    issues.push({ index: items[0]!.index, text: `Neuester Eintrag ist ${items[0]!.index}, der Kopf nennt ${headSize} Einträge.` })
  }
  for (let i = 1; i < items.length; i++) {
    const prev = items[i - 1]!
    const cur = items[i]!
    if (cur.index !== prev.index - 1) issues.push({ index: cur.index, text: `Lücke oder Sprung zwischen ${prev.index} und ${cur.index}.` })
    if (Date.parse(cur.time) > Date.parse(prev.time)) issues.push({ index: cur.index, text: `Eintrag ${cur.index} ist jünger als ${prev.index}.` })
  }
  return issues
}

export async function checkEntry(entry: Pick<LogEntry, 'digest' | 'envelope'> & { envelope_sha256?: string | null }): Promise<EntryCheck> {
  const env = entry.envelope as { payload?: unknown } | null | undefined
  if (!env || typeof env.payload !== 'string') return 'no_envelope'
  try {
    if ((await digestOf(base64ToBytes(env.payload))) !== entry.digest) return 'mismatch'
    // The lab stores compact JSON envelopes; JSON.stringify of the parsed object gives the same bytes.
    if (entry.envelope_sha256 && (await digestOf(JSON.stringify(env))) !== entry.envelope_sha256) return 'mismatch'
    return 'ok'
  }
  catch {
    return 'error'
  }
}

/** Fields of a log entry that enter its leaf (contracts/log-tree.schema.json). */
export type TreeEntry = Pick<LogEntry, 'index' | 'time' | 'kind' | 'ref' | 'digest' | 'summary'> & { envelope_sha256?: string | null }

/** Canonical leaf data: line-based text, so Go, Python and the browser produce the same bytes. */
export function leafData(e: TreeEntry): string {
  return `schild.log-leaf/1\nindex:${e.index}\ntime:${e.time}\nkind:${e.kind}\nref:${e.ref}\ndigest:${e.digest}\nsummary:${e.summary}\nenvelope:${e.envelope_sha256 ?? ''}\n`
}

async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  const len = parts.reduce((n, p) => n + p.length, 0)
  const buf = new Uint8Array(len)
  let o = 0
  for (const p of parts) {
    buf.set(p, o)
    o += p.length
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf as BufferSource))
}

const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

/** RFC 6962 MTH over entries 0..n-1 (leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || l || r)). */
export async function treeRoot(entries: TreeEntry[]): Promise<string> {
  const enc = new TextEncoder()
  const leaves = await Promise.all(entries.map(e => sha256([new Uint8Array([0]), enc.encode(leafData(e))])))
  const mth = async (lo: number, hi: number): Promise<Uint8Array> => {
    const n = hi - lo
    if (n === 0) return sha256([])
    if (n === 1) return leaves[lo]!
    let k = 1
    while (k * 2 < n) k *= 2
    return sha256([new Uint8Array([1]), await mth(lo, lo + k), await mth(lo + k, hi)])
  }
  return `sha256:${hex(await mth(0, leaves.length))}`
}

export type RootCheck = 'ok' | 'mismatch' | 'incomplete'

/** Recomputes the root of the first `size` entries (any order in, index 0.. required) and compares. */
export async function checkRoot(entries: TreeEntry[], size: number, root: string): Promise<RootCheck> {
  const sorted = [...entries].sort((a, b) => a.index - b.index).slice(0, size)
  if (sorted.length !== size || sorted.some((e, i) => e.index !== i)) return 'incomplete'
  return (await treeRoot(sorted)) === root ? 'ok' : 'mismatch'
}

/** The log head {size, root} the newest checkpoint entry signs, if the entry carries its envelope. */
export function signedHead(entries: Pick<LogEntry, 'index' | 'kind' | 'envelope'>[]): { size: number, root: string, index: number } | null {
  const cps = entries.filter(e => e.kind === 'checkpoint' && e.envelope).sort((a, b) => b.index - a.index)
  for (const e of cps) {
    try {
      const env = e.envelope as { payload?: string }
      const payload = JSON.parse(new TextDecoder().decode(base64ToBytes(env.payload ?? ''))) as { log?: { size: number, root: string } }
      if (payload.log) return { ...payload.log, index: e.index }
    }
    catch {
      // not a readable checkpoint payload: try the next one
    }
  }
  return null
}
