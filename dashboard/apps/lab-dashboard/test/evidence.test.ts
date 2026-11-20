import { describe, expect, it } from 'vitest'
import { actionsUpTo, dominatedOpenPatterns, evidenceLevel, labCapReasons, ladder, levelWithApproval, missingFor } from '../src/lib/evidence'

const E = (o: Partial<Parameters<typeof evidenceLevel>[1]> = {}) => ({ reproduced_operators: 0, sensor_operators: 0, tip_issuers: 0, max_issuer_share: 1, human_approval_orgs: 0, ...o })

describe('evidence ladder (G2, mirrors contract/msg.EvidenceLevel)', () => {
  it.each([
    ['nothing', 'virtual_patch', E(), null],
    ['tips from 2 issuers', 'heuristic', E({ tip_issuers: 2, max_issuer_share: 0.3 }), null],
    ['tips from 3 issuers, one dominant', 'heuristic', E({ tip_issuers: 3, max_issuer_share: 0.35 }), null],
    ['tips from 3 issuers at 34 %', 'heuristic', E({ tip_issuers: 3, max_issuer_share: 0.34 }), 'observe'],
    ['sensors of 1 operator', 'heuristic', E({ sensor_operators: 1 }), 'observe'],
    ['sensors of 2 operators', 'behavioral', E({ sensor_operators: 2 }), 'challenge'],
    ['1 reproduction', 'virtual_patch', E({ reproduced_operators: 1 }), 'challenge'],
    ['2 reproductions, 1 org', 'virtual_patch', E({ reproduced_operators: 2, human_approval_orgs: 1 }), 'challenge'],
    ['2 reproductions, 2 orgs', 'virtual_patch', E({ reproduced_operators: 2, human_approval_orgs: 2 }), 'block'],
    ['behavioral never blocks', 'behavioral', E({ reproduced_operators: 5, human_approval_orgs: 5 }), 'challenge'],
    ['heuristic never blocks', 'heuristic', E({ reproduced_operators: 2, human_approval_orgs: 2 }), 'challenge'],
  ] as const)('%s', (_name, cls, e, want) => {
    expect(evidenceLevel(cls, e)).toBe(want)
  })

  it('explains in plain words why block is not possible (usability task L3)', () => {
    const e = E({ reproduced_operators: 1, sensor_operators: 1, tip_issuers: 3, max_issuer_share: 0.33 })
    const why = missingFor('block', 'virtual_patch', e)
    expect(why).toEqual([
      'Reproduziert hat bisher 1 Lab-Betreiber, nötig sind 2 verschiedene.',
      'Freigegeben haben bisher 0 Organisationen, nötig sind 2.',
    ])
    expect(missingFor('challenge', 'virtual_patch', e)).toEqual([])
    expect(missingFor('block', 'behavioral', e)[0]).toContain('Nur virtuelle Patches')
  })

  it('names a dominant issuer for observe', () => {
    expect(missingFor('observe', 'heuristic', E({ tip_issuers: 4, max_issuer_share: 0.41 })).join(' ')).toContain('41 %')
  })

  it('an approval from a new organisation can unlock block, the same organisation cannot', () => {
    const e = E({ reproduced_operators: 2, human_approval_orgs: 1 })
    expect(levelWithApproval('virtual_patch', e, 'org-b', ['org-a'], 'challenge')).toBe('block')
    expect(levelWithApproval('virtual_patch', e, 'org-a', ['org-a'], 'challenge')).toBe('challenge')
    expect(levelWithApproval('virtual_patch', E({ reproduced_operators: 1 }), 'org-b', [], 'challenge')).toBe('challenge')
  })

  it('never exceeds the server-allowed level otherwise', () => {
    // Server says observe although the local count would allow challenge: trust the server.
    expect(levelWithApproval('heuristic', E({ reproduced_operators: 1 }), 'org-b', [], 'observe')).toBe('observe')
    expect(levelWithApproval('heuristic', E(), 'org-b', [], null)).toBeNull()
  })

  it('lists actions up to a level', () => {
    expect(actionsUpTo(null)).toEqual([])
    expect(actionsUpTo('challenge')).toEqual(['observe', 'challenge'])
  })

  it('marks reached steps of the ladder', () => {
    const steps = ladder('virtual_patch', E({ reproduced_operators: 1 }))
    expect(steps.map(s => s.reached)).toEqual([true, true, false])
    expect(steps[2]!.mode).toBe('all')
  })
})

describe('labCapReasons', () => {
  it('explains the negative corpus gate and the simulated operators cap', () => {
    const e = E({ reproduced_operators: 1, tip_issuers: 3, max_issuer_share: 0.3 })
    expect(labCapReasons('virtual_patch', e, 'observe')[0]).toContain('Negativkorpus')
    expect(labCapReasons('virtual_patch', { ...e, negative_corpus: { version: 'c-1', matches: 2 } }, 'observe')[0]).toContain('2 Treffer')
    expect(labCapReasons('virtual_patch', { ...e, negative_corpus: { version: 'c-1', matches: 0 } }, 'observe')[0]).toContain('simulierte Betreiber')
    expect(labCapReasons('virtual_patch', { ...e, negative_corpus: { version: 'c-1', matches: 0 } }, 'challenge')).toEqual([])
    expect(labCapReasons('virtual_patch', E({ tip_issuers: 3, max_issuer_share: 0.3 }), 'observe')).toEqual([])
  })
})

describe('dominated open patterns (pattern list quick answer)', () => {
  it('counts only new or watching patterns above the 34 % limit, not proposed or published ones', () => {
    const items = [
      { status: 'published', max_issuer_share: 0.471 },
      { status: 'proposed', max_issuer_share: 0.5 },
      { status: 'new', max_issuer_share: 0.41 },
      { status: 'watching', max_issuer_share: 0.34 },
      { status: 'ignored', max_issuer_share: 0.9 },
    ]
    expect(dominatedOpenPatterns(items).map(p => p.status)).toEqual(['new'])
  })
})
