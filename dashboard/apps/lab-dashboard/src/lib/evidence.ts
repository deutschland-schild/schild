import type { Evidence, MaxAction, ProposalClass } from '@/api/types'

/**
 * Evidence ladder (concept 18 G2), mirrored from contract/msg.EvidenceLevel.
 * The server's allowed_max_action stays authoritative; the UI uses this only to explain and to
 * never offer an action above what the evidence allows.
 *
 *   block:     class virtual_patch, reproduced by >= 2 operators, human approval in >= 2 organisations
 *   challenge: reproduced by >= 1 operator, or own sensors of >= 2 operators
 *   observe:   any of the above, own sensors of 1 operator, or tips from >= 3 issuers with max share <= 0.34
 */
export const ACTIONS: MaxAction[] = ['observe', 'challenge', 'block']

export const MIN_TIP_ISSUERS = 3
export const MAX_ISSUER_SHARE = 0.34

export function actionRank(a: MaxAction | null | undefined): number {
  return a ? ACTIONS.indexOf(a) + 1 : 0
}

type EvidenceCounts = Pick<Evidence, 'reproduced_operators' | 'sensor_operators' | 'tip_issuers' | 'max_issuer_share' | 'human_approval_orgs'>

export function evidenceLevel(cls: ProposalClass, e: EvidenceCounts): MaxAction | null {
  if (cls === 'virtual_patch' && e.reproduced_operators >= 2 && e.human_approval_orgs >= 2) return 'block'
  if (e.reproduced_operators >= 1 || e.sensor_operators >= 2) return 'challenge'
  if (e.sensor_operators >= 1 || (e.tip_issuers >= MIN_TIP_ISSUERS && e.max_issuer_share <= MAX_ISSUER_SHARE)) return 'observe'
  return null
}

/** The lower of two actions (null is below observe). */
export function minAction(a: MaxAction | null | undefined, b: MaxAction | null | undefined): MaxAction | null {
  return actionRank(a) <= actionRank(b) ? (a ?? null) : (b ?? null)
}

/** Actions up to and including `level`. */
export function actionsUpTo(level: MaxAction | null | undefined): MaxAction[] {
  return ACTIONS.slice(0, actionRank(level))
}

/**
 * Highest action an approval by `org` could set. A new organisation's approval counts as one more
 * human approval; the result never exceeds what the evidence then allows, and never exceeds the
 * server's allowed level unless it is exactly that extra approval that unlocks block.
 */
export function levelWithApproval(cls: ProposalClass, e: EvidenceCounts, org: string, approvedOrgs: string[], serverAllowed: MaxAction | null): MaxAction | null {
  const isNewOrg = !!org && !approvedOrgs.includes(org)
  const simulated = evidenceLevel(cls, { ...e, human_approval_orgs: e.human_approval_orgs + (isNewOrg ? 1 : 0) })
  // Trust the server for everything except the approval-dependent block step.
  if (simulated === 'block' && actionRank(serverAllowed) >= actionRank('challenge')) return 'block'
  return minAction(simulated, serverAllowed)
}

export interface Requirement {
  text: string
  met: boolean
  /** e.g. "1 von 2" */
  progress?: string
}

export interface LadderStep {
  action: MaxAction
  /** 'any': one requirement suffices; 'all': every requirement is needed. */
  mode: 'any' | 'all'
  requirements: Requirement[]
  reached: boolean
}

const share = (n: number) => `${Math.round(n * 100)} %`

export function ladder(cls: ProposalClass, e: EvidenceCounts): LadderStep[] {
  const level = evidenceLevel(cls, e)
  return [
    {
      action: 'observe',
      mode: 'any',
      reached: actionRank(level) >= 1,
      requirements: [
        { text: 'Eigene Sensoren bei mindestens 1 Lab-Betreiber', met: e.sensor_operators >= 1, progress: `${e.sensor_operators} von 1` },
        {
          text: `Hinweise von mindestens ${MIN_TIP_ISSUERS} Bürgen, keiner über ${share(MAX_ISSUER_SHARE)}`,
          met: e.tip_issuers >= MIN_TIP_ISSUERS && e.max_issuer_share <= MAX_ISSUER_SHARE,
          progress: `${e.tip_issuers} Bürgen, größter Anteil ${share(e.max_issuer_share)}`,
        },
      ],
    },
    {
      action: 'challenge',
      mode: 'any',
      reached: actionRank(level) >= 2,
      requirements: [
        { text: 'Reproduktion bei mindestens 1 Lab-Betreiber', met: e.reproduced_operators >= 1, progress: `${e.reproduced_operators} von 1` },
        { text: 'Eigene Sensoren bei mindestens 2 Lab-Betreibern', met: e.sensor_operators >= 2, progress: `${e.sensor_operators} von 2` },
      ],
    },
    {
      action: 'block',
      mode: 'all',
      reached: actionRank(level) >= 3,
      requirements: [
        { text: 'Klasse „virtueller Patch“ (Verhaltensmuster sperren nie aus dem Netz)', met: cls === 'virtual_patch' },
        { text: 'Reproduktion bei mindestens 2 Lab-Betreibern', met: e.reproduced_operators >= 2, progress: `${e.reproduced_operators} von 2` },
        { text: 'Menschliche Freigabe in mindestens 2 Organisationen', met: e.human_approval_orgs >= 2, progress: `${e.human_approval_orgs} von 2` },
      ],
    },
  ]
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/** Plain-language reasons why `target` is not (yet) allowed. Empty when it is allowed. */
export function missingFor(target: MaxAction, cls: ProposalClass, e: EvidenceCounts, opts: { withOwnApproval?: boolean } = {}): string[] {
  const level = evidenceLevel(cls, e)
  if (actionRank(level) >= actionRank(target)) return []
  const out: string[] = []
  if (target === 'block') {
    if (cls !== 'virtual_patch') {
      out.push('Nur virtuelle Patches dürfen aus dem Netz sperren. Dieses Muster bleibt höchstens bei Challenge.')
      return out
    }
    if (e.reproduced_operators < 2) {
      out.push(`Reproduziert hat bisher ${plural(e.reproduced_operators, 'Lab-Betreiber', 'Lab-Betreiber')}, nötig sind 2 verschiedene.`)
    }
    if (e.human_approval_orgs < 2) {
      out.push(opts.withOwnApproval
        ? `Mit deiner Freigabe sind es ${plural(e.human_approval_orgs, 'Organisation', 'Organisationen')}, nötig sind 2.`
        : `Freigegeben haben bisher ${plural(e.human_approval_orgs, 'Organisation', 'Organisationen')}, nötig sind 2.`)
    }
    return out
  }
  if (target === 'challenge') {
    out.push(`Es fehlt eine Reproduktion (bisher ${e.reproduced_operators}) oder eigene Sensoren bei 2 Lab-Betreibern (bisher ${e.sensor_operators}).`)
    return out
  }
  // observe
  if (e.tip_issuers < MIN_TIP_ISSUERS) out.push(`Hinweise kommen bisher von ${plural(e.tip_issuers, 'Bürgen', 'Bürgen')}, nötig sind ${MIN_TIP_ISSUERS}.`)
  if (e.max_issuer_share > MAX_ISSUER_SHARE) out.push(`Ein Bürge trägt ${share(e.max_issuer_share)} der Hinweise, erlaubt sind höchstens ${share(MAX_ISSUER_SHARE)}.`)
  if (e.sensor_operators < 1) out.push('Eigene Sensoren haben das Muster noch nicht gesehen.')
  return out
}

/**
 * Why the lab allows less than the G2 table (`evidenceLevel`) would: the lab's own gates, mirrored
 * from lab/internal/rules (Engine.Level). Above observe needs a negative corpus run without hits
 * (G3 gate 1); independence that exists only through simulated operators caps at observe (E5).
 * Empty when the server's level is not below the table's level.
 */
export function labCapReasons(cls: ProposalClass, e: EvidenceCounts & Pick<Evidence, 'negative_corpus'>, allowed: MaxAction | null): string[] {
  const table = evidenceLevel(cls, e)
  if (actionRank(table) <= actionRank(allowed) || actionRank(table) <= actionRank('observe')) return []
  const corpus = e.negative_corpus
  if (!corpus) return ['Es fehlt ein Lauf gegen den Negativkorpus. Ohne ihn bleibt jede Regel bei Beobachten (Beleg anhängen: Negativkorpus).']
  if ((corpus.matches ?? 0) > 0) return [`Der Negativkorpus ${corpus.version ?? ''} hat ${corpus.matches} Treffer bei harmlosen Anfragen. Mit Treffern bleibt die Regel bei Beobachten.`.replace('  ', ' ')]
  return ['Die Unabhängigkeit besteht nur über simulierte Betreiber (Testprofil). Dann bleibt es bei Beobachten.']
}

/**
 * Patterns that still depend on tips alone (status new or watching) and where one issuer carries more than
 * MAX_ISSUER_SHARE of the window. Proposed or published patterns are left out: their proposal rests on the labs'
 * own evidence (reproduction, sensors), so a dominant tip issuer does not hold them back and counting them as
 * "über Grenze" would read like a broken gate.
 */
export function dominatedOpenPatterns<T extends { status: string, max_issuer_share: number }>(items: T[]): T[] {
  return items.filter(p => (p.status === 'new' || p.status === 'watching') && p.max_issuer_share > MAX_ISSUER_SHARE)
}
