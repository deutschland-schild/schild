<script setup lang="ts">
// Isoflow-style diagram of the Schild network (concepts 13, 20, 21), rebuilt in Vue/SVG without the React editor.
// Node drawings come from <IsoIcon> (own isoflow-style icons). Topology is a peer-to-peer ring, not a stack: five
// Labs of different, independent operators form a full mesh in the middle (no centre node, no headquarters), and
// every website talks to three Labs, each through a different relay of the relay ring between Labs and websites. A
// relay sees the sending server's IP but not the encrypted content (OHTTP-style), a Lab sees the content but never
// the server's IP; that only holds if no single relay carries everything. Rules come back the same way, so nothing
// is a single point of failure. Signals never contain visitor IPs (decision E4). Every Lab keeps its own public log,
// cross-witnessed by the others. Around the Schild team lies the open internet: visitors,
// crawlers, a botnet and servers without Schild. Dashed nodes are placeholders – the drawn ones are examples.
// One numbered journey of five steps tells the story for admins; it starts by itself when the diagram scrolls into
// view (not with reduced motion), pauses on hover/focus or when a step is picked, and loops. Sample data.

// ── Isometric grid (2:1, like isoflow) ──────────────────────────────────────────────────────────────────────
const HW = 40 // half tile width
const HH = 20 // half tile height
const OX = 600
const OY = 400
type Pt = [number, number]
const iso = (gx: number, gy: number, z = 0): Pt => [OX + (gx - gy) * HW, OY + (gx + gy) * HH - z]
const pts = (list: Pt[]) => list.map(p => p.map(n => Math.round(n * 10) / 10).join(',')).join(' ')
// Floor position given as screen offset from the centre → grid coordinates.
const floor = (x: number, y: number): Pt => [(x / HW + y / HH) / 2, (y / HH - x / HW) / 2]
// Point on an isometric circle (rx = 2 * ry) around the centre, angle in screen degrees.
const ring = (rx: number, deg: number): Pt => floor(rx * Math.cos(deg * Math.PI / 180), rx / 2 * Math.sin(deg * Math.PI / 180))
const at = (g: Pt, z = 0) => iso(g[0], g[1], z)

// ── Scene ───────────────────────────────────────────────────────────────────────────────────────────────────
type Vote = 'proposer' | 'confirm' | 'none'
interface Lab { id: string, label: string, operator: string, color: string, vote: Vote, offset: number, g: Pt }
const LAB_R = 330
const LABS: Lab[] = [
  { id: 'uni', label: 'Hochschul-Lab', operator: 'Hochschule', color: '#6366F1', vote: 'proposer', offset: 0, g: ring(LAB_R, -126) },
  { id: 'hoster', label: 'Hoster-Lab', operator: 'Hoster', color: '#0EA5E9', vote: 'confirm', offset: 5, g: ring(LAB_R, -54) },
  { id: 'community', label: 'Community-Lab', operator: 'Community', color: '#14B8A6', vote: 'confirm', offset: 6, g: ring(LAB_R, 18) },
  { id: 'verein', label: 'Vereins-Lab', operator: 'Verein', color: '#A855F7', vote: 'none', offset: 5, g: ring(LAB_R, 90) },
  { id: 'cert', label: 'CERT-Lab', operator: 'CERT', color: '#64748B', vote: 'confirm', offset: 5, g: ring(LAB_R, 162) },
]
// Relays: one ring between the Lab ring and the website ring, each relay in the gap between two neighbouring Labs
// (positions nudged by hand where the flat isometric ellipse leaves little room). A relay only forwards to its two
// neighbouring Labs, so the lines stay short and never cross the middle.
const RELAY_R = 455
const RELAYS = [
  { id: 'r1', g: ring(390, -90), labs: ['uni', 'hoster'] }, // top: the ellipse is flat here, so a bit further in
  { id: 'r2', g: ring(420, -12), labs: ['hoster', 'community'] },
  { id: 'r3', g: ring(RELAY_R, 30), labs: ['community', 'verein'] },
  { id: 'r4', g: ring(RELAY_R, 70), labs: ['community', 'verein'] },
  { id: 'r5', g: ring(RELAY_R, 110), labs: ['verein', 'cert'] },
  { id: 'r6', g: ring(RELAY_R, 150), labs: ['verein', 'cert'] },
  { id: 'r7', g: ring(420, 192), labs: ['cert', 'uni'] },
]
const CLIENT_R = 530
const CLIENTS = [
  { name: 'buchhaltungstool.example', deg: -90 },
  { name: 'arztpraxis-meyer.example', deg: -30 },
  { name: 'hof-berger.example', deg: 10 },
  { name: 'wiesenbrunner-bote.example', deg: 50 },
  { name: 'tischlerei-schulz.example', deg: 90 },
  { name: 'tsv-wiesenbrunn.example', deg: 130 },
  { name: 'alex-blogt.example', deg: 170 },
  { name: 'mueller-maschinenbau.example', deg: 210 },
].map(c => ({ ...c, id: `c-${c.name}`, g: ring(CLIENT_R, c.deg) }))
const FIRST_HIT = 2 // step 2: the botnet hits this website first
const LATER_HITS = [2, 5] // step 5: the next attack bounces off the Schild in front of these (labels must not cover the ray)
// the open internet: one row outside the Schild team, side by side
const OUTER_Y = 375
const VISITORS = floor(-490, OUTER_Y)
const CRAWLER = floor(-300, OUTER_Y)
const UNPROTECTED = [
  { name: 'steuerkanzlei-wolf.example', g: floor(-110, OUTER_Y) },
  { name: 'fahrschule-krause.example', g: floor(170, OUTER_Y) },
]
const ATTACKER = floor(440, OUTER_Y)
const HIT_UNPROTECTED = 1 // the botnet also hits this server without Schild
// dashed placeholders: more websites, Labs and unprotected servers than drawn
const GHOST_CLIENTS = [190, -10].map(deg => ring(CLIENT_R, deg))
const GHOST_LABS = [54, 126].map(deg => ring(LAB_R, deg))
const GHOST_OUTER = [floor(40, OUTER_Y - 6), floor(290, OUTER_Y - 6)]
const PROPOSER = LABS.find(l => l.vote === 'proposer')!
const OFFLINE_LAB = 'hoster'

// ── Edges (straight lines on the floor). Forward flow = a → b, i.e. from the Lab towards the website ─────────
// mesh: Lab ↔ Lab · down: Lab → relay (a = Lab, b = relay) · up: relay → website (a = relay, b = website)
type Kind = 'mesh' | 'down' | 'up'
interface Edge { id: string, a: string, b: string, kind: Kind, lab: string }
const POS: Record<string, Pt> = {}
for (const l of LABS) POS[l.id] = l.g
for (const r of RELAYS) POS[r.id] = r.g
for (const c of CLIENTS) POS[c.id] = c.g
const dist = (p: Pt, q: Pt) => { const a = at(p), b = at(q); return Math.hypot(a[0] - b[0], a[1] - b[1]) }
const EDGES: Edge[] = []
LABS.forEach((l, i) => LABS.slice(i + 1).forEach(m => EDGES.push({ id: `${l.id}-${m.id}`, a: l.id, b: m.id, kind: 'mesh', lab: '' })))
// every website reports to three Labs (different operators): one may fail or lie, the signal still arrives. It uses
// its three nearest relays on the ring, each forwarding to one of its neighbouring Labs, so no relay sees all of a
// website's traffic and no line crosses the middle.
const SIGNAL_LABS = 3
interface Route { client: string, relay: string, lab: string }
const ROUTES: Route[] = []
CLIENTS.forEach((c) => {
  // three relays next to the website, each forwarding to one of its two neighbouring Labs, three different Labs
  const relays = RELAYS.map(r => ({ r, d: dist(r.g, c.g) })).sort((x, y) => x.d - y.d).slice(0, SIGNAL_LABS).map(x => x.r)
  const best = Array.from({ length: 2 ** SIGNAL_LABS }, (_, bits) => bits)
    .map(bits => relays.map((r, k) => ({ relay: r.id, lab: r.labs[(bits >> k) & 1]! })))
    .filter(rs => new Set(rs.map(x => x.lab)).size === SIGNAL_LABS)
    .map(rs => ({ rs, d: rs.reduce((sum, x) => sum + dist(POS[x.relay]!, POS[x.lab]!) + 0.3 * dist(c.g, POS[x.lab]!), 0) }))
    .sort((x, y) => x.d - y.d)[0]!.rs
  best.forEach(x => ROUTES.push({ client: c.id, relay: x.relay, lab: x.lab }))
})
for (const r of ROUTES) {
  EDGES.push({ id: `${r.relay}-${r.client}`, a: r.relay, b: r.client, kind: 'up', lab: r.lab })
  if (!EDGES.some(e => e.id === `${r.lab}-${r.relay}`)) EDGES.push({ id: `${r.lab}-${r.relay}`, a: r.lab, b: r.relay, kind: 'down', lab: r.lab })
}
const edgeLine = (e: Edge) => { const a = at(POS[e.a]!), b = at(POS[e.b]!); return `M${a.join(',')} L${b.join(',')}` }
const lineTo = (from: Pt, to: Pt) => { const a = at(from), b = at(to); return `M${a.join(',')} L${b.join(',')}` }
const routesOf = (clientId: string) => ROUTES.filter(r => r.client === clientId)
const labsOf = (clientId: string) => routesOf(clientId).map(r => r.lab)
const onRoute = (e: Edge, clientIds: string[]) => ROUTES.some(r => clientIds.includes(r.client)
  && ((e.kind === 'up' && e.a === r.relay && e.b === r.client) || (e.kind === 'down' && e.a === r.lab && e.b === r.relay)))

const GRID = (() => {
  const lines: string[] = []
  for (let x = -12; x <= 12; x++) lines.push(pts([iso(x, -12), iso(x, 12)]))
  for (let y = -12; y <= 12; y++) lines.push(pts([iso(-12, y), iso(12, y)]))
  return lines
})()
const ringPoly = (rx: number) => pts(Array.from({ length: 72 }, (_, i) => { const g = ring(rx, i * 5); return at(g) }))

// ── Sandbox jobs (parallel verification) ────────────────────────────────────────────────────────────────────
interface Job { req: string, result: string, ok: boolean }
const PROPOSER_JOBS: Job[] = [
  { req: 'Signal auswerten', result: 'Galerie-Plugin < 2.4.1', ok: true },
  { req: 'Angriff nachstellen', result: 'Lücke bestätigt', ok: true },
  { req: 'KI entwirft Regel', result: 'Regel vorgeschlagen', ok: true },
]
const VERIFY_JOBS: Job[] = [
  { req: 'Angriff shell.php', result: '403 geblockt', ok: true },
  { req: 'Upload avatar.png', result: '200 durch', ok: true },
  { req: '48.000 echte Anfragen', result: '0 Fehlalarme', ok: true },
]
const NONE_JOBS: Job[] = [
  { req: 'Plugin installieren', result: 'nicht im Testlab', ok: false },
]
const jobsOf = (l: Lab) => l.vote === 'proposer' ? PROPOSER_JOBS : l.vote === 'confirm' ? VERIFY_JOBS : NONE_JOBS

// ── Journey ─────────────────────────────────────────────────────────────────────────────────────────────────
const threshold = ref(3)
const confirmations = LABS.filter(l => l.vote !== 'none').length
const live = computed(() => confirmations >= threshold.value)

const step = ref(0)
const cycle = ref(0) // bumps on every (re)entry of a step so pulses and jobs replay
const STEPS = computed<{ short: string, title: string, text: string }[]>(() => [
  { short: 'Selbstschutz', title: 'Jeder Server schützt sich selbst.', text: 'Schild prüft jede Anfrage direkt auf der Website. Meist passiert hier nichts.' },
  { short: 'Angriff', title: 'Ein Angriff trifft eine Website.', text: 'Sie blockt, was sie kennt, und meldet das neue Muster pseudonym an drei Labs, jedes über ein anderes Relay.' },
  { short: 'Labs prüfen', title: 'Mehrere Labs prüfen gleichzeitig.', text: 'Unabhängige Betreiber prüfen das Muster, jedes Lab in seiner eigenen Sandbox.' },
  live.value
    ? { short: 'Konsens', title: 'Genug Labs stimmen zu, die Regel gilt.', text: `${confirmations} von ${LABS.length} Labs bestätigen, nötig sind ${threshold.value}.` }
    : { short: 'Konsens', title: 'Zu wenig Bestätigungen, die Regel wartet.', text: `${confirmations} von ${LABS.length} Labs bestätigen, nötig sind ${threshold.value}. Bis dahin zählt sie nur mit.` },
  live.value
    ? { short: 'Regel verteilen', title: 'Die Regel wird an alle verteilt.', text: 'Über mehrere Relays. Auch wenn ein Lab ausfällt, hat jede Website noch zwei weitere.' }
    : { short: 'Regel verteilen', title: 'Ohne Konsens wird nur gezählt.', text: 'Die Grundregeln greifen weiter, die neue Regel sperrt noch nichts.' },
])
const current = computed(() => STEPS.value[step.value]!)

// Jobs in step 3 (index 2): driven by the journey clock (see Autoplay), one tick per TICK_MS.
const TICK_MS = 300
const tick = ref(0)
const resolvesAt = (l: Lab, i: number) => l.offset + i + 2
const jobState = (l: Lab, i: number): 'waiting' | 'running' | 'done' =>
  step.value !== 2 || tick.value >= resolvesAt(l, i) ? 'done' : tick.value < l.offset ? 'waiting' : 'running'
const labDone = (l: Lab) => jobsOf(l).every((_, i) => jobState(l, i) === 'done')
const runningJobs = (l: Lab) => step.value === 2 ? jobsOf(l).filter((_, i) => jobState(l, i) === 'running').length : 0
const confirmedSoFar = computed(() => LABS.filter(l => l.vote !== 'none' && (step.value > 2 || labDone(l))).length)
const labDoneAt = (l: Lab) => (resolvesAt(l, jobsOf(l).length - 1) * TICK_MS) / 1000 + 0.1

// step 2: the report reaches the three Labs when its second pulse (relay → Lab) lands; step 4: logs get the entry
// after the vote wave
const reportArrived = computed(() => tick.value * TICK_MS >= 2400)
const logWritten = computed(() => step.value > 3 || tick.value * TICK_MS >= 1200)

const outage = computed(() => step.value === 4)
const offline = (id: string) => outage.value && id === OFFLINE_LAB
const edgeDown = (e: Edge) => offline(e.a) || offline(e.b) || offline(e.lab)
const firstHitId = CLIENTS[FIRST_HIT]!.id
const firstHitLabs = labsOf(firstHitId)
const firstHitRelays = routesOf(firstHitId).map(r => r.relay)

function labStatus(l: Lab): { text: string, cls: string } {
  const s = step.value
  if (offline(l.id)) return { text: 'offline', cls: 'bg-slate-200 text-slate' }
  if (s === 1) return firstHitLabs.includes(l.id) && reportArrived.value ? { text: 'Signal erhalten', cls: 'bg-slate-100 text-ink' } : { text: 'gleichberechtigt', cls: 'bg-slate-100 text-slate' }
  if (s === 2) {
    if (jobState(l, 0) === 'waiting') return { text: 'wartet auf Vorschlag', cls: 'bg-slate-100 text-slate' }
    if (!labDone(l)) return l.vote === 'proposer' ? { text: 'analysiert …', cls: 'bg-sky-100 text-sky-800' } : { text: 'prüft …', cls: 'bg-amber-100 text-amber-900' }
  }
  if (s >= 2) {
    if (l.vote === 'proposer') return { text: 'Vorschlag', cls: 'bg-signal text-on-signal' }
    return l.vote === 'confirm' ? { text: '✓ bestätigt', cls: 'bg-signal text-on-signal' } : { text: 'kein Befund', cls: 'bg-slate-100 text-slate' }
  }
  return { text: 'gleichberechtigt', cls: 'bg-slate-100 text-slate' }
}
function labIcon(l: Lab) {
  if (offline(l.id)) return 'offline'
  return step.value >= 2 && l.vote !== 'none' && labDone(l) ? 'active' : 'normal'
}

type ClientState = 'idle' | 'signal' | 'active' | 'shadow' | 'blocked' | 'counted'
const rulePublished = computed(() => step.value === 4 && live.value)
const shadowOnly = computed(() => step.value === 4 && !live.value)
function clientState(i: number): ClientState {
  if (step.value === 1 && i === FIRST_HIT) return 'signal'
  if (step.value === 4 && LATER_HITS.includes(i)) return live.value ? 'blocked' : 'counted'
  if (rulePublished.value) return 'active'
  if (shadowOnly.value) return 'shadow'
  return 'idle'
}
const CLIENT_ICON = { idle: 'protected', signal: 'attacked', active: 'active', shadow: 'pending', blocked: 'active', counted: 'pending' } as const
const CLIENT_BADGE: Record<ClientState, { text: string, cls: string } | null> = {
  idle: null,
  signal: { text: 'neu! Signal an 3 Labs', cls: 'bg-red-100 text-red-800' },
  active: { text: 'Regel 0412 aktiv', cls: 'bg-signal-tint text-signal-deep' },
  shadow: { text: 'Probelauf', cls: 'bg-amber-100 text-amber-900' },
  blocked: { text: 'abgewehrt', cls: 'bg-signal-deep text-white' },
  counted: { text: 'nur gezählt', cls: 'bg-amber-100 text-amber-900' },
}
const attackTargets = computed(() => step.value === 1 ? [FIRST_HIT] : step.value === 4 ? LATER_HITS : [])
const unprotectedHit = computed(() => step.value === 4)
// Step 5: the attack ray stops at a green Schild mark just in front of the website (instead of a red 403).
const SHIELD_GAP = 62 // px in front of the website, along the ray
const shieldPoint = (i: number): [number, number] => {
  const a = at(ATTACKER), b = at(CLIENTS[i]!.g, 20)
  const len = Math.hypot(b[0] - a[0], b[1] - a[1])
  return [b[0] - (b[0] - a[0]) / len * SHIELD_GAP, b[1] - (b[1] - a[1]) / len * SHIELD_GAP]
}
const deflected = (i: number) => step.value === 4 && live.value && LATER_HITS.includes(i)
const rayTo = (i: number) => deflected(i) ? `M${at(ATTACKER).join(',')} L${shieldPoint(i).join(',')}` : lineTo(ATTACKER, CLIENTS[i]!.g)

// Pulses: by default nothing moves. Only when a signal has to be evaluated does a short laser-like streak run
// along a connection, once. forward = a → b (Lab → website), reverse = towards the Lab. delay in seconds.
// Every way between website and Lab has two legs (via a relay): the second leg starts HOP s after the first.
interface Pulse { color: string, reverse?: boolean, delay: number }
const SLATE = '#475569', GREEN = '#0F873B', RED = '#DC2626', BLUE = '#2563EB'
const HOP = 0.6
const ATTACK_DELAY = computed(() => step.value === 4 ? 1.2 : 0.2)
const pulses = computed<Record<string, Pulse[]>>(() => {
  const s = step.value
  const f: Record<string, Pulse[]> = {}
  const add = (pred: (e: Edge) => boolean, p: (e: Edge) => Pulse) => { for (const e of EDGES) if (pred(e) && !edgeDown(e)) (f[e.id] ??= []).push(p(e)) }
  if (s === 1) {
    add(e => e.kind === 'up' && onRoute(e, [firstHitId]), () => ({ color: SLATE, reverse: true, delay: 0.9 }))
    add(e => e.kind === 'down' && onRoute(e, [firstHitId]), () => ({ color: SLATE, reverse: true, delay: 0.9 + HOP }))
  }
  else if (s === 2) {
    // proposal from the proposer, then each Lab sends its vote the moment its own checks are done
    add(e => e.kind === 'mesh' && (e.a === PROPOSER.id || e.b === PROPOSER.id), e => ({ color: BLUE, reverse: e.b === PROPOSER.id, delay: labDoneAt(PROPOSER) }))
    for (const l of LABS) {
      if (l.vote !== 'confirm') continue
      add(e => e.kind === 'mesh' && (e.a === l.id || e.b === l.id), e => ({ color: BLUE, reverse: e.b === l.id, delay: labDoneAt(l) }))
    }
  }
  else if (s === 3 && live.value) {
    // the vote goes round, then the Labs witness each other's log entry
    add(e => e.kind === 'mesh', () => ({ color: BLUE, delay: 0.2 }))
    add(e => e.kind === 'mesh', () => ({ color: BLUE, reverse: true, delay: 1.5 }))
  }
  else if (s === 4) {
    const ruleColor = live.value ? GREEN : '#D97706'
    add(e => e.kind === 'down', () => ({ color: ruleColor, delay: 0.2 }))
    add(e => e.kind === 'up', () => ({ color: ruleColor, delay: 0.2 + HOP }))
    const hit = LATER_HITS.map(i => CLIENTS[i]!.id)
    add(e => e.kind === 'up' && onRoute(e, hit), () => ({ color: SLATE, reverse: true, delay: 2.0 }))
    add(e => e.kind === 'down' && onRoute(e, hit), () => ({ color: SLATE, reverse: true, delay: 2.0 + HOP }))
  }
  return f
})
const pulseKey = computed(() => `${step.value}-${threshold.value}-${cycle.value}`)

// Highlight: each step shows the parts it is about and dims the rest.
type Part = 'labs' | 'logs' | 'mesh' | 'links' | 'relays' | 'clients' | 'dash' | 'visitors' | 'crawler' | 'unprotected' | 'botnet'
const STEP_PARTS: Part[][] = [
  ['clients', 'links', 'relays', 'dash', 'visitors', 'crawler'],
  ['botnet', 'clients', 'links', 'relays', 'labs'],
  ['labs', 'mesh'],
  ['labs', 'logs', 'mesh'],
  ['labs', 'logs', 'mesh', 'links', 'relays', 'clients', 'dash', 'visitors', 'crawler', 'unprotected', 'botnet'],
]
const dim = (p: Part) => STEP_PARTS[step.value]!.includes(p) ? '' : 'dimmed'
// step 2 focuses on one website, its three relays and its three Labs
const dimClient = (i: number) => step.value === 1 ? (i === FIRST_HIT ? '' : 'dimmed') : dim('clients')
const dimEdge = (e: Edge) => {
  if (step.value === 1) return e.kind !== 'mesh' && onRoute(e, [firstHitId]) ? '' : 'dimmed'
  return dim(e.kind === 'mesh' ? 'mesh' : 'links')
}
const dimRelay = (id: string) => step.value === 1 ? (firstHitRelays.includes(id) ? '' : 'dimmed') : dim('relays')
const dimLab = (l: Lab) => step.value === 1 ? (firstHitLabs.includes(l.id) ? '' : 'dimmed') : dim('labs')

// ── Autoplay ────────────────────────────────────────────────────────────────────────────────────────────────
// One clock drives everything: `elapsed` (ms into the current step) advances per animation frame while the
// journey runs. It fills the progress bar (written straight to the DOM, no re-render per frame), derives the job
// ticks of step 3, and switches steps. The short CSS pulses start with their step and are paused together with
// the clock, so they stay in sync. Every step lasts exactly STEP_MS, the loop has no extra pause.
const STEP_MS = 5000
const root = ref<HTMLElement>()
const inView = ref(false)
const hovered = ref(false)
const userPaused = ref(false)
const preview = ref(false) // a picked step plays once to its end, then holds
const running = computed(() => inView.value && !hovered.value && !userPaused.value)
const clockOn = computed(() => running.value || preview.value)
let elapsed = 0
let raf = 0
let lastFrame = 0
let bar: HTMLElement | null = null
function paint() {
  if (bar) bar.style.transform = `scaleX(${Math.min(elapsed / STEP_MS, 1)})`
  const t = Math.floor(elapsed / TICK_MS)
  if (tick.value !== t) tick.value = t
}
const setBar = (el: unknown) => { bar = el as HTMLElement | null; paint() }
function enter(i: number) { elapsed = 0; step.value = i; cycle.value++; paint() }
function frame(now: number) {
  elapsed += lastFrame ? Math.min(now - lastFrame, 100) : 0 // clamp: no jumps after a hidden tab
  lastFrame = now
  if (elapsed >= STEP_MS) {
    if (running.value) enter((step.value + 1) % STEPS.value.length)
    else { elapsed = STEP_MS; preview.value = false } // picked step done: hold
  }
  paint()
  if (clockOn.value) raf = requestAnimationFrame(frame)
}
watch(clockOn, (on) => {
  cancelAnimationFrame(raf)
  lastFrame = 0
  if (on) raf = requestAnimationFrame(frame)
})
function go(i: number) { userPaused.value = true; preview.value = true; enter(i) }
function togglePlay() {
  if (userPaused.value) { userPaused.value = false; inView.value = true }
  else { userPaused.value = true; preview.value = false }
}
function onFocusOut(ev: FocusEvent) { if (!root.value?.contains(ev.relatedTarget as Node)) hovered.value = false }

let io: IntersectionObserver | undefined
const scroller = ref<HTMLElement>()
onMounted(() => {
  // reduced motion: no autoplay, show step 1 with a play button
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) userPaused.value = true
  io = new IntersectionObserver(([entry]) => { inView.value = !!entry?.isIntersecting }, { threshold: 0.35 })
  if (root.value) io.observe(root.value)
  // On narrow screens the diagram scrolls horizontally: start centred on the ring.
  const el = scroller.value
  if (el && el.scrollWidth > el.clientWidth) el.scrollLeft = (el.scrollWidth - el.clientWidth) / 2
})
onBeforeUnmount(() => { cancelAnimationFrame(raf); io?.disconnect() })

// Labels: HTML in foreignObject, anchored above a point with a stem.
const LABEL_W = 150
const labelBox = (anchor: Pt, lift: number) => ({ x: anchor[0] - LABEL_W / 2, y: anchor[1] - lift - 220, stemTop: anchor[1] - lift, stemBottom: anchor[1] - 2 })
const LAB_TOP = 116 // icon height (incl. flask) in px at scale 1.15
const LAB_SCALE = 1.15
const CLIENT_TOP = 60
const labelBelow = (deg: number) => deg > 30 && deg < 150

// Legend ("Was ist was")
const LEGEND = [
  { type: 'website', state: 'protected', label: 'Website mit Schild' },
  { type: 'website-unprotected', state: 'normal', label: 'Website ohne Schild' },
  { type: 'lab', state: 'normal', label: 'Lab' },
  { type: 'relay', state: 'normal', label: 'Relay' },
  { type: 'visitor', state: 'normal', label: 'Besucher:innen' },
  { type: 'crawler', state: 'normal', label: 'Crawler, KI-Bot' },
  { type: 'botnet', state: 'normal', label: 'Botnetz' },
] as const


const legendOpen = ref(false)
</script>

<template>
  <div
    ref="root" class="rounded-xl border border-line bg-white" :class="clockOn ? '' : 'halted'"
    @mouseenter="hovered = true" @mouseleave="hovered = false" @focusin="hovered = true" @focusout="onFocusOut"
  >
    <!-- explanation: one headline, one sentence -->
    <div class="min-h-[4.5rem] px-4 pt-4 pb-1 sm:px-5" :aria-live="running ? 'off' : 'polite'">
      <h3 class="text-base leading-snug font-semibold sm:text-lg">{{ current.title }}</h3>
      <p class="mt-0.5 text-sm leading-relaxed text-slate">
        {{ current.text }}
      </p>
    </div>

    <!-- player: play/pause, prev/next, timeline with five segments -->
    <div class="flex items-center gap-2 border-b border-line px-3 py-3 sm:gap-3 sm:px-5">
      <button
        type="button" class="grid size-11 shrink-0 place-items-center rounded-full bg-ink text-white transition hover:bg-ink-800"
        :aria-label="userPaused ? 'Abspielen' : 'Anhalten'" @click="togglePlay"
      >
        <svg v-if="userPaused" viewBox="0 0 16 16" class="ml-0.5 size-4" aria-hidden="true"><path d="M4 2.5v11l9-5.5z" fill="currentColor" /></svg>
        <svg v-else viewBox="0 0 16 16" class="size-4" aria-hidden="true"><path d="M4 2.5h3v11H4zM9 2.5h3v11H9z" fill="currentColor" /></svg>
      </button>
      <ol class="grid min-w-0 flex-1 grid-cols-5 gap-1.5 sm:gap-2" aria-label="Ablauf in fünf Schritten">
        <li v-for="(s, i) in STEPS" :key="i">
          <button type="button" class="group block w-full py-1 text-left" :aria-current="i === step ? 'step' : undefined" :aria-label="`Schritt ${i + 1}: ${s.short}`" @click="go(i)">
            <span class="relative block h-1.5 overflow-hidden rounded-full bg-line transition group-hover:bg-slate/40">
              <span v-if="i < step" class="absolute inset-0 rounded-full bg-ink" />
              <span v-else-if="i === step" :key="`bar-${cycle}-${step}`" :ref="setBar" class="progress absolute inset-0 rounded-full bg-signal" />
            </span>
            <span class="mt-1.5 block truncate text-[12px] font-semibold max-sm:hidden" :class="i === step ? 'text-ink' : 'text-slate'">{{ i + 1 }} · {{ s.short }}</span>
          </button>
        </li>
      </ol>
      <span class="shrink-0 font-mono text-xs text-slate max-sm:hidden">{{ step + 1 }}/{{ STEPS.length }}</span>
    </div>

    <!-- diagram -->
    <div class="relative">
    <div ref="scroller" class="overflow-x-auto">
      <p class="pointer-events-none sticky left-0 z-10 px-4 pt-2 text-xs text-slate sm:hidden">← seitlich wischen →</p>
      <svg viewBox="-70 -30 1340 950" class="mx-auto block h-auto max-h-[calc(100svh-18rem)] w-full min-w-[600px] sm:max-h-[calc(100svh-15rem)] sm:min-w-[760px]" role="img" :aria-label="`Diagramm: innen das Schild-Team mit fünf gleichberechtigten Labs verschiedener Betreiber, voll vernetzt, darum die Websites mit Schild. Jede Website ist mit drei Labs verbunden, jede Verbindung läuft über ein anderes Relay: Das Relay sieht die IP des Servers, aber nicht den Inhalt, das Lab sieht den Inhalt, aber nicht die IP. Auch Regeln kommen über mehrere Relays zurück. Außen das offene Netz mit Besuchern, Crawlern, Websites ohne Schild und einem Botnetz. Schritt ${step + 1}: ${current.title}`">
        <!-- floor -->
        <g stroke="#EEF2F6" stroke-width="1"><polyline v-for="(l, i) in GRID" :key="i" :points="l" fill="none" /></g>
        <polygon :points="ringPoly(CLIENT_R + 70)" fill="#F5F9FF" stroke="#93C5FD" stroke-width="1.6" />
        <polygon :points="ringPoly(RELAY_R)" fill="none" stroke="#CBD5E1" stroke-width="1.2" stroke-dasharray="3 6" :class="dim('relays')" />
        <polygon :points="ringPoly(LAB_R + 70)" fill="#F4FBF8" stroke="#A7F3D0" stroke-width="1.2" stroke-dasharray="5 4" :class="dim('labs')" />

        <!-- edges: grey base line, laser pulses on top; dashed when a Lab is offline -->
        <g fill="none" stroke-linecap="round">
          <path v-for="e in EDGES" :key="`b-${e.id}`" :d="edgeLine(e)" :stroke="e.kind === 'mesh' ? '#A7D7C5' : '#CBD5E1'" :stroke-width="e.kind === 'mesh' ? 3 : 2.5" :stroke-dasharray="edgeDown(e) ? '2 6' : undefined" :stroke-opacity="edgeDown(e) ? 0.6 : 0.9" :class="dimEdge(e)" />
          <template v-for="e in EDGES" :key="`f-${e.id}`">
            <template v-for="(pl, k) in pulses[e.id] ?? []" :key="`${pulseKey}-${e.id}-${k}`">
              <path :d="edgeLine(e)" pathLength="100" :stroke="pl.color" stroke-width="11" stroke-opacity=".25" class="pulse" :class="[pl.reverse ? 'pulse-reverse' : '', dimEdge(e)]" :style="{ animationDelay: `${pl.delay}s` }" />
              <path :d="edgeLine(e)" pathLength="100" :stroke="pl.color" stroke-width="3.5" class="pulse" :class="[pl.reverse ? 'pulse-reverse' : '', dimEdge(e)]" :style="{ animationDelay: `${pl.delay}s` }" />
            </template>
          </template>
          <!-- attacks from the botnet -->
          <g v-for="i in attackTargets" :key="`att-${i}`">
            <path :d="rayTo(i)" stroke="#FECACA" stroke-width="3" />
            <path :key="`att-p-${pulseKey}`" :d="rayTo(i)" pathLength="100" :stroke="RED" stroke-width="3" class="pulse" :style="{ animationDelay: `${ATTACK_DELAY}s` }" />
          </g>
          <template v-if="unprotectedHit">
            <path :d="lineTo(ATTACKER, UNPROTECTED[HIT_UNPROTECTED]!.g)" stroke="#FECACA" stroke-width="3" />
            <path :key="`att-u-${pulseKey}`" :d="lineTo(ATTACKER, UNPROTECTED[HIT_UNPROTECTED]!.g)" pathLength="100" :stroke="RED" stroke-width="3" class="pulse" :style="{ animationDelay: `${ATTACK_DELAY}s` }" />
          </template>
        </g>

        <!-- dashed placeholders: the drawn nodes are only examples -->
        <IsoIcon v-for="(g, i) in GHOST_CLIENTS" :key="`gc-${i}`" type="website" state="ghost" :x="at(g)[0]" :y="at(g)[1]" :scale="1.15" :class="dim('clients')" />
        <IsoIcon v-for="(g, i) in GHOST_LABS" :key="`gl-${i}`" type="lab" state="ghost" :x="at(g)[0]" :y="at(g)[1]" :scale="LAB_SCALE" :class="dim('labs')" />
        <IsoIcon v-for="(g, i) in GHOST_OUTER" :key="`go-${i}`" type="website-unprotected" state="ghost" :x="at(g)[0]" :y="at(g)[1]" :scale="1.1" :class="dim('unprotected')" />

        <!-- labs -->
        <template v-for="l in LABS" :key="l.id">
          <IsoIcon type="lab" :state="labIcon(l)" :accent="l.color" :busy="runningJobs(l) > 0" :x="at(l.g)[0]" :y="at(l.g)[1]" :scale="LAB_SCALE" :class="[dimLab(l), offline(l.id) ? 'offline' : '']" />
        </template>

        <!-- relays: between Labs and websites -->
        <IsoIcon v-for="r in RELAYS" :key="r.id" type="relay" :x="at(r.g)[0]" :y="at(r.g)[1]" :scale="0.85" :class="dimRelay(r.id)" />

        <!-- websites with Schild -->
        <IsoIcon v-for="(c, i) in CLIENTS" :key="c.name" type="website" :state="CLIENT_ICON[clientState(i)]" :x="at(c.g)[0]" :y="at(c.g)[1]" :scale="1.15" :class="dimClient(i)" />

        <!-- step 5: Schild deflects the red attack ray -->
        <template v-for="i in LATER_HITS" :key="`shield-${i}-${pulseKey}`">
          <g v-if="deflected(i)" :transform="`translate(${shieldPoint(i).join(',')})`">
            <g class="deflect" :style="{ animationDelay: `${ATTACK_DELAY + 0.45}s` }">
              <circle r="30" fill="#0F873B" fill-opacity=".14" />
              <path d="M-16 -22l-10 -8M-24 0h-13M-16 22l-10 8" stroke="#F87171" stroke-width="3" stroke-linecap="round" class="sparks" />
              <BrandMark x="-22" y="-24" width="44" height="44" shield="#0F873B" />
            </g>
          </g>
        </template>


        <!-- the open internet: visitors, crawler, servers without Schild, botnet -->
        <IsoIcon type="visitor" :x="at(VISITORS)[0]" :y="at(VISITORS)[1]" :scale="1.3" :class="dim('visitors')" />
        <IsoIcon type="crawler" :x="at(CRAWLER)[0]" :y="at(CRAWLER)[1]" :scale="1.1" :class="dim('crawler')" />
        <IsoIcon v-for="(u, i) in UNPROTECTED" :key="u.name" type="website-unprotected" :state="unprotectedHit && i === HIT_UNPROTECTED ? 'attacked' : 'normal'" :x="at(u.g)[0]" :y="at(u.g)[1]" :scale="1.15" :class="dim('unprotected')" />
        <IsoIcon type="botnet" :x="at(ATTACKER)[0]" :y="at(ATTACKER)[1]" :scale="1.35" :class="dim('botnet')" />

        <!-- labels (on top) -->
        <g class="zone-label text-[12px] font-semibold">
          <text :x="OX" :y="at(LABS[0]!.g)[1] + 38" text-anchor="middle" fill="#0B6E30" :class="dim('labs')">Labs tauschen sich aus</text>
          <text x="26" y="58" class="text-[14px]" fill="#1D4ED8">Innen: das Schild-Team</text>
          <text x="26" y="76" class="font-normal" fill="#475569">Websites mit Schild und Labs, Peer-to-Peer</text>
          <text x="26" y="94" class="font-normal" fill="#475569">Dazwischen Relays, je Verbindung ein anderes</text>
          <!-- relay names; in step 2 the used relays say what they see -->
          <template v-for="r in RELAYS" :key="`relay-label-${r.id}`">
            <g :class="dimRelay(r.id)">
              <text :x="at(r.g)[0]" :y="at(r.g)[1] + 24" text-anchor="middle" fill="#475569">Relay</text>
              <text v-if="step === 1 && firstHitRelays.includes(r.id)" :x="at(r.g)[0]" :y="at(r.g)[1] + 40" text-anchor="middle" class="font-normal" fill="#475569">sieht IP, nicht Inhalt</text>
            </g>
          </template>
          <text x="26" y="845" class="text-[14px]" fill="#475569">Außen: das offene Netz</text>
          <text x="1174" y="58" text-anchor="end" class="font-normal" fill="#475569">Gestrichelt: nur angedeutet.</text>
          <text x="1174" y="76" text-anchor="end" class="font-normal" fill="#475569">Im Netz sind es Millionen Server.</text>
        </g>
        <g class="text-ink">
          <template v-for="l in LABS" :key="`lab-label-${l.id}`">
            <g :class="dimLab(l)">
              <line :x1="at(l.g)[0]" :x2="at(l.g)[0]" :y1="labelBox(at(l.g, LAB_TOP), 10).stemTop" :y2="labelBox(at(l.g, LAB_TOP), 10).stemBottom" stroke="#94A3B8" />
              <foreignObject :x="labelBox(at(l.g, LAB_TOP), 10).x" :y="labelBox(at(l.g, LAB_TOP), 10).y" :width="LABEL_W" height="220" class="overflow-visible">
                <div class="flex h-full flex-col justify-end">
                  <div class="label" :class="offline(l.id) ? 'opacity-60' : ''" :style="step === 2 ? { borderColor: l.color, boxShadow: `inset 3px 0 0 ${l.color}` } : undefined">
                    <p class="flex items-center gap-1.5 truncate font-semibold"><span class="size-2 shrink-0 rotate-45 rounded-[1px]" :style="{ background: l.color }" />{{ l.label }}</p>
                    <ul v-if="step === 2" class="mt-1 space-y-0.5 font-mono text-[10px] leading-tight">
                      <li v-for="(j, k) in jobsOf(l)" :key="k" class="flex items-center gap-1.5">
                        <span class="size-1.5 shrink-0 rounded-full" :class="jobState(l, k) === 'running' ? 'bg-amber-500 blink' : jobState(l, k) === 'waiting' ? 'bg-slate/30' : j.ok ? 'bg-signal' : 'bg-slate/40'" />
                        <span class="truncate" :class="jobState(l, k) !== 'done' ? 'text-slate' : j.ok ? 'text-signal-deep' : 'text-slate'">{{ jobState(l, k) === 'done' ? j.result : j.req }}</span>
                      </li>
                    </ul>
                    <p v-if="step >= 3 && !offline(l.id)" class="mt-1 font-mono text-[10px]" :class="l.vote !== 'none' && live && logWritten ? 'text-signal-deep' : 'text-slate'">{{ l.vote !== 'none' && live && logWritten ? 'eigenes Log: + 0412' : 'eigenes Log, bezeugt andere' }}</p>
                    <p class="mt-1 flex items-center gap-1.5">
                      <span class="inline-block rounded-full px-1.5 py-0.5 text-[10px] font-semibold whitespace-nowrap" :class="labStatus(l).cls">{{ labStatus(l).text }}</span>
                      <span v-if="runningJobs(l)" class="font-mono text-[10px] whitespace-nowrap text-amber-700">{{ runningJobs(l) }} {{ runningJobs(l) === 1 ? 'läuft' : 'laufen' }}</span>
                    </p>
                  </div>
                </div>
              </foreignObject>
            </g>
          </template>

          <template v-for="(c, i) in CLIENTS" :key="`client-label-${c.name}`">
            <!-- websites in the lower half carry their label below, so it does not cover the Labs -->
            <foreignObject :x="Math.min(Math.max(labelBox(at(c.g, CLIENT_TOP), 6).x - 40, -20), 1200 - LABEL_W - 60)" :y="labelBelow(c.deg) ? at(c.g)[1] + 24 : labelBox(at(c.g, CLIENT_TOP), 6).y" :width="LABEL_W + 80" :height="labelBelow(c.deg) ? 60 : 220" class="overflow-visible" :class="dimClient(i)">
              <div class="flex h-full flex-col items-center" :class="labelBelow(c.deg) ? 'justify-start' : 'justify-end'">
                <div class="label text-center">
                  <p class="font-mono text-[12px] font-semibold whitespace-nowrap">{{ c.name }}</p>
                  <span v-if="CLIENT_BADGE[clientState(i)]" class="mt-0.5 inline-block rounded-full px-1.5 py-0.5 text-[11px] font-semibold" :class="CLIENT_BADGE[clientState(i)]!.cls">{{ CLIENT_BADGE[clientState(i)]!.text }}</span>
                </div>
              </div>
            </foreignObject>
          </template>


          <!-- labels of the open internet, below the row -->
          <foreignObject :x="at(VISITORS)[0] - 80" :y="at(VISITORS)[1] + 18" width="160" height="60" class="overflow-visible" :class="dim('visitors')">
            <div class="flex justify-center"><p class="label font-semibold">Besucher:innen</p></div>
          </foreignObject>
          <foreignObject :x="at(CRAWLER)[0] - 80" :y="at(CRAWLER)[1] + 18" width="160" height="60" class="overflow-visible" :class="dim('crawler')">
            <div class="flex justify-center"><p class="label font-semibold">Crawler, KI-Bots</p></div>
          </foreignObject>
          <foreignObject v-for="(u, i) in UNPROTECTED" :key="`ul-${u.name}`" :x="at(u.g)[0] - 80" :y="at(u.g)[1] + 18" width="160" height="60" class="overflow-visible" :class="dim('unprotected')">
            <div class="flex justify-center">
              <div class="label text-center">
                <p class="font-mono text-[12px] font-semibold whitespace-nowrap">{{ u.name }}</p>
                <span class="mt-0.5 inline-block rounded-full px-1.5 py-0.5 text-[11px] font-semibold" :class="unprotectedHit && i === HIT_UNPROTECTED ? 'bg-red-100 text-red-800' : 'bg-slate-100 text-slate'">{{ unprotectedHit && i === HIT_UNPROTECTED ? 'getroffen, kein Schutz' : 'ohne Schild' }}</span>
              </div>
            </div>
          </foreignObject>
          <foreignObject :x="at(ATTACKER)[0] - 80" :y="at(ATTACKER)[1] + 22" width="160" height="60" class="overflow-visible" :class="dim('botnet')">
            <div class="flex justify-center"><p class="label font-semibold" :class="attackTargets.length ? 'border-red-300 text-red-700' : ''">Botnetz</p></div>
          </foreignObject>
        </g>
      </svg>
    </div>

    <!-- legend: collapsible panel on the right, outside the horizontal scroller -->
    <button
      type="button" class="absolute top-2 right-2 z-20 inline-flex items-center gap-1.5 rounded-lg border border-line bg-white/95 px-3 py-1.5 text-[13px] font-semibold shadow-sm backdrop-blur transition hover:border-slate"
      :aria-expanded="legendOpen" aria-controls="net-legend" @click="legendOpen = !legendOpen"
    >
      {{ legendOpen ? 'Legende schließen' : 'Legende' }}
      <svg class="size-3.5 transition" :class="legendOpen && 'rotate-180'" viewBox="0 0 16 16" aria-hidden="true"><path d="M10 3 5 8l5 5" fill="none" stroke="currentColor" stroke-width="2" /></svg>
    </button>
    <aside
      v-show="legendOpen" id="net-legend"
      class="absolute top-12 right-2 bottom-2 z-20 w-[min(18rem,calc(100%-1rem))] overflow-y-auto rounded-xl border border-line bg-white/97 p-4 shadow-lg backdrop-blur"
      aria-label="Legende"
    >
      <p class="text-[12px] font-semibold text-slate">Was ist was</p>
      <ul class="mt-2 grid gap-1.5">
        <li v-for="it in LEGEND" :key="it.label" class="flex items-center gap-2 text-[13px] text-ink">
          <IsoIcon :type="it.type" :state="it.state" standalone :size="30" />{{ it.label }}
        </li>
      </ul>
      <p class="mt-4 text-[12px] font-semibold text-slate">Linien</p>
      <ul class="mt-2 grid gap-1.5 text-[12px] text-slate">
        <li class="flex items-center gap-2"><span class="legend" style="--c:#DC2626" />Angriff</li>
        <li class="flex items-center gap-2"><BrandMark class="size-[22px]" shield="#0F873B" />Schild wehrt ab</li>
        <li class="flex items-center gap-2"><span class="legend" style="--c:#64748B" />Meldung einer Website, über ein Relay</li>
        <li class="flex items-center gap-2"><span class="legend" style="--c:#2563EB" />Abstimmung zwischen Labs</li>
        <li class="flex items-center gap-2"><span class="legend" style="--c:#0F873B" />geprüfte Regel an alle, über Relays</li>
      </ul>
      <p class="mt-4 text-xs leading-snug text-slate">
        Beispiel mit erfundenen Websites und Betreibern. Gestrichelt: stellvertretend für viele weitere Server und Labs.
        Jede Website meldet an mindestens 3 Labs, jedes Mal über ein anderes Relay. Das Relay sieht, von welchem Server
        die Meldung kommt, aber nicht den Inhalt. Das Lab sieht den Inhalt, aber nicht die IP des Servers. Besucher-IPs
        stehen in keiner Meldung. Für eine Regel stimmen netzweit nie unter 2 Labs zu, jeder Server kann erhöhen.
      </p>
    </aside>
    </div>
  </div>
</template>

<style scoped>
.zone-label text { paint-order: stroke; stroke: #fff; stroke-width: 4px; stroke-linejoin: round; }
.label { display: inline-block; border: 1px solid var(--color-line); background: #fff; border-radius: 8px; padding: 5px 8px; font-size: 13px; line-height: 1.3; box-shadow: 0 1px 2px rgb(10 26 51 / 0.06); max-width: 100%; }
/* one short streak per pulse, then gone (pathLength = 100) */
.pulse { stroke-dasharray: 22 230; stroke-dashoffset: 22; animation: pulse 0.9s cubic-bezier(.45, 0, .25, 1) both; }
.pulse-reverse { animation-name: pulse-reverse; }
@keyframes pulse { from { stroke-dashoffset: 22; } to { stroke-dashoffset: -100; } }
@keyframes pulse-reverse { from { stroke-dashoffset: -100; } to { stroke-dashoffset: 22; } }
.blink { animation: blink 0.7s ease-in-out infinite alternate; }
@keyframes blink { from { opacity: 1; } to { opacity: 0.25; } }
.dimmed { opacity: 0.22; transition: opacity 0.3s; }
.offline { opacity: 0.45; filter: grayscale(1); }
.legend { display: inline-block; width: 22px; height: 3px; border-radius: 2px; background: linear-gradient(90deg, transparent, var(--c)); }
.progress { transform-origin: left; transform: scaleX(0); }
/* the Schild mark pops up where the attack ray ends, sparks fly back */
.deflect { transform-box: fill-box; transform-origin: center; opacity: 0; transform: scale(.5); animation: deflect .35s cubic-bezier(.34, 1.56, .64, 1) both; }
@keyframes deflect { to { opacity: 1; transform: scale(1); } }
/* pulses and blinking pause together with the journey clock */
.halted .pulse, .halted .blink, .halted .deflect { animation-play-state: paused; }
@media (prefers-reduced-motion: reduce) {
  .blink { animation: none; }
  .deflect { animation: none; opacity: 1; transform: none; }
  /* no motion: show the pulse path as a static highlight instead */
  .pulse { animation: none; stroke-dasharray: none; stroke-dashoffset: 0; }
}
</style>
