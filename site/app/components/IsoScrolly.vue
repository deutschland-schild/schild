<script setup lang="ts">
// Scrollytelling with an isometric scene: step texts (real HTML) scroll past a large sticky SVG scene. The step in
// view drives the scene: which nodes are in focus, which connections carry a flow, which tags show, and where the
// "camera" looks. Same visual language as <SchildNetwork> (2:1 isometric floor, <IsoIcon> nodes, small HTML tags).
//
//   <IsoScrolly :steps="zeroDay" :scene="zeroDayScene" numbered bg="mist" />
//
// Desktop (lg): text column (~38 %) left, scene (~62 %) right, sticky over the full viewport height. Below lg: the
// scene sticks on top (~45 % of the viewport), the texts scroll below it. No card, no box: the floor fades out at the
// edges. The active step comes from an IntersectionObserver on a thin band of the viewport (no scroll listener).
// Motion uses transform and opacity only: eased crossfades, a gentle camera move toward the actors of the step,
// dots running along the flows. With prefers-reduced-motion: no camera, no dots, states just crossfade.
// The scene is a principle illustration; the SVG carries role="img" and an aria-label for the current step.
import type { IsoIconState, IsoIconType } from './IsoIcon.vue'

export interface ScrollyStep { who: string, text: string }
export interface ScrollyNode {
  id: string
  type: IsoIconType
  /** floor point in viewBox coordinates */
  x: number
  y: number
  scale?: number
  label?: string
  accent?: string
}
export interface ScrollyLink { id: string, from: string, to: string }
/** attack = red, signal = slate (with an envelope), check = blue, vote = blue, rule = green */
export type ScrollyFlowKind = 'attack' | 'signal' | 'check' | 'vote' | 'rule'
export interface ScrollyFlow {
  link: string
  kind: ScrollyFlowKind
  /** run from `to` to `from` */
  reverse?: boolean
  /** attack only: the ray ends at a Schild mark in front of the target */
  stop?: boolean
  delay?: number
}
export type ScrollyTone = 'red' | 'green' | 'amber' | 'slate' | 'blue' | 'ink'
export interface ScrollyTag {
  /** node id, or link id (tag sits on the middle of the link) */
  at: string
  text: string
  tone?: ScrollyTone
  dx?: number
  dy?: number
}
export interface ScrollyFrame {
  /** what the scene shows in this step, for the aria-label */
  aria: string
  /** nodes in focus; all others are dimmed */
  focus: string[]
  states?: Record<string, IsoIconState>
  busy?: string[]
  flows?: ScrollyFlow[]
  tags?: ScrollyTag[]
}
export interface ScrollyScene {
  /** short description of the whole scene, for the aria-label */
  title: string
  width: number
  height: number
  nodes: ScrollyNode[]
  links: ScrollyLink[]
  /** one frame per step */
  frames: ScrollyFrame[]
}


const props = withDefaults(defineProps<{
  steps: ScrollyStep[]
  scene: ScrollyScene
  /** prefix step labels with "1.", "2." … */
  numbered?: boolean
  caption?: string
  /** section background behind the sticky scene on small screens */
  bg?: 'white' | 'mist'
}>(), { numbered: false, caption: '', bg: 'white' })

const active = ref(0)
const frame = computed(() => props.scene.frames[Math.min(active.value, props.scene.frames.length - 1)]!)
// read after mount, so server and client render the same first frame (the CSS media query covers the gap)
const reduced = ref(false)
const uid = useId()

// ── Geometry ────────────────────────────────────────────────────────────────────────────────────────────────
type Pt = [number, number]
const byId = computed(() => Object.fromEntries(props.scene.nodes.map(n => [n.id, n])) as Record<string, ScrollyNode>)
const linkById = computed(() => Object.fromEntries(props.scene.links.map(l => [l.id, l])) as Record<string, ScrollyLink>)
const r1 = (n: number) => Math.round(n * 10) / 10
const pos = (id: string): Pt => { const n = byId.value[id]!; return [n.x, n.y] }
const ends = (l: ScrollyLink, reverse = false): [Pt, Pt] => reverse ? [pos(l.to), pos(l.from)] : [pos(l.from), pos(l.to)]
const line = (a: Pt, b: Pt) => `M${r1(a[0])},${r1(a[1])} L${r1(b[0])},${r1(b[1])}`
const lerp = (a: Pt, b: Pt, t: number): Pt => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t]
// a stopped attack ends this many px in front of the target
const STOP_GAP = 58
const stopPoint = (a: Pt, b: Pt): Pt => { const len = Math.hypot(b[0] - a[0], b[1] - a[1]) || 1; return lerp(a, b, Math.max(0, 1 - STOP_GAP / len)) }

// icon height (px at scale 1) – tags start above it
const TOP: Record<IsoIconType, number> = { 'website': 62, 'website-unprotected': 62, 'lab': 112, 'relay': 34, 'log': 40, 'dashboard': 52, 'visitor': 32, 'crawler': 58, 'botnet': 48, 'advisory': 54, 'unknown': 50, 'sources': 40 }

// The isometric floor (2:1), larger than the view so the camera never shows its end; faded out by a mask
const GRID = computed(() => {
  const { width: w, height: h } = props.scene
  const out: string[] = []
  const step = 40
  for (let c = -w - h * 2; c <= w * 2; c += step * 2) {
    out.push(line([c, -h], [c + h * 6, h * 2]))
    out.push(line([c, h * 2], [c + h * 6, -h]))
  }
  return out
})

// ── Camera: lean toward the nodes in focus, gently (scale 1 … 1.15) ───────────────────────────────────────────────
const camera = computed(() => {
  const { width: W, height: H } = props.scene
  if (reduced.value) return 'translate(0px, 0px) scale(1)'
  const ns = frame.value.focus.map(id => byId.value[id]).filter(Boolean) as ScrollyNode[]
  if (!ns.length) return 'translate(0px, 0px) scale(1)'
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity
  for (const n of ns) {
    const s = n.scale ?? 1
    x0 = Math.min(x0, n.x - 60 * s); x1 = Math.max(x1, n.x + 60 * s)
    y0 = Math.min(y0, n.y - TOP[n.type] * s - 40); y1 = Math.max(y1, n.y + 30 * s)
  }
  const s = Math.min(1.15, Math.max(1, Math.min(W / (x1 - x0), H / (y1 - y0)) * 0.8))
  // move the focus centre part of the way toward the middle (the floor is larger than the view and fades out)
  const cx = (x0 + x1) / 2, cy = (y0 + y1) / 2
  const tx = (W / 2 - s * cx) * 0.5 + (W - W * s) / 2 * 0.5
  const ty = (H / 2 - s * cy) * 0.5 + (H - H * s) / 2 * 0.5
  return `translate(${r1(tx)}px, ${r1(ty)}px) scale(${r1(s * 1000) / 1000})`
})

// ── Frame state ─────────────────────────────────────────────────────────────────────────────────────────────
const inFocus = (id: string) => frame.value.focus.includes(id)
const flowsOn = computed(() => (frame.value.flows ?? []).filter(f => linkById.value[f.link]))
const flowLinks = computed(() => new Set(flowsOn.value.map(f => f.link)))
const COLOR: Record<ScrollyFlowKind, string> = { attack: '#DC2626', signal: '#475569', check: '#2563EB', vote: '#2563EB', rule: '#0F873B' }
const BASE: Record<ScrollyFlowKind, string> = { attack: '#FCA5A5', signal: '#CBD5E1', check: '#93C5FD', vote: '#93C5FD', rule: '#6EE7B7' }
const flows = computed(() => flowsOn.value.map((f) => {
  const [a, b] = ends(linkById.value[f.link]!, f.reverse)
  const end = f.stop ? stopPoint(a, b) : b
  return { key: `${active.value}-${f.link}`, kind: f.kind, path: line(a, end), rest: lerp(a, end, 0.6), delay: f.delay ?? 0, dur: Math.max(1.2, Math.hypot(end[0] - a[0], end[1] - a[1]) / 140) }
}))
const stops = computed(() => flowsOn.value.filter(f => f.kind === 'attack' && f.stop).map((f) => {
  const [a, b] = ends(linkById.value[f.link]!, f.reverse)
  return { key: `${active.value}-${f.link}`, at: stopPoint(a, b) }
}))

const TONE: Record<ScrollyTone, string> = {
  red: 'border-red-200 bg-red-50 text-red-800',
  green: 'border-emerald-200 bg-signal-tint text-signal-deep',
  amber: 'border-amber-200 bg-amber-50 text-amber-900',
  slate: 'border-line bg-white text-ink',
  blue: 'border-blue-200 bg-blue-50 text-blue-800',
  ink: 'border-ink bg-ink text-white',
}
const TAG_W = 240
const TAG_H = 26
const tags = computed(() => {
  const stack: Record<string, number> = {}
  return (frame.value.tags ?? []).map((t, i) => {
    let anchor: Pt
    const n = byId.value[t.at]
    if (n) {
      const k = stack[t.at] = (stack[t.at] ?? -1) + 1
      anchor = [n.x, n.y - TOP[n.type] * (n.scale ?? 1) - 6 - k * (TAG_H + 4)]
    }
    else {
      const l = linkById.value[t.at]!
      const m = lerp(pos(l.from), pos(l.to), 0.5)
      anchor = [m[0], m[1] + TAG_H / 2]
    }
    return { key: `${active.value}-${i}`, x: anchor[0] + (t.dx ?? 0) - TAG_W / 2, y: anchor[1] + (t.dy ?? 0) - TAG_H, text: t.text, cls: TONE[t.tone ?? 'slate'] }
  })
})
const sortedNodes = computed(() => [...props.scene.nodes].sort((a, b) => a.y - b.y))
const ariaLabel = computed(() => `${props.scene.title} Schritt ${active.value + 1} von ${props.steps.length}: ${frame.value.aria}`)

// ── Active step: IntersectionObserver on a thin band of the viewport ────────────────────────────────────────
const items: HTMLElement[] = []
const setItem = (i: number) => (el: unknown) => { if (el) items[i] = el as HTMLElement }
let io: IntersectionObserver | undefined
onMounted(() => {
  const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
  reduced.value = mq.matches
  mq.addEventListener('change', e => (reduced.value = e.matches))
  // Below lg the scene sticks on top, so the reading band sits lower.
  const wide = window.matchMedia('(min-width: 1024px)').matches
  io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue
      const i = items.indexOf(e.target as HTMLElement)
      if (i >= 0) active.value = i
    }
  }, { rootMargin: wide ? '-48% 0px -48% 0px' : '-70% 0px -24% 0px' })
  for (const el of items) io.observe(el)
})
onBeforeUnmount(() => io?.disconnect())
</script>

<template>
  <div class="scrolly grid lg:grid-cols-[38fr_62fr] lg:gap-10" :class="reduced ? 'still' : ''">
    <!-- scene: sticky; on top on small screens, right and full height on large ones -->
    <figure
      class="sticky top-16 z-10 -mx-5 h-[45svh] py-2 sm:-mx-8 lg:order-2 lg:mx-0 lg:h-[calc(100svh-4rem)] lg:pt-8 lg:pb-14 lg:-mr-8 xl:mr-[calc((72rem-100vw)/2-2rem)]"
      :class="bg === 'mist' ? 'bg-mist lg:bg-transparent' : 'bg-white lg:bg-transparent'"
    >
      <svg
        :viewBox="`0 0 ${scene.width} ${scene.height}`" class="scene block size-full"
        role="img" :aria-label="ariaLabel" focusable="false"
      >
        <defs>
          <radialGradient :id="`${uid}-fade`" cx="50%" cy="50%" r="50%">
            <stop offset="55%" stop-color="#fff" />
            <stop offset="100%" stop-color="#fff" stop-opacity="0" />
          </radialGradient>
          <mask :id="`${uid}-floor`" maskUnits="userSpaceOnUse" :x="0" :y="0" :width="scene.width" :height="scene.height">
            <rect :width="scene.width" :height="scene.height" :fill="`url(#${uid}-fade)`" />
          </mask>
        </defs>
        <g :mask="`url(#${uid}-floor)`">
          <g class="camera" :style="{ transform: camera }">
            <g stroke="#E2E8F0" stroke-width="1" fill="none"><path v-for="(d, i) in GRID" :key="i" :d="d" /></g>
          </g>
        </g>

        <g class="camera" :style="{ transform: camera }">
          <!-- connections: faint dashed base, coloured line + moving dots for flows -->
          <g fill="none" stroke-linecap="round">
            <path
              v-for="l in scene.links" :key="`b-${l.id}`" :d="line(pos(l.from), pos(l.to))" stroke="#CBD5E1" stroke-width="1.5" stroke-dasharray="3 5"
              class="ease" :class="flowLinks.has(l.id) ? 'opacity-0' : 'opacity-50'"
            />
          </g>
          <TransitionGroup tag="g" name="soft">
            <g v-for="f in flows" :key="f.key" fill="none" stroke-linecap="round">
              <path :d="f.path" :stroke="BASE[f.kind]" stroke-width="2.5" />
              <template v-if="!reduced && f.kind !== 'signal'">
                <circle v-for="k in 3" :key="k" r="3.6" :fill="COLOR[f.kind]" stroke="#fff" stroke-width="1.2" opacity="0">
                  <animateMotion :path="f.path" :dur="`${f.dur}s`" :begin="`${f.delay + (k - 1) * f.dur / 3}s`" repeatCount="indefinite" calcMode="spline" keyTimes="0;1" keySplines="0.45 0 0.55 1" />
                  <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.15;0.85;1" :dur="`${f.dur}s`" :begin="`${f.delay + (k - 1) * f.dur / 3}s`" repeatCount="indefinite" />
                </circle>
              </template>
              <!-- signals travel as a small envelope; with reduced motion it rests on the line -->
              <g v-if="f.kind === 'signal'" :transform="reduced ? `translate(${r1(f.rest[0])},${r1(f.rest[1])})` : undefined" :opacity="reduced ? 1 : 0">
                <rect x="-9" y="-6.5" width="18" height="13" rx="2" fill="#FFFFFF" stroke="#475569" stroke-width="1.4" />
                <path d="M-8.5 -5.5 0 1l8.5-6.5" stroke="#475569" stroke-width="1.4" stroke-linejoin="round" />
                <template v-if="!reduced">
                  <animateMotion :path="f.path" :dur="`${f.dur * 1.4}s`" :begin="`${f.delay}s`" repeatCount="indefinite" calcMode="spline" keyTimes="0;1" keySplines="0.45 0 0.55 1" />
                  <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.12;0.85;1" :dur="`${f.dur * 1.4}s`" :begin="`${f.delay}s`" repeatCount="indefinite" />
                </template>
              </g>
            </g>
          </TransitionGroup>

          <!-- nodes, back to front; a state change crossfades -->
          <g v-for="n in sortedNodes" :key="n.id" class="ease" :class="inFocus(n.id) ? 'opacity-100' : 'opacity-35'">
            <Transition name="soft">
              <IsoIcon
                :key="`${frame.states?.[n.id] ?? 'normal'}-${!!frame.busy?.includes(n.id)}`"
                :type="n.type" :state="frame.states?.[n.id] ?? 'normal'" :busy="!reduced && !!frame.busy?.includes(n.id)" :accent="n.accent" :x="n.x" :y="n.y" :scale="n.scale ?? 1"
              />
            </Transition>
            <text v-if="n.label" :x="n.x" :y="n.y + 24 * (n.scale ?? 1) + 6" text-anchor="middle" class="node-label">{{ n.label }}</text>
          </g>

          <!-- Schild stops the attack in front of the website -->
          <TransitionGroup tag="g" name="pop">
            <g v-for="s in stops" :key="s.key" :transform="`translate(${r1(s.at[0])},${r1(s.at[1])})`">
              <g class="shield">
                <circle r="20" fill="#0F873B" fill-opacity=".14" />
                <BrandMark x="-15" y="-16" width="30" height="30" shield="#0F873B" />
              </g>
            </g>
          </TransitionGroup>

          <!-- tags -->
          <TransitionGroup tag="g" name="rise">
            <foreignObject v-for="t in tags" :key="t.key" :x="t.x" :y="t.y" :width="TAG_W" :height="TAG_H" class="overflow-visible">
              <div class="flex h-full items-end justify-center">
                <span class="tag" :class="t.cls">{{ t.text }}</span>
              </div>
            </foreignObject>
          </TransitionGroup>
        </g>
      </svg>
      <!-- small screens: texts scroll softly under the scene -->
      <div class="pointer-events-none absolute inset-x-0 top-full h-8 bg-gradient-to-b lg:hidden" :class="bg === 'mist' ? 'from-mist' : 'from-white'" aria-hidden="true" />
      <figcaption v-if="caption" class="absolute bottom-3 left-5 text-xs text-slate max-lg:sr-only lg:left-0">{{ caption }}</figcaption>
    </figure>

    <!-- steps: real HTML, each one a scroll stop, centred in the viewport when active -->
    <ol class="relative pt-6 lg:order-1 lg:pt-0 lg:pb-[8svh]">
      <li
        v-for="(s, i) in steps" :key="i" :ref="setItem(i)"
        class="ease flex min-h-[55svh] items-center lg:min-h-[78svh]"
        :class="i === active ? 'opacity-100' : 'opacity-25'"
        :aria-current="i === active ? 'step' : undefined"
      >
        <div class="max-w-md">
          <p class="text-sm font-semibold text-signal-deep">{{ numbered ? `${i + 1}. ` : '' }}{{ s.who }}</p>
          <p class="mt-2 text-lg leading-snug text-ink sm:text-xl lg:text-2xl lg:leading-snug">{{ s.text }}</p>
        </div>
      </li>
    </ol>
    <p v-if="caption" class="pb-4 text-xs text-slate lg:hidden">{{ caption }}</p>
  </div>
</template>

<style scoped>
/* one easing for everything: calm, no bounce */
.scrolly { --ease: cubic-bezier(0.22, 1, 0.36, 1); }
.ease { transition: opacity 600ms var(--ease); }
.camera { transform-origin: 0 0; transition: transform 900ms var(--ease); will-change: transform; }
/* no box: the scene fades out softly at its edges */
.scene {
  --fade-y: linear-gradient(to bottom, transparent, #000 7%, #000 86%, transparent);
  --fade-x: linear-gradient(to right, transparent, #000 7%, #000 93%, transparent);
  -webkit-mask-image: var(--fade-y), var(--fade-x); -webkit-mask-composite: source-in;
  mask-image: var(--fade-y), var(--fade-x); mask-composite: intersect;
}
.node-label { font-size: 12px; font-weight: 600; fill: var(--color-ink); paint-order: stroke; stroke: #fff; stroke-width: 4px; stroke-linejoin: round; }
.tag { display: inline-block; max-width: 100%; border-width: 1px; border-radius: 9999px; padding: 2px 9px; font-size: 12px; font-weight: 600; line-height: 1.5; white-space: nowrap; box-shadow: 0 1px 2px rgb(10 26 51 / 0.06); }

/* crossfade (states, flows) */
.soft-enter-active, .soft-leave-active { transition: opacity 600ms var(--ease); }
.soft-enter-from, .soft-leave-to { opacity: 0; }
/* tags rise in, fade out */
.rise-enter-active { transition: opacity 600ms var(--ease) 150ms, transform 600ms var(--ease) 150ms; }
.rise-leave-active { transition: opacity 300ms var(--ease); }
.rise-enter-from { opacity: 0; transform: translateY(8px); }
.rise-leave-to { opacity: 0; }
/* the Schild mark grows in where the attack ends */
.shield { transform-box: fill-box; transform-origin: center; }
.pop-enter-active { transition: opacity 500ms var(--ease) 400ms; }
.pop-enter-active .shield { transition: transform 600ms var(--ease) 400ms; }
.pop-leave-active { transition: opacity 300ms var(--ease); }
.pop-enter-from, .pop-leave-to { opacity: 0; }
.pop-enter-from .shield { transform: scale(.6); }

/* no motion: no camera, no dots (not rendered), states just crossfade */
.still .camera { transition: none; }
.still .rise-enter-from, .still .pop-enter-from .shield { transform: none; }
@media (prefers-reduced-motion: reduce) {
  .camera { transition: none; }
  .rise-enter-from, .pop-enter-from .shield { transform: none; }
}
</style>
