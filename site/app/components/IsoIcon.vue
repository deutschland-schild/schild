<script setup lang="ts">
// Isoflow-style isometric icons for the Schild network (own drawings in the visual language of isoflow:
// 2:1 isometric grid, light top faces, darker sides, thin ink outlines). Not copied from isoflow/isopacks.
//
// Two modes:
//  1. Inside an existing <svg> (default): renders a <g>, the origin is the floor centre of the icon.
//       <IsoIcon type="lab" :x="320" :y="210" :scale="1.2" state="active" accent="#6366F1" />
//  2. Standalone in HTML (e.g. the simulator): renders its own square <svg>, aria-hidden unless `title` is set.
//       <IsoIcon type="website" standalone />                      // 48 px
//       <IsoIcon type="botnet" standalone :size="32" />
//       <IsoIcon type="website" state="attacked" standalone title="Website mit Schild, Angriff geblockt" />
//
// Types:  website (server with Schild shield) · website-unprotected · lab (rack with flask) · relay (flat box
//         with antennas and arrows) · log (stacked ledger cylinders) · dashboard (laptop with chart) ·
//         visitor (people) · crawler (robot head) · botnet (hijacked router, camera, phone) · advisory (document) ·
//         unknown (neutral box with a question mark: source not known) · sources (several unknown sources, same pattern)
// States: normal · protected · unprotected · active · pending · attacked · offline · ghost (dashed outline only)

export type IsoIconType = 'website' | 'website-unprotected' | 'lab' | 'relay' | 'log' | 'dashboard' | 'visitor' | 'crawler' | 'botnet' | 'advisory' | 'unknown' | 'sources'
export type IsoIconState = 'normal' | 'protected' | 'unprotected' | 'active' | 'pending' | 'attacked' | 'offline' | 'ghost'

const props = withDefaults(defineProps<{
  type: IsoIconType
  state?: IsoIconState
  /** standalone: render an own <svg> (for HTML); otherwise a <g> inside a parent <svg> */
  standalone?: boolean
  /** standalone: edge length in px */
  size?: number
  /** inline: position of the floor centre and scale (1 = one tile of 64 × 32 px) */
  x?: number
  y?: number
  scale?: number
  /** lab: operator colour of the flask */
  accent?: string
  /** lab: LEDs blink amber (jobs running) */
  busy?: boolean
  /** accessible name; without it the icon is decorative (aria-hidden) */
  title?: string
}>(), { state: 'normal', standalone: false, size: 48, x: 0, y: 0, scale: 1, accent: '', busy: false, title: '' })

// ── Palette (mirrors docs/brand/tokens.css; presentation attributes cannot read CSS vars reliably) ──────────
const INK = '#2A3A55'
const GREEN = '#0F873B'
const AMBER = '#F59E0B'
const RED = '#DC2626'
const GREY = '#94A3B8'
interface Faces { top: string, left: string, right: string, stroke: string, led: string }
const FACES: Record<Exclude<IsoIconState, 'ghost'>, Faces> = {
  normal: { top: '#FFFFFF', left: '#E4EBF4', right: '#C5D2E2', stroke: INK, led: GREEN },
  protected: { top: '#FFFFFF', left: '#E4EBF4', right: '#C5D2E2', stroke: INK, led: GREEN },
  unprotected: { top: '#F7F7F8', left: '#E4E4E7', right: '#CFCFD4', stroke: '#52525B', led: GREY },
  active: { top: '#F0FDF4', left: '#BBF7D0', right: '#86EFAC', stroke: INK, led: GREEN },
  pending: { top: '#FFFBEB', left: '#FDE68A', right: '#FBBF24', stroke: INK, led: AMBER },
  attacked: { top: '#FEF2F2', left: '#FECACA', right: '#F87171', stroke: '#991B1B', led: RED },
  offline: { top: '#F8FAFC', left: '#E2E8F0', right: '#CBD5E1', stroke: GREY, led: GREY },
}
const BOT_FACES: Faces = { top: '#FEF2F2', left: '#FECACA', right: '#F87171', stroke: '#991B1B', led: RED }

// ── Isometric helpers (origin = floor centre, one tile = 64 × 32 px) ─────────────────────────────────────────
const U = 32
const V = 16
type P = [number, number]
const p = (gx: number, gy: number, z = 0): P => [(gx - gy) * U, (gx + gy) * V - z]
const r1 = (n: number) => Math.round(n * 10) / 10

interface Shape { tag: string, attrs: Record<string, string | number | undefined>, detail?: boolean }

const model = computed(() => {
  const ghost = props.state === 'ghost'
  const base: Faces = props.type === 'botnet' && props.state !== 'offline' && !ghost
    ? BOT_FACES
    : FACES[ghost ? 'normal' : props.type === 'website-unprotected' && props.state === 'normal' ? 'unprotected' : props.state as Exclude<IsoIconState, 'ghost'>]
  const f = ghost ? { top: 'none', left: 'none', right: 'none', stroke: GREY, led: GREY } : base
  const shapes: Shape[] = []
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  const ext = (...list: P[]) => { for (const [x, y] of list) { minX = Math.min(minX, x); maxX = Math.max(maxX, x); minY = Math.min(minY, y); maxY = Math.max(maxY, y) } }
  const pts = (list: P[]) => { ext(...list); return list.map(q => `${r1(q[0])},${r1(q[1])}`).join(' ') }
  const add = (tag: string, attrs: Shape['attrs'], detail = false) => shapes.push({ tag, attrs, detail })

  // cuboid on (cx, cy), w × d tiles, h px high, standing at z0
  function box(cx: number, cy: number, w: number, d: number, h: number, z0 = 0, faces: Faces = f) {
    const a = w / 2, b = d / 2
    const q = (dx: number, dy: number, z: number) => p(cx + dx, cy + dy, z0 + z)
    add('polygon', { points: pts([q(-a, b, h), q(a, b, h), q(a, b, 0), q(-a, b, 0)]), fill: faces.left })
    add('polygon', { points: pts([q(a, -b, h), q(a, b, h), q(a, b, 0), q(a, -b, 0)]), fill: faces.right })
    add('polygon', { points: pts([q(-a, -b, h), q(a, -b, h), q(a, b, h), q(-a, b, h)]), fill: faces.top })
    return {
      // horizontal line on the front-left face at height z (drive slots)
      slot: (z: number, inset = 0.1, end = 0.22) => add('polyline', { points: pts([q(-a + inset, b, z), q(a - end, b, z)]), 'stroke-opacity': 0.55 }, true),
      leftAt: (dx: number, z: number) => q(dx, b, z),
      rightAt: (dy: number, z: number) => q(a, dy, z),
      topAt: (dx: number, dy: number) => q(dx, dy, h),
    }
  }
  const led = (at: P, color = f.led, r = 2.2, i = 0) => add('circle', { 'cx': r1(at[0]), 'cy': r1(at[1]), r, 'fill': color, 'stroke': 'none', 'class': props.busy ? 'iso-blink' : undefined, 'style': props.busy ? `animation-delay:${i * 0.13}s` : undefined }, true)
  // upright badge (24 × 24 path) centred at x, bottom at y
  const badge = (d: string, x: number, y: number, s: number, attrs: Shape['attrs'], detail = true) => {
    ext([x - 12 * s, y - 24 * s], [x + 12 * s, y])
    add('path', { d, transform: `translate(${r1(x - 12 * s)},${r1(y - 23 * s)}) scale(${s})`, ...attrs }, detail)
  }
  const SHIELD = 'M12 2 3 5.5v6.2c0 5.3 3.8 9.4 9 10.8 5.2-1.4 9-5.5 9-10.8V5.5L12 2Z'
  const CHECK = 'M7.8 12.2l3 3 5.4-6'
  const shieldColor = props.state === 'offline' ? GREY : props.state === 'pending' ? AMBER : GREEN
  // cylinder disc (rx = 2 ry), front side + top ellipse
  const disc = (z0: number, h: number, rx: number, faces: Faces) => {
    const ry = rx / 2
    ext([-rx, -z0 - h - ry], [rx, -z0 + ry])
    add('path', { d: `M${-rx},${-z0 - h} L${-rx},${-z0} A${rx},${ry} 0 0 0 ${rx},${-z0} L${rx},${-z0 - h} A${rx},${ry} 0 0 1 ${-rx},${-z0 - h} Z`, fill: faces.left })
    add('path', { d: `M0,${-z0} L0,${-z0 + ry} A${rx},${ry} 0 0 0 ${rx},${-z0} L${rx},${-z0 - h} L0,${-z0 - h + ry} Z`, fill: faces.right, stroke: 'none' }, true)
    add('ellipse', { cx: 0, cy: -z0 - h, rx, ry, fill: faces.top })
  }

  switch (props.type) {
    case 'website':
    case 'website-unprotected': {
      const s = box(0, 0, 1, 1, 30)
      s.slot(10); s.slot(20)
      led(s.leftAt(0.36, 13)); led(s.leftAt(0.36, 23))
      if (props.type === 'website') {
        badge(SHIELD, 0, -27, 0.95, { fill: ghost ? 'none' : shieldColor, stroke: ghost ? GREY : '#0A1A33', 'stroke-width': 1.2 }, false)
        badge(CHECK, 0, -27, 0.95, { 'fill': 'none', 'stroke': '#FFFFFF', 'stroke-width': 2.2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })
      }
      else if (props.state === 'attacked') {
        // hit: red warning sign instead of a shield
        badge('M12 3 22 20H2Z', 0, -30, 0.85, { 'fill': '#DC2626', 'stroke': '#7F1D1D', 'stroke-linejoin': 'round' })
        badge('M12 9v5.5M12 17.2v.3', 0, -30, 0.85, { 'fill': 'none', 'stroke': '#FFFFFF', 'stroke-width': 2.4, 'stroke-linecap': 'round' })
      }
      else {
        // no shield: an empty, dashed shield outline
        badge(SHIELD, 0, -28, 0.9, { 'fill': '#FFFFFF', 'fill-opacity': 0.6, 'stroke': '#52525B', 'stroke-width': 1.4, 'stroke-dasharray': '3 2' })
      }
      break
    }
    case 'lab': {
      // tall, narrow rack (taller than a website) with a flask on top
      const H = 70
      const s = box(0, 0, 0.95, 0.95, H)
      for (let k = 1; k <= 5; k++) { s.slot(k * 11.5); led(s.leftAt(0.33, k * 11.5 + 3), props.busy ? AMBER : f.led, 2.1, k) }
      const flask = 'M9.5 2.5h5M10.5 2.5v6L4.8 18.6A1.8 1.8 0 0 0 6.4 21.3h11.2a1.8 1.8 0 0 0 1.6-2.7L13.5 8.5v-6'
      const liquid = 'M7.4 14.5h9.2l2.6 4.1a1.8 1.8 0 0 1-1.6 2.7H6.4a1.8 1.8 0 0 1-1.6-2.7Z'
      const top = s.topAt(0, 0)
      badge('M10.5 2.5v6L4.8 18.6A1.8 1.8 0 0 0 6.4 21.3h11.2a1.8 1.8 0 0 0 1.6-2.7L13.5 8.5v-6Z', top[0], top[1] + 4, 1.4, { fill: ghost ? 'none' : '#FFFFFF', stroke: 'none' }, false)
      badge(liquid, top[0], top[1] + 4, 1.4, { fill: props.state === 'offline' ? GREY : props.accent || (props.state === 'active' ? GREEN : '#3D9BF5'), stroke: 'none' })
      badge(flask, top[0], top[1] + 4, 1.4, { 'fill': 'none', 'stroke': ghost ? GREY : '#0A1A33', 'stroke-width': 1.3, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, false)
      break
    }
    case 'relay': {
      const s = box(0, 0, 1.25, 0.85, 12)
      for (const dx of [-0.3, 0.3]) {
        const a = s.topAt(dx, -0.3)
        add('line', { 'x1': r1(a[0]), 'y1': r1(a[1]), 'x2': r1(a[0]), 'y2': r1(a[1] - 18), 'stroke-width': 1.6 }, true)
        add('circle', { cx: r1(a[0]), cy: r1(a[1] - 19), r: 2.4, fill: f.led }, true)
        ext([a[0], a[1] - 22])
      }
      for (let k = 0; k < 4; k++) led(s.leftAt(-0.4 + k * 0.17, 6), f.led, 1.8)
      // two arrows on the top face: forwarding in both directions
      const arrow = (y: number, from: number, to: number) => {
        const dir = Math.sign(to - from)
        add('polyline', { 'points': pts([s.topAt(from, y), s.topAt(to, y)]), 'stroke-width': 1.4 }, true)
        add('polyline', { 'points': pts([s.topAt(to - dir * 0.14, y - 0.1), s.topAt(to, y), s.topAt(to - dir * 0.14, y + 0.1)]), 'stroke-width': 1.4, 'stroke-linejoin': 'round' }, true)
      }
      arrow(-0.12, -0.42, 0.42); arrow(0.16, 0.42, -0.42)
      break
    }
    case 'log': {
      const done: Faces = props.state === 'active' ? FACES.active : f
      disc(0, 7, 18, f); disc(9, 7, 18, f); disc(18, 7, 18, done)
      // append marker on top
      if (!ghost) add('path', { 'd': `M-5,-29 h10 M0,-31.5 v5`, 'stroke': props.state === 'active' ? '#0B6E30' : INK, 'stroke-width': 1.6, 'stroke-linecap': 'round' }, true)
      break
    }
    case 'dashboard': {
      const s = box(0, 0.15, 1.2, 0.8, 4)
      // keyboard area on the base
      add('polygon', { 'points': pts([s.topAt(-0.42, -0.05), s.topAt(0.42, -0.05), s.topAt(0.42, 0.22), s.topAt(-0.42, 0.22)]), 'fill': ghost ? 'none' : '#CBD5E1', 'stroke-opacity': 0.4 }, true)
      // screen: upright plane on the back edge, facing the viewer
      const sc = (gx: number, z: number) => p(gx, -0.25, z)
      add('polygon', { points: pts([sc(-0.6, 4), sc(0.6, 4), sc(0.6, 42), sc(-0.6, 42)]), fill: ghost ? 'none' : '#0A1A33', stroke: ghost ? GREY : '#0A1A33' })
      add('polygon', { 'points': pts([sc(-0.52, 9), sc(0.52, 9), sc(0.52, 38), sc(-0.52, 38)]), 'fill': '#13284A', 'stroke': 'none' }, true)
      const hs = [7, 12, 9, 19]
      hs.forEach((hk, k) => {
        const a = sc(-0.33 + k * 0.22, 13), b = sc(-0.33 + k * 0.22, 13 + hk)
        const last = k === hs.length - 1
        add('line', { 'x1': r1(a[0]), 'y1': r1(a[1]), 'x2': r1(b[0]), 'y2': r1(b[1]), 'stroke': last ? (props.state === 'active' ? GREEN : props.state === 'pending' ? AMBER : '#3D9BF5') : '#5B7BA6', 'stroke-width': 4, 'stroke-linecap': 'butt' }, true)
      })
      break
    }
    case 'visitor': {
      const body = 'M-8,0 C-8,-11 -5.5,-16 0,-16 C5.5,-16 8,-11 8,0 Z'
      const half = 'M0,-16 C5.5,-16 8,-11 8,0 L0,0 Z'
      for (const [dx, dy] of [[-13, -2], [13, -2], [0, 5]] as P[]) {
        ext([dx - 9, dy - 29], [dx + 9, dy + 3])
        add('ellipse', { cx: dx, cy: dy, rx: 10, ry: 4, fill: '#0A1A33', 'fill-opacity': 0.08, stroke: 'none' }, true)
        add('path', { d: body, transform: `translate(${dx},${dy})`, fill: ghost ? 'none' : '#BFD3EC' })
        add('path', { d: half, transform: `translate(${dx},${dy})`, fill: '#9DB7D9', stroke: 'none' }, true)
        add('circle', { cx: dx, cy: dy - 22, r: 6, fill: ghost ? 'none' : '#FFFFFF' })
      }
      break
    }
    case 'crawler': {
      box(0, 0, 0.45, 0.45, 9)
      const s = box(0, 0, 1, 0.9, 26, 9)
      const ant = s.topAt(0, 0)
      add('line', { 'x1': r1(ant[0]), 'y1': r1(ant[1]), 'x2': r1(ant[0]), 'y2': r1(ant[1] - 12), 'stroke-width': 1.6 }, true)
      add('circle', { cx: r1(ant[0]), cy: r1(ant[1] - 14), r: 3, fill: ghost ? 'none' : '#3D9BF5' })
      ext([ant[0], ant[1] - 18])
      // eyes and mouth grille on the front face
      for (const dx of [-0.22, 0.2]) {
        const e = s.leftAt(dx, 17)
        add('ellipse', { cx: r1(e[0]), cy: r1(e[1]), rx: 4.2, ry: 4.6, fill: '#0A1A33', stroke: 'none' }, true)
        add('circle', { cx: r1(e[0] + 0.8), cy: r1(e[1] - 0.6), r: 1.9, fill: '#7DD3FC', stroke: 'none' }, true)
      }
      add('polyline', { 'points': pts([s.leftAt(-0.24, 7), s.leftAt(0.22, 7)]), 'stroke-width': 2.2, 'stroke-dasharray': '2 2' }, true)
      // ear on the right face
      const ear = s.rightAt(0, 14)
      add('rect', { x: r1(ear[0] - 2), y: r1(ear[1] - 6), width: 5, height: 9, rx: 1.5, fill: f.right }, true)
      break
    }
    case 'botnet': {
      // dotted links between the hijacked devices
      add('polyline', { 'points': pts([p(-0.5, 0.3), p(0.38, -0.42), p(0.55, 0.52), p(-0.5, 0.3)]), 'fill': 'none', 'stroke': ghost ? GREY : RED, 'stroke-dasharray': '2 3', 'stroke-opacity': 0.7 }, true)
      // router
      const r = box(-0.5, 0.3, 0.62, 0.42, 8)
      const ra = r.topAt(-0.18, -0.12)
      add('line', { 'x1': r1(ra[0]), 'y1': r1(ra[1]), 'x2': r1(ra[0]), 'y2': r1(ra[1] - 13), 'stroke-width': 1.5 }, true)
      led(r.leftAt(0.1, 4), RED, 1.6); led(r.leftAt(0.22, 4), RED, 1.6)
      // camera on a post
      const post = p(0.38, -0.42)
      add('line', { 'x1': r1(post[0]), 'y1': r1(post[1]), 'x2': r1(post[0]), 'y2': r1(post[1] - 12), 'stroke-width': 2 })
      const c = box(0.38, -0.42, 0.5, 0.36, 13, 12)
      const lens = c.leftAt(0, 6.5)
      add('circle', { cx: r1(lens[0]), cy: r1(lens[1]), r: 4, fill: ghost ? 'none' : '#0A1A33', stroke: 'none' }, true)
      add('circle', { cx: r1(lens[0]), cy: r1(lens[1]), r: 1.6, fill: RED, stroke: 'none' }, true)
      // phone, standing
      const ph = box(0.55, 0.52, 0.1, 0.5, 30)
      add('polygon', { 'points': pts([ph.rightAt(-0.2, 4), ph.rightAt(0.2, 4), ph.rightAt(0.2, 26), ph.rightAt(-0.2, 26)]), 'fill': ghost ? 'none' : '#7F1D1D', 'stroke': 'none' }, true)
      ext(ra, [ra[0], ra[1] - 14])
      break
    }
    case 'unknown':
    case 'sources': {
      // neutral: nothing about who is behind it, only that the source is not known
      const QMARK = 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18Z'
      const QLINE = 'M9.3 9.4a2.8 2.8 0 1 1 4 2.5c-.8.4-1.3 1-1.3 1.9v.5M12 17.2v.3'
      const question = (at: P, s: number) => {
        badge(QMARK, at[0], at[1], s, { fill: ghost ? 'none' : '#FFFFFF', stroke: ghost ? GREY : INK, 'stroke-width': 1.2 }, false)
        badge(QLINE, at[0], at[1], s, { 'fill': 'none', 'stroke': INK, 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })
      }
      if (props.type === 'unknown') {
        const s = box(0, 0, 0.8, 0.8, 24)
        s.slot(9, 0.1, 0.3)
        led(s.leftAt(0.25, 12), GREY, 2)
        const t = s.topAt(0, 0)
        question([t[0], t[1] + 3], 0.95)
        break
      }
      add('polyline', { 'points': pts([p(-0.5, 0.3), p(0.38, -0.42), p(0.55, 0.52), p(-0.5, 0.3)]), 'fill': 'none', 'stroke': GREY, 'stroke-dasharray': '2 3' }, true)
      for (const [gx, gy] of [[0.38, -0.42], [-0.5, 0.3], [0.55, 0.52]] as P[]) {
        const s = box(gx, gy, 0.48, 0.48, 14)
        led(s.leftAt(0.1, 7), GREY, 1.6)
      }
      const t = p(0.38, -0.42, 14)
      question([t[0], t[1] - 2], 0.8)
      break
    }
    case 'advisory': {
      const sc = (gx: number, z: number) => p(gx, 0, z)
      add('polygon', { points: pts([sc(-0.42, 0), sc(0.42, 0), sc(0.42, 48), sc(-0.42, 48)]), fill: ghost ? 'none' : '#FFFFFF', stroke: ghost ? GREY : '#B91C1C' })
      add('polygon', { 'points': pts([sc(-0.42, 40), sc(0.42, 40), sc(0.42, 48), sc(-0.42, 48)]), 'fill': '#FCA5A5', 'stroke': 'none' }, true)
      for (let k = 1; k <= 3; k++) add('polyline', { 'points': pts([sc(-0.3, 40 - k * 9), sc(k === 3 ? 0 : 0.28, 40 - k * 9)]), 'stroke': '#FCA5A5', 'stroke-width': 2.2 }, true)
      break
    }
  }

  const visible = ghost ? shapes.filter(s => !s.detail) : shapes
  const pad = 3
  const w = maxX - minX + pad * 2, h = maxY - minY + pad * 2
  const side = Math.max(w, h)
  const viewBox = [r1(minX - pad - (side - w) / 2), r1(minY - pad - (side - h) / 2), r1(side), r1(side)].join(' ')
  return { shapes: visible, stroke: f.stroke, viewBox, dashed: ghost }
})
</script>

<template>
  <svg
    v-if="standalone"
    :viewBox="model.viewBox" :width="size" :height="size" class="iso-icon inline-block shrink-0 overflow-visible"
    :role="title ? 'img' : undefined" :aria-label="title || undefined" :aria-hidden="title ? undefined : 'true'" focusable="false"
  >
    <title v-if="title">{{ title }}</title>
    <g :stroke="model.stroke" stroke-width="1" stroke-linejoin="round" fill="none" :stroke-dasharray="model.dashed ? '4 3' : undefined">
      <component :is="s.tag" v-for="(s, i) in model.shapes" :key="i" v-bind="s.attrs" />
    </g>
  </svg>
  <g
    v-else
    class="iso-icon" :transform="`translate(${x},${y})${scale !== 1 ? ` scale(${scale})` : ''}`"
    :stroke="model.stroke" stroke-width="1" stroke-linejoin="round" fill="none" :stroke-dasharray="model.dashed ? '4 3' : undefined"
    :aria-hidden="title ? undefined : 'true'"
  >
    <title v-if="title">{{ title }}</title>
    <component :is="s.tag" v-for="(s, i) in model.shapes" :key="i" v-bind="s.attrs" />
  </g>
</template>

<style scoped>
.iso-icon :deep(*) { vector-effect: non-scaling-stroke; }
.iso-icon :deep(.iso-blink) { animation: iso-blink 0.7s ease-in-out infinite alternate; }
@keyframes iso-blink { from { opacity: 1; } to { opacity: 0.25; } }
@media (prefers-reduced-motion: reduce) { .iso-icon :deep(.iso-blink) { animation: none; } }
</style>
