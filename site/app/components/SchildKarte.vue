<script setup lang="ts">
// Hero visual: Germany made of dots – every dot a website. One after another, websites are attacked. The signal goes to
// several Schild-Labs (target picture: a peer-to-peer network of independent operators), each copy through a different
// relay: a relay sees the sending server's IP but not the encrypted content, a Lab sees the content but never the
// server's IP. That split only holds if no single relay carries everything, so the four copies of every signal use four
// different relays. The Labs evaluate, compare notes and send the rule back through the relays to everyone (the green
// waves start at the relays). The four steps run along at the bottom. Signals never contain visitor IPs (decision E4).
// Illustration of the principle with made-up examples, no real incidents. Outline heavily simplified.
// tone 'dark': drawn straight onto a dark photo (start page hero) – light dots, white names with a dark halo, light
// lines; the attack labels stay white chips and the green signal colour stays.
const props = withDefaults(defineProps<{ caption?: boolean, tone?: 'light' | 'dark' }>(), { caption: true, tone: 'light' })
const TONES = {
  light: {
    land: 'fill-slate/25', peer: 'stroke-signal-deep/60', hop: 'stroke-slate', rule: 'stroke-signal-deep', check: 'stroke-slate/60',
    relay: 'fill-white stroke-slate', relayDot: 'fill-slate', lab: 'fill-white stroke-line', name: 'fill-ink', halo: '#FFFFFF',
    keyTitle: 'fill-ink', keyText: 'fill-slate', step: 'fill-slate', stepOn: 'fill-signal-deep',
  },
  dark: {
    land: 'fill-white/35', peer: 'stroke-signal-soft/80', hop: 'stroke-white/80', rule: 'stroke-signal-soft', check: 'stroke-white/60',
    relay: 'fill-ink stroke-white', relayDot: 'fill-white', lab: 'fill-white stroke-white/40', name: 'fill-white', halo: 'rgb(10 26 51 / 0.75)',
    keyTitle: 'fill-white', keyText: 'fill-white/85', step: 'fill-white/75', stepOn: 'fill-signal-soft',
  },
} as const
const c = computed(() => TONES[props.tone])

const OUTLINE: [number, number][] = [
  [8.6, 54.9], [9.4, 54.83], [10.2, 54.42], [11.1, 54.5], [10.9, 54.02], [12.1, 54.2], [12.5, 54.47], [13.4, 54.68],
  [14.2, 53.95], [14.4, 53.3], [14.6, 52.6], [14.7, 52.1], [15.0, 51.3], [15.0, 51.1], [14.8, 50.85], [14.3, 50.9],
  [13.5, 50.6], [12.9, 50.4], [12.3, 50.2], [12.1, 50.3], [12.5, 49.8], [12.6, 49.5], [13.0, 49.3], [13.8, 48.8],
  [13.5, 48.55], [13.0, 48.2], [12.9, 47.9], [13.0, 47.7], [13.0, 47.5], [12.2, 47.7], [11.4, 47.45], [11.0, 47.4],
  [10.4, 47.3], [9.7, 47.55], [9.0, 47.7], [8.6, 47.65], [7.6, 47.58], [7.6, 48.1], [7.9, 48.6], [8.2, 48.98],
  [7.6, 49.05], [6.8, 49.15], [6.4, 49.45], [6.4, 49.8], [6.1, 50.1], [6.2, 50.5], [6.0, 50.75], [5.9, 51.0],
  [6.2, 51.4], [6.1, 51.85], [6.8, 51.95], [7.05, 52.25], [7.0, 52.65], [7.2, 53.2], [7.2, 53.3], [7.0, 53.6],
  [8.0, 53.7], [8.2, 53.5], [8.6, 53.88], [9.0, 53.9], [8.9, 54.1], [8.8, 54.5],
]
type Point = [number, number]
const project = ([lon, lat]: Point): Point => [(lon - 5.75) * 37.8 + 6, (55.05 - lat) * 60 + 6]

// Schild-Labs: independently operated, selectable at installation (concept 04). Examples, not partners.
const LABS = [
  { name: 'Community-Lab', at: project([13.4, 52.52]), labelAbove: false }, // Berlin
  { name: 'Vereins-Lab', at: project([9.73, 52.37]), labelAbove: true }, // Hanover
  { name: 'Hoster-Lab', at: project([8.68, 50.11]), labelAbove: false }, // Frankfurt
  { name: 'Hochschul-Lab', at: project([11.58, 48.14]), labelAbove: false }, // Munich
]
// Relays: forward signals and rules between websites and Labs. Rough places only, no real hosts; every node keeps
// a margin to the outline so it sits clearly inside the map.
const RELAYS = [project([13.6, 53.4]), project([7.63, 51.96]), project([12.1, 49.02]), project([10.9, 49.5])]
// Attacks one after another; labelOffset = position of the label relative to the dot
const ATTACKS = [
  { who: 'Website Sportverein, Köln', what: 'WordPress-Login-Versuche', at: project([6.96, 50.94]), labelOffset: [-110, -58] },
  { who: 'Website Lokalzeitung, Hamburg', what: 'Bot-Scan auf PHP 7.4', at: project([9.99, 53.55]), labelOffset: [12, -62] },
  { who: 'Website Arztpraxis, Leipzig', what: 'SQL-Injection-Versuch', at: project([12.37, 51.34]), labelOffset: [-80, 16] },
  { who: 'Website Handwerker, Stuttgart', what: 'Login-Versuche aus Botnetz', at: project([9.18, 48.78]), labelOffset: [-196, 14] },
] as const
const STEPS = ['Angriff', 'Signal über Relays', 'Konsens', 'Abgewehrt']

// Every Lab gets its copy of a signal through a different relay: per attack, the assignment Lab → relay is the
// permutation with the shortest total path (so no relay carries all copies, and lines stay short).
const len = (a: Point, b: Point) => Math.hypot(a[0] - b[0], a[1] - b[1])
const permutations = (n: number): number[][] => n === 0 ? [[]] : permutations(n - 1).flatMap(p => Array.from({ length: n }, (_, i) => [...p.slice(0, i), n - 1, ...p.slice(i)]))
const routeOf = (from: Point) => permutations(RELAYS.length)
  .map(p => ({ p, d: LABS.reduce((sum, lab, k) => sum + len(from, RELAYS[p[k]!]!) + len(RELAYS[p[k]!]!, lab.at), 0) }))
  .sort((a, b) => a.d - b.d)[0]!.p

// Dot grid inside the outline
const polygon = OUTLINE.map(project)
const inside = (px: number, py: number) => {
  let isInside = false
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, yi] = polygon[i]!, [xj, yj] = polygon[j]!
    if ((yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) isInside = !isInside
  }
  return isInside
}
const SPACING = 9.5
const dots: Point[] = []
for (let row = 0, y = 6; y < 490; row++, y += SPACING * 0.866) {
  for (let x = 6 + (row % 2) * SPACING / 2; x < 365; x += SPACING) if (inside(x, y)) dots.push([x, y])
}

// Timeline: one cycle of T seconds, each attack gets a window of T / count.
const T = 12
const WINDOW = T / ATTACKS.length
const track = (keys: [number, number | string][]) => {
  const sorted = keys.map(([t, v]) => [((t % T) + T) % T, v] as const).sort((a, b) => a[0] - b[0])
  const all = [[0, sorted.at(-1)![1]] as const, ...sorted, [T, sorted.at(-1)![1]] as const]
  return { values: all.map(a => a[1]).join(';'), keyTimes: all.map(a => (a[0] / T).toFixed(4)).join(';'), dur: `${T}s`, repeatCount: 'indefinite' }
}
const on = (from: number, to: number, high: number | string = 1, low: number | string = 0) =>
  track([[from, low], [from + 0.15, high], [to, high], [to + 0.3, low]])

const RED = '#DC2626' // red-600: reads on white; SMIL cannot animate CSS variables
const GREEN = '#0F873B' // = signal; SMIL cannot animate CSS variables
const LABEL_WIDTH = 230
const start = (i: number) => 0.2 + i * WINDOW
// Phases per attack, relative to its start: attack → signal → consensus → protection
const PHASE = [[0, 0.5], [0.55, 1.15], [1.2, 1.75], [1.8, 2.9]] as const
const WAVE = PHASE[3][0] + 0.25 // the wave leaves the relays once the rule has reached them
const timeWindow = (from: number, to: number) => [[from, 0], [from + 0.15, 1], [to, 1], [to + 0.3, 0]] as [number, number][]

const scenes = ATTACKS.map((a, i) => {
  const o = start(i)
  return {
    ...a,
    marker: on(o, o + 5.4),
    fill: track([[o, RED], [o + PHASE[3][0] - 0.1, RED], [o + PHASE[3][0] + 0.1, GREEN]]),
    ring: { r: track([[o, 4], [o + 0.9, 24], [o + 0.95, 4]]), op: track([[o - 0.05, 0], [o, 1], [o + 0.9, 0]]) },
    // signal: website → relay, then relay → Lab (one relay per Lab)
    hops: LABS.map((lab, k) => ({ lab: lab.at, relay: RELAYS[routeOf(a.at)[k]!]! })),
    signal: on(o + PHASE[1][0], o + PHASE[2][1]),
    forward: on(o + PHASE[1][0] + 0.25, o + PHASE[2][1]),
    // rule: Lab → relay, then the wave from every relay to all websites
    rule: on(o + PHASE[3][0], o + PHASE[3][1]),
    status: [
      { text: a.what, cls: 'fill-danger', op: on(o, o + PHASE[1][0] - 0.05) },
      { text: `${LABS.length} Labs prüfen …`, cls: 'fill-slate', op: on(o + PHASE[1][0], o + PHASE[3][0] - 0.2) },
      { text: '✓ geblockt · Regel an alle', cls: 'fill-signal-deep font-semibold', op: on(o + PHASE[3][0], o + 5.4) },
    ],
    check: { r: track([[o + 0.85, 17], [o + 1.5, 32], [o + 1.55, 17]]), op: track([[o + 0.8, 0], [o + 0.85, 1], [o + 1.5, 0]]) },
    wave: { r: track([[o + WAVE, 0], [o + WAVE + 2.5, 330], [o + WAVE + 2.55, 0]]), op: track([[o + WAVE - 0.05, 0], [o + WAVE, 1], [o + WAVE + 2.5, 0]]) },
  }
})
const phaseTrack = (k: number, rest = 0) => track(ATTACKS.flatMap((_, i) => timeWindow(start(i) + PHASE[k]![0], start(i) + PHASE[k]![1]))
  .map(([t, v]) => [t, v || rest] as [number, number]))
const consensus = phaseTrack(2, 0.3)
const steps = STEPS.map((title, k) => ({ title, op: phaseTrack(k), x: [-55, 50, 200, 300][k]! }))
// Peer to peer: every lab with every other lab
const links = LABS.flatMap((a, i) => LABS.slice(i + 1).map(b => [a.at, b.at] as const))

const maskId = `schildkarte-dots-${useId()}`

// Reduced motion: still frame in the end state "Köln blocked · rule to all" (rule at the relays, waves leaving them).
const svg = ref<SVGSVGElement>()
onMounted(() => {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches && svg.value) {
    svg.value.pauseAnimations()
    svg.value.setCurrentTime(start(0) + PHASE[3][0] + 1.1)
  }
})
</script>

<template>
  <figure>
    <svg ref="svg" viewBox="-60 -10 500 540" class="h-auto w-full overflow-visible" role="img" aria-label="Prinzip-Darstellung mit erfundenen Beispielen: Karte von Deutschland aus Punkten, jeder Punkt eine Website. Nacheinander werden die Websites eines Sportvereins in Köln, einer Lokalzeitung in Hamburg, einer Arztpraxis in Leipzig und eines Handwerkers in Stuttgart angegriffen. Das Signal geht jeweils an vier Labs verschiedener Betreiber – Community, Verein, Hoster und Hochschule –, und zwar über vier verschiedene Relays, für jedes Lab ein anderes. Ein Relay sieht, von welchem Server das Signal kommt, aber nicht den Inhalt. Ein Lab sieht den Inhalt, aber nicht die IP des Servers. Die Labs werten aus, gleichen sich ab und schicken eine Empfehlung zurück an die Relays: Von dort verteilen grüne Wellen die Regel an alle Websites.">
      <defs>
        <mask :id="maskId" maskUnits="userSpaceOnUse" x="-60" y="-10" width="500" height="540">
          <circle v-for="([x, y], i) in dots" :key="i" :cx="x" :cy="y" r="2.7" fill="white" />
        </mask>
      </defs>

      <!-- Websites: quiet grey dots; the labs' green waves shine through them -->
      <g :mask="`url(#${maskId})`">
        <rect x="-60" y="-10" width="500" height="540" :class="c.land" />
        <template v-for="s in scenes" :key="`w${s.who}`">
          <circle v-for="(relay, k) in RELAYS" :key="k" :cx="relay[0]" :cy="relay[1]" r="0" fill="none" class="stroke-signal" stroke-width="34">
            <animate attributeName="r" v-bind="s.wave.r" />
            <animate attributeName="opacity" v-bind="s.wave.op" />
          </circle>
        </template>
      </g>

      <!-- Network: labs compare notes peer to peer -->
      <g :class="c.peer" stroke-width="1.2" stroke-dasharray="3 5" fill="none">
        <line v-for="([a, b], i) in links" :key="i" :x1="a[0]" :y1="a[1]" :x2="b[0]" :y2="b[1]">
          <animate attributeName="opacity" v-bind="consensus" />
          <animate attributeName="stroke-dashoffset" values="0;-16" dur="1s" repeatCount="indefinite" />
        </line>
      </g>

      <!-- Attacks: signal to all labs, every copy through a different relay; rule back to the relays
           (lines sit below relays, labs and labels) -->
      <g v-for="s in scenes" :key="s.who">
        <template v-for="(h, k) in s.hops" :key="k">
          <line :x1="s.at[0]" :y1="s.at[1]" :x2="h.relay[0]" :y2="h.relay[1]" :class="c.hop" stroke-width="1.1" stroke-dasharray="2 4" opacity="0">
            <animate attributeName="opacity" v-bind="s.signal" />
            <animate attributeName="stroke-dashoffset" values="0;-12" dur=".6s" repeatCount="indefinite" />
          </line>
          <line :x1="h.relay[0]" :y1="h.relay[1]" :x2="h.lab[0]" :y2="h.lab[1]" :class="c.hop" stroke-width="1.1" stroke-dasharray="2 4" opacity="0">
            <animate attributeName="opacity" v-bind="s.forward" />
            <animate attributeName="stroke-dashoffset" values="0;-12" dur=".6s" repeatCount="indefinite" />
          </line>
          <line :x1="h.lab[0]" :y1="h.lab[1]" :x2="h.relay[0]" :y2="h.relay[1]" :class="c.rule" stroke-width="1.3" stroke-dasharray="3 4" opacity="0">
            <animate attributeName="opacity" v-bind="s.rule" />
            <animate attributeName="stroke-dashoffset" values="0;-14" dur=".6s" repeatCount="indefinite" />
          </line>
        </template>
        <circle v-for="lab in LABS" :key="`p${lab.name}`" :cx="lab.at[0]" :cy="lab.at[1]" r="17" fill="none" :class="c.check" stroke-width="1" opacity="0">
          <animate attributeName="r" v-bind="s.check.r" />
          <animate attributeName="opacity" v-bind="s.check.op" />
        </circle>
        <circle :cx="s.at[0]" :cy="s.at[1]" r="4" fill="none" :stroke="RED" stroke-width="1.5" opacity="0">
          <animate attributeName="r" v-bind="s.ring.r" />
          <animate attributeName="opacity" v-bind="s.ring.op" />
        </circle>
      </g>

      <!-- Relays: small diamonds, explained in the key at the top left -->
      <g v-for="(relay, k) in RELAYS" :key="`r${k}`" :transform="`translate(${relay[0]} ${relay[1]})`">
        <rect x="-5.5" y="-5.5" width="11" height="11" rx="2" transform="rotate(45)" :class="c.relay" stroke-width="1.4" />
        <circle r="1.8" :class="c.relayDot" />
      </g>

      <!-- Schild-Labs -->
      <g v-for="lab in LABS" :key="lab.name" :transform="`translate(${lab.at[0]} ${lab.at[1]})`">
        <circle r="17" :class="c.lab" stroke-width="1" />
        <g transform="translate(-12 -13) scale(.375)">
          <path d="M32 4.5C37.39 9.38 45.48 11 56.5 11V24C56.5 43.53 42.29 57.0 32 59.5C21.71 57.0 7.5 43.53 7.5 24V11C18.52 11 26.61 9.38 32 4.5Z" class="fill-white stroke-signal-deep" stroke-width="4" stroke-linejoin="round" />
          <path d="M32 11.6C36.03 15.35 42.06 16.6 50.3 16.6V26C50.3 40.41 39.69 49.7 32 52.2C24.31 49.7 13.7 40.41 13.7 26V16.6C21.93 16.6 27.97 15.35 32 11.6Z" class="fill-signal" />
        </g>
        <text :y="lab.labelAbove ? -25 : 33" text-anchor="middle" :class="c.name" class="font-semibold max-md:hidden" font-size="13" paint-order="stroke" :stroke="c.halo" stroke-width="4">{{ lab.name }}</text>
      </g>

      <!-- Attacks: dot and label, always on top. Labels only from md – below that they would be under 8 px. -->
      <g v-for="s in scenes" :key="`e${s.who}`">
        <g opacity="0">
          <animate attributeName="opacity" v-bind="s.marker" />
          <circle :cx="s.at[0]" :cy="s.at[1]" r="4.5" stroke="#FFFFFF" stroke-width="1.5">
            <animate attributeName="fill" v-bind="s.fill" />
          </circle>
          <g :transform="`translate(${s.at[0] + s.labelOffset[0]} ${s.at[1] + s.labelOffset[1]})`" class="max-md:hidden">
            <rect :width="LABEL_WIDTH" height="44" rx="6" class="fill-white stroke-line" />
            <text x="10" y="18" class="fill-ink font-semibold" font-size="13">{{ s.who }}</text>
            <text v-for="st in s.status" :key="st.text" x="10" y="35" :class="st.cls" font-size="12" opacity="0">
              {{ st.text }}<animate attributeName="opacity" v-bind="st.op" />
            </text>
          </g>
        </g>
      </g>

      <!-- Key for the relays (from md) -->
      <g class="max-md:hidden" font-size="12" paint-order="stroke" :stroke="c.halo" stroke-width="4">
        <g transform="translate(-48 8)" stroke-width="1.4">
          <rect x="-5.5" y="-5.5" width="11" height="11" rx="2" transform="rotate(45)" :class="c.relay" />
          <circle r="1.8" :class="c.relayDot" stroke="none" />
        </g>
        <text x="-36" y="12" :class="c.keyTitle" class="font-semibold" font-size="13">Relay</text>
        <text x="-55" y="30" :class="c.keyText">sieht die Server-IP,</text>
        <text x="-55" y="45" :class="c.keyText">nicht den Inhalt.</text>
        <text x="-55" y="60" :class="c.keyText">Das Lab sieht nur den Inhalt.</text>
      </g>

      <!-- Steps: the active one lights up (from md) -->
      <g font-size="13" class="font-semibold max-md:hidden" paint-order="stroke" :stroke="c.halo" stroke-width="4">
        <g v-for="(st, k) in steps" :key="st.title" :transform="`translate(${st.x} 518)`">
          <text :class="c.step"><tspan class="font-mono">{{ k + 1 }}</tspan> {{ st.title }}</text>
          <text :class="c.stepOn" opacity="0"><tspan class="font-mono">{{ k + 1 }}</tspan> {{ st.title }}<animate attributeName="opacity" v-bind="st.op" /></text>
        </g>
      </g>
    </svg>

    <figcaption v-if="props.caption" class="mx-auto mt-4 max-w-md text-center text-xs leading-relaxed text-slate">
      <span class="inline-flex items-center gap-1.5 font-semibold text-ink"><BrandMark class="size-3.5" /> Labs</span>
      werten Signale aus und verteilen Empfehlungen, beides über mehrere Relays. Ziel ist ein Verbund unabhängiger Betreiber, und du wählst, wem du vertraust.
    </figcaption>
  </figure>
</template>
