<script setup lang="ts">
import type { GroupMember, GroupStatus } from '@/api/group'
import { formatDecimal, formatPercent } from '@schild/ui'
import { computed } from 'vue'
import { gateways, nodeView } from '@/lib/group'

/**
 * Map of the cluster (MVP-27): the internet above, below it every gateway side by side, each linked with the
 * internet. From nine gateways on the boxes are narrow and their words stand upright, so sixteen fit in one
 * row. No gateway stands above another or in the middle: a cluster has no main server, and the map must
 * not look as if it had one. The line of a gateway says whether it takes requests, as it told this server.
 * The links between the gateways are not drawn; the cards and the list below carry the state of the sync.
 * A node opens its details (`select`). Hidden on narrow screens, where the list below does the same.
 */
const props = defineProps<{ status: GroupStatus }>()
const emit = defineEmits<{ select: [id: string] }>()

const W = 960
const PAD = 16
/** Up to this many gateways are boxes with their words across; more are narrow boxes with the words upright. */
const ACROSS_MAX = 8
const NET = { x: W / 2, y: 40 }
const BUS_Y = 104
const nodes = computed(() => gateways(props.status))
const upright = computed(() => nodes.value.length > ACROSS_MAX)
const boxH = computed(() => upright.value ? 138 : 54)
const rowY = computed(() => BUS_Y + 37 + boxH.value / 2)
const H = computed(() => rowY.value + boxH.value / 2 + 22)
const away = (m: GroupMember) => m.state === 'unreachable' || m.state === 'no_contact'

interface Placed { m: GroupMember, x: number, y: number, w: number, kind: 'ready' | 'not' | 'unknown', tone: string, name: string, line: string }
const fit = (s: string, n: number) => s.length > n ? `${s.slice(0, Math.max(1, n - 1))}…` : s

/** One row, this server first, all the same size. */
const placed = computed<Placed[]>(() => {
  const all = [...nodes.value].sort((a, b) => Number(b.state === 'self') - Number(a.state === 'self'))
  const n = all.length
  const step = Math.min(upright.value ? 64 : 196, (W - 2 * PAD) / Math.max(n, 1))
  const w = Math.min(176, step - (upright.value ? 10 : 12))
  // Upright the words run along the height of the box, below the dot.
  const room = upright.value ? boxH.value - 34 : w
  return all.map((m, i) => {
    const view = nodeView(m)
    const v = away(m) ? undefined : m.vitals
    const kind = view.tone === 'success' ? 'ready' : view.tone === 'neutral' ? 'unknown' : 'not'
    // A gateway that takes requests shows its load; any other shows why not, which matters more than a number.
    const load = v ? `${formatDecimal(v.requests_per_s)}/s${v.cpu_usage == null ? '' : ` · CPU ${formatPercent(v.cpu_usage)}`}` : ''
    const line = kind === 'ready' && load ? load : view.label
    return {
      m,
      x: W / 2 + (i - (n - 1) / 2) * step,
      y: rowY.value,
      w,
      kind,
      tone: view.tone,
      name: fit(m.name, Math.floor((room - (upright.value ? 0 : 34)) / 7.6)),
      line: fit(line, Math.floor((room - (upright.value ? 0 : 20)) / (upright.value ? 5.4 : 6.2))),
    }
  })
})
const bus = computed(() => {
  const xs = placed.value.map(p => p.x)
  return { x1: Math.min(NET.x, ...xs), x2: Math.max(NET.x, ...xs) }
})
const TONE: Record<string, string> = { success: 'fill-status-success', warning: 'fill-status-warning', danger: 'fill-status-danger', neutral: 'fill-status-neutral', info: 'fill-status-info', signal: 'fill-status-signal' }
const label = computed(() => `Karte des Clusters: ${nodes.value.length} Gateways nebeneinander hinter dem Loadbalancer. Jeder Server lässt sich öffnen.`)
</script>

<template>
  <figure class="hidden rounded-xl border bg-card p-4 md:block" data-testid="group-map">
    <svg :viewBox="`0 0 ${W} ${H}`" class="h-auto w-full" role="group" :aria-label="label">
      <g fill="none" stroke-linecap="round">
        <path :d="`M${NET.x} ${NET.y + 24} V${BUS_Y} M${bus.x1} ${BUS_Y} H${bus.x2}`" class="stroke-muted-foreground opacity-50" stroke-width="2" />
        <template v-for="p in placed" :key="`l-${p.m.id}`">
          <g v-if="p.kind === 'ready'" data-testid="group-map-link" data-kind="ready">
            <line :x1="p.x" :y1="BUS_Y" :x2="p.x" :y2="p.y - boxH / 2" class="stroke-status-success opacity-35" stroke-width="2.5" />
            <line :x1="p.x" :y1="BUS_Y" :x2="p.x" :y2="p.y - boxH / 2" class="flow stroke-status-success" stroke-width="2.5" stroke-dasharray="6 14" />
          </g>
          <line v-else-if="p.kind === 'not'" :x1="p.x" :y1="BUS_Y" :x2="p.x" :y2="p.y - boxH / 2" class="stroke-status-warning" stroke-width="2" stroke-dasharray="3 8" data-testid="group-map-link" data-kind="not" />
          <line v-else :x1="p.x" :y1="BUS_Y" :x2="p.x" :y2="p.y - boxH / 2" class="stroke-muted-foreground opacity-50" stroke-width="2" data-testid="group-map-link" data-kind="unknown" />
        </template>
      </g>

      <g data-testid="group-map-internet">
        <rect :x="NET.x - 92" :y="NET.y - 24" width="184" height="48" rx="24" class="fill-muted stroke-border" stroke-width="1" />
        <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" :transform="`translate(${NET.x - 78} ${NET.y - 15}) scale(1.2)`" fill="none" class="stroke-muted-foreground" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
        <text :x="NET.x - 40" :y="NET.y - 2" class="fill-foreground text-[13px] font-medium">Internet</text>
        <text :x="NET.x - 40" :y="NET.y + 13" class="fill-muted-foreground text-[11px]">über den Loadbalancer</text>
      </g>

      <g
        v-for="p in placed" :key="p.m.id" role="button" tabindex="0"
        class="cursor-pointer outline-none [&:focus-visible>rect]:stroke-ring [&:focus-visible>rect]:stroke-[3px] [&:hover>rect]:stroke-foreground"
        data-testid="group-map-node" :data-name="p.m.name" :data-state="p.m.state"
        @click="emit('select', p.m.id)" @keydown.enter.prevent="emit('select', p.m.id)" @keydown.space.prevent="emit('select', p.m.id)"
      >
        <rect
          :x="p.x - p.w / 2" :y="p.y - boxH / 2" :width="p.w" :height="boxH" rx="12"
          :class="['fill-card', p.m.state === 'self' ? 'stroke-foreground' : 'stroke-border']" :stroke-width="p.m.state === 'self' ? 2 : 1.25"
        />
        <template v-if="upright">
          <circle :cx="p.x" :cy="p.y - boxH / 2 + 15" r="4.5" :class="TONE[p.tone]" />
          <text :transform="`rotate(-90 ${p.x - 3} ${p.y + boxH / 2 - 10})`" :x="p.x - 3" :y="p.y + boxH / 2 - 10" class="fill-foreground text-[13px] font-semibold">{{ p.name }}</text>
          <text :transform="`rotate(-90 ${p.x + 13} ${p.y + boxH / 2 - 10})`" :x="p.x + 13" :y="p.y + boxH / 2 - 10" class="fill-muted-foreground text-[10.5px] tabular-nums">{{ p.line }}</text>
        </template>
        <template v-else>
          <circle :cx="p.x - p.w / 2 + 14" :cy="p.y - 9" r="4.5" :class="TONE[p.tone]" />
          <text :x="p.x - p.w / 2 + 25" :y="p.y - 4" class="fill-foreground text-[13px] font-semibold">{{ p.name }}</text>
          <text :x="p.x - p.w / 2 + 10" :y="p.y + 15" class="fill-muted-foreground text-[11px] tabular-nums">{{ p.line }}</text>
        </template>
        <text v-if="p.m.state === 'self'" :x="p.x" :y="p.y + boxH / 2 + 14" text-anchor="middle" class="fill-muted-foreground text-[11px]">dieser Server</text>
      </g>
    </svg>
    <figcaption class="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
      <span><span class="mr-1.5 inline-block h-0.5 w-5 rounded bg-status-success align-middle" />nimmt Anfragen an</span>
      <span><span class="mr-1.5 inline-block w-5 border-t-2 border-dashed border-status-warning align-middle" />nimmt gerade keine an oder ist von diesem Server aus nicht erreichbar</span>
      <span>Klick auf einen Server zeigt seine Details.</span>
    </figcaption>
  </figure>
</template>

<style scoped>
.flow {
  animation: group-map-flow 1.6s linear infinite;
}
@keyframes group-map-flow {
  to {
    stroke-dashoffset: -20;
  }
}
@media (prefers-reduced-motion: reduce) {
  .flow {
    animation: none;
  }
}
</style>
