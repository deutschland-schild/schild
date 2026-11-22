<script setup lang="ts">
import type { GroupMember, GroupStatus } from '@/api/group'
import { formatDecimal, formatPercent } from '@schild/ui'
import { computed } from 'vue'
import { gateways, nodeView } from '@/lib/group'

/**
 * Map of the cluster (MVP-27): the internet above, below it every gateway on one ring, each linked with every
 * other. No gateway stands in the middle: a cluster has no main server. The links of this server are drawn in
 * colour (reached or not), the links between the other servers in grey, because their state is not visible
 * from here. A node opens its details (`select`). Hidden on narrow screens, where the list below does the same.
 */
const props = defineProps<{ status: GroupStatus }>()

const emit = defineEmits<{ select: [id: string] }>()

const W = 960
/** Above this many gateways the nodes are drawn smaller and the internet gets one stem instead of a line to each. */
const FEW_MAX = 6
const nodes = computed(() => gateways(props.status))
const many = computed(() => nodes.value.length > FEW_MAX)
const box = computed(() => ({ w: many.value ? 118 : 176, h: many.value ? 50 : 58 }))
const top = computed(() => 104)
const ry = computed(() => {
  const n = nodes.value.length
  return n <= 2 ? 0 : n <= 4 ? 110 : n <= 6 ? 150 : n <= 10 ? 165 : 215
})
const cy = computed(() => top.value + ry.value + box.value.h / 2 + 22)
const H = computed(() => cy.value + ry.value + box.value.h / 2 + 24)
const away = (m: GroupMember) => m.state === 'unreachable' || m.state === 'no_contact'

interface Placed { m: GroupMember, x: number, y: number, w: number, h: number, tone: string, name: string, line: string }
const fit = (s: string, n: number) => s.length > n ? `${s.slice(0, n - 1)}…` : s

/**
 * Every gateway stands on one ring below the internet, none in the middle: the cluster has no main server, and
 * the map must not look as if it had one. The ring is symmetric below the internet; this server is the first
 * to the left of the top and differs only by its outline and its label.
 */
const placed = computed<Placed[]>(() => {
  const all = [...nodes.value].sort((a, b) => Number(b.state === 'self') - Number(a.state === 'self'))
  const n = all.length
  const { w, h } = box.value
  const rx = n === 1 ? 0 : Math.min(W / 2 - w / 2 - 20, n <= 2 ? 200 : n <= 4 ? 260 : n <= 6 ? 340 : W)
  return all.map((m, i) => {
    const a = -Math.PI / 2 - (2 * Math.PI * (i + 0.5)) / n
    const view = nodeView(m)
    const v = away(m) ? undefined : m.vitals
    const line = v ? `${formatDecimal(v.requests_per_s)}/s${v.cpu_usage == null ? '' : ` · CPU ${formatPercent(v.cpu_usage)}`}` : view.label
    return { m, x: W / 2 + rx * Math.cos(a), y: n === 1 ? cy.value : cy.value + ry.value * Math.sin(a), w, h, tone: view.tone, name: fit(m.name, many.value ? 12 : m.state === 'self' ? 11 : 20), line: fit(line, many.value ? 17 : 26) }
  })
})

interface Link { key: string, x1: number, y1: number, x2: number, y2: number, kind: 'ok' | 'away' | 'unseen' }
const links = computed<Link[]>(() => {
  const out: Link[] = []
  const p = placed.value
  for (let i = 0; i < p.length; i++) {
    for (let j = i + 1; j < p.length; j++) {
      const a = p[i]!
      const b = p[j]!
      const own = a.m.state === 'self' ? b : b.m.state === 'self' ? a : null
      out.push({ key: `${a.m.id}-${b.m.id}`, x1: a.x, y1: a.y, x2: b.x, y2: b.y, kind: own ? (away(own.m) ? 'away' : 'ok') : 'unseen' })
    }
  }
  // Grey first, so the links of this server lie on top.
  return out.sort((a, b) => Number(a.kind !== 'unseen') - Number(b.kind !== 'unseen'))
})

/**
 * The internet stands above the cluster. With few gateways a dotted line leads to every one that says it is
 * ready for the balancer; with many, one short stem stands for all of them.
 */
const NET = { x: W / 2, y: 40 }
const intake = computed(() => many.value ? [] : placed.value.filter(p => !away(p.m) && p.m.vitals?.service === 'ready'))
const TONE: Record<string, string> = { success: 'fill-status-success', warning: 'fill-status-warning', danger: 'fill-status-danger', neutral: 'fill-status-neutral', info: 'fill-status-info', signal: 'fill-status-signal' }
const label = computed(() => `Karte des Clusters: ${nodes.value.length} Gateways hinter dem Loadbalancer. Jeder Server lässt sich öffnen.`)
</script>

<template>
  <figure class="hidden rounded-xl border bg-card p-4 md:block" data-testid="group-map">
    <svg :viewBox="`0 0 ${W} ${H}`" class="h-auto w-full" role="group" :aria-label="label">
      <g fill="none" stroke-linecap="round">
        <line v-for="p in intake" :key="`in-${p.m.id}`" :x1="NET.x" :y1="NET.y + 26" :x2="p.x" :y2="p.y" class="stroke-muted-foreground opacity-50" stroke-width="1.5" stroke-dasharray="1 7" data-testid="group-map-intake" />
        <path v-if="many" :d="`M${NET.x} ${NET.y + 26} V${NET.y + 58} m-6 -8 l6 8 l6 -8`" class="stroke-muted-foreground opacity-60" stroke-width="1.5" stroke-linejoin="round" />
        <template v-for="l in links" :key="l.key">
          <line v-if="l.kind === 'unseen'" :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" :class="['stroke-border', many ? 'opacity-70' : '']" :stroke-width="many ? 1 : 1.5" data-testid="group-map-link" data-kind="unseen" />
          <line v-else-if="l.kind === 'away'" :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="stroke-status-warning" stroke-width="2" stroke-dasharray="3 9" data-testid="group-map-link" data-kind="away" />
          <g v-else data-testid="group-map-link" data-kind="ok">
            <line :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="stroke-status-success opacity-35" stroke-width="2.5" />
            <line :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="flow stroke-status-success" stroke-width="2.5" stroke-dasharray="6 14" />
          </g>
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
          :x="p.x - p.w / 2" :y="p.y - p.h / 2" :width="p.w" :height="p.h" rx="12"
          :class="['fill-card', p.m.state === 'self' ? 'stroke-foreground' : 'stroke-border']" :stroke-width="p.m.state === 'self' ? 2 : 1.25"
        />
        <circle :cx="p.x - p.w / 2 + 15" :cy="p.y - p.h / 2 + 19" r="4.5" :class="TONE[p.tone]" />
        <text :x="p.x - p.w / 2 + 26" :y="p.y - p.h / 2 + 24" :class="['fill-foreground font-semibold', p.w > 150 ? 'text-[14px]' : 'text-[13px]']">{{ p.name }}</text>
        <text :x="p.x - p.w / 2 + 15" :y="p.y + p.h / 2 - 10" :class="['fill-muted-foreground tabular-nums', p.w > 150 ? 'text-[12px]' : 'text-[11px]']">{{ p.line }}</text>
        <text v-if="p.m.state === 'self'" :x="p.x - p.w / 2 + 4" :y="p.y - p.h / 2 - 7" class="fill-muted-foreground text-[11px]">dieser Server</text>
      </g>
    </svg>
    <figcaption class="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
      <span><span class="mr-1.5 inline-block h-0.5 w-5 rounded bg-status-success align-middle" />von diesem Server erreicht</span>
      <span><span class="mr-1.5 inline-block w-5 border-t-2 border-dashed border-status-warning align-middle" />nicht erreicht</span>
      <span v-if="nodes.length > 2"><span class="mr-1.5 inline-block h-0.5 w-5 rounded bg-border align-middle" />Verbindungen der anderen untereinander, von hier nicht zu sehen</span>
      <span v-if="many">Anfragen aus dem Internet verteilt der Loadbalancer auf die Server, die sich bereit melden.</span>
      <span v-else><span class="mr-1.5 inline-block w-5 border-t-2 border-dotted border-muted-foreground align-middle" />Anfragen aus dem Internet, an Server, die sich bereit melden</span>
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
