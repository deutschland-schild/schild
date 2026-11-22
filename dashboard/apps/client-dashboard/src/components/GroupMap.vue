<script setup lang="ts">
import type { GroupMember, GroupStatus } from '@/api/group'
import { formatDecimal, formatPercent } from '@schild/ui'
import { computed } from 'vue'
import { edges, gateways, nodeView } from '@/lib/group'

/**
 * Map of the cluster (MVP-27): the gateways on a ring, every one linked with every other, the balancer VMs
 * above. It draws only what this server knows: its own links in colour (reached or not), the links between
 * the other servers in grey, because their state is not visible from here. A picture next to the cards below,
 * which carry every value as text; hidden on narrow screens.
 */
const props = defineProps<{ status: GroupStatus }>()

const W = 960
const nodes = computed(() => gateways(props.status))
const edgeRows = computed(() => edges(props.status))
const small = computed(() => nodes.value.length > 8)
const box = computed(() => ({ w: small.value ? 118 : 176, h: 58 }))
const top = computed(() => edgeRows.value.length ? 118 : 24)
const ry = computed(() => {
  const n = nodes.value.length
  return n <= 2 ? 0 : n <= 4 ? 120 : n <= 8 ? 150 : 215
})
const cy = computed(() => top.value + ry.value + box.value.h / 2 + 22)
const H = computed(() => cy.value + ry.value + box.value.h / 2 + 24)
const away = (m: GroupMember) => m.state === 'unreachable' || m.state === 'no_contact'

interface Placed { m: GroupMember, x: number, y: number, tone: string, name: string, line: string, title: string }
const fit = (s: string, n: number) => s.length > n ? `${s.slice(0, n - 1)}…` : s

/** This server stands at the left, the others follow clockwise. */
const placed = computed<Placed[]>(() => {
  const all = [...nodes.value].sort((a, b) => Number(b.state === 'self') - Number(a.state === 'self'))
  const n = all.length
  const rx = n === 1 ? 0 : Math.min(W / 2 - box.value.w / 2 - 28, n <= 2 ? 200 : n <= 4 ? 260 : n <= 8 ? 340 : W)
  return all.map((m, i) => {
    const a = Math.PI + (2 * Math.PI * i) / n
    const view = nodeView(m)
    const v = away(m) ? undefined : m.vitals
    const line = v ? `${formatDecimal(v.requests_per_s)}/s${v.cpu_usage == null ? '' : ` · CPU ${formatPercent(v.cpu_usage)}`}` : view.label
    return { m, x: W / 2 + rx * Math.cos(a), y: cy.value + ry.value * Math.sin(a), tone: view.tone, name: fit(m.name, small.value ? 13 : 20), line: fit(line, small.value ? 16 : 26), title: `${m.name}: ${view.label}` }
  })
})
const self = computed(() => placed.value.find(p => p.m.state === 'self'))

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

/** Balancer VMs in a row above the ring; one that asks this server is linked with it. */
const placedEdges = computed(() => {
  const n = edgeRows.value.length
  const gap = Math.min(190, (W - 80) / Math.max(n, 1))
  return edgeRows.value.map((m, i) => ({ m, x: W / 2 + (i - (n - 1) / 2) * gap, y: 46, here: m.state === 'ok', name: fit(m.name, 16) }))
})
const TONE: Record<string, string> = { success: 'fill-status-success', warning: 'fill-status-warning', danger: 'fill-status-danger', neutral: 'fill-status-neutral', info: 'fill-status-info', signal: 'fill-status-signal' }
const label = computed(() => `Karte des Clusters: ${nodes.value.length} Gateways${edgeRows.value.length ? ` und ${edgeRows.value.length} Balancer-VMs` : ''}. Die Karten darunter nennen jeden Server mit allen Werten.`)
</script>

<template>
  <figure class="hidden rounded-xl border bg-card p-4 md:block" data-testid="group-map">
    <svg :viewBox="`0 0 ${W} ${H}`" class="h-auto w-full" role="img" :aria-label="label">
      <g fill="none" stroke-linecap="round">
        <template v-for="e in placedEdges" :key="`l-${e.m.id}`">
          <line v-if="e.here && self" :x1="e.x" :y1="e.y" :x2="self.x" :y2="self.y" class="stroke-status-success" stroke-width="1.5" stroke-dasharray="2 6" data-testid="group-map-edge-link" />
        </template>
        <template v-for="l in links" :key="l.key">
          <line v-if="l.kind === 'unseen'" :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="stroke-border" stroke-width="1.5" data-testid="group-map-link" data-kind="unseen" />
          <line v-else-if="l.kind === 'away'" :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="stroke-status-warning" stroke-width="2" stroke-dasharray="3 9" data-testid="group-map-link" data-kind="away" />
          <g v-else data-testid="group-map-link" data-kind="ok">
            <line :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="stroke-status-success opacity-35" stroke-width="2.5" />
            <line :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="flow stroke-status-success" stroke-width="2.5" stroke-dasharray="6 14" />
          </g>
        </template>
      </g>

      <g v-for="e in placedEdges" :key="e.m.id" data-testid="group-map-edge" :data-state="e.m.state">
        <title>{{ e.m.name }}: Balancer-VM, {{ e.here ? 'fragt diesen Server' : 'fragt einen anderen Server' }}</title>
        <rect :x="e.x - 76" :y="e.y - 22" width="152" height="44" rx="22" class="fill-muted stroke-border" stroke-width="1" />
        <circle :cx="e.x - 56" :cy="e.y" r="4.5" :class="e.here ? 'fill-status-success' : 'fill-status-neutral'" />
        <text :x="e.x - 44" :y="e.y - 2" class="fill-foreground text-[13px] font-medium">{{ e.name }}</text>
        <text :x="e.x - 44" :y="e.y + 13" class="fill-muted-foreground text-[11px]">Balancer-VM</text>
      </g>

      <g v-for="p in placed" :key="p.m.id" data-testid="group-map-node" :data-name="p.m.name" :data-state="p.m.state">
        <title>{{ p.title }}</title>
        <rect
          :x="p.x - box.w / 2" :y="p.y - box.h / 2" :width="box.w" :height="box.h" rx="12"
          :class="['fill-card', p.m.state === 'self' ? 'stroke-foreground' : 'stroke-border']" :stroke-width="p.m.state === 'self' ? 2 : 1.25"
        />
        <circle :cx="p.x - box.w / 2 + 16" :cy="p.y - 9" r="5" :class="TONE[p.tone]" />
        <text :x="p.x - box.w / 2 + 28" :y="p.y - 4" class="fill-foreground text-[14px] font-semibold">{{ p.name }}</text>
        <text :x="p.x - box.w / 2 + 16" :y="p.y + 16" class="fill-muted-foreground text-[12px] tabular-nums">{{ p.line }}</text>
        <text v-if="p.m.state === 'self'" :x="p.x - box.w / 2 + 4" :y="p.y - box.h / 2 - 7" class="fill-muted-foreground text-[11px]">dieser Server</text>
      </g>
    </svg>
    <figcaption class="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
      <span><span class="mr-1.5 inline-block h-0.5 w-5 rounded bg-status-success align-middle" />von diesem Server erreicht</span>
      <span><span class="mr-1.5 inline-block w-5 border-t-2 border-dashed border-status-warning align-middle" />nicht erreicht</span>
      <span v-if="nodes.length > 2"><span class="mr-1.5 inline-block h-0.5 w-5 rounded bg-border align-middle" />Verbindungen der anderen untereinander, von hier nicht zu sehen</span>
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
