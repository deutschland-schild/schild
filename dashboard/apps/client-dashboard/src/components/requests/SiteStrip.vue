<script setup lang="ts">
import type { SiteStripPoint } from '@/api/requests'
import { formatNumber } from '@schild/ui'
import { computed } from 'vue'
import { OUTCOME_COLORS } from '@/lib/monitoring'

/**
 * Site-wide strip of the Kontext window (10 s steps, exact): all requests of the website, stacked
 * durchgelassen (wash), erkannt (mid) and gesperrt (deep) on the tonal scale, with a line at the
 * event. Each bar has a native tooltip; a screen-reader table lists the same numbers.
 */
const props = defineProps<{ points: SiteStripPoint[], anchor?: string | null }>()

const BAR = 8
const GAP = 2
const H = 56
const time = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const max = computed(() => Math.max(1, ...props.points.map(p => p.requests)))
const bars = computed(() => props.points.map((p, i) => {
  const k = (H - 2) / max.value
  const stopped = p.stopped * k
  const would = p.would_block * k
  const passed = Math.max(0, p.requests - p.stopped - p.would_block) * k
  const x = i * (BAR + GAP)
  return {
    x,
    t: time.format(new Date(p.t)),
    p,
    // bottom-up: gesperrt, erkannt, durchgelassen (attacks sit on the baseline where they are easy to compare)
    segs: [
      { y: H - stopped, h: stopped, color: OUTCOME_COLORS.stopped },
      { y: H - stopped - would, h: would, color: OUTCOME_COLORS.would },
      { y: H - stopped - would - passed, h: passed, color: OUTCOME_COLORS.passed },
    ].filter(s => s.h > 0),
  }
}))
const width = computed(() => Math.max(1, props.points.length * (BAR + GAP) - GAP))
const anchorX = computed(() => {
  if (!props.anchor || !props.points.length) return null
  const t = Date.parse(props.anchor)
  const i = props.points.findIndex((p, k) => {
    const next = props.points[k + 1]
    return Date.parse(p.t) <= t && (!next || Date.parse(next.t) > t)
  })
  return i < 0 ? null : i * (BAR + GAP) + BAR / 2
})
</script>

<template>
  <figure class="min-w-0" data-testid="site-strip">
    <svg :viewBox="`0 0 ${width} ${H + 2}`" class="h-16 w-full" preserveAspectRatio="none" role="img" aria-label="Alle Anfragen der Website in diesem Zeitraum, in Schritten von 10 Sekunden">
      <line x1="0" :x2="width" :y1="H + 0.5" :y2="H + 0.5" stroke="var(--border)" stroke-width="1" vector-effect="non-scaling-stroke" />
      <g v-for="b in bars" :key="b.x">
        <title>{{ b.t }}: {{ formatNumber(b.p.requests) }} Anfragen, {{ formatNumber(b.p.would_block) }} erkannt, {{ formatNumber(b.p.stopped) }} gesperrt</title>
        <rect :x="b.x" y="0" :width="BAR" :height="H" fill="transparent" />
        <rect v-for="(s, k) in b.segs" :key="k" :x="b.x" :y="s.y" :width="BAR" :height="s.h" :style="{ fill: s.color }" rx="1" />
      </g>
      <line v-if="anchorX !== null" :x1="anchorX" :x2="anchorX" y1="0" :y2="H" stroke="var(--foreground)" stroke-width="1.5" stroke-dasharray="3 2" vector-effect="non-scaling-stroke" data-testid="strip-anchor" />
    </svg>
    <figcaption class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      <span class="inline-flex items-center gap-1"><span class="size-2.5 rounded-sm border" :style="{ background: OUTCOME_COLORS.passed }" aria-hidden="true" />durchgelassen</span>
      <span class="inline-flex items-center gap-1"><span class="size-2.5 rounded-sm" :style="{ background: OUTCOME_COLORS.would }" aria-hidden="true" />erkannt</span>
      <span class="inline-flex items-center gap-1"><span class="size-2.5 rounded-sm" :style="{ background: OUTCOME_COLORS.stopped }" aria-hidden="true" />gesperrt</span>
      <span v-if="anchorX !== null" class="inline-flex items-center gap-1"><span class="h-3 border-l border-dashed border-foreground" aria-hidden="true" />dieser Alarm</span>
    </figcaption>
    <table class="sr-only">
      <caption>Anfragen der Website pro 10 Sekunden</caption>
      <thead><tr><th scope="col">Zeit</th><th scope="col">Anfragen</th><th scope="col">Erkannt</th><th scope="col">Gesperrt</th></tr></thead>
      <tbody>
        <tr v-for="b in bars" :key="b.x">
          <th scope="row">{{ b.t }}</th><td>{{ b.p.requests }}</td><td>{{ b.p.would_block }}</td><td>{{ b.p.stopped }}</td>
        </tr>
      </tbody>
    </table>
  </figure>
</template>
