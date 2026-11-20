<script setup lang="ts">
import type { AlertItem } from '@/api/websites'
import { countryName, Skeleton } from '@schild/ui'
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { letThroughText, WOULD_BLOCK_REASON } from '@/lib/labels'
import { NET_CLASSES } from '@/lib/monitoring'
import { websitePath } from '@/lib/nav'
import { contextLink } from '@/lib/requests'
import { ALERT_OUTCOMES, RULE_CATEGORIES } from '@/lib/websites'

/**
 * "Letzte Alarme" next to the main chart on Zugriffe (D36, D68): the newest detections of this website, newest first.
 * Each entry opens the event (with address and context). The gateway marks a WAF alert whose rule and
 * page have a false-positive hint of the website (possible_false_positive, D36 amendment): "möglicher Fehlalarm".
 */
const props = defineProps<{
  items: AlertItem[]
  loading?: boolean
  /** Website id: each alert opens on the Ereignisse page of this website. */
  site: string
  /** The request ring runs: offer "Kontext" per alert (MVP-22). */
  ring?: boolean
}>()

const route = useRoute()
const time = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit' })
const day = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit' })
const rows = computed(() => {
  const today = new Date().toDateString()
  return props.items.map((a) => {
    const d = new Date(a.t)
    const fp = a.possible_false_positive === true
    return {
      a,
      when: d.toDateString() === today ? time.format(d) : `${day.format(d)} ${time.format(d)}`,
      title: RULE_CATEGORIES[a.category] ?? a.category,
      outcome: ALERT_OUTCOMES[a.outcome] ?? { label: a.outcome, strong: false },
      where: [a.country ? countryName(a.country) : '', a.net_class ? NET_CLASSES[a.net_class] ?? a.net_class : ''].filter(Boolean).join(' · '),
      fp,
      // would_block and would_rate_limit: why it was let through (would_block_reason, v0.5).
      letThrough: a.outcome === 'would_block' || a.outcome === 'would_rate_limit' ? letThroughText(a.would_block_reason) : null,
      reason: a.would_block_reason ? WOULD_BLOCK_REASON[a.would_block_reason] : null,
    }
  })
})
</script>

<template>
  <div class="flex min-h-0 flex-col" data-testid="alert-feed">
    <div v-if="loading && !items.length" class="space-y-3">
      <Skeleton v-for="i in 6" :key="i" class="h-12 w-full" />
    </div>
    <p v-else-if="!items.length" class="py-6 text-sm text-muted-foreground" data-testid="alerts-empty">
      In diesem Zeitraum hat Schild hier nichts erkannt.
    </p>
    <ol v-else class="-mx-2 divide-y overflow-y-auto" aria-label="Letzte Alarme">
      <li v-for="r in rows" :key="r.a.event_id" class="group relative">
        <!-- MVP-22: what this client did before and after (Kontext drawer). -->
        <RouterLink
          v-if="ring"
          :to="contextLink(route, r.a.event_id)"
          class="absolute right-2 bottom-2 z-10 inline-flex min-h-6 items-center rounded-md border bg-card px-1.5 text-xs text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
          :title="`Kontext: was dieser Besucher davor und danach getan hat`"
          data-testid="alert-context"
        >
          Kontext
        </RouterLink>
        <RouterLink
          :to="{ path: websitePath(site, 'events'), query: { event: r.a.event_id, time: '7d' } }"
          class="block rounded-md px-2 py-2 text-sm hover:bg-muted/60 focus-visible:outline-2 focus-visible:outline-ring"
          :data-alert="r.a.event_id"
        >
          <span class="flex items-baseline justify-between gap-2">
            <span class="min-w-0 truncate font-medium">{{ r.title }}<span v-if="r.a.rules?.length" class="font-normal text-muted-foreground"> · {{ r.a.rules.join(', ') }}</span></span>
            <span class="shrink-0 text-xs text-muted-foreground tabular-nums">{{ r.when }}</span>
          </span>
          <span v-if="r.a.path" class="mt-0.5 block truncate font-mono text-xs text-muted-foreground" :title="r.a.path">{{ r.a.path }}</span>
          <span class="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground" :class="ring ? 'pr-16' : ''">
            <span :class="['rounded-full border px-1.5 py-px font-medium', r.outcome.strong ? 'border-transparent bg-foreground/85 text-background' : 'bg-card']" :title="r.letThrough ?? undefined">{{ r.outcome.label }}<span v-if="r.reason" data-testid="alert-reason">{{ r.a.outcome === 'would_block' ? `, aber durchgelassen: ${r.reason}` : ` (${r.reason})` }}</span></span>
            <span v-if="r.fp" class="rounded-full border border-status-info/40 bg-status-info-subtle px-1.5 py-px text-status-info" data-testid="possible-fp">möglicher Fehlalarm</span>
            <span v-if="r.where">{{ r.where }}</span>
            <span v-if="r.a.client_pseudonym" class="font-mono" title="Pseudonym der Adresse; die Adresse selbst steht im Ereignis">{{ r.a.client_pseudonym.slice(0, 11) }}</span>
            <span v-if="r.a.incident" class="font-mono">{{ r.a.incident }}</span>
          </span>
        </RouterLink>
      </li>
    </ol>
  </div>
</template>
