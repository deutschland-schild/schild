<script setup lang="ts">
import { ErrorState, formatDecimal, formatNumber, PageHeader, Skeleton, StatCard, StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { errorMessage } from '@/api/client'
import { useGroupStatus } from '@/api/group'
import GroupCard from '@/components/GroupCard.vue'
import GroupNodeCard from '@/components/GroupNodeCard.vue'
import { configHint, edges, gateways, groupTotals, stateView } from '@/lib/group'
import { plural } from '@/lib/summary'

/**
 * Page "Gruppe" (/server/group, MVP-27, D103): every gateway of the group with its state and its load of the
 * last minute, the totals above, the sync in detail below. Every number is what a server told this one within
 * the last seconds; nothing is asked of another server for this page. Read only: membership is changed on the
 * host with `schild cluster`.
 */
const q = useGroupStatus()
const s = computed(() => q.data.value)
const inGroup = computed(() => s.value?.mode === 'group')
const state = computed(() => s.value?.state ? stateView(s.value) : null)
const nodes = computed(() => s.value ? gateways(s.value) : [])
const totals = computed(() => s.value ? groupTotals(s.value) : null)
const edgeRows = computed(() => s.value ? edges(s.value) : [])
const edgesHere = computed(() => edgeRows.value.filter(e => e.state === 'ok').length)
const hint = computed(() => s.value ? configHint(s.value) : null)
const away = computed(() => nodes.value.filter(m => m.state === 'unreachable' || m.state === 'no_contact').map(m => m.name))
const readyHint = computed(() => {
  const t = totals.value
  if (!t) return ''
  if (away.value.length) return `${away.value.join(', ')} von hier nicht erreichbar`
  return t.ready === t.gateways ? 'Alle melden sich dem Loadbalancer als bereit' : 'Nicht alle melden sich als bereit'
})
</script>

<template>
  <div data-testid="group-page" :data-mode="s?.mode ?? ''">
    <PageHeader title="Gruppe" description="Alle Gateways der Gruppe, ihr Zustand und ihre Last. Die Zahlen meldet jeder Server alle fünf Sekunden.">
      <template v-if="state" #meta>
        <StatusPill :tone="state.tone" size="sm" data-testid="group-page-state">
          {{ state.label }}
        </StatusPill>
        <span class="text-sm text-muted-foreground">{{ state.text }}</span>
      </template>
    </PageHeader>

    <ErrorState v-if="q.isError.value && !s" title="Der Stand der Gruppe lässt sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
    <div v-else-if="!s" class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      <Skeleton v-for="i in 3" :key="i" class="h-64 w-full" />
    </div>
    <template v-else-if="inGroup && totals">
      <section aria-label="Die Gruppe in Zahlen" class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" data-testid="group-totals">
        <StatCard label="Server bereit" :value="`${formatNumber(totals.ready)} von ${formatNumber(totals.gateways)}`" :hint="readyHint" :tone="totals.ready === totals.gateways ? 'success' : 'warning'" data-testid="group-total-ready" />
        <StatCard
          label="Anfragen pro Sekunde" :value="totals.requestsPerS === null ? '–' : formatDecimal(totals.requestsPerS)"
          :hint="totals.reporting === totals.gateways ? 'Alle Server zusammen, letzte Minute' : `Summe aus ${plural(totals.reporting, 'Server', 'Servern')}, letzte Minute`" data-testid="group-total-rps"
        />
        <StatCard label="Laufende Sperren" :value="s.shared?.blocks ?? null" hint="Gelten auf jedem Server der Gruppe" data-testid="group-total-blocks" />
        <StatCard
          label="Balancer-VMs" :value="edgeRows.length"
          :hint="edgeRows.length ? `${formatNumber(edgesHere)} fragen gerade diesen Server` : 'Keine in der Gruppe. Sperren greifen auf den Gateways.'" data-testid="group-total-edges"
        />
      </section>

      <p v-if="hint" class="mt-4 rounded-lg border border-status-warning/30 bg-status-warning-subtle px-3 py-2 text-sm" role="note" data-testid="group-page-config-hint">
        {{ hint }}
      </p>

      <section aria-labelledby="group-nodes-title" class="mt-6">
        <h2 id="group-nodes-title" class="mb-3 text-lg font-semibold">
          Gateways
        </h2>
        <div class="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
          <GroupNodeCard v-for="m in nodes" :key="m.id" :member="m" :config-version="s.config?.version" />
        </div>
      </section>

      <GroupCard class="mt-6" heading="Balancer-VMs und Abgleich" brief />
    </template>
    <GroupCard v-else />
  </div>
</template>
