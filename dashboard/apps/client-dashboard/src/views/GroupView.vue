<script setup lang="ts">
import { ErrorState, formatDecimal, formatNumber, formatPercent, PageHeader, Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, Skeleton, StatCard, StatusDot, StatusPill } from '@schild/ui'
import { computed, ref } from 'vue'
import { errorMessage } from '@/api/client'
import { useGroupStatus } from '@/api/group'
import GroupCard from '@/components/GroupCard.vue'
import GroupMap from '@/components/GroupMap.vue'
import GroupNodeCard from '@/components/GroupNodeCard.vue'
import { configHint, edges, gateways, groupTotals, nodeView, stateView } from '@/lib/group'
import { plural } from '@/lib/summary'

/**
 * Page "Cluster" (/server/group, MVP-27, D103): the totals, a map of the gateways and their links, every gateway
 * with its state and its load of the last minute, the sync in detail below. Every number is what a server told this one within
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
/** Up to this many gateways each gets a card; above, a table whose rows open the details. */
const CARDS_MAX = 6
const selectedId = ref<string | null>(null)
const selected = computed(() => nodes.value.find(m => m.id === selectedId.value))
const detailOpen = computed({ get: () => !!selected.value, set: (v) => { if (!v) selectedId.value = null } })
const vitalsOf = (m: (typeof nodes.value)[number]) => m.state === 'unreachable' || m.state === 'no_contact' ? undefined : m.vitals
const readyHint = computed(() => {
  const t = totals.value
  if (!t) return ''
  if (away.value.length) return `${away.value.join(', ')} von hier nicht erreichbar`
  return t.ready === t.gateways ? 'Alle melden sich als bereit' : 'Nicht alle melden sich als bereit'
})
</script>

<template>
  <div data-testid="group-page" :data-mode="s?.mode ?? ''">
    <PageHeader title="Cluster" description="Mehrere Gateways, die Sperren, Einstellungen und Logins teilen. Fällt ein Server aus, bedienen die anderen weiter. Für mehr Last nimmst du weitere Server dazu.">
      <template v-if="state" #meta>
        <StatusPill :tone="state.tone" size="sm" data-testid="group-page-state">
          {{ state.label }}
        </StatusPill>
        <span class="text-sm text-muted-foreground">{{ state.text }}</span>
      </template>
    </PageHeader>

    <ErrorState v-if="q.isError.value && !s" title="Der Stand des Clusters lässt sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
    <div v-else-if="!s" class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      <Skeleton v-for="i in 3" :key="i" class="h-64 w-full" />
    </div>
    <template v-else-if="inGroup && totals">
      <section aria-label="Der Cluster in Zahlen" class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" data-testid="group-totals">
        <StatCard label="Server bereit" :value="`${formatNumber(totals.ready)} von ${formatNumber(totals.gateways)}`" :hint="readyHint" :tone="totals.ready === totals.gateways ? 'success' : 'warning'" data-testid="group-total-ready" />
        <StatCard
          label="Anfragen pro Sekunde" :value="totals.requestsPerS === null ? '–' : formatDecimal(totals.requestsPerS)"
          :hint="totals.reporting === totals.gateways ? 'Alle Server zusammen, letzte Minute' : `Summe aus ${plural(totals.reporting, 'Server', 'Servern')}, letzte Minute`" data-testid="group-total-rps"
        />
        <StatCard label="Laufende Sperren" :value="s.shared?.blocks ?? null" hint="Gelten auf jedem Server des Clusters" data-testid="group-total-blocks" />
        <StatCard
          label="Balancer-VMs" :value="edgeRows.length"
          :hint="edgeRows.length ? `${formatNumber(edgesHere)} fragen gerade diesen Server` : 'Keine im Cluster. Sperren greifen auf den Gateways.'" data-testid="group-total-edges"
        />
      </section>

      <p v-if="hint" class="mt-4 rounded-lg border border-status-warning/30 bg-status-warning-subtle px-3 py-2 text-sm" role="note" data-testid="group-page-config-hint">
        {{ hint }}
      </p>

      <GroupMap :status="s" class="mt-6" @select="selectedId = $event" />

      <section aria-labelledby="group-nodes-title" class="mt-6">
        <h2 id="group-nodes-title" class="mb-3 text-lg font-semibold">
          Gateways
        </h2>
        <div v-if="nodes.length <= CARDS_MAX" class="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
          <GroupNodeCard v-for="m in nodes" :key="m.id" :member="m" :config-version="s.config?.version" />
        </div>
        <div v-else class="overflow-x-auto rounded-xl border bg-card focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none" tabindex="0" role="region" aria-labelledby="group-nodes-title">
          <table class="w-full text-sm" data-testid="group-node-table">
            <thead class="text-left text-xs text-muted-foreground">
              <tr class="border-b">
                <th scope="col" class="px-4 py-2 font-medium">
                  Server
                </th>
                <th scope="col" class="px-4 py-2 font-medium">
                  Zustand
                </th>
                <th scope="col" class="px-4 py-2 text-right font-medium">
                  Anfragen/s
                </th>
                <th scope="col" class="px-4 py-2 text-right font-medium">
                  CPU
                </th>
                <th scope="col" class="px-4 py-2 text-right font-medium">
                  Arbeitsspeicher
                </th>
                <th scope="col" class="px-4 py-2 text-right font-medium">
                  Festplatte
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in nodes" :key="m.id" class="cursor-pointer border-b last:border-0 hover:bg-muted/50" data-testid="group-node-row" :data-name="m.name" @click="selectedId = m.id">
                <td class="px-4 py-2 whitespace-nowrap">
                  <button type="button" class="inline-flex items-center gap-2 rounded font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none" @click.stop="selectedId = m.id">
                    <StatusDot :tone="nodeView(m).tone" />
                    {{ m.name }}
                  </button>
                  <span v-if="m.state === 'self'" class="ml-2 text-xs text-muted-foreground">dieser Server</span>
                </td>
                <td class="px-4 py-2 whitespace-nowrap">
                  {{ nodeView(m).label }}
                </td>
                <td class="px-4 py-2 text-right tabular-nums">
                  {{ vitalsOf(m) ? formatDecimal(vitalsOf(m)!.requests_per_s) : '–' }}
                </td>
                <td class="px-4 py-2 text-right tabular-nums">
                  {{ formatPercent(vitalsOf(m)?.cpu_usage) }}
                </td>
                <td class="px-4 py-2 text-right tabular-nums">
                  {{ formatPercent(vitalsOf(m)?.memory_used_ratio) }}
                </td>
                <td class="px-4 py-2 text-right tabular-nums">
                  {{ formatPercent(vitalsOf(m)?.disk_used_ratio) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <GroupCard class="mt-6" heading="Balancer-VMs und Abgleich" brief />

      <Sheet v-model:open="detailOpen">
        <SheetContent class="w-full gap-0 overflow-y-auto sm:max-w-lg" data-testid="group-node-sheet">
          <SheetHeader class="border-b">
            <SheetTitle>{{ selected?.name ?? 'Server' }}</SheetTitle>
            <SheetDescription>Was dieser Server zuletzt von ihm gehört hat.</SheetDescription>
          </SheetHeader>
          <GroupNodeCard v-if="selected" :member="selected" :config-version="s.config?.version" class="rounded-none border-0 shadow-none" />
        </SheetContent>
      </Sheet>
    </template>
    <GroupCard v-else />
  </div>
</template>
