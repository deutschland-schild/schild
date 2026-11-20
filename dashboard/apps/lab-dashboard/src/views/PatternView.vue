<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { Proposal, ReceivedSignal } from '@/api/types'
import {
  AreaChart,
  BarList,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataTable,
  formatNumber,
  formatPercent,
  JsonView,
  PageHeader,
  RelativeTime,
  StatusPill,
  toast,
} from '@schild/ui'
import { ArrowLeft, Lightbulb } from '@lucide/vue'
import { computed, h, ref } from 'vue'
import { useRouter } from 'vue-router'
import { usePattern } from '@/api/queries'
import ProposalFormDialog from '@/components/ProposalFormDialog.vue'
import QueryState from '@/components/QueryState.vue'
import ShareMeter from '@/components/ShareMeter.vue'
import { useSession } from '@/composables/useSession'
import { useShortcuts } from '@/composables/useShortcuts'
import { MAX_ISSUER_SHARE, missingFor } from '@/lib/evidence'
import { asnLabel, countryLabel, netClassLabel, toBarItems } from '@/lib/geo'
import { PATTERN_STATUS } from '@/lib/labels'
import { hourlyWindow } from '@/lib/timeline'

const props = defineProps<{ patternId: string }>()
const router = useRouter()
const { canEdit } = useSession()
const q = usePattern(() => props.patternId)
const d = computed(() => q.data.value)
const p = computed(() => d.value?.pattern)

const independence = computed(() => {
  if (!p.value) return []
  return missingFor('observe', 'heuristic', { tip_issuers: p.value.issuers, max_issuer_share: p.value.max_issuer_share, reproduced_operators: 0, sensor_operators: 0, human_approval_orgs: 0 })
})

const issuerItems = computed(() => {
  const total = d.value?.by_issuer.reduce((a, c) => a + c.count, 0) || 1
  return (d.value?.by_issuer ?? []).map(c => ({ id: String(c.key), label: String(c.key), value: c.count, hint: `${formatPercent(c.count / total)}${c.count / total > MAX_ISSUER_SHARE ? ' · über Grenze' : ''}` }))
})
// The API lists only hours with signals: show the full 24 h window (one active hour is otherwise an invisible single point).
const timeline = computed(() => hourlyWindow(d.value?.timeline ?? []))
const timelineLabels = computed(() => timeline.value.map(t => new Date(t.bucket).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })))
const series = computed(() => [
  { id: 'signals', label: 'Signale', values: timeline.value.map(t => t.signals), slot: 1 as const },
])
const issuerSeries = computed(() => [
  { id: 'issuers', label: 'Bürgen', values: timeline.value.map(t => t.issuers), slot: 2 as const },
])

const sampleColumns: ColumnDef<ReceivedSignal, any>[] = [
  { accessorKey: 'received_at', header: 'Empfangen', cell: ({ row }) => h(RelativeTime, { value: row.original.received_at, class: 'text-xs whitespace-nowrap' }) },
  { accessorKey: 'issuer', header: 'Bürge', cell: ({ row }) => h('span', { class: 'font-mono text-xs' }, row.original.issuer) },
  { id: 'origin', header: 'Herkunft', enableSorting: false, cell: ({ row }) => `${row.original.payload.origin?.country ?? '–'} · ${row.original.payload.origin?.asn ? asnLabel(row.original.payload.origin.asn) : '–'}` },
  { id: 'score', header: 'Score', meta: { class: 'text-right tabular-nums' }, accessorFn: r => r.payload.score, cell: ({ row }) => row.original.payload.score ?? '–' },
]

const formOpen = ref(false)
function onCreated(pr: Proposal) {
  toast.success('Vorschlag angelegt', { description: `${pr.rule_id} ist jetzt in Prüfung. Häng als Nächstes eine Reproduktion an.` })
  void router.push(`/proposals/${pr.id}`)
}

useShortcuts([
  { keys: 'n', description: 'Vorschlag aus diesem Muster anlegen', group: 'Muster', run: () => canEdit.value && (formOpen.value = true) },
  { keys: 'Backspace', description: 'Zurück zur Liste', group: 'Muster', run: () => void router.push('/signals') },
])
</script>

<template>
  <div class="space-y-6">
    <Button variant="ghost" size="sm" class="-ml-2" as-child>
      <RouterLink to="/signals">
        <ArrowLeft aria-hidden="true" /> Alle Muster
      </RouterLink>
    </Button>
    <QueryState :pending="q.isPending.value" :error="q.error.value" :rows="4" :retrying="q.isFetching.value" @retry="q.refetch()">
      <template v-if="d && p">
        <PageHeader :title="p.action_sig" :description="p.categories?.join(', ')">
          <template #meta>
            <StatusPill :tone="PATTERN_STATUS[p.status].tone" size="sm">
              {{ PATTERN_STATUS[p.status].text }}
            </StatusPill>
            <span class="text-xs text-muted-foreground">
              Zuerst <RelativeTime :value="p.first_seen" /> · zuletzt <RelativeTime :value="p.last_seen" />
            </span>
          </template>
          <template #actions>
            <Button v-if="p.proposal_id" variant="outline" as-child>
              <RouterLink :to="`/proposals/${p.proposal_id}`">
                Zum Vorschlag {{ p.proposal_id }}
              </RouterLink>
            </Button>
            <Button v-if="canEdit" :variant="p.proposal_id ? 'outline' : 'default'" aria-keyshortcuts="n" @click="formOpen = true">
              <Lightbulb aria-hidden="true" /> {{ p.proposal_id ? 'Weiteren Vorschlag anlegen' : 'Vorschlag anlegen' }}
            </Button>
          </template>
        </PageHeader>

        <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <Card class="gap-1 p-4">
            <p class="text-sm text-muted-foreground">
              Bürgen
            </p>
            <p class="text-2xl font-bold tabular-nums">
              {{ p.issuers }}
            </p>
            <p class="text-xs text-muted-foreground">
              {{ formatNumber(p.clients ?? 0) }} Clients, zählen nicht für Schwellen
            </p>
          </Card>
          <Card class="gap-1 p-4">
            <p class="text-sm text-muted-foreground">
              Größter Anteil eines Bürgen
            </p>
            <ShareMeter :share="p.max_issuer_share" class="py-2" />
            <p class="text-xs text-muted-foreground">
              Grenze {{ formatPercent(MAX_ISSUER_SHARE) }}
            </p>
          </Card>
          <Card class="gap-1 p-4">
            <p class="text-sm text-muted-foreground">
              Signale
            </p>
            <p class="text-2xl font-bold tabular-nums">
              {{ formatNumber(p.signals) }}
            </p>
            <p class="text-xs text-muted-foreground">
              {{ p.request_sigs ?? '–' }} Anfrageformen · Score Ø {{ p.score_avg ?? '–' }}
            </p>
          </Card>
          <Card class="gap-1 p-4" data-testid="pattern-verdict">
            <p class="text-sm text-muted-foreground">
              Reichen die Hinweise für Beobachten?
            </p>
            <p class="text-sm font-medium" :class="independence.length ? 'text-status-warning' : ''">
              {{ independence.length ? 'Noch nicht' : 'Ja, aus Hinweisen' }}
            </p>
            <ul v-if="independence.length" class="list-disc pl-4 text-xs text-muted-foreground">
              <li v-for="r in independence" :key="r">
                {{ r }}
              </li>
            </ul>
            <p v-if="independence.length && (p.status === 'proposed' || p.status === 'published')" class="text-xs text-muted-foreground">
              Der Vorschlag dazu stützt sich auf eigene Belege der Labs, nicht nur auf Hinweise.
            </p>
            <p v-else class="text-xs text-muted-foreground">
              Mehr als Beobachten braucht eigene Belege der Labs.
            </p>
          </Card>
        </div>

        <div class="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Signale über Zeit</CardTitle>
              <CardDescription>Stundenweise, letzte 24 Stunden.</CardDescription>
            </CardHeader>
            <CardContent>
              <AreaChart :series="series" :labels="timelineLabels" label="Signale pro Stunde" :height="180" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Bürgen über Zeit</CardTitle>
              <CardDescription>Wie viele unabhängige Bürgen je Stunde melden.</CardDescription>
            </CardHeader>
            <CardContent>
              <AreaChart :series="issuerSeries" :labels="timelineLabels" label="Bürgen pro Stunde" :height="180" />
            </CardContent>
          </Card>
        </div>

        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle>Nach Bürge</CardTitle>
              <CardDescription>Die Einheit der Unabhängigkeit.</CardDescription>
            </CardHeader>
            <CardContent>
              <BarList :items="issuerItems" label="Signale nach Bürge" />
            </CardContent>
          </Card>
          <Card v-if="d.by_operator?.length">
            <CardHeader>
              <CardTitle>Von Peer-Labs</CardTitle>
              <CardDescription>Nach Betreiber gezählt.</CardDescription>
            </CardHeader>
            <CardContent>
              <BarList :items="toBarItems(d.by_operator)" label="Signale nach Betreiber" color="var(--chart-2)" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Länder</CardTitle>
              <CardDescription>Herkunft laut Client, ohne IP-Adressen.</CardDescription>
            </CardHeader>
            <CardContent>
              <BarList :items="toBarItems(d.countries, countryLabel)" label="Signale nach Land" color="var(--chart-2)" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Netze (ASN)</CardTitle>
            </CardHeader>
            <CardContent>
              <BarList :items="toBarItems(d.asns, asnLabel)" label="Signale nach ASN" color="var(--chart-3)" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Netzklassen</CardTitle>
            </CardHeader>
            <CardContent>
              <BarList :items="toBarItems(d.net_classes, netClassLabel)" label="Signale nach Netzklasse" color="var(--chart-4)" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Programme</CardTitle>
            </CardHeader>
            <CardContent>
              <BarList :items="toBarItems(d.agents)" label="Signale nach Programm" color="var(--chart-5)" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>WAF-Regeln</CardTitle>
            </CardHeader>
            <CardContent>
              <BarList :items="toBarItems(d.waf_rules)" label="Signale nach WAF-Regel" color="var(--chart-1)" />
            </CardContent>
          </Card>
        </div>

        <section class="space-y-2">
          <h2 class="font-bold">
            Beispiel-Signale
          </h2>
          <p class="text-xs text-muted-foreground">
            So kommen Signale im Lab an: nur die Felder der Positivliste, nie eine IP-Adresse.
          </p>
          <DataTable
            :columns="sampleColumns"
            :data="d.samples ?? []"
            label="Beispiel-Signale"
            :get-row-id="(s: ReceivedSignal) => s.payload.id"
            hide-column-menu
            :page-sizes="[25]"
            empty-title="Keine Beispiele gespeichert"
            :detail-title="(s: ReceivedSignal) => `Signal von ${s.issuer}`"
          >
            <template #detail="{ row }">
              <JsonView :value="row.payload" label="Signal" :expand-depth="3" />
            </template>
          </DataTable>
        </section>

        <ProposalFormDialog v-model:open="formOpen" :pattern="p" @created="onCreated" />
      </template>
    </QueryState>
  </div>
</template>
