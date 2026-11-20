<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { EmergencyStopInput, Withdrawal } from '@/api/types'
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Checkbox,
  DataTable,
  NativeSelect,
  NativeSelectOption,
  PageHeader,
  RelativeTime,
  StatusPill,
  toast,
} from '@schild/ui'
import { Check, Circle, ListX, Undo2 } from '@lucide/vue'
import { computed, h, ref } from 'vue'
import { useBundles, useCosignWithdrawal, useCreateWithdrawal, useEmergencyStop, useHealth, useWithdrawals } from '@/api/queries'
import RelayCoverage from '@/components/bundle/RelayCoverage.vue'
import WithdrawAllDialog from '@/components/WithdrawAllDialog.vue'
import FormField from '@/components/FormField.vue'
import PasswordConfirmDialog from '@/components/PasswordConfirmDialog.vue'
import QueryState from '@/components/QueryState.vue'
import SignatureProgress from '@/components/SignatureProgress.vue'
import { useSession } from '@/composables/useSession'
import { WITHDRAW_ALL_PHRASE, WITHDRAWAL_REASON, WITHDRAWAL_STATUS } from '@/lib/labels'

const { canEdit } = useSession()
const health = useHealth()
const withdrawals = useWithdrawals()
const bundles = useBundles()
const ownLab = computed(() => health.data.value?.lab)
const items = computed(() => withdrawals.items.value)
const current = computed(() => bundles.items.value.find(b => b.status === 'published'))
const threshold = computed(() => items.value[0]?.threshold ?? current.value?.threshold ?? 2)

// The newest withdrawal of all network rules decides the status panel: collecting, or effective within the last 24 h.
const stop = computed(() => items.value.find(w => w.scope === 'all' && (w.status === 'collecting' || (w.effective_at && Date.now() - Date.parse(w.effective_at) < 24 * 3600_000))))
const signedByUs = (w: Withdrawal) => !!ownLab.value && w.signatures.some(s => s.lab === ownLab.value)
const distinctOps = (w: Withdrawal) => new Set(w.signatures.map(s => s.operator)).size

// ---------- withdraw all network rules (wire: emergency stop) ----------
const withdrawAllOpen = ref(false)
const emergency = useEmergencyStop()
function openWithdrawAll() {
  emergency.reset()
  withdrawAllOpen.value = true
}
function onWithdrawAll(body: EmergencyStopInput) {
  emergency.mutate(body, {
    onSuccess: (w) => {
      withdrawAllOpen.value = false
      const missing = Math.max(0, w.threshold - distinctOps(w))
      toast.success('Rückzug aller Netzregeln signiert', { description: missing ? `Wirksam, sobald ${missing === 1 ? '1 weiterer Betreiber mitzeichnet' : `${missing} weitere Betreiber mitzeichnen`}.` : 'Wirksam.' })
    },
  })
}

// ---------- co-sign ----------
const cosignTarget = ref<Withdrawal | null>(null)
const cosignOpen = computed({ get: () => !!cosignTarget.value, set: (v) => { if (!v) cosignTarget.value = null } })
const cosign = useCosignWithdrawal()
function openCosign(w: Withdrawal) {
  cosign.reset()
  cosignTarget.value = w
}
function onCosign(v: { password: string, note?: string }) {
  const w = cosignTarget.value!
  cosign.mutate({ seq: w.seq, body: v }, {
    onSuccess: (res) => {
      cosignTarget.value = null
      toast.success(`Rückzug ${res.seq} mitgezeichnet`, { description: res.status === 'effective' ? 'Er ist jetzt wirksam.' : 'Es fehlen noch Mitzeichnungen.' })
    },
  })
}
const cosignConsequences = computed(() => {
  const w = cosignTarget.value
  if (!w) return []
  return [
    w.scope === 'all' ? 'Alle Netzregeln werden auf allen Servern entfernt, sobald genug Betreiber signiert haben. Der Grundschutz läuft überall weiter.' : `Die Regeln ${w.rule_ids?.join(', ')} werden auf allen Servern entfernt.`,
    'Lokale Regeln jedes Servers bleiben.',
    'Deine Signatur steht im öffentlichen Log.',
  ]
})

// ---------- withdraw single rules ----------
const withdrawOpen = ref(false)
const withdraw = useCreateWithdrawal()
const ruleIds = ref<string[]>([])
const reason = ref<'false_positives' | 'superseded' | 'compromised_key' | 'other'>('false_positives')
function openWithdraw() {
  withdraw.reset()
  ruleIds.value = []
  reason.value = 'false_positives'
  withdrawOpen.value = true
}
function onWithdraw(v: { password: string, note?: string }) {
  withdraw.mutate({ rule_ids: ruleIds.value, reason: reason.value, ...(v.note ? { note: v.note } : {}), confirm: { password: v.password } }, {
    onSuccess: (w) => {
      withdrawOpen.value = false
      toast.success(`Rückzug ${w.seq} signiert`, { description: 'Wirksam, sobald genug Betreiber mitzeichnen.' })
    },
  })
}

const columns: ColumnDef<Withdrawal, any>[] = [
  { accessorKey: 'seq', header: 'Nr.', meta: { class: 'tabular-nums w-14' }, cell: ({ row }) => h('span', { class: 'font-mono' }, String(row.original.seq)) },
  {
    accessorKey: 'scope',
    header: 'Umfang',
    enableSorting: false,
    cell: ({ row }) => (row.original.scope === 'all'
      ? h(StatusPill, { tone: 'info', size: 'sm' }, () => 'Alle Netzregeln')
      : h('span', { class: 'font-mono text-xs whitespace-nowrap' }, row.original.rule_ids?.join(', ') ?? '')),
  },
  { accessorKey: 'reason', header: 'Grund', cell: ({ row }) => h('div', {}, [h('span', {}, WITHDRAWAL_REASON[row.original.reason]), row.original.note ? h('span', { class: 'block max-w-64 truncate text-xs text-muted-foreground', title: row.original.note }, row.original.note) : null]) },
  { accessorKey: 'status', header: 'Status', cell: ({ row }) => h(StatusPill, { tone: WITHDRAWAL_STATUS[row.original.status].tone, size: 'sm' }, () => WITHDRAWAL_STATUS[row.original.status].text) },
  { id: 'sigs', header: 'Mitzeichnungen', enableSorting: false, cell: ({ row }) => h(SignatureProgress, { signatures: row.original.signatures, threshold: row.original.threshold, compact: true, collecting: row.original.status === 'collecting' }) },
  { accessorKey: 'proposed_by', header: 'Von', meta: { hideOnMobile: true }, cell: ({ row }) => row.original.proposed_by ?? '–' },
  { accessorKey: 'created_at', header: 'Erstellt', meta: { hideOnMobile: true }, cell: ({ row }) => h(RelativeTime, { value: row.original.created_at, class: 'text-xs' }) },
  {
    id: 'action',
    header: () => h('span', { class: 'sr-only' }, 'Aktion'),
    enableSorting: false,
    enableHiding: false,
    cell: ({ row }) => (canEdit.value && row.original.status === 'collecting' && !signedByUs(row.original)
      ? h(Button, { size: 'sm', variant: 'outline', onClick: () => openCosign(row.original) }, () => 'Mitzeichnen …')
      : null),
  },
]
</script>

<template>
  <div class="space-y-6">
    <PageHeader title="Rückzüge" description="Netzregeln zurückziehen: einzeln oder alle auf einmal. Wirksam erst mit Signaturen mehrerer unabhängiger Betreiber. Der Grundschutz auf den Servern bleibt immer aktiv." />

    <QueryState :pending="withdrawals.isPending.value" :error="withdrawals.error.value" :retrying="withdrawals.isFetching.value" @retry="withdrawals.refetch()">
      <Card v-if="stop" data-testid="withdraw-all-status">
        <CardHeader>
          <CardTitle class="flex flex-wrap items-center gap-2">
            Rückzug aller Netzregeln · Nr. {{ stop.seq }}
            <StatusPill :tone="WITHDRAWAL_STATUS[stop.status].tone" size="sm">
              {{ WITHDRAWAL_STATUS[stop.status].text }}
            </StatusPill>
          </CardTitle>
          <CardDescription>
            {{ WITHDRAWAL_REASON[stop.reason] }}<template v-if="stop.note">
              · {{ stop.note }}
            </template>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ol class="grid gap-4 md:grid-cols-3" aria-label="Fortschritt des Rückzugs aller Netzregeln">
            <li class="space-y-1">
              <p class="flex items-center gap-2 text-sm font-medium">
                <Check class="size-4 text-status-success" aria-hidden="true" /> 1. Signiert
              </p>
              <p class="text-sm text-muted-foreground">
                von {{ stop.proposed_by ?? stop.signatures[0]?.lab }} · <RelativeTime :value="stop.created_at" />
              </p>
            </li>
            <li class="space-y-1">
              <p class="flex items-center gap-2 text-sm font-medium">
                <Check v-if="distinctOps(stop) >= stop.threshold" class="size-4 text-status-success" aria-hidden="true" />
                <Circle v-else class="size-4 text-status-warning" aria-hidden="true" />
                2. Mitzeichnungen
              </p>
              <SignatureProgress :signatures="stop.signatures" :threshold="stop.threshold" :collecting="stop.status === 'collecting'" />
              <Button v-if="canEdit && stop.status === 'collecting' && !signedByUs(stop)" size="sm" variant="outline" @click="openCosign(stop)">
                Mitzeichnen …
              </Button>
            </li>
            <li class="space-y-1">
              <p class="flex items-center gap-2 text-sm font-medium">
                <Check v-if="stop.status === 'effective'" class="size-4 text-status-success" aria-hidden="true" />
                <Circle v-else class="size-4 text-muted-foreground" aria-hidden="true" />
                3. Wirksam und verteilt
              </p>
              <template v-if="stop.status === 'effective' && stop.effective_at">
                <p class="text-sm text-muted-foreground">
                  seit <RelativeTime :value="stop.effective_at" />
                </p>
                <RelayCoverage what="den Rückzug" />
              </template>
              <p v-else class="text-sm text-muted-foreground">
                Wartet auf die Mitzeichnungen. Bis dahin gelten die Netzregeln weiter.
              </p>
            </li>
          </ol>
        </CardContent>
      </Card>

      <div class="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle class="flex items-center gap-2">
              <Undo2 class="size-5" aria-hidden="true" /> Einzelne Regeln zurückziehen
            </CardTitle>
            <CardDescription>Zum Beispiel bei Fehlalarmen einer bestimmten Regel.</CardDescription>
          </CardHeader>
          <CardContent class="space-y-3 text-sm">
            <p class="text-muted-foreground">
              Zurückziehen kann nur entfernen, nie etwas lockern oder abschalten, was Server selbst schützt.
            </p>
            <Button v-if="canEdit" variant="outline" :disabled="!current?.rules.length" @click="openWithdraw">
              Regeln zurückziehen …
            </Button>
          </CardContent>
        </Card>
        <Card data-testid="withdraw-all-option">
          <CardHeader>
            <CardTitle class="flex items-center gap-2">
              <ListX class="size-5" aria-hidden="true" /> Alle Netzregeln zurückziehen
            </CardTitle>
            <CardDescription>Für den Fall, dass Netzregeln stören und die Ursache noch unklar ist.</CardDescription>
          </CardHeader>
          <CardContent class="space-y-3 text-sm">
            <ul class="list-disc space-y-1 pl-5 text-muted-foreground">
              <li>Entfernt alle Netzregeln<template v-if="current"> aus Bündel v{{ current.version }} ({{ current.rules.length }} Regeln)</template> auf allen Servern.</li>
              <li>Der Grundschutz läuft auf jedem Server weiter, ebenso die lokalen Regeln.</li>
              <li>Wirksam erst mit {{ threshold }} unabhängigen Betreibern. Danach steht der neue Regelstand im öffentlichen Log.</li>
              <li>Netzregeln kommen mit einem neuen Bündel wieder.</li>
            </ul>
            <p v-if="stop?.status === 'collecting'" class="text-muted-foreground">
              Ein Rückzug aller Netzregeln sammelt schon Mitzeichnungen.
            </p>
            <Button v-else-if="canEdit" variant="outline" data-testid="open-withdraw-all" @click="openWithdrawAll">
              Alle Netzregeln zurückziehen …
            </Button>
            <p v-else class="text-muted-foreground">
              Mit Leserechten kannst du keine Netzregeln zurückziehen.
            </p>
          </CardContent>
        </Card>
      </div>

      <section class="space-y-2">
        <h2 class="font-bold">
          Rückzüge
        </h2>
        <DataTable :columns="columns" :data="items" label="Rückzüge" :get-row-id="(w: Withdrawal) => String(w.seq)" empty-title="Noch keine Rückzüge" cursor :has-more="withdrawals.hasNextPage.value" :loading-more="withdrawals.isFetchingNextPage.value" @load-more="withdrawals.fetchNextPage()" />
      </section>
    </QueryState>

    <WithdrawAllDialog
      v-model:open="withdrawAllOpen"
      :threshold="threshold"
      :rules-active="current?.rules.length"
      :pending="emergency.isPending.value"
      :error="emergency.error.value"
      @confirm="onWithdrawAll"
    />
    <PasswordConfirmDialog
      v-model:open="cosignOpen"
      :title="cosignTarget?.scope === 'all' ? `Rückzug aller Netzregeln (Nr. ${cosignTarget?.seq}) mitzeichnen?` : `Rückzug Nr. ${cosignTarget?.seq} mitzeichnen?`"
      :description="cosignTarget ? `Vorgeschlagen von ${cosignTarget.proposed_by ?? 'einem anderen Lab'}: ${WITHDRAWAL_REASON[cosignTarget.reason]}${cosignTarget.note ? ` – ${cosignTarget.note}` : ''}` : undefined"
      :consequences="cosignConsequences"
      confirm-label="Mitzeichnen"
      with-note
      :destructive="cosignTarget?.scope === 'all'"
      :confirm-phrase="cosignTarget?.scope === 'all' ? WITHDRAW_ALL_PHRASE : undefined"
      :pending="cosign.isPending.value"
      :error="cosign.error.value"
      @confirm="onCosign"
    />
    <PasswordConfirmDialog
      v-model:open="withdrawOpen"
      title="Regeln zurückziehen?"
      description="Die gewählten Regeln verschwinden auf allen Servern, sobald genug Betreiber mitzeichnen."
      confirm-label="Zurückziehen und signieren"
      with-note
      note-label="Notiz für die anderen Labs (optional)"
      :disabled="!ruleIds.length"
      :pending="withdraw.isPending.value"
      :error="withdraw.error.value"
      @confirm="onWithdraw"
    >
      <fieldset class="grid gap-2">
        <legend class="mb-1 text-sm font-medium">
          Regeln aus v{{ current?.version }}
        </legend>
        <label v-for="r in current?.rules ?? []" :key="r.rule_id" class="flex items-center gap-2.5 text-sm">
          <Checkbox :model-value="ruleIds.includes(r.rule_id)" :aria-label="`${r.rule_id} zurückziehen`" @update:model-value="(v) => (ruleIds = v === true ? [...ruleIds, r.rule_id] : ruleIds.filter(x => x !== r.rule_id))" />
          <span class="font-mono">{{ r.rule_id }}</span>
        </label>
      </fieldset>
      <FormField v-slot="{ id, aria }" label="Grund" required>
        <NativeSelect :id="id" v-model="reason" v-bind="aria" class="w-full">
          <NativeSelectOption value="false_positives">
            Fehlalarme
          </NativeSelectOption>
          <NativeSelectOption value="superseded">
            Ersetzt
          </NativeSelectOption>
          <NativeSelectOption value="compromised_key">
            Schlüssel kompromittiert
          </NativeSelectOption>
          <NativeSelectOption value="other">
            Anderer Grund
          </NativeSelectOption>
        </NativeSelect>
      </FormField>
    </PasswordConfirmDialog>
  </div>
</template>
