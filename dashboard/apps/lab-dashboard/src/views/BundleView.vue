<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { Bundle } from '@/api/types'
import { Button, Card, CardContent, CardHeader, CardTitle, DataTable, formatDateTime, JsonView, PageHeader, RelativeTime, StatusPill, toast } from '@schild/ui'
import { ArrowLeft, PenLine } from '@lucide/vue'
import { computed, h, ref } from 'vue'
import { useBundle, useCosignBundle, useHealth } from '@/api/queries'
import PasswordConfirmDialog from '@/components/PasswordConfirmDialog.vue'
import { useSession } from '@/composables/useSession'
import ActionPill from '@/components/ActionPill.vue'
import RelayCoverage from '@/components/bundle/RelayCoverage.vue'
import QueryState from '@/components/QueryState.vue'
import SignatureProgress from '@/components/SignatureProgress.vue'
import { BUNDLE_STATUS, CLASS_LABEL, STAGE_LABEL } from '@/lib/labels'

const props = defineProps<{ version: number }>()
const q = useBundle(() => props.version)
const b = computed(() => q.data.value)

// Co-signing (contracts v0.1): a bundle another lab assembled waits here for this lab's signature.
const { canEdit } = useSession()
const health = useHealth()
const ownLab = computed(() => health.data.value?.lab)
const canCosign = computed(() => !!b.value && canEdit.value && b.value.status === 'collecting' && !!ownLab.value
  && !!b.value.proposed_by && b.value.proposed_by !== ownLab.value && !b.value.signatures.some(s => s.lab === ownLab.value))
const cosignOpen = ref(false)
const cosign = useCosignBundle()
function openCosign() {
  cosign.reset()
  cosignOpen.value = true
}
function onCosign(v: { password: string, note?: string }) {
  cosign.mutate({ version: props.version, body: v }, {
    onSuccess: (res) => {
      cosignOpen.value = false
      toast.success(`Bündel v${res.version} mitgezeichnet`, { description: res.status === 'published' ? 'Genug Betreiber haben signiert: Das Bündel wird verteilt.' : 'Deine Signatur ist beim vorschlagenden Lab.' })
    },
  })
}
type Rule = Bundle['rules'][number]
const CHANGE: Record<string, string> = { added: 'Neu', changed: 'Geändert', unchanged: 'Unverändert' }
const columns: ColumnDef<Rule, any>[] = [
  { accessorKey: 'rule_id', header: 'Regel', cell: ({ row }) => h('span', { class: 'font-mono' }, row.original.rule_id) },
  { accessorKey: 'class', header: 'Klasse', cell: ({ row }) => CLASS_LABEL[row.original.class as keyof typeof CLASS_LABEL] ?? row.original.class },
  { accessorKey: 'max_action', header: 'Höchstaktion', cell: ({ row }) => h(ActionPill, { action: row.original.max_action }) },
  { accessorKey: 'stage', header: 'Stufe', cell: ({ row }) => STAGE_LABEL[row.original.stage] ?? row.original.stage },
  { accessorKey: 'change', header: 'Änderung', cell: ({ row }) => (row.original.change ? CHANGE[row.original.change] : '–') },
]
</script>

<template>
  <div class="space-y-6">
    <Button variant="ghost" size="sm" class="-ml-2" as-child>
      <RouterLink to="/published">
        <ArrowLeft aria-hidden="true" /> Alle Bündel
      </RouterLink>
    </Button>
    <QueryState :pending="q.isPending.value" :error="q.error.value" :rows="3" @retry="q.refetch()">
      <template v-if="b">
        <PageHeader :title="`Bündel v${b.version}`" :description="`Kanal ${b.channel}`">
          <template #meta>
            <StatusPill :tone="BUNDLE_STATUS[b.status].tone" size="sm">
              {{ BUNDLE_STATUS[b.status].text }}
            </StatusPill>
            <span class="text-xs text-muted-foreground">erstellt <RelativeTime :value="b.issued_at" /> · läuft ab {{ formatDateTime(b.expires) }}<template v-if="b.proposed_by"> · vorgeschlagen von {{ b.proposed_by }}</template></span>
          </template>
          <template v-if="canCosign" #actions>
            <Button data-testid="cosign-bundle" @click="openCosign">
              <PenLine aria-hidden="true" /> Mitzeichnen …
            </Button>
          </template>
        </PageHeader>
        <div class="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Signaturen</CardTitle>
            </CardHeader>
            <CardContent>
              <SignatureProgress :signatures="b.signatures" :threshold="b.threshold" :collecting="b.status === 'collecting'" />
              <p v-if="b.digest" class="mt-3 text-xs text-muted-foreground">
                Prüfsumme <code class="font-mono break-all">{{ b.digest }}</code>
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Verteilung</CardTitle>
            </CardHeader>
            <CardContent>
              <RelayCoverage :what="b.status === 'published' ? 'diese Version' : 'den aktuellen Stand'" :version="b.status === 'published' ? b.version : undefined" />
              <p v-if="b.status === 'collecting'" class="mt-2 text-xs text-muted-foreground">
                Diese Version wird erst verteilt, wenn genug Betreiber signiert haben.
              </p>
            </CardContent>
          </Card>
        </div>
        <section class="space-y-2">
          <h2 class="font-bold">
            Regeln
          </h2>
          <DataTable :columns="columns" :data="b.rules" label="Regeln im Bündel" :get-row-id="(r: Rule) => r.rule_id" hide-column-menu empty-title="Keine Regeln" />
        </section>
        <section v-if="b.envelope" class="space-y-2">
          <h2 class="font-bold">
            Signierter Umschlag
          </h2>
          <JsonView :value="b.envelope" label="DSSE-Umschlag" :expand-depth="1" />
        </section>
      </template>
    </QueryState>

    <PasswordConfirmDialog
      v-model:open="cosignOpen"
      :title="`Bündel v${version} mitzeichnen?`"
      :description="b ? `Vorgeschlagen von ${b.proposed_by}. Dein Lab signiert genau diese Fassung mit seinem Regel-Schlüssel.` : undefined"
      :consequences="['Prüf die Regeln oben: Mit deiner Signatur zählt dein Betreiber für die Freigabe.', 'Sobald genug unabhängige Betreiber signiert haben, verteilen die Relays das Bündel an alle Websites.']"
      confirm-label="Mitzeichnen"
      :pending="cosign.isPending.value"
      :error="cosign.error.value"
      @confirm="onCosign"
    />
  </div>
</template>
