<script setup lang="ts">
import type { MetaItem } from '@schild/ui'
import type { EvidenceInput, MaxAction, Proposal, ProposalStatus } from '@/api/types'
import { Button, EmptyState, MetaLine, PageHeader, PaneItem, Skeleton, SplitPane, StatusPill, Tabs, TabsList, TabsTrigger, toast } from '@schild/ui'
import { ArrowLeft, Lightbulb } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, nextTick, ref, watch } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { keys, useAddEvidence, useApproveProposal, useProposal, useProposals, useRejectProposal, useSettings } from '@/api/queries'
import ActionPill from '@/components/ActionPill.vue'
import Kbd from '@/components/Kbd.vue'
import ApproveDialog from '@/components/proposal/ApproveDialog.vue'
import EvidenceDialog from '@/components/proposal/EvidenceDialog.vue'
import ProposalDetail from '@/components/proposal/ProposalDetail.vue'
import RejectDialog from '@/components/proposal/RejectDialog.vue'
import QueryState from '@/components/QueryState.vue'
import { useRouteQuery } from '@/composables/useRouteQuery'
import { useSession } from '@/composables/useSession'
import { useShortcuts } from '@/composables/useShortcuts'
import { ACTION_LABEL, CLASS_LABEL, PROPOSAL_STATUS } from '@/lib/labels'

const props = defineProps<{ id?: string }>()
const router = useRouter()
const qc = useQueryClient()
const { user, canEdit } = useSession()
const settings = useSettings()

const TABS: { value: string, label: string }[] = [
  { value: 'review', label: 'In Prüfung' },
  { value: 'approved', label: 'Freigegeben' },
  { value: 'draft', label: 'Entwürfe' },
  { value: 'published', label: 'Veröffentlicht' },
  { value: 'rejected', label: 'Abgelehnt' },
  { value: 'all', label: 'Alle' },
]
const statusQuery = useRouteQuery('status')
const tab = computed({
  get: () => statusQuery.value || 'review',
  set: v => (statusQuery.value = v === 'review' ? '' : v),
})
const list = useProposals(() => (tab.value === 'all' ? undefined : tab.value as ProposalStatus))
const items = computed(() => list.items.value)

const selectedId = computed(() => props.id ?? items.value[0]?.id)
const detailQuery = useProposal(() => selectedId.value)
const selected = computed<Proposal | undefined>(() => detailQuery.data.value ?? items.value.find(p => p.id === selectedId.value))
const index = computed(() => items.value.findIndex(p => p.id === selectedId.value))

function go(id: string) {
  void router.replace({ path: `/proposals/${id}`, query: statusQuery.value ? { status: statusQuery.value } : {} })
  void nextTick(() => document.querySelector<HTMLElement>(`[data-proposal="${id}"]`)?.focus({ preventScroll: false }))
}
function move(delta: number) {
  if (!items.value.length) return
  const i = index.value < 0 ? 0 : Math.min(items.value.length - 1, Math.max(0, index.value + delta))
  go(items.value[i]!.id)
}
function onListKey(e: KeyboardEvent) {
  if (e.key === 'ArrowDown') {
    e.preventDefault()
    move(1)
  }
  else if (e.key === 'ArrowUp') {
    e.preventDefault()
    move(-1)
  }
}

// ---------- actions ----------
const approveOpen = ref(false)
const rejectOpen = ref(false)
const evidenceOpen = ref(false)
const approve = useApproveProposal()
const reject = useRejectProposal()
const evidence = useAddEvidence()

const reviewable = computed(() => !!selected.value && canEdit.value && ['draft', 'review', 'approved'].includes(selected.value.status))
const approvable = computed(() => reviewable.value && !!selected.value && selected.value.status !== 'draft' && selected.value.seclang_check.valid
  && selected.value.created_by !== user.value && !selected.value.approvals.some(a => a.by === user.value))
function openApprove() {
  if (approvable.value) {
    approve.reset()
    approveOpen.value = true
  }
}
function openReject() {
  if (reviewable.value) {
    reject.reset()
    rejectOpen.value = true
  }
}
function openEvidence() {
  if (reviewable.value) {
    evidence.reset()
    evidenceOpen.value = true
  }
}

function store(p: Proposal) {
  qc.setQueryData(keys.proposal(p.id), p)
}

function onApprove(body: { max_action: MaxAction, org: string, max_action_until?: string, note?: string }) {
  const p = selected.value!
  approve.mutate({ id: p.id, body }, {
    onSuccess: (res) => {
      store(res)
      approveOpen.value = false
      toast.success(`${res.rule_id} freigegeben`, { description: `Als ${user.value} (${body.org}), höchstens ${ACTION_LABEL[body.max_action]}. Veröffentlicht wird mit dem nächsten Bündel.` })
    },
  })
}
function onReject(reason: string) {
  const p = selected.value!
  reject.mutate({ id: p.id, reason }, {
    onSuccess: (res) => {
      store(res)
      rejectOpen.value = false
      toast.success(`${res.rule_id} abgelehnt`)
    },
  })
}
function onEvidence(body: EvidenceInput) {
  const p = selected.value!
  evidence.mutate({ id: p.id, body }, {
    onSuccess: (res) => {
      store(res)
      evidenceOpen.value = false
      const level = res.allowed_max_action ? ACTION_LABEL[res.allowed_max_action] : 'noch nichts'
      toast.success('Beleg angehängt', { description: `Die Belege erlauben jetzt: ${level}.` })
    },
  })
}

useShortcuts([
  { keys: 'j', description: 'Nächster Vorschlag', group: 'Vorschläge', run: () => move(1) },
  { keys: 'k', description: 'Vorheriger Vorschlag', group: 'Vorschläge', run: () => move(-1) },
  { keys: 'a', description: 'Freigeben … (öffnet Dialog)', group: 'Vorschläge', run: openApprove },
  { keys: 'r', description: 'Ablehnen … (öffnet Dialog)', group: 'Vorschläge', run: openReject },
  { keys: 'e', description: 'Beleg anhängen …', group: 'Vorschläge', run: openEvidence },
])

// Keep the selection visible when the list changes under it (live updates).
watch(() => props.id, id => id && nextTick(() => document.querySelector(`[data-proposal="${id}"]`)?.scrollIntoView({ block: 'nearest' })))

function reproItem(p: Proposal): MetaItem {
  const done = p.evidence.reproductions.filter(r => r.status === 'reproduced').length
  const text = `${done} von ${p.evidence.reproductions.length || 0} Labs reproduziert`
  return done > 0 ? { text, tone: 'signal' } : text
}
</script>

<template>
  <div class="space-y-4">
    <PageHeader title="Vorschläge" description="Belege prüfen, dann freigeben oder ablehnen. Nichts wird ohne Menschen veröffentlicht.">
      <template #meta>
        <span class="hidden items-center gap-1 text-xs text-muted-foreground md:inline-flex">
          <Kbd>J</Kbd><Kbd>K</Kbd> wechseln · <Kbd>A</Kbd> freigeben · <Kbd>R</Kbd> ablehnen · <Kbd>E</Kbd> Beleg · <Kbd>?</Kbd> alle Kürzel
        </span>
      </template>
    </PageHeader>

    <SplitPane list-label="Vorschläge" list-width="md" sticky-list :hide-list-on-mobile="!!props.id">
      <template #tabs>
        <Tabs v-model="tab">
          <TabsList variant="line" aria-label="Status der Vorschläge">
            <TabsTrigger v-for="t in TABS" :key="t.value" :value="t.value">
              {{ t.label }}
            </TabsTrigger>
          </TabsList>
        </Tabs>
      </template>

      <template v-if="!list.isPending.value && !list.error.value && items.length" #list>
        <ul class="space-y-1.5" @keydown="onListKey">
          <li v-for="p in items" :key="p.id">
            <PaneItem
              :as="RouterLink"
              :to="{ path: `/proposals/${p.id}`, query: statusQuery ? { status: statusQuery } : {} }"
              replace
              :data-proposal="p.id"
              :active="p.id === selectedId"
            >
              <span class="flex items-center justify-between gap-2">
                <span class="min-w-0 truncate font-mono font-semibold">{{ p.rule_id }}</span>
                <StatusPill :tone="PROPOSAL_STATUS[p.status].tone" size="sm">{{ PROPOSAL_STATUS[p.status].text }}</StatusPill>
              </span>
              <MetaLine class="mt-0.5 truncate" :items="[CLASS_LABEL[p.class], `${p.target.software} ${p.target.versions}`]" />
              <span class="mt-1.5 flex flex-wrap items-center gap-1.5 text-xs">
                <span class="text-muted-foreground">erlaubt</span>
                <ActionPill :action="p.allowed_max_action" />
                <template v-if="p.requested_max_action !== p.allowed_max_action">
                  <span class="text-muted-foreground">gewünscht</span>
                  <ActionPill :action="p.requested_max_action" />
                </template>
              </span>
              <MetaLine class="mt-1" :items="[reproItem(p), `${p.approvals.length} ${p.approvals.length === 1 ? 'Freigabe' : 'Freigaben'}`]" />
            </PaneItem>
          </li>
        </ul>
        <Button v-if="list.hasNextPage.value" variant="outline" size="sm" class="mt-2 w-full" @click="list.fetchNextPage()">
          Weitere laden
        </Button>
      </template>

      <QueryState :pending="list.isPending.value" :error="list.error.value" :retrying="list.isFetching.value" @retry="list.refetch()">
        <template #skeleton>
          <div class="space-y-3">
            <Skeleton class="h-6 w-1/2" />
            <Skeleton class="h-72" />
          </div>
        </template>
        <EmptyState
          v-if="!items.length && !props.id"
          :icon="Lightbulb"
          :title="tab === 'review' ? 'Nichts zu prüfen' : 'Keine Vorschläge in dieser Ansicht'"
          description="Neue Vorschläge legst du aus einem Muster an."
        >
          <Button variant="outline" as-child>
            <RouterLink to="/signals">
              Zu den Mustern
            </RouterLink>
          </Button>
        </EmptyState>
        <div v-else class="min-w-0">
          <Button v-if="props.id" variant="ghost" size="sm" class="-ml-2 mb-2 lg:hidden" as-child>
            <RouterLink :to="{ path: '/proposals', query: statusQuery ? { status: statusQuery } : {} }">
              <ArrowLeft aria-hidden="true" /> Alle Vorschläge
            </RouterLink>
          </Button>
          <QueryState :pending="!selected && detailQuery.isPending.value" :error="selected ? null : detailQuery.error.value" @retry="detailQuery.refetch()">
            <ProposalDetail v-if="selected" :proposal="selected" :user="user" :can-edit="canEdit" @approve="openApprove" @reject="openReject" @evidence="openEvidence" />
          </QueryState>
        </div>
      </QueryState>
    </SplitPane>

    <template v-if="selected">
      <ApproveDialog v-model:open="approveOpen" :proposal="selected" :user="user" :default-org="settings.data.value?.identity.operator" :pending="approve.isPending.value" :error="approve.error.value" @confirm="onApprove" />
      <RejectDialog v-model:open="rejectOpen" :proposal="selected" :pending="reject.isPending.value" :error="reject.error.value" @confirm="onReject" />
      <EvidenceDialog v-model:open="evidenceOpen" :proposal="selected" :pending="evidence.isPending.value" :error="evidence.error.value" @confirm="onEvidence" />
    </template>
  </div>
</template>
