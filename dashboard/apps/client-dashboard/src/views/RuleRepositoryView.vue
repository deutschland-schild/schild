<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { Rule, RuleRepositoryId, RuleStatus } from '@/api/types'
import {
  DataTable,
  ErrorState,
  formatDuration,
  formatNumber,
  MetaLine,
  NativeSelect,
  NativeSelectOption,
  PageHeader,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  Skeleton,
  Tabs,
  TabsList,
  TabsTrigger,
} from '@schild/ui'
import { computed, h, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ruleError, useRuleExceptions, useRuleRepository, useRules } from '@/api/rules'
import FalsePositiveHints from '@/components/rules/FalsePositiveHints.vue'
import RepositoryCard from '@/components/rules/RepositoryCard.vue'
import RuleDetailPanel from '@/components/rules/RuleDetailPanel.vue'
import RuleExceptions from '@/components/rules/RuleExceptions.vue'
import RuleStatusPill from '@/components/rules/RuleStatusPill.vue'
import SheetStepper from '@/components/SheetStepper.vue'
import { DISABLED_BY, groupExceptions, LOCAL_RULES, REPOSITORIES, RULE_EFFECT, RULE_STATUS, RULE_STATUS_ORDER, ruleMeta, ruleText } from '@/lib/rules'

/**
 * One rule repository (D73): its switch and state on top, its rules below, a rule opens in a sheet
 * (?rule=<id>). Rules that wait for a person come first.
 */
const route = useRoute()
const router = useRouter()
const id = computed(() => route.meta.repository as RuleRepositoryId)
const meta = computed(() => REPOSITORIES[id.value])

const { repo, ...repoQ } = useRuleRepository(id)

const status = computed(() => (typeof route.query.status === 'string' && route.query.status in RULE_STATUS ? route.query.status as RuleStatus : undefined))
function setQuery(patch: Record<string, string | undefined>) {
  const query = { ...route.query }
  for (const [k, v] of Object.entries(patch)) {
    if (!v) delete query[k]
    else query[k] = v
  }
  void router.replace({ query })
}
const statusModel = computed({ get: () => status.value ?? '', set: v => setQuery({ status: String(v) || undefined }) })

const rulesQ = useRules(() => ({ repository: id.value, ...(status.value ? { status: status.value } : {}) }))
/** The API sorts by hits; what settles goes first, the rest keeps its order. */
const rank = (s: RuleStatus) => s === 'settling' ? 0 : 1
const items = computed(() => (rulesQ.data.value?.pages.flatMap(p => p.items) ?? [])
  .map((r, i) => ({ r, i }))
  .sort((a, b) => rank(a.r.status) - rank(b.r.status) || a.i - b.i)
  .map(x => x.r))

/** "noch 20 Stunden": until a settling update blocks on its own. */
const settlingLeft = (until: string) => `noch ${formatDuration(Math.max(60, (Date.parse(until) - Date.now()) / 1000))}`

const detailId = computed(() => typeof route.query.rule === 'string' ? route.query.rule : null)
const detailOpen = computed({ get: () => !!detailId.value, set: v => !v && setQuery({ rule: undefined }) })

const columns = computed<ColumnDef<Rule, unknown>[]>(() => [
  {
    id: 'rule',
    header: 'Regel',
    accessorFn: r => ruleText(r).title,
    enableHiding: false,
    meta: { label: 'Regel', class: 'min-w-44 max-w-[30rem] whitespace-normal sm:min-w-60' },
    cell: ({ row }) => h('div', { class: 'min-w-0 py-0.5' }, [
      h('p', { class: 'font-semibold' }, ruleText(row.original).title),
      ruleText(row.original).explain ? h('p', { class: 'mt-0.5 hidden text-sm text-muted-foreground sm:block' }, ruleText(row.original).explain) : null,
      h(MetaLine, { class: 'mt-0.5', items: ruleMeta(row.original) }),
    ]),
  },
  {
    id: 'status',
    header: 'Status',
    accessorKey: 'status',
    meta: { label: 'Status' },
    cell: ({ row }) => {
      const r = row.original
      const sub = r.status === 'disabled' && r.disabled_by
        ? DISABLED_BY[r.disabled_by]
        : r.status === 'settling' && r.crowdsec?.settling_until ? settlingLeft(r.crowdsec.settling_until) : ''
      return h('div', { class: 'space-y-0.5' }, [
        h(RuleStatusPill, { status: r.status }),
        sub ? h('p', { class: 'text-xs text-muted-foreground' }, sub) : null,
      ])
    },
  },
  {
    id: 'effect',
    header: 'Wirkung',
    accessorKey: 'effect',
    meta: { label: 'Wirkung', hideOnMobile: true },
    // Why it does not block is on the card above (mode, repository) and in the status column (waiting).
    cell: ({ row }) => RULE_EFFECT[row.original.effect].label,
  },
  {
    id: 'hits',
    header: 'Treffer 24 h',
    accessorKey: 'hits_24h',
    meta: { label: 'Treffer 24 h', class: 'text-right tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.hits_24h),
  },
])

/** Own rules and exceptions share a page, one tab each: the rules first, the exceptions under ?view=exceptions. */
const local = computed(() => id.value === 'local')
const exceptionsQ = useRuleExceptions()
const exceptionCount = computed(() => exceptionsQ.data.value && groupExceptions(exceptionsQ.data.value.items).length)
const showExceptions = computed(() => local.value && route.query.view === 'exceptions')
const exceptions = ref<InstanceType<typeof RuleExceptions> | null>(null)
const tabModel = computed({ get: () => showExceptions.value ? 'exceptions' : 'rules', set: v => setQuery({ view: v === 'exceptions' ? 'exceptions' : undefined }) })

const emptyText = computed(() => {
  if (status.value) return { title: `Keine Regel mit dem Status „${RULE_STATUS[status.value].label}“`, description: 'Wähle oben einen anderen Status.' }
  if (id.value === 'local') return { title: 'Noch keine eigenen Regeln', description: `Leg eine Datei mit der Endung .conf in ${repo.value?.local?.dir ?? 'rules.d'} an und lade oben neu. Für einen Fehlalarm brauchst du keine Datei: Leg im Reiter Ausnahmen eine Ausnahme an.` }
  return { title: 'Keine Regeln', description: 'Sobald Regeln geladen sind, stehen sie hier.' }
})
</script>

<template>
  <div>
    <PageHeader :title="meta.name" :description="meta.lead" />

    <Tabs v-if="local" v-model="tabModel" class="mb-5">
      <TabsList variant="line" aria-label="Ansicht">
        <TabsTrigger value="rules" data-testid="tab-rules">
          {{ LOCAL_RULES }}
        </TabsTrigger>
        <TabsTrigger value="exceptions" data-testid="tab-exceptions">
          Ausnahmen<template v-if="exceptionCount">
            ({{ formatNumber(exceptionCount) }})
          </template>
        </TabsTrigger>
      </TabsList>
    </Tabs>

    <template v-if="showExceptions">
      <RuleExceptions ref="exceptions" class="mb-4" always />
      <FalsePositiveHints @add="preset => exceptions?.create(preset)" />
    </template>
    <template v-else>
      <Skeleton v-if="repoQ.isPending.value" class="mb-4 h-40 w-full rounded-xl" />
      <ErrorState v-else-if="repoQ.isError.value && !repo" class="mb-4" title="Der Stand dieser Regeln lässt sich gerade nicht laden" :description="ruleError(repoQ.error.value)" @retry="repoQ.refetch()" />
      <RepositoryCard v-else-if="repo" :repo="repo" />

      <ErrorState v-if="rulesQ.isError.value && !items.length" title="Die Regeln lassen sich gerade nicht laden" :description="ruleError(rulesQ.error.value)" @retry="rulesQ.refetch()" />
      <DataTable
        v-else
        :columns="columns"
        :data="items"
        :label="`Regeln: ${local ? LOCAL_RULES : meta.name}`"
        :loading="rulesQ.isPending.value"
        :get-row-id="(r: Rule) => r.id"
        cursor
        :has-more="rulesQ.hasNextPage.value"
        :loading-more="rulesQ.isFetchingNextPage.value"
        :estimate-row-height="64"
        :empty-title="emptyText.title"
        :empty-description="emptyText.description"
        data-testid="rule-table"
        @row-click="(r: Rule) => setQuery({ rule: r.id })"
        @load-more="rulesQ.fetchNextPage()"
      >
        <template #toolbar>
          <div class="flex flex-wrap items-center gap-2">
            <p class="mr-auto font-bold">
              Regeln
            </p>
            <NativeSelect v-model="statusModel" aria-label="Status" data-testid="rule-status-filter">
              <NativeSelectOption value="">
                Jeder Status
              </NativeSelectOption>
              <NativeSelectOption v-for="key in RULE_STATUS_ORDER" :key="key" :value="key">
                {{ RULE_STATUS[key].label }}
              </NativeSelectOption>
            </NativeSelect>
          </div>
        </template>
      </DataTable>

      <RuleExceptions v-if="!local" class="mt-4" :repository="id === 'local' ? undefined : id" />
    </template>

    <Sheet v-model:open="detailOpen">
      <SheetContent class="w-full gap-0 overflow-y-auto sm:max-w-2xl xl:max-w-3xl" data-testid="rule-sheet">
        <SheetHeader class="border-b">
          <SheetTitle>Regel</SheetTitle>
          <SheetDescription>{{ meta.name }}: was sie tut und was du mit ihr machen kannst.</SheetDescription>
          <SheetStepper :ids="items.map(x => x.id)" :current="detailId" @select="rule => setQuery({ rule })" />
        </SheetHeader>
        <RuleDetailPanel v-if="detailId" :id="detailId" :repository="id" />
      </SheetContent>
    </Sheet>
  </div>
</template>
