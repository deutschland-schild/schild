<script setup lang="ts">
import type { ColumnDef, FilterChip } from '@schild/ui'
import type { LocationQueryRaw } from 'vue-router'
import type { AuditEntry } from '@/api/audit'
import type { AuditField_, AuditFilters } from '@/lib/audit'
import {
  Button,
  DataTable,
  ErrorState,
  FilterBar,
  formatDateTime,
  Input,
  Label,
  NativeSelect,
  NativeSelectOption,
  PageHeader,
  Popover,
  PopoverContent,
  PopoverTrigger,
  RelativeTime,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  StatusPill,
} from '@schild/ui'
import { RefreshCw, SlidersHorizontal } from '@lucide/vue'
import { computed, h, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAgentTokens } from '@/api/agentapi'
import { useAudit } from '@/api/audit'
import { errorMessage } from '@/api/client'
import { useWebsites } from '@/api/websites'
import AuditEntryPanel from '@/components/audit/AuditEntryPanel.vue'
import SheetStepper from '@/components/SheetStepper.vue'
import { tokenName } from '@/lib/agentapi'
import {
  ACTION_OPTIONS,
  actorName,
  AUDIT_COPY as COPY,
  AUDIT_FIELDS,
  auditChips,
  CLASS_ORDER,
  CLASSES,
  countText,
  entryTitle,
  parseAuditFilters,
  splitOperation,
  SUBJECT_OPTIONS,
  subjectLabel,
  toAuditQuery,
  validFilter,
  WAY_ORDER,
  wayLabel,
  WAYS,
} from '@/lib/audit'
import { websiteName } from '@/lib/websites'

/**
 * Einstellungen > Protokoll (MVP-36, contracts/audit.md section 8): one list of the audit log with the
 * filters of listAudit. The filters and the open entry (?entry=<id>) live in the URL, so every name in
 * an entry, and every "Zuletzt geändert von …" elsewhere in the app, is a link to this page.
 */
const route = useRoute()
const router = useRouter()

const filters = computed(() => parseAuditFilters(route.query))
const apiQuery = computed(() => toAuditQuery(filters.value))
const filtered = computed(() => Object.keys(filters.value).length > 0)

function update(patch: Partial<Record<AuditField_ | 'entry', string | undefined>>) {
  const query: LocationQueryRaw = { ...route.query }
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined || v === '') delete query[k]
    else query[k] = v
  }
  if (!query.subject) delete query.subject_id
  void router.replace({ query })
}
function clear() {
  const query: LocationQueryRaw = { ...route.query }
  for (const k of AUDIT_FIELDS) delete query[k]
  void router.replace({ query })
}

// ---------------------------------------------------------------- list
const list = useAudit(apiQuery)
const rows = computed<AuditEntry[]>(() => list.data.value?.pages.flatMap(p => p.items) ?? [])

// ---------------------------------------------------------------- names for filters and rows
const websites = useWebsites()
const sites = computed(() => websites.data.value?.websites ?? [])
const siteName = (id: string) => websiteName(sites.value.find(w => w.id === id), id)
const tokens = useAgentTokens()
const tokenLabel = (id: string) => {
  const t = tokens.data.value?.find(x => x.id === id)
  return t?.label ? `${tokenName(t)} (${id})` : id
}

const chips = computed<FilterChip[]>({
  get: () => auditChips(filters.value, { website: siteName, token: tokenLabel }),
  set: () => {},
})
function onRemoveChip(chip: FilterChip) {
  update(chip.key === 'subject' ? { subject: undefined, subject_id: undefined } : { [chip.key]: undefined })
}

const select = (key: AuditField_) => computed({
  get: () => filters.value[key] ?? '',
  set: (v: string) => update({ [key]: String(v) || undefined }),
})
const websiteModel = select('website')
const classModel = select('class')
const wayModel = select('way')
const actionModel = select('action')

// ---------------------------------------------------------------- further filters (a form, applied at once)
const MORE = ['from', 'to', 'actor', 'subject', 'subject_id', 'session', 'event', 'incident'] as const
type MoreField = typeof MORE[number]
const moreOpen = ref(false)
const draft = reactive<Record<MoreField, string>>({ from: '', to: '', actor: '', subject: '', subject_id: '', session: '', event: '', incident: '' })
const HINTS: Partial<Record<MoreField, string>> = {
  actor: 'Die Kennung eines Tokens, z. B. tok_0123456789ab',
  session: 'Acht Zeichen, wie sie im Eintrag einer Anmeldung stehen',
  event: 'Die Kennung eines Ereignisses',
  incident: 'Eine Vorfallnummer, z. B. K7QM-4XWD',
}
const normal = (k: MoreField, v: string) => k === 'incident' ? v.trim().toUpperCase() : k === 'subject_id' ? v.trim() : v.trim().toLowerCase()
const draftErrors = computed(() => Object.fromEntries(MORE.map((k) => {
  const v = normal(k, draft[k])
  return [k, v && !validFilter(k, v) ? (HINTS[k] ?? 'Das passt nicht.') : null]
})) as Record<MoreField, string | null>)
watch(moreOpen, (open) => {
  if (open) for (const k of MORE) draft[k] = filters.value[k] ?? ''
})
function applyMore() {
  if (Object.values(draftErrors.value).some(Boolean)) return
  const patch: AuditFilters = {}
  for (const k of MORE) patch[k] = normal(k, draft[k]) || undefined
  update(patch)
  moreOpen.value = false
}
const moreCount = computed(() => MORE.filter(k => k !== 'subject_id' && filters.value[k]).length)

// ---------------------------------------------------------------- the open entry (deep link ?entry=<id>)
const entryId = computed(() => typeof route.query.entry === 'string' ? route.query.entry : null)
const entry = computed(() => entryId.value ? rows.value.find(r => r.id === entryId.value) ?? null : null)
const detailOpen = computed({
  get: () => !!entryId.value,
  set: (v) => {
    if (!v) update({ entry: undefined })
  },
})
function open(e: AuditEntry | string) {
  update({ entry: typeof e === 'string' ? e : e.id })
}

// ---------------------------------------------------------------- table
const columns: ColumnDef<AuditEntry, unknown>[] = [
  {
    id: 'time',
    header: 'Wann',
    enableSorting: false,
    enableHiding: false,
    meta: { label: 'Wann', class: 'w-40 whitespace-nowrap' },
    cell: ({ row }) => h('div', {}, [
      h('time', { datetime: row.original.time, class: 'block tabular-nums' }, formatDateTime(row.original.time)),
      h(RelativeTime, { value: row.original.time, class: 'text-xs text-muted-foreground' }),
    ]),
  },
  {
    id: 'what',
    header: 'Was',
    enableSorting: false,
    enableHiding: false,
    meta: { label: 'Was', class: 'min-w-48' },
    cell: ({ row }) => {
      const e = row.original
      return h('div', { class: 'min-w-0 space-y-0.5' }, [
        h('p', { class: 'flex flex-wrap items-center gap-2' }, [
          h('span', { 'class': 'font-medium', 'data-testid': 'audit-row-title' }, entryTitle(e)),
          e.class !== 'change' ? h(StatusPill, { tone: CLASSES[e.class]?.tone ?? 'neutral', size: 'sm' }, () => CLASSES[e.class]?.label ?? e.class) : null,
        ]),
        h('p', { class: 'text-xs text-muted-foreground [overflow-wrap:anywhere]' }, [
          subjectLabel(e.subject.kind),
          e.subject.id ? h('span', { class: 'font-mono' }, ` ${e.subject.id}`) : null,
          e.count ? ` · ${countText(e.count)}` : null,
        ]),
      ])
    },
  },
  {
    id: 'who',
    header: 'Wer',
    enableSorting: false,
    meta: { label: 'Wer', class: 'max-w-56' },
    cell: ({ row }) => h('div', { class: 'min-w-0' }, [
      // A name is text from outside: a text node, nothing else.
      h('p', { 'class': 'truncate', 'data-testid': 'audit-row-actor' }, row.original.actor.kind === 'dashboard' && !row.original.actor.user ? 'Ohne Namen' : actorName(row.original.actor)),
      h('p', { class: 'text-xs text-muted-foreground' }, wayLabel(splitOperation(row.original.operation).way)),
    ]),
  },
  {
    id: 'website',
    header: 'Website',
    enableSorting: false,
    meta: { label: 'Website', hideOnMobile: true, class: 'max-w-44' },
    cell: ({ row }) => row.original.website
      ? h('span', { class: 'block max-w-40 truncate', title: siteName(row.original.website) }, siteName(row.original.website))
      : h('span', { class: 'text-muted-foreground' }, 'alle'),
  },
]
</script>

<template>
  <div>
    <PageHeader :title="COPY.title" :description="COPY.lead">
      <template #actions>
        <Button variant="ghost" size="sm" aria-label="Neu laden" :disabled="list.isFetching.value" @click="list.refetch()">
          <RefreshCw :class="list.isFetching.value ? 'motion-safe:animate-spin' : ''" aria-hidden="true" />
        </Button>
      </template>
    </PageHeader>

    <p class="mb-4 max-w-prose text-sm text-pretty text-muted-foreground" data-testid="audit-keep">
      {{ COPY.keep }} {{ COPY.addresses }}
    </p>

    <ErrorState
      v-if="list.isError.value && !rows.length"
      :title="COPY.loadFailed"
      :description="errorMessage(list.error.value)"
      :retrying="list.isFetching.value"
      @retry="list.refetch()"
    />

    <DataTable
      v-else
      cursor
      hide-column-menu
      :has-more="list.hasNextPage.value"
      :loading-more="list.isFetchingNextPage.value"
      :columns="columns"
      :data="rows"
      :label="COPY.title"
      :loading="list.isPending.value"
      :get-row-id="(r: AuditEntry) => r.id"
      max-height="68vh"
      :empty-title="filtered ? COPY.emptyFilteredTitle : COPY.emptyTitle"
      :empty-description="filtered ? COPY.emptyFilteredText : COPY.emptyText"
      @row-click="open"
      @load-more="list.fetchNextPage()"
    >
      <template #toolbar>
        <FilterBar v-model:chips="chips" :show-search="false" @remove="onRemoveChip" @clear="clear">
          <NativeSelect v-model="websiteModel" aria-label="Website" data-testid="audit-filter-website">
            <NativeSelectOption value="">
              Alle Websites
            </NativeSelectOption>
            <NativeSelectOption v-for="w in sites" :key="w.id" :value="w.id">
              {{ websiteName(w, w.id) }}
            </NativeSelectOption>
          </NativeSelect>
          <NativeSelect v-model="classModel" aria-label="Art" data-testid="audit-filter-class">
            <NativeSelectOption value="">
              Alle Arten
            </NativeSelectOption>
            <NativeSelectOption v-for="c in CLASS_ORDER" :key="c" :value="c">
              {{ CLASSES[c].label }}
            </NativeSelectOption>
          </NativeSelect>
          <NativeSelect v-model="wayModel" aria-label="Weg" data-testid="audit-filter-way">
            <NativeSelectOption value="">
              Alle Wege
            </NativeSelectOption>
            <NativeSelectOption v-for="w in WAY_ORDER" :key="w" :value="w">
              {{ WAYS[w] }}
            </NativeSelectOption>
          </NativeSelect>
          <NativeSelect v-model="actionModel" aria-label="Aktion" class="max-w-56" data-testid="audit-filter-action">
            <NativeSelectOption value="">
              Alle Aktionen
            </NativeSelectOption>
            <NativeSelectOption v-for="a in ACTION_OPTIONS" :key="a.value" :value="a.value">
              {{ a.label }}
            </NativeSelectOption>
          </NativeSelect>
          <Popover v-model:open="moreOpen">
            <PopoverTrigger as-child>
              <Button variant="outline" size="sm" class="h-9" data-testid="audit-filter-more">
                <SlidersHorizontal aria-hidden="true" />
                Weitere Filter<span v-if="moreCount" class="ml-0.5 rounded-full bg-primary px-1.5 text-xs text-primary-foreground">{{ moreCount }}</span>
              </Button>
            </PopoverTrigger>
            <PopoverContent align="start" class="w-80">
              <form class="grid gap-3" novalidate data-testid="audit-more-form" @submit.prevent="applyMore">
                <div class="grid grid-cols-2 gap-3">
                  <div class="grid gap-1.5">
                    <Label for="af-from">Von</Label>
                    <Input id="af-from" v-model="draft.from" type="date" :aria-invalid="!!draftErrors.from" />
                  </div>
                  <div class="grid gap-1.5">
                    <Label for="af-to">Bis einschließlich</Label>
                    <Input id="af-to" v-model="draft.to" type="date" :aria-invalid="!!draftErrors.to" />
                  </div>
                </div>
                <div class="grid gap-1.5">
                  <Label for="af-actor">Token</Label>
                  <Input id="af-actor" v-model="draft.actor" placeholder="tok_…" class="font-mono" :aria-invalid="!!draftErrors.actor" />
                  <p v-if="draftErrors.actor" class="text-xs text-destructive">
                    {{ draftErrors.actor }}
                  </p>
                </div>
                <div class="grid grid-cols-2 gap-3">
                  <div class="grid gap-1.5">
                    <Label for="af-subject">Objekt</Label>
                    <NativeSelect id="af-subject" v-model="draft.subject" class="w-full">
                      <NativeSelectOption value="">
                        Alle
                      </NativeSelectOption>
                      <NativeSelectOption v-for="s in SUBJECT_OPTIONS" :key="s.value" :value="s.value">
                        {{ s.label }}
                      </NativeSelectOption>
                    </NativeSelect>
                  </div>
                  <div class="grid gap-1.5">
                    <Label for="af-subject-id">Kennung</Label>
                    <Input id="af-subject-id" v-model="draft.subject_id" class="font-mono" :disabled="!draft.subject" />
                  </div>
                </div>
                <div class="grid gap-1.5">
                  <Label for="af-session">Sitzung</Label>
                  <Input id="af-session" v-model="draft.session" class="font-mono" maxlength="8" :aria-invalid="!!draftErrors.session" />
                  <p v-if="draftErrors.session" class="text-xs text-destructive">
                    {{ draftErrors.session }}
                  </p>
                </div>
                <div class="grid gap-1.5">
                  <Label for="af-event">Ereignis</Label>
                  <Input id="af-event" v-model="draft.event" class="font-mono" :aria-invalid="!!draftErrors.event" />
                  <p v-if="draftErrors.event" class="text-xs text-destructive">
                    {{ draftErrors.event }}
                  </p>
                </div>
                <div class="grid gap-1.5">
                  <Label for="af-incident">Vorfall</Label>
                  <Input id="af-incident" v-model="draft.incident" placeholder="K7QM-4XWD" class="font-mono uppercase" :aria-invalid="!!draftErrors.incident" />
                  <p v-if="draftErrors.incident" class="text-xs text-destructive">
                    {{ draftErrors.incident }}
                  </p>
                </div>
                <div class="flex justify-end gap-2 pt-1">
                  <Button type="button" variant="ghost" size="sm" @click="moreOpen = false">
                    Abbrechen
                  </Button>
                  <Button type="submit" size="sm" data-testid="audit-more-apply">
                    Anwenden
                  </Button>
                </div>
              </form>
            </PopoverContent>
          </Popover>
        </FilterBar>
      </template>
    </DataTable>

    <Sheet v-model:open="detailOpen">
      <SheetContent class="w-full gap-0 overflow-y-auto sm:max-w-xl xl:max-w-2xl" data-testid="audit-sheet">
        <SheetHeader class="border-b">
          <SheetTitle>Eintrag im Protokoll</SheetTitle>
          <SheetDescription>So hat Schild die Änderung aufgezeichnet. Ein Eintrag wird nachträglich nicht verändert.</SheetDescription>
          <SheetStepper :ids="rows.map(x => x.id)" :current="entryId" @select="open" />
        </SheetHeader>
        <div class="p-4">
          <AuditEntryPanel v-if="entry" :key="entry.id" :entry="entry" />
          <p v-else-if="!list.isPending.value" class="text-sm text-muted-foreground" data-testid="audit-entry-missing">
            Dieser Eintrag steht nicht in der Auswahl. Nimm Filter heraus oder lade weitere Einträge. Ist er älter als die Aufbewahrung, hat Schild ihn gelöscht.
          </p>
        </div>
      </SheetContent>
    </Sheet>
  </div>
</template>
