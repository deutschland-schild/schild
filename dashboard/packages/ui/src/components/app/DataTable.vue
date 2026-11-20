<script setup lang="ts" generic="TData">
import type { ColumnDef, PaginationState, Row, SortingState, VisibilityState } from '@tanstack/vue-table'
import type { Ref } from 'vue'
import { Button } from '@schild/ui/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@schild/ui/components/ui/dropdown-menu'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@schild/ui/components/ui/sheet'
import { Skeleton } from '@schild/ui/components/ui/skeleton'
import { formatNumber } from '@schild/ui/lib/format'
import { cn, valueUpdater } from '@schild/ui/lib/utils'
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, Columns3 } from '@lucide/vue'
import { FlexRender, getCoreRowModel, getPaginationRowModel, getSortedRowModel, useVueTable } from '@tanstack/vue-table'
import { useVirtualizer } from '@tanstack/vue-virtual'
import { computed, nextTick, ref, shallowRef, useSlots, useTemplateRef, watch } from 'vue'
import EmptyState from './EmptyState.vue'
import './table-meta'

/**
 * Data table on TanStack Table: sorting, column visibility, roving keyboard focus
 * (arrow keys, Home/End, Enter opens the row), sticky header, pagination (client or server)
 * and an optional detail sheet per row (`#detail` slot).
 *
 * Cursor mode (`cursor`): for cursor-paginated APIs (`next_cursor`), where the total is unknown.
 * All loaded rows are shown; the footer reads "N geladen · Mehr laden" and emits `loadMore`
 * while `hasMore` is set. No page numbers, no "von N".
 *
 * Large row sets (more than `virtualizeAbove` rows on screen, e.g. 10,000 loaded events) are
 * virtualized: only the rows in and near the scroll window are in the DOM, spacer rows keep the
 * scroll height. Rows keep their absolute `aria-rowindex`; keyboard navigation scrolls the target
 * row into view before focusing it. Pagination controls are hidden when everything fits on one page.
 */
const props = withDefaults(defineProps<{
  columns: ColumnDef<TData, any>[]
  data: TData[]
  /** Accessible name of the table. */
  label: string
  loading?: boolean
  getRowId?: (row: TData, index: number) => string
  /** Server-side mode: set rowCount and handle v-model:pagination / v-model:sorting yourself. */
  manual?: boolean
  rowCount?: number
  pageSizes?: number[]
  /** CSS max-height of the scroll area; the header sticks inside it. */
  maxHeight?: string
  emptyTitle?: string
  emptyDescription?: string
  /** Title of the detail sheet for a row. */
  detailTitle?: (row: TData) => string
  /** Hide the column visibility menu. */
  hideColumnMenu?: boolean
  /** Cursor mode: show every loaded row, "N geladen · Mehr laden" instead of pages. */
  cursor?: boolean
  /** Cursor mode: the API has more rows (next_cursor is set). */
  hasMore?: boolean
  /** Cursor mode: the next page is being fetched. */
  loadingMore?: boolean
  /** Virtualize the body above this many rows (0 = never). Needs a bounded `maxHeight`. */
  virtualizeAbove?: number
  /** Estimated row height in px for the virtualizer (rows are measured once rendered). */
  estimateRowHeight?: number
}>(), {
  loading: false,
  getRowId: undefined,
  manual: false,
  rowCount: undefined,
  pageSizes: () => [25, 50, 100],
  maxHeight: '70vh',
  emptyTitle: 'Keine Einträge',
  emptyDescription: 'Für diese Auswahl gibt es noch nichts zu zeigen.',
  detailTitle: undefined,
  hideColumnMenu: false,
  cursor: false,
  hasMore: false,
  loadingMore: false,
  virtualizeAbove: 150,
  estimateRowHeight: 52,
})

const emit = defineEmits<{ rowClick: [row: TData], loadMore: [] }>()
const slots = useSlots()

const sorting = defineModel<SortingState>('sorting', { default: () => [] })
const pagination = defineModel<PaginationState>('pagination', { default: () => ({ pageIndex: 0, pageSize: 25 }) })
const columnVisibility = defineModel<VisibilityState>('columnVisibility', { default: () => ({}) })

const table = useVueTable({
  get data() { return props.data },
  get columns() { return props.columns },
  get rowCount() { return props.rowCount },
  get manualPagination() { return props.manual || props.cursor },
  get manualSorting() { return props.manual },
  getRowId: props.getRowId,
  getCoreRowModel: getCoreRowModel(),
  getSortedRowModel: getSortedRowModel(),
  getPaginationRowModel: getPaginationRowModel(),
  autoResetPageIndex: false,
  state: {
    get sorting() { return sorting.value },
    get pagination() { return pagination.value },
    get columnVisibility() { return columnVisibility.value },
  },
  onSortingChange: u => valueUpdater(u, sorting as Ref<SortingState>),
  onPaginationChange: u => valueUpdater(u, pagination as Ref<PaginationState>),
  onColumnVisibilityChange: u => valueUpdater(u, columnVisibility as Ref<VisibilityState>),
})

const rows = computed(() => table.getRowModel().rows)
const total = computed(() => props.manual ? (props.rowCount ?? props.data.length) : table.getPrePaginationRowModel().rows.length)
// aria-rowcount: -1 means "unknown" (cursor mode with more rows on the server).
const ariaRowCount = computed(() => props.cursor ? (props.hasMore ? -1 : props.data.length) : total.value)
function rowIndex(i: number) {
  return (props.cursor ? 0 : pagination.value.pageIndex * pagination.value.pageSize) + i + 2
}
const singlePage = computed(() => !props.manual && total.value <= Math.min(...props.pageSizes) && pagination.value.pageIndex === 0)
const from = computed(() => total.value === 0 ? 0 : pagination.value.pageIndex * pagination.value.pageSize + 1)
const to = computed(() => Math.min(total.value, (pagination.value.pageIndex + 1) * pagination.value.pageSize))
const hideableColumns = computed(() => table.getAllLeafColumns().filter(c => c.getCanHide()))

// Virtual window over the body rows (only for large row sets).
const scrollEl = useTemplateRef<HTMLDivElement>('scroll')
// The virtualizer measures with ResizeObserver; without it (old browsers, jsdom) every row is rendered.
const canVirtualize = typeof window !== 'undefined' && 'ResizeObserver' in window
const virtual = computed(() => canVirtualize && props.virtualizeAbove > 0 && rows.value.length > props.virtualizeAbove)
const virtualizer = useVirtualizer(computed(() => ({
  count: virtual.value ? rows.value.length : 0,
  getScrollElement: () => scrollEl.value ?? null,
  estimateSize: () => props.estimateRowHeight,
  // Rows not laid out (yet) report 0: keep the estimate instead of collapsing them.
  measureElement: (el: Element) => el.getBoundingClientRect().height || props.estimateRowHeight,
  overscan: 10,
  // Render a first screenful before the scroll area is measured (and where it cannot be, e.g. jsdom).
  initialRect: { width: 0, height: 800 },
  getItemKey: (i: number) => rows.value[i]?.id ?? i,
})))
const visible = computed(() => {
  if (!virtual.value) return rows.value.map((row, i) => ({ row, i }))
  return virtualizer.value.getVirtualItems().flatMap(v => rows.value[v.index] ? [{ row: rows.value[v.index]!, i: v.index }] : [])
})
const padTop = computed(() => virtual.value ? (virtualizer.value.getVirtualItems()[0]?.start ?? 0) : 0)
const padBottom = computed(() => {
  if (!virtual.value) return 0
  const last = virtualizer.value.getVirtualItems().at(-1)
  return last ? Math.max(0, virtualizer.value.getTotalSize() - last.end) : 0
})
function measure(el: unknown) {
  if (virtual.value && el instanceof HTMLElement) virtualizer.value.measureElement(el)
}

// Roving tabindex across body rows.
const focusIndex = ref(0)
const body = useTemplateRef<HTMLTableSectionElement>('body')
watch(rows, () => {
  if (focusIndex.value >= rows.value.length) focusIndex.value = Math.max(0, rows.value.length - 1)
})
function focusRow(i: number) {
  focusIndex.value = Math.max(0, Math.min(rows.value.length - 1, i))
  const focus = () => body.value?.querySelector<HTMLTableRowElement>(`tr[data-row][data-index="${focusIndex.value}"]`)?.focus()
  if (!virtual.value) {
    nextTick(focus)
    return
  }
  // Virtual window: bring the row into the DOM first, then focus it.
  virtualizer.value.scrollToIndex(focusIndex.value, { align: 'auto' })
  nextTick(() => requestAnimationFrame(focus))
}

const detailRow = shallowRef<Row<TData> | null>(null)
const detailOpen = computed({
  get: () => detailRow.value !== null,
  set: (v) => {
    if (!v) {
      detailRow.value = null
      focusRow(focusIndex.value)
    }
  },
})

function activate(row: Row<TData>, i: number) {
  focusIndex.value = i
  emit('rowClick', row.original)
  if (slots.detail) detailRow.value = row
}

function onRowKey(e: KeyboardEvent, row: Row<TData>, i: number) {
  switch (e.key) {
    case 'ArrowDown': focusRow(i + 1); break
    case 'ArrowUp': focusRow(i - 1); break
    case 'Home': focusRow(0); break
    case 'End': focusRow(rows.value.length - 1); break
    case 'PageDown':
      if (!props.cursor && table.getCanNextPage()) {
        table.nextPage()
        focusRow(0)
      }
      break
    case 'PageUp':
      if (!props.cursor && table.getCanPreviousPage()) {
        table.previousPage()
        focusRow(0)
      }
      break
    case 'Enter':
    case ' ':
      if (e.target !== e.currentTarget) return
      activate(row, i)
      break
    default: return
  }
  e.preventDefault()
}

function onRowClick(e: MouseEvent, row: Row<TData>, i: number) {
  // Let interactive children (links, buttons, copy) handle their own clicks.
  if ((e.target as HTMLElement).closest('a,button,input,select,textarea,[role="button"]')) return
  activate(row, i)
}

function ariaSort(dir: false | 'asc' | 'desc') {
  return dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none'
}
function colLabel(id: string, meta?: { label?: string }) {
  return meta?.label ?? id
}
</script>

<template>
  <div class="space-y-3">
    <div v-if="$slots.toolbar || !hideColumnMenu" class="flex flex-wrap items-start gap-2">
      <div class="min-w-0 flex-1">
        <slot name="toolbar" />
      </div>
      <DropdownMenu v-if="!hideColumnMenu && hideableColumns.length">
        <DropdownMenuTrigger as-child>
          <Button variant="outline" size="sm">
            <Columns3 aria-hidden="true" />
            <span>Spalten</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" class="w-52">
          <DropdownMenuLabel>Spalten anzeigen</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuCheckboxItem
            v-for="column in hideableColumns"
            :key="column.id"
            :model-value="column.getIsVisible()"
            @update:model-value="(v: boolean) => column.toggleVisibility(!!v)"
            @select.prevent
          >
            {{ colLabel(column.id, column.columnDef.meta) }}
          </DropdownMenuCheckboxItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>

    <div ref="scroll" class="relative overflow-auto rounded-xl border bg-card shadow-sm" :style="{ maxHeight }" data-testid="table-scroll">
      <table class="w-full caption-bottom text-sm" :aria-label="label" :aria-busy="loading" :aria-rowcount="ariaRowCount">
        <thead class="sticky top-0 z-10 bg-muted shadow-[inset_0_-1px_0_var(--border)]">
          <tr v-for="hg in table.getHeaderGroups()" :key="hg.id">
            <th
              v-for="header in hg.headers"
              :key="header.id"
              scope="col"
              :aria-sort="header.column.getCanSort() ? ariaSort(header.column.getIsSorted()) : undefined"
              :class="cn('h-10 px-3 text-left align-middle text-xs font-semibold whitespace-nowrap text-muted-foreground', header.column.columnDef.meta?.class, header.column.columnDef.meta?.hideOnMobile && 'hidden md:table-cell')"
            >
              <template v-if="!header.isPlaceholder">
                <button
                  v-if="header.column.getCanSort()"
                  type="button"
                  class="-mx-1.5 inline-flex items-center gap-1 rounded-md px-1.5 py-1 hover:bg-card hover:text-foreground"
                  @click="header.column.toggleSorting(header.column.getIsSorted() === 'asc')"
                >
                  <FlexRender :render="header.column.columnDef.header" :props="header.getContext()" />
                  <ArrowUp v-if="header.column.getIsSorted() === 'asc'" class="size-3.5" aria-hidden="true" />
                  <ArrowDown v-else-if="header.column.getIsSorted() === 'desc'" class="size-3.5" aria-hidden="true" />
                  <ArrowUpDown v-else class="size-3.5 opacity-50" aria-hidden="true" />
                </button>
                <FlexRender v-else :render="header.column.columnDef.header" :props="header.getContext()" />
              </template>
            </th>
          </tr>
        </thead>
        <tbody ref="body">
          <template v-if="loading && rows.length === 0">
            <tr v-for="i in 6" :key="`sk-${i}`" class="border-b last:border-0">
              <td v-for="c in table.getVisibleLeafColumns()" :key="c.id" class="px-3 py-3">
                <Skeleton class="h-4 w-full max-w-40" />
              </td>
            </tr>
          </template>
          <tr v-else-if="rows.length === 0">
            <td :colspan="table.getVisibleLeafColumns().length" class="p-4">
              <slot name="empty">
                <EmptyState :title="emptyTitle" :description="emptyDescription" class="border-0" />
              </slot>
            </td>
          </tr>
          <template v-else>
            <tr v-if="padTop > 0" aria-hidden="true" data-slot="virtual-pad">
              <td :colspan="table.getVisibleLeafColumns().length" class="p-0" :style="{ height: `${padTop}px` }" />
            </tr>
            <tr
              v-for="{ row, i } in visible"
              :key="row.id"
              :ref="measure"
              data-row
              :data-index="i"
              :data-row-id="row.id"
              :tabindex="i === focusIndex ? 0 : -1"
              :aria-rowindex="rowIndex(i)"
              :data-state="detailRow?.id === row.id ? 'selected' : undefined"
              :class="cn('border-b transition-colors last:border-0 cursor-pointer hover:bg-muted/50 focus-visible:bg-accent focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring data-[state=selected]:bg-muted')"
              @click="onRowClick($event, row, i)"
              @keydown="onRowKey($event, row, i)"
              @focus="focusIndex = i"
            >
              <td
                v-for="cell in row.getVisibleCells()"
                :key="cell.id"
                :class="cn('px-3 py-2.5 align-middle', cell.column.columnDef.meta?.class, cell.column.columnDef.meta?.hideOnMobile && 'hidden md:table-cell')"
              >
                <FlexRender :render="cell.column.columnDef.cell" :props="cell.getContext()" />
              </td>
            </tr>
            <tr v-if="padBottom > 0" aria-hidden="true" data-slot="virtual-pad">
              <td :colspan="table.getVisibleLeafColumns().length" class="p-0" :style="{ height: `${padBottom}px` }" />
            </tr>
          </template>
        </tbody>
      </table>
    </div>

    <div v-if="cursor" class="flex flex-wrap items-center gap-2 text-sm text-muted-foreground" data-slot="cursor-footer">
      <p aria-live="polite" class="tabular-nums">
        {{ formatNumber(data.length) }} geladen<template v-if="!hasMore && data.length > 0">
          · alle Einträge
        </template>
      </p>
      <template v-if="hasMore">
        <span aria-hidden="true">·</span>
        <Button
          variant="outline"
          size="sm"
          :disabled="loadingMore"
          :aria-busy="loadingMore"
          data-testid="load-more"
          @click="emit('loadMore')"
        >
          {{ loadingMore ? 'Lädt …' : 'Mehr laden' }}
        </Button>
      </template>
    </div>
    <p v-else-if="singlePage" class="text-sm text-muted-foreground tabular-nums" aria-live="polite">
      {{ total === 1 ? '1 Eintrag' : `${formatNumber(total)} Einträge` }}
    </p>
    <div v-else class="flex flex-wrap items-center justify-between gap-2 text-sm text-muted-foreground">
      <p aria-live="polite" class="tabular-nums">
        <template v-if="total > 0">
          {{ formatNumber(from) }}–{{ formatNumber(to) }} von {{ formatNumber(total) }}
        </template>
        <template v-else>
          0 Einträge
        </template>
      </p>
      <div class="flex items-center gap-2">
        <label class="flex items-center gap-2">
          <span class="hidden sm:inline">Pro Seite</span>
          <select
            class="h-8 rounded-md border border-input bg-background px-2 text-sm text-foreground"
            :value="pagination.pageSize"
            aria-label="Einträge pro Seite"
            @change="table.setPageSize(Number(($event.target as HTMLSelectElement).value))"
          >
            <option v-for="s in pageSizes" :key="s" :value="s">{{ s }}</option>
          </select>
        </label>
        <Button variant="outline" size="icon-sm" :disabled="!table.getCanPreviousPage()" aria-label="Vorherige Seite" @click="table.previousPage()">
          <ChevronLeft aria-hidden="true" />
        </Button>
        <span class="tabular-nums">{{ pagination.pageIndex + 1 }} / {{ Math.max(1, table.getPageCount()) }}</span>
        <Button variant="outline" size="icon-sm" :disabled="!table.getCanNextPage()" aria-label="Nächste Seite" @click="table.nextPage()">
          <ChevronRight aria-hidden="true" />
        </Button>
      </div>
    </div>

    <Sheet v-if="$slots.detail" v-model:open="detailOpen">
      <SheetContent class="w-full gap-0 overflow-y-auto sm:max-w-xl">
        <SheetHeader class="border-b">
          <SheetTitle>{{ detailRow && detailTitle ? detailTitle(detailRow.original) : 'Details' }}</SheetTitle>
          <SheetDescription class="sr-only">
            Details zum ausgewählten Eintrag
          </SheetDescription>
        </SheetHeader>
        <div v-if="detailRow" class="p-4">
          <slot name="detail" :row="detailRow.original" :close="() => (detailOpen = false)" />
        </div>
      </SheetContent>
    </Sheet>
  </div>
</template>
