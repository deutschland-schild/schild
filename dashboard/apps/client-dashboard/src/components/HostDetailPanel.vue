<script setup lang="ts">
import type { FindingAnnotation, HostDetail, HostFinding } from '@/api/hosts'
import type { StatusTone } from '@schild/ui'
import type { FindingRow, FindingState } from '@/lib/hosts'
import { Button, CommandBlock, FilterBar, formatDateTime, formatRelative, MetaLine, NativeSelect, NativeSelectOption, StatusPill, Tag, toast } from '@schild/ui'
import { ChevronDown, Clock, Info, PlugZap, Unplug } from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { errorMessage } from '@/api/client'
import { useAcceptFinding, useReopenFinding } from '@/api/hosts'
import FindingItem from '@/components/FindingItem.vue'
import InventoryTable from '@/components/InventoryTable.vue'
import Term from '@/components/Term.vue'
import { acceptedInForce, AREAS, countsText, eolState, evidenceItems, FINDING_STATES, findingKey, findingRows, findingSearchText, formatDay, HOST_STATUS, intervalText, openCount, rejectReason, SEVERITY } from '@/lib/hosts'
import { versionText } from '@/lib/labels'
import { plural } from '@/lib/summary'

/** Detail of one host: header with system facts, state banners, the results of the check as one searchable list, inventory, history. */
const props = defineProps<{ detail: HostDetail }>()
const h = computed(() => props.detail.host)
const r = computed(() => props.detail.report)
const rows = computed(() => r.value ? findingRows(r.value, props.detail.accepted) : [])

/**
 * The list of results: one line per check, the detail opens on click. Search and the two filters
 * work on what the page shows (for agent reports the gateway's own title).
 */
const search = ref('')
const stateFilter = ref<FindingState | ''>('')
const areaFilter = ref('')
const expanded = ref(new Set<string>())
const rowTitle = (row: FindingRow) => annotationOf(row.finding)?.title ?? row.finding.title
const stateCount = (s: FindingState) => rows.value.filter(x => x.state === s).length
const areaOptions = computed(() => AREAS.filter(a => rows.value.some(x => x.finding.area === a.id)))
const shown = computed(() => {
  const words = search.value.trim().toLowerCase().split(/\s+/).filter(Boolean)
  return rows.value.filter((row) => {
    if (stateFilter.value && row.state !== stateFilter.value) return false
    if (areaFilter.value && row.finding.area !== areaFilter.value) return false
    if (!words.length) return true
    const text = findingSearchText(row, rowTitle(row))
    return words.every(w => text.includes(w))
  })
})
const filtered = computed(() => !!(search.value.trim() || stateFilter.value || areaFilter.value))
function resetFilters() {
  search.value = ''
  stateFilter.value = ''
  areaFilter.value = ''
}
const allExpanded = computed(() => shown.value.length > 0 && shown.value.every(x => expanded.value.has(x.key)))
function toggle(key: string) {
  const next = new Set(expanded.value)
  if (!next.delete(key)) next.add(key)
  expanded.value = next
}
function toggleAll() {
  expanded.value = allExpanded.value ? new Set() : new Set(shown.value.map(x => x.key))
}
// Another server: start with a closed, unfiltered list.
watch(() => h.value.id, () => {
  resetFilters()
  expanded.value = new Set()
})
function badge(row: FindingRow): { label: string, tone: StatusTone } {
  if (row.state === 'open') return SEVERITY[row.finding.severity]
  if (row.state === 'ok') return { label: 'In Ordnung', tone: 'success' }
  return { label: row.state === 'accepted' ? 'Akzeptiert' : 'Nicht lesbar', tone: 'neutral' }
}
/** The first typed fact of a result (port, package, path) as a hint in its line. */
function hint(row: FindingRow): string {
  const first = evidenceItems(row.finding)[0]
  return first ? (typeof first === 'string' ? first : first.text) : ''
}
/** Accepted findings (D102): the ones in force by finding key, and the ones the newest report no longer holds at that severity. */
const inForce = computed(() => acceptedInForce(r.value, props.detail.accepted))
const acceptedOf = (f: HostFinding) => inForce.value.get(findingKey(f)) ?? null
const notInForce = computed(() => props.detail.accepted.filter(a => !a.active))
/** Title of an acceptance that is not in force: from the newest report when it still holds the check, else the check id. */
function titleOf(a: { id: string, subject?: string | null }) {
  const f = r.value?.findings.find(x => findingKey(x) === findingKey(a))
  return f ? (annotationOf(f)?.title ?? f.title) : a.id
}
const accept = useAcceptFinding()
const reopen = useReopenFinding()
const busy = computed(() => accept.isPending.value || reopen.isPending.value)
function onAccept(f: HostFinding, note: string) {
  accept.mutate({ host: h.value.id, id: f.id, subject: f.subject, note }, {
    onSuccess: () => toast('Befund akzeptiert', { description: 'Er zählt nicht mehr als offen und steht unter „Akzeptiert“.' }),
    onError: err => toast.error('Der Befund ließ sich nicht akzeptieren', { description: errorMessage(err) }),
  })
}
function onReopen(a: { id: string, subject?: string | null }) {
  reopen.mutate({ host: h.value.id, id: a.id, subject: a.subject }, {
    onSuccess: () => toast('Befund ist wieder offen'),
    onError: err => toast.error('Der Befund ließ sich nicht wieder öffnen', { description: errorMessage(err) }),
  })
}
/** Agent reports: the gateway's own text per finding, keyed like the list items. */
const annotations = computed(() => {
  const m = new Map<string, FindingAnnotation>()
  for (const a of props.detail.annotations ?? []) m.set(`${a.id}:${a.subject ?? ''}`, a)
  return m
})
const annotationOf = (f: { id: string, subject?: string | null }) => props.detail.annotations ? (annotations.value.get(`${f.id}:${f.subject ?? ''}`) ?? null) : undefined
const os = computed(() => r.value?.host.os)
const osEol = computed(() => eolState(os.value?.eol))
const extEol = computed(() => eolState(os.value?.extended_support_until))
const isGateway = computed(() => h.value.role === 'gateway')
const silent = computed(() => h.value.silent || h.value.status === 'silent')
const status = computed(() => HOST_STATUS[silent.value ? 'silent' : h.value.status])

const headerMeta = computed(() => {
  const o = os.value
  return [
    o ? o.name : '',
    o ? { text: `Kernel ${o.kernel} (${o.arch})`, mono: false } : '',
    h.value.last_report_at ? `geprüft ${formatRelative(h.value.last_report_at)}` : 'noch nicht geprüft',
    intervalText(h.value.interval_minutes) ? `plant ${intervalText(h.value.interval_minutes)}` : '',
    r.value ? (r.value.run.as_root ? 'lief als root' : 'lief ohne root') : '',
  ]
})
const osSupport = computed(() => {
  const o = os.value
  if (!o?.eol) return null
  if (osEol.value === 'past') {
    if (o.extended_support_until && extEol.value !== 'past') return { tone: 'warning' as const, text: `Reguläre Updates endeten am ${formatDay(o.eol)}. Langzeit-Support noch bis ${formatDay(o.extended_support_until)}.` }
    return { tone: 'danger' as const, text: `Seit ${formatDay(o.extended_support_until ?? o.eol)} gibt es für dieses System keine Sicherheitsupdates mehr.` }
  }
  return { tone: osEol.value === 'soon' ? 'warning' as const : 'neutral' as const, text: `Updates bis ${formatDay(o.eol)}${o.extended_support_until ? `, Langzeit-Support bis ${formatDay(o.extended_support_until)}` : ''}.` }
})
const unreadableTotal = computed(() => h.value.unreadable)
const eolEnded = (inv: { eol: string | null }[]) => inv.filter(i => eolState(i.eol) === 'past').length
</script>

<template>
  <article class="space-y-5 text-sm" :aria-labelledby="`host-${h.id}-title`" data-testid="host-detail">
    <header class="space-y-1.5">
      <div class="flex flex-wrap items-center gap-2">
        <h2 :id="`host-${h.id}-title`" class="min-w-0 text-base font-bold break-all">
          {{ h.hostname }}
        </h2>
        <Tag :tone="isGateway ? 'signal' : 'neutral'">
          {{ isGateway ? 'Gateway' : 'App-Server' }}
        </Tag>
        <StatusPill :tone="status.tone" size="sm" data-testid="host-status">
          {{ status.label }}
        </StatusPill>
      </div>
      <p class="leading-snug text-muted-foreground">
        <template v-if="isGateway">
          Der Server, auf dem dieses <Term k="gateway">Gateway</Term> läuft. Der Check läuft hier als eigener Prozess und liest nur.
        </template>
        <template v-else>
          Ein App-Server hinter dem Gateway. Sein <Term k="agent">Agent</Term> prüft ihn selbst und schickt den Bericht hierher. Er bleibt auf deinen Servern.
        </template>
      </p>
      <MetaLine :items="headerMeta" data-testid="host-meta" />
      <p v-if="osSupport" :class="['text-xs', osSupport.tone === 'danger' ? 'font-semibold text-status-danger' : osSupport.tone === 'warning' ? 'text-status-warning' : 'text-muted-foreground']" data-testid="os-support">
        {{ osSupport.text }}
      </p>
    </header>

    <!-- State banners -->
    <div v-if="silent" class="flex items-start gap-3 rounded-xl border bg-muted p-3" role="status" data-testid="silent-banner">
      <Unplug class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <div class="space-y-2">
        <p>
          <strong>Dieser Server meldet sich nicht.</strong>
          Der letzte Bericht kam {{ h.last_report_at ? formatRelative(h.last_report_at) : 'nie' }}<template v-if="h.interval_minutes">, erwartet wird einer {{ intervalText(h.interval_minutes) }}</template>.
          Das ändert nichts am Grundschutz und an deinen Anfragen. Die Befunde unten sind vom letzten Bericht.
        </p>
        <p class="text-muted-foreground">
          Schau auf dem App-Server nach, ob der Agent läuft und das Gateway erreicht:
        </p>
        <CommandBlock command="sudo journalctl -u schild-agent --since -48h" copy-label="Befehl zum Nachsehen kopieren" />
      </div>
    </div>
    <div v-else-if="h.status === 'revoked'" class="flex items-start gap-3 rounded-xl border bg-muted p-3" role="status">
      <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <p>
        <strong>Der Agent dieses Servers ist zurückgezogen.</strong> Neue Berichte nimmt Schild nicht mehr an. Alte Berichte bleiben sichtbar, bis die Aufbewahrung sie löscht.
      </p>
    </div>
    <div v-else-if="!r" class="flex items-start gap-3 rounded-xl border bg-muted p-3" role="status" data-testid="waiting-banner">
      <Clock class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <p v-if="isGateway">
        <strong>Noch kein Bericht.</strong> Der Server-Check läuft als eigener Prozess auf dem Server und liest nur. Einmal eingerichtet, prüft er {{ intervalText(h.interval_minutes) || 'täglich' }}. Zum Einrichten führst du auf dem Server <code class="rounded bg-card px-1 font-mono text-xs">sudo schild check install</code> aus. Läuft Schild in Docker, kopierst du das Binary vorher aus dem Container (Doku: Betreiben, „Server-Check einrichten“).
      </p>
      <p v-else>
        <strong>Noch kein Bericht.</strong> Der Agent ist bestätigt und schickt seinen ersten Bericht nach dem nächsten Lauf. Das kann ein paar Minuten dauern.
      </p>
    </div>
    <div v-if="detail.last_rejected" class="flex items-start gap-3 rounded-xl border border-status-warning/40 bg-status-warning-subtle p-3" data-testid="last-rejected">
      <PlugZap class="mt-0.5 size-4 shrink-0 text-status-warning" aria-hidden="true" />
      <p>
        <strong>Eine Lieferung wurde {{ formatRelative(detail.last_rejected.at) }} abgelehnt.</strong>
        {{ rejectReason(detail.last_rejected.code) }}
        <span class="text-muted-foreground">Der Agent versucht es beim nächsten Lauf neu.</span>
      </p>
    </div>

    <!-- Results of the check: one searchable list -->
    <template v-if="r">
      <p class="sr-only" data-testid="host-summary">
        {{ openCount(h.counts) ? `${plural(openCount(h.counts), 'offener Befund', 'offene Befunde')}: ${countsText(h.counts)}.` : 'Keine offenen Befunde.' }}
        {{ unreadableTotal ? `${plural(unreadableTotal, 'Prüfung', 'Prüfungen')} nicht lesbar.` : '' }}
        {{ h.accepted ? `${plural(h.accepted, 'Befund', 'Befunde')} akzeptiert.` : '' }}
      </p>
      <section :aria-labelledby="`findings-${h.id}`" class="space-y-3" data-testid="findings">
        <h3 :id="`findings-${h.id}`" class="font-bold">
          Was der Check gefunden hat
        </h3>
        <p class="text-muted-foreground">
          Der Check sieht den Server von innen. Was von außen davor steht, zum Beispiel eine Firewall deines Hosters, sieht er nicht. Trifft ein Befund deshalb bei dir nicht zu, markierst du ihn als akzeptiert.
        </p>
        <FilterBar
          v-model:search="search"
          search-placeholder="Titel, Port, Paket, Pfad …"
          search-label="Befunde durchsuchen"
        >
          <NativeSelect v-model="stateFilter" aria-label="Status" data-testid="filter-state">
            <NativeSelectOption value="">
              Alle ({{ rows.length }})
            </NativeSelectOption>
            <NativeSelectOption v-for="s in FINDING_STATES" :key="s.id" :value="s.id">
              {{ s.label }} ({{ stateCount(s.id) }})
            </NativeSelectOption>
          </NativeSelect>
          <NativeSelect v-model="areaFilter" aria-label="Bereich" data-testid="filter-area">
            <NativeSelectOption value="">
              Alle Bereiche
            </NativeSelectOption>
            <NativeSelectOption v-for="a in areaOptions" :key="a.id" :value="a.id">
              {{ a.label }}
            </NativeSelectOption>
          </NativeSelect>
          <template #end>
            <Button v-if="filtered" type="button" variant="ghost" size="sm" data-testid="filter-reset" @click="resetFilters">
              Filter zurücksetzen
            </Button>
            <Button type="button" variant="ghost" size="sm" :disabled="!shown.length" data-testid="expand-all" @click="toggleAll">
              {{ allExpanded ? 'Alle zuklappen' : 'Alle aufklappen' }}
            </Button>
          </template>
        </FilterBar>
        <p class="text-xs text-muted-foreground" aria-live="polite" data-testid="finding-count">
          {{ filtered ? `${shown.length} von ${rows.length} Prüfungen` : plural(rows.length, 'Prüfung', 'Prüfungen') }}
        </p>
        <ul v-if="shown.length" class="divide-y overflow-hidden rounded-xl border bg-card" data-testid="finding-list">
          <li
            v-for="row in shown"
            :key="row.key"
            data-testid="finding-row"
            :data-state="row.state"
            :data-area="row.finding.area"
            :data-severity="row.state === 'open' ? row.finding.severity : undefined"
          >
            <button
              type="button"
              class="flex w-full items-center gap-x-3 px-3 py-2 text-left hover:bg-muted/60 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring"
              :aria-expanded="expanded.has(row.key)"
              :aria-controls="`finding-${h.id}-${row.key}`"
              data-testid="finding-toggle"
              @click="toggle(row.key)"
            >
              <span class="w-24 shrink-0">
                <Tag :tone="badge(row).tone">
                  <span v-if="row.state === 'open'" class="sr-only">Stufe: </span>{{ badge(row).label }}
                </Tag>
              </span>
              <span class="min-w-0 flex-1">
                <span :class="['block', row.state === 'open' ? 'font-semibold' : '']">{{ rowTitle(row) }}</span>
                <span class="block truncate text-xs text-muted-foreground">{{ row.area }}<template v-if="hint(row)"> · {{ hint(row) }}</template></span>
              </span>
              <ChevronDown :class="['size-4 shrink-0 text-muted-foreground motion-safe:transition-transform', expanded.has(row.key) ? 'rotate-180' : '']" aria-hidden="true" />
            </button>
            <div v-if="expanded.has(row.key)" :id="`finding-${h.id}-${row.key}`" class="border-t bg-background/40 px-3 py-2 sm:pl-[7.5rem]">
              <FindingItem
                flat
                :finding="row.finding"
                :checked-at="r.run.started_at"
                :annotation="annotationOf(row.finding)"
                :accepted="row.state === 'accepted' ? acceptedOf(row.finding) : null"
                :acceptable="row.state === 'open'"
                :busy="busy"
                @accept="onAccept(row.finding, $event)"
                @reopen="onReopen(row.finding)"
              />
            </div>
          </li>
        </ul>
        <p v-else class="rounded-xl border bg-card p-4 text-muted-foreground" data-testid="finding-empty">
          Dazu passt keine Prüfung dieses Berichts.
        </p>
      </section>

      <section v-if="r.inventory.length" :aria-labelledby="`inventory-${h.id}`" class="space-y-2" data-testid="inventory-section">
        <div class="flex flex-wrap items-baseline justify-between gap-x-3 border-b pb-1.5">
          <h3 :id="`inventory-${h.id}`" class="font-bold">
            Installierte Software
          </h3>
          <p v-if="eolEnded(r.inventory)" class="text-xs text-muted-foreground">
            {{ eolEnded(r.inventory) === 1 ? '1 Eintrag ohne Support' : `${eolEnded(r.inventory)} Einträge ohne Support` }}
          </p>
        </div>
        <InventoryTable :items="r.inventory" />
      </section>

      <section v-if="notInForce.length" :aria-labelledby="`accepted-rest-${h.id}`" class="space-y-1.5" data-testid="accepted-rest">
        <h3 :id="`accepted-rest-${h.id}`" class="border-b pb-1.5 font-bold">
          Akzeptiert, trifft gerade nicht zu
        </h3>
        <p class="text-muted-foreground">
          Diese Befunde hast du akzeptiert. Im neuesten Bericht fehlen sie, oder der Check meldet sie mit einer höheren Stufe, dann stehen sie oben wieder als offen. Kommt einer mit derselben Stufe zurück, gilt er weiter als akzeptiert.
        </p>
        <ul class="divide-y">
          <li v-for="a in notInForce" :key="findingKey(a)" class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 py-1.5">
            <span class="min-w-0">
              <span class="font-semibold">{{ titleOf(a) }}</span>
              <span v-if="a.subject" class="font-mono text-xs break-all"> {{ a.subject }}</span>
              <span v-if="a.note" class="text-muted-foreground"> · {{ a.note }}</span>
            </span>
            <Button type="button" variant="ghost" size="sm" :disabled="busy" @click="onReopen(a)">
              Entfernen
            </Button>
          </li>
        </ul>
      </section>

      <section v-if="detail.history.length > 1" :aria-labelledby="`history-${h.id}`" class="space-y-1.5">
        <h3 :id="`history-${h.id}`" class="border-b pb-1.5 font-bold">
          Verlauf
        </h3>
        <ol class="divide-y" data-testid="history">
          <li v-for="(x, i) in detail.history.slice(0, 7)" :key="x.report_id" class="flex flex-wrap items-baseline justify-between gap-x-3 py-1.5">
            <span>
              <time :datetime="x.started_at" :title="formatDateTime(x.started_at)">{{ formatRelative(x.started_at) }}</time>
              <span v-if="i === 0" class="text-muted-foreground"> (dieser Bericht)</span>
            </span>
            <span class="text-xs text-muted-foreground">{{ openCount(x.counts) ? `${plural(openCount(x.counts), 'offener Befund', 'offene Befunde')} (${countsText(x.counts)})` : 'keine offenen Befunde' }}</span>
          </li>
        </ol>
      </section>
      <p class="text-xs text-muted-foreground">
        Bericht {{ r.report_id.slice(0, 8) }} · Schild {{ versionText(r.run.schild_version) }} · EOL-Tabelle vom {{ formatDay(r.run.eol_table) }} · Dauer {{ (r.run.duration_ms / 1000).toLocaleString('de-DE', { maximumFractionDigits: 1 }) }} s
      </p>
    </template>
  </article>
</template>
