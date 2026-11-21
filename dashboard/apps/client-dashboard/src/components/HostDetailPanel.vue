<script setup lang="ts">
import type { FindingAnnotation, HostDetail, HostFinding } from '@/api/hosts'
import { Button, CommandBlock, formatDateTime, formatRelative, MetaLine, StatusPill, Tag, toast } from '@schild/ui'
import { CircleCheck, Clock, Info, PlugZap, Unplug } from '@lucide/vue'
import { computed } from 'vue'
import { errorMessage } from '@/api/client'
import { useAcceptFinding, useReopenFinding } from '@/api/hosts'
import FindingItem from '@/components/FindingItem.vue'
import InventoryTable from '@/components/InventoryTable.vue'
import Term from '@/components/Term.vue'
import { acceptedInForce, countsText, eolState, findingKey, formatDay, groupByArea, HOST_STATUS, intervalText, openCount, rejectReason } from '@/lib/hosts'
import { versionText } from '@/lib/labels'
import { plural } from '@/lib/summary'

/** Detail of one host: header with system facts, state banners, findings grouped by area, inventory, history. */
const props = defineProps<{ detail: HostDetail }>()
const h = computed(() => props.detail.host)
const r = computed(() => props.detail.report)
const groups = computed(() => r.value ? groupByArea(r.value, props.detail.accepted) : [])
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

    <!-- Findings by area -->
    <template v-if="r">
      <p class="sr-only" data-testid="host-summary">
        {{ openCount(h.counts) ? `${plural(openCount(h.counts), 'offener Befund', 'offene Befunde')}: ${countsText(h.counts)}.` : 'Keine offenen Befunde.' }}
        {{ unreadableTotal ? `${plural(unreadableTotal, 'Prüfung', 'Prüfungen')} nicht lesbar.` : '' }}
        {{ h.accepted ? `${plural(h.accepted, 'Befund', 'Befunde')} akzeptiert.` : '' }}
      </p>
      <section v-for="g in groups" :key="g.id" :aria-labelledby="`area-${h.id}-${g.id}`" class="space-y-2" :data-testid="`area-${g.id}`">
        <div class="flex flex-wrap items-baseline justify-between gap-x-3 border-b pb-1.5">
          <h3 :id="`area-${h.id}-${g.id}`" class="font-bold">
            {{ g.label }}
          </h3>
          <p class="text-xs text-muted-foreground">
            <template v-if="g.open.length">
              {{ plural(g.open.length, 'Befund', 'Befunde') }}
            </template>
            <template v-else-if="g.id === 'software' && eolEnded(r.inventory)">
              {{ eolEnded(r.inventory) === 1 ? '1 Eintrag ohne Support' : `${eolEnded(r.inventory)} Einträge ohne Support` }}
            </template>
            <template v-else-if="!g.unreadable.length && !g.accepted.length">
              <CircleCheck class="mr-0.5 inline size-3 -translate-y-px text-status-success" aria-hidden="true" />in Ordnung
            </template>
            <template v-if="g.unreadable.length">
              {{ g.open.length ? ' · ' : '' }}{{ g.unreadable.length }} nicht lesbar
            </template>
            <template v-if="g.accepted.length">
              {{ g.open.length || g.unreadable.length ? ' · ' : '' }}{{ g.accepted.length }} akzeptiert
            </template>
          </p>
        </div>
        <ul v-if="g.open.length || g.unreadable.length" class="grid gap-2">
          <li v-for="f in [...g.open, ...g.unreadable]" :key="`${f.id}:${f.subject ?? ''}`">
            <FindingItem :finding="f" :checked-at="r.run.started_at" :annotation="annotationOf(f)" acceptable :busy="busy" @accept="onAccept(f, $event)" />
          </li>
        </ul>
        <ul v-if="g.accepted.length" class="divide-y" :aria-label="`${g.label}: akzeptiert`" data-testid="accepted-list">
          <li v-for="f in g.accepted" :key="findingKey(f)">
            <FindingItem :finding="f" :checked-at="r.run.started_at" :annotation="annotationOf(f)" :accepted="acceptedOf(f)" :busy="busy" @reopen="onReopen(f)" />
          </li>
        </ul>
        <ul v-if="g.ok.length" class="divide-y" :aria-label="`${g.label}: ohne Befund`">
          <li v-for="f in g.ok" :key="`${f.id}:${f.subject ?? ''}`">
            <FindingItem :finding="f" :checked-at="r.run.started_at" :annotation="annotationOf(f)" />
          </li>
        </ul>
        <template v-if="g.id === 'software' && r.inventory.length">
          <h4 class="pt-1 text-xs font-semibold text-muted-foreground">
            Installierte Software
          </h4>
          <InventoryTable :items="r.inventory" />
        </template>
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
