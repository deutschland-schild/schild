<script setup lang="ts">
import type { RuleExceptionInput } from '@/api/rules'
import type { WebsiteRangeKey } from '@/api/websites'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, CommandBlock, ErrorState, formatNumber, formatPercent, Skeleton } from '@schild/ui'
import { ChevronDown, ChevronRight, Plus } from '@lucide/vue'
import { computed, ref } from 'vue'
import { errorMessage } from '@/api/client'
import { isRingBusy, useRuleAlerts } from '@/api/requests'
import { useFalsePositiveHints } from '@/api/websites'
import RuleExceptionDialog from '@/components/rules/RuleExceptionDialog.vue'
import { explainRule } from '@/lib/explain'
import { REQUESTS_COPY } from '@/lib/requests'

/**
 * Alerts with traffic, per rule (getRuleAlerts, MVP-22): how often a rule fired, on which pages and with
 * what share of their requests, and how many of the hit visitors otherwise behaved normally. A rule the
 * gateway marks as possible false positive shows the narrow exception of listFalsePositiveHints: set with
 * one click (D84) or copied into the repository (scope website or gateway, suggested file). schild never
 * applies it on its own (D32).
 */
const props = defineProps<{ site: string, range: WebsiteRangeKey, observe?: boolean, activeRule?: string | null }>()
const emit = defineEmits<{ filter: [expr: string] }>()

const q = useRuleAlerts(() => ({ site: props.site, range: props.range, top: 12 }))
const hintsQ = useFalsePositiveHints(() => props.site)
const open = ref<string | null>(null)
const rows = computed(() => (q.data.value?.items ?? []).map((r) => {
  const hints = (hintsQ.data.value?.items ?? []).filter(h => h.rule_id === r.rule_id)
  const top = [...r.pages].sort((a, b) => b.rate - a.rate)[0]
  return { r, title: explainRule(r.rule_id).title, hints, top, normal: r.clients.hit ? r.clients.in_session / r.clients.hit : null }
}))
const exceptionOpen = ref(false)
const preset = ref<Partial<RuleExceptionInput>>({})
function addException(p: Partial<RuleExceptionInput>) {
  preset.value = p
  exceptionOpen.value = true
}
const ringFrom = computed(() => q.data.value?.ring_from ?? null)
</script>

<template>
  <Card class="min-w-0" data-testid="rule-alerts">
    <CardHeader>
      <CardTitle>Alarme nach Regel</CardTitle>
      <CardDescription>
        Welche Regel wie oft angeschlagen hat, auf welchen Seiten und bei wem. Seiten und Besucher stammen aus den einzelnen Anfragen.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <div v-if="q.isPending.value" class="space-y-2">
        <Skeleton v-for="i in 4" :key="i" class="h-9 w-full" />
      </div>
      <ErrorState v-else-if="q.isError.value" title="Die Regeln lassen sich gerade nicht laden" :description="isRingBusy(q.error.value) ? REQUESTS_COPY.busy : errorMessage(q.error.value)" :retrying="q.isFetching.value" @retry="q.refetch()" />
      <p v-else-if="!rows.length" class="text-sm text-muted-foreground">
        In diesem Zeitraum hat keine Regel angeschlagen.
      </p>
      <ul v-else class="divide-y">
        <li v-for="x in rows" :key="x.r.rule_id" class="py-2" :data-rule="x.r.rule_id">
          <div class="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <button
              type="button"
              class="min-w-0 text-left text-sm font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring"
              :aria-pressed="activeRule === x.r.rule_id"
              :title="`Nach Regel ${x.r.rule_id} filtern`"
              @click="emit('filter', `rule:${x.r.rule_id}`)"
            >
              {{ x.title }} <span class="font-normal text-muted-foreground">· Regel {{ x.r.rule_id }}</span>
            </button>
            <span class="text-sm tabular-nums">
              {{ formatNumber(x.r.detections) }} Erkennungen
              <span class="text-muted-foreground">· {{ observe ? `${formatNumber(x.r.would_block)} erkannt` : `${formatNumber(x.r.blocked)} gesperrt` }}</span>
            </span>
          </div>
          <p class="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span v-if="x.top">
              meist auf <span class="font-mono">{{ x.top.path }}</span>, {{ formatPercent(x.top.rate) }} der Anfragen dort
            </span>
            <span v-if="x.r.clients.hit">
              {{ formatNumber(x.r.clients.hit) }} Besucher, davon {{ formatNumber(x.r.clients.in_session) }} mit sonst normalem Besuch und {{ formatNumber(x.r.clients.alert_only) }} nur mit Alarmen
            </span>
            <button
              v-if="x.r.possible_false_positive"
              type="button"
              class="inline-flex items-center gap-0.5 rounded-full border border-status-info/40 bg-status-info-subtle px-1.5 py-px font-medium text-status-info focus-visible:outline-2 focus-visible:outline-ring"
              :aria-expanded="open === x.r.rule_id"
              data-testid="rule-fp"
              @click="open = open === x.r.rule_id ? null : x.r.rule_id"
            >
              <component :is="open === x.r.rule_id ? ChevronDown : ChevronRight" class="size-3" aria-hidden="true" />{{ REQUESTS_COPY.falsePositive }}
            </button>
          </p>
          <div v-if="open === x.r.rule_id" class="mt-2 space-y-3 rounded-lg border bg-card p-3 text-sm" data-testid="rule-fp-detail">
            <p class="text-muted-foreground">
              {{ REQUESTS_COPY.falsePositiveText }}
            </p>
            <p v-if="!x.hints.length" class="text-muted-foreground">
              Den Vorschlag für die Ausnahme zeigt Schild hier, sobald es genug normale Besuche gesehen hat.
            </p>
            <div v-for="h in x.hints" :key="`${h.rule_id}|${h.path}|${h.target ?? ''}`" class="space-y-1">
              <p>
                Seite <span class="font-mono">{{ h.path }}</span><template v-if="h.target">, Feld <span class="font-mono">{{ h.target }}</span></template>
                · {{ formatNumber(h.clients_in_session) }} von {{ formatNumber(h.clients_hit) }} Besuchern sonst ganz normal
              </p>
              <p class="text-xs text-muted-foreground">
                {{ h.exception.scope === 'gateway' ? 'Gilt für alle Websites auf diesem Server, weil die Website keinen eigenen Namen hat.' : 'Gilt nur für die Adressen dieser Website.' }}
                Datei: <span class="font-mono">{{ h.exception.file }}</span>. {{ REQUESTS_COPY.exceptionNotApplied }}
              </p>
              <Button size="sm" variant="outline" data-testid="rule-fp-add" @click="addException({ website: h.site || site, path: h.path, target: h.target, repository: 'crs', rules: [h.rule_id] })">
                <Plus aria-hidden="true" />
                Ausnahme anlegen
              </Button>
              <CommandBlock :command="h.exception.snippet" copy-label="Ausnahme kopieren" caption="Ausnahme (SecLang)" subject="Ausnahme" />
            </div>
          </div>
        </li>
      </ul>
      <p v-if="ringFrom === null && q.data.value" class="mt-2 text-xs text-muted-foreground">
        {{ REQUESTS_COPY.ringOnly }}
      </p>
    </CardContent>

    <RuleExceptionDialog v-model:open="exceptionOpen" :preset="preset" />
  </Card>
</template>
