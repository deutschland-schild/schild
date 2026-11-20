<script setup lang="ts">
import type { MetaItem } from '@schild/ui'
import type { RuleRepository } from '@/api/types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, formatNumber, MetaLine, PageHeader, Skeleton, StatusPill } from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import { computed } from 'vue'
import { useBehaviourSettings, useRateLimits } from '@/api/behaviour'
import { useDistributedSettings } from '@/api/distributed'
import { ruleError, useRuleExceptions, useRuleRepositories } from '@/api/rules'
import { BEHAVIOUR_EFFECT, behaviourStatus } from '@/lib/behaviour'
import { BEHAVIOUR_RULES_PATH } from '@/lib/nav'
import { countFacts, groupExceptions, REPOSITORIES, REPOSITORY_EFFECT, rulesPath } from '@/lib/rules'

/**
 * Regeln (D62, D73): the three sources of rules side by side and what each does now; their switches decide,
 * there is no protection mode above them (D89). Each source has its own page with its switch and its rules. Below them what looks across requests,
 * scenarios and limits (2026-11-18): they block the address, not the request.
 */
const q = useRuleRepositories()
const repos = computed(() => q.data.value?.items ?? [])
/** Own rules and exceptions are one page: its card counts the exceptions too. */
const exceptions = useRuleExceptions()
function facts(r: RuleRepository): MetaItem[] {
  if (r.id !== 'local') return countFacts(r)
  const n = exceptions.data.value && groupExceptions(exceptions.data.value.items).length
  return [...countFacts(r), ...(n === undefined ? [] : [n === 1 ? '1 Ausnahme' : `${formatNumber(n)} Ausnahmen`])]
}
const behaviour = useBehaviourSettings()
const limits = useRateLimits()
const waves = useDistributedSettings()
const status = computed(() => behaviour.data.value ? behaviourStatus(behaviour.data.value, limits.data.value?.items ?? null, Date.now(), waves.data.value?.detectors ?? null) : null)
</script>

<template>
  <div>
    <PageHeader title="Regeln" description="Woher die Regeln kommen, die jede Anfrage prüfen, und was sie gerade tun. Jede Quelle hat ihren eigenen Schalter." />

    <ErrorState v-if="q.isError.value && !repos.length" title="Die Regeln lassen sich gerade nicht laden" :description="ruleError(q.error.value)" @retry="q.refetch()" />
    <div v-else class="grid gap-4 lg:grid-cols-3" data-testid="rule-repositories">
      <template v-if="q.isPending.value">
        <Skeleton v-for="i in 3" :key="i" class="h-52 rounded-xl" />
      </template>
      <Card v-for="r in repos" :key="r.id" class="flex min-w-0 flex-col" :data-testid="`rules-${r.id}`">
        <CardHeader>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <CardTitle>
              <RouterLink :to="rulesPath(r.id)" class="hover:underline">
                {{ REPOSITORIES[r.id]?.name ?? r.name }}
              </RouterLink>
            </CardTitle>
            <StatusPill :tone="REPOSITORY_EFFECT[r.effect].tone" size="sm">
              {{ REPOSITORY_EFFECT[r.effect].label }}
            </StatusPill>
          </div>
          <CardDescription>{{ REPOSITORIES[r.id]?.lead }}</CardDescription>
        </CardHeader>
        <CardContent class="mt-auto space-y-3">
          <MetaLine :items="facts(r)" :data-testid="`rules-${r.id}-facts`" />
          <RouterLink :to="rulesPath(r.id)" class="inline-flex items-center gap-1.5 text-sm font-semibold underline-offset-4 hover:underline">
            {{ r.id === 'local' ? 'Regeln und Ausnahmen' : 'Schalter und Regeln' }}
            <ArrowRight class="size-4" aria-hidden="true" />
          </RouterLink>
        </CardContent>
      </Card>
    </div>

    <h2 class="mt-8 mb-1 text-base font-semibold">
      Über mehrere Anfragen
    </h2>
    <p class="mb-3 text-sm text-muted-foreground">
      Die Regeln oben prüfen jede Anfrage für sich und blocken nur diese eine. Szenarien und Limits sehen auf das Verhalten einer Adresse über viele Anfragen und sperren die ganze Adresse für eine Weile. Die Wellen-Erkennung sieht auf Angriffe, die sich über viele Adressen verteilen.
    </p>
    <Card class="min-w-0" data-testid="rules-behaviour">
      <CardHeader>
        <div class="flex flex-wrap items-center justify-between gap-2">
          <CardTitle>
            <RouterLink :to="BEHAVIOUR_RULES_PATH" class="hover:underline">
              Szenarien und Limits
            </RouterLink>
          </CardTitle>
          <StatusPill v-if="status" :tone="BEHAVIOUR_EFFECT[status.effect].tone" size="sm" data-testid="rules-behaviour-status">
            {{ BEHAVIOUR_EFFECT[status.effect].label }}
          </StatusPill>
        </div>
        <CardDescription>Passwort-Raten, Suche nach Schwachstellen, wiederholte Angriffsversuche, zu viele Anfragen, verteilte Angriffe über viele Adressen.</CardDescription>
      </CardHeader>
      <CardContent class="space-y-3">
        <MetaLine v-if="status" :items="status.facts" data-testid="rules-behaviour-facts" />
        <div class="flex flex-wrap gap-x-5 gap-y-2">
          <RouterLink :to="BEHAVIOUR_RULES_PATH" class="inline-flex items-center gap-1.5 text-sm font-semibold underline-offset-4 hover:underline">
            Szenarien und Limits
            <ArrowRight class="size-4" aria-hidden="true" />
          </RouterLink>
          <RouterLink :to="{ path: BEHAVIOUR_RULES_PATH, query: { view: 'detectors' } }" class="inline-flex items-center gap-1.5 text-sm font-semibold underline-offset-4 hover:underline" data-testid="rules-behaviour-waves">
            Wellen-Erkennung
            <ArrowRight class="size-4" aria-hidden="true" />
          </RouterLink>
          <RouterLink to="/blocks" class="inline-flex items-center gap-1.5 text-sm font-semibold underline-offset-4 hover:underline">
            Gesperrte Adressen
            <ArrowRight class="size-4" aria-hidden="true" />
          </RouterLink>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
