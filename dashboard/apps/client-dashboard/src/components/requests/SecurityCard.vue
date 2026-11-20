<script setup lang="ts">
import type { WebsiteKpis } from '@/api/websites'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, formatNumber } from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import { computed } from 'vue'
import { useFalsePositiveHints } from '@/api/websites'
import { WOULD_BLOCK_MIXED } from '@/lib/labels'
import { websitePath } from '@/lib/nav'
import { OVERVIEW_COPY } from '@/lib/requests-overview'

/**
 * Small "Sicherheit" card of the Zugriffe overview: gesperrt and erkannt in the range (KPIs) and how many
 * rules look like a possible false positive (listFalsePositiveHints, request ring only). The details,
 * "Alarme nach Regel" with the exceptions to copy, live on the Ereignisse page of the website (D68).
 */
const props = defineProps<{ site: string, kpis?: WebsiteKpis, ring?: boolean }>()

const hintsQ = useFalsePositiveHints(() => props.site)
const fpRules = computed(() => hintsQ.data.value ? new Set(hintsQ.data.value.items.map(h => h.rule_id)).size : null)
const stopped = computed(() => props.kpis?.current.stopped.value ?? null)
const would = computed(() => props.kpis?.current.would_block.value ?? null)
</script>

<template>
  <Card class="min-w-0 gap-4" data-testid="overview-security">
    <CardHeader>
      <CardTitle>{{ OVERVIEW_COPY.security }}</CardTitle>
      <CardDescription>{{ OVERVIEW_COPY.securityText }}</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-1 flex-col">
      <dl class="grid grid-cols-3 gap-3">
        <div class="min-w-0">
          <dt class="text-xs text-muted-foreground">
            Gesperrt
          </dt>
          <dd class="text-xl font-semibold" data-slot="security-stopped">
            {{ formatNumber(stopped) }}
          </dd>
        </div>
        <div class="min-w-0">
          <dt class="text-xs text-muted-foreground" :title="WOULD_BLOCK_MIXED">
            Erkannt
          </dt>
          <dd class="text-xl font-semibold" data-slot="security-would">
            {{ formatNumber(would) }}
          </dd>
        </div>
        <div class="min-w-0">
          <dt class="text-xs text-muted-foreground" :title="OVERVIEW_COPY.fpHint">
            Mögliche Fehlalarme
          </dt>
          <dd class="text-xl font-semibold" data-slot="security-fp">
            <template v-if="ring">
              {{ formatNumber(fpRules) }}
            </template>
            <span v-else class="text-xs font-normal text-muted-foreground">{{ OVERVIEW_COPY.fpNeedsRing }}</span>
          </dd>
        </div>
      </dl>
      <p v-if="ring && fpRules" class="mt-2 text-xs text-muted-foreground">
        {{ OVERVIEW_COPY.fpHint }}
      </p>
      <div class="mt-auto pt-3">
        <Button as-child variant="link" size="sm" class="h-auto p-0 text-xs">
          <RouterLink :to="websitePath(site, 'events')" data-testid="overview-to-events">
            {{ OVERVIEW_COPY.toEvents }}
            <ArrowRight class="size-3" aria-hidden="true" />
          </RouterLink>
        </Button>
      </div>
    </CardContent>
  </Card>
</template>
