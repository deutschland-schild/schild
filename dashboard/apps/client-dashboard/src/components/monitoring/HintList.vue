<script setup lang="ts">
import type { HealthHint } from '@/api/monitoring'
import type { HintContext } from '@/lib/monitoring'
import { Button, StatusPill } from '@schild/ui'
import { ArrowRight, CircleCheck } from '@lucide/vue'
import { computed } from 'vue'
import { COPY, hintView } from '@/lib/monitoring'

/** "Hinweise": each hint as one sentence plus the next step; calm levels only. */
const props = defineProps<{ hints: HealthHint[], context?: HintContext }>()
const views = computed(() => props.hints.map(h => ({ h, v: hintView(h, props.context) })))
</script>

<template>
  <ul v-if="views.length" class="grid gap-2" data-testid="hints">
    <li v-for="{ h, v } in views" :key="`${h.code}-${h.object ?? ''}`" class="flex flex-col gap-2 rounded-xl border bg-card p-4 sm:flex-row sm:items-center" :data-hint="h.code">
      <StatusPill :tone="v.tone" size="sm" class="self-start sm:self-center">
        {{ v.levelLabel }}
      </StatusPill>
      <div class="min-w-0 flex-1">
        <p class="text-sm font-medium text-pretty">
          {{ v.text }}
        </p>
        <p v-if="v.next" class="text-sm text-muted-foreground">
          {{ v.next }}
        </p>
      </div>
      <Button v-if="v.to" as-child variant="outline" size="sm" class="self-start sm:self-center">
        <RouterLink :to="v.to">
          {{ v.action }}
          <ArrowRight aria-hidden="true" />
        </RouterLink>
      </Button>
    </li>
  </ul>
  <p v-else class="flex items-center gap-2 rounded-xl border bg-card p-4 text-sm" data-testid="no-hints">
    <CircleCheck class="size-4 text-status-success" aria-hidden="true" />
    {{ COPY.noHints }}
  </p>
</template>
