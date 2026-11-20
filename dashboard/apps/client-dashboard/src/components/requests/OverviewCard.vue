<script setup lang="ts">
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Skeleton } from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import EstimateNote from '@/components/monitoring/EstimateNote.vue'
import GapNote from '@/components/monitoring/GapNote.vue'
import { OVERVIEW_COPY } from '@/lib/requests-overview'
import { WEBSITE_COPY } from '@/lib/websites'

/**
 * Frame of one card of the Zugriffe overview: title, the calm Näherungswert and gap notes, and the
 * states every card shares (loading, only within 48 h with this filter, no data, error). A "more" link
 * opens the tab with the full table.
 */
withDefaults(defineProps<{
  title: string
  description?: string
  testid: string
  state: 'loading' | 'unavailable' | 'empty' | 'error' | 'ok'
  /** Text of the Näherungswert note; none when the numbers are counted. */
  estimate?: string | null
  partial?: boolean
  /** The request ring answers this within 48 h: offer the switch. */
  offerRange?: boolean
  more?: string | null
  skeletonRows?: number
}>(), { description: undefined, estimate: null, partial: false, offerRange: false, more: null, skeletonRows: 5 })
const emit = defineEmits<{ range: [], more: [] }>()
</script>

<template>
  <Card class="min-w-0 gap-4" :data-testid="testid">
    <CardHeader>
      <div class="flex flex-wrap items-center gap-2">
        <CardTitle>{{ title }}</CardTitle>
        <EstimateNote v-if="estimate && state === 'ok'" :text="estimate" />
        <GapNote v-if="partial && state === 'ok'" />
      </div>
      <CardDescription v-if="description">
        {{ description }}
      </CardDescription>
    </CardHeader>
    <CardContent class="flex flex-1 flex-col">
      <div v-if="state === 'loading'" class="space-y-2">
        <Skeleton v-for="i in skeletonRows" :key="i" class="h-7 w-full" />
      </div>
      <div v-else-if="state === 'unavailable'" class="rounded-lg border border-dashed p-4 text-sm">
        <p class="text-muted-foreground">
          {{ OVERVIEW_COPY.unavailable }}
        </p>
        <Button v-if="offerRange" size="sm" variant="outline" class="mt-2" @click="emit('range')">
          {{ WEBSITE_COPY.to48h }}
        </Button>
      </div>
      <p v-else-if="state === 'error'" class="text-sm text-muted-foreground">
        Diese Zahlen lassen sich gerade nicht laden. Schild versucht es gleich noch einmal.
      </p>
      <p v-else-if="state === 'empty'" class="text-sm text-muted-foreground">
        {{ OVERVIEW_COPY.noData }}
      </p>
      <slot v-else />
      <div v-if="more && state === 'ok'" class="mt-auto pt-3">
        <Button variant="link" size="sm" class="h-auto p-0 text-xs" @click="emit('more')">
          {{ more }}
          <ArrowRight class="size-3" aria-hidden="true" />
        </Button>
      </div>
    </CardContent>
  </Card>
</template>
