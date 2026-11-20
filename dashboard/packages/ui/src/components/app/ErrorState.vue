<script setup lang="ts">
import { Button } from '@schild/ui/components/ui/button'
import { RotateCw, TriangleAlert } from '@lucide/vue'

withDefaults(defineProps<{
  title?: string
  description?: string
  /** Technical detail (shown collapsed). */
  detail?: string
  retryLabel?: string
  retrying?: boolean
}>(), {
  title: 'Das hat nicht geklappt',
  description: 'Die Daten konnten nicht geladen werden. Versuch es gleich noch einmal.',
  detail: undefined,
  retryLabel: 'Erneut versuchen',
  retrying: false,
})
const emit = defineEmits<{ retry: [] }>()
</script>

<template>
  <div class="flex flex-col items-center justify-center gap-3 rounded-xl border border-status-danger/30 bg-status-danger-subtle/50 px-6 py-10 text-center" role="alert">
    <div class="flex size-12 items-center justify-center rounded-full bg-status-danger-subtle text-status-danger" aria-hidden="true">
      <TriangleAlert class="size-6" />
    </div>
    <div class="space-y-1">
      <p class="font-medium">
        {{ title }}
      </p>
      <p class="max-w-sm text-sm text-muted-foreground text-pretty">
        {{ description }}
      </p>
    </div>
    <details v-if="detail" class="max-w-md text-left text-xs text-muted-foreground">
      <summary class="cursor-pointer rounded select-none">
        Technische Details
      </summary>
      <pre class="mt-2 overflow-x-auto rounded-md bg-muted p-2 font-mono whitespace-pre-wrap">{{ detail }}</pre>
    </details>
    <Button variant="outline" size="sm" :disabled="retrying" @click="emit('retry')">
      <RotateCw :class="retrying ? 'motion-safe:animate-spin' : ''" aria-hidden="true" />
      {{ retryLabel }}
    </Button>
  </div>
</template>
