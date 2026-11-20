<script setup lang="ts">
import { ErrorState, Skeleton } from '@schild/ui'
import { problemDetail, problemMessage } from '@/lib/problem'

/** Skeleton while loading, calm error with retry, else the content. */
withDefaults(defineProps<{ pending: boolean, error?: unknown, rows?: number, retrying?: boolean }>(), { error: undefined, rows: 3, retrying: false })
const emit = defineEmits<{ retry: [] }>()
</script>

<template>
  <ErrorState
    v-if="error && !pending"
    :description="problemMessage(error)"
    :detail="problemDetail(error)"
    :retrying="retrying"
    @retry="emit('retry')"
  />
  <div v-else-if="pending" class="space-y-3" aria-busy="true" aria-label="Wird geladen">
    <slot name="skeleton">
      <Skeleton v-for="i in rows" :key="i" class="h-16 w-full" />
    </slot>
  </div>
  <slot v-else />
</template>
