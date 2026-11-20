<script setup lang="ts">
// Bottom padding only when the page wrapper does not space its sections itself (space-y-6).
defineProps<{ title: string, description?: string }>()
</script>

<template>
  <header class="flex flex-col gap-3 pb-6 sm:flex-row sm:items-end sm:justify-between [.space-y-6>&]:pb-0">
    <div class="min-w-0 space-y-1">
      <div v-if="$slots.eyebrow" class="text-xs font-semibold text-status-signal-text">
        <slot name="eyebrow" />
      </div>
      <h1 class="text-2xl font-bold tracking-tight text-balance">
        {{ title }}
      </h1>
      <p v-if="description" class="max-w-prose text-sm text-muted-foreground text-pretty">
        {{ description }}
      </p>
      <div v-if="$slots.meta" class="flex flex-wrap items-center gap-2 pt-1">
        <slot name="meta" />
      </div>
    </div>
    <div v-if="$slots.actions" class="flex flex-wrap items-center gap-2">
      <slot name="actions" />
    </div>
  </header>
</template>
