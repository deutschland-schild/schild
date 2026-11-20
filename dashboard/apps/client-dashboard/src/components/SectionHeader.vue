<script setup lang="ts">
/** PageHeader for a section further down a page: an h2 with description and actions on the right. */
defineProps<{ title: string, description?: string }>()
</script>

<template>
  <header class="flex flex-col gap-3 pb-3 sm:flex-row sm:items-end sm:justify-between">
    <div class="min-w-0 space-y-1">
      <h2 class="text-lg font-semibold tracking-tight text-balance">
        {{ title }}
      </h2>
      <p v-if="description" class="max-w-prose text-sm text-muted-foreground text-pretty">
        {{ description }}
      </p>
    </div>
    <div v-if="$slots.actions" class="flex flex-wrap items-center gap-2">
      <slot name="actions" />
    </div>
  </header>
</template>
