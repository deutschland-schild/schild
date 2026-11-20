<script setup lang="ts">
defineProps<{ id: string, title: string, description?: string }>()
</script>

<template>
  <section :id="id" :aria-labelledby="`${id}-title`" class="scroll-mt-20 space-y-4 border-t pt-8 first:border-0 first:pt-0">
    <div class="space-y-1">
      <h2 :id="`${id}-title`" class="text-lg font-bold tracking-tight">
        {{ title }}
      </h2>
      <p v-if="description" class="max-w-prose text-sm text-muted-foreground">
        {{ description }}
      </p>
    </div>
    <slot />
  </section>
</template>
