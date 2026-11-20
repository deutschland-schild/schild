<script setup lang="ts">
import type { Component } from 'vue'
import { Inbox } from '@lucide/vue'

withDefaults(defineProps<{ title: string, description?: string, icon?: Component }>(), { description: undefined, icon: () => Inbox })
</script>

<template>
  <div class="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed bg-muted/60 px-6 py-12 text-center" role="status">
    <div class="flex size-12 items-center justify-center rounded-full bg-card text-muted-foreground ring-1 ring-border" aria-hidden="true">
      <component :is="icon" class="size-6" />
    </div>
    <div class="space-y-1">
      <p class="font-bold">
        {{ title }}
      </p>
      <p v-if="description" class="max-w-sm text-sm text-muted-foreground text-pretty">
        {{ description }}
      </p>
    </div>
    <div v-if="$slots.default" class="pt-2">
      <slot />
    </div>
  </div>
</template>
