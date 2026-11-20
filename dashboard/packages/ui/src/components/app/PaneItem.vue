<script setup lang="ts">
import type { Component, HTMLAttributes } from 'vue'
import { cn } from '@schild/ui/lib/utils'

/**
 * Entry of a SplitPane list: transparent on paper, the active one as a white rounded card
 * with a thin warm border (website preset list). Renders as a button by default;
 * pass `as` (e.g. RouterLink) for links. Set `current` to the aria-current value you need.
 */
const props = withDefaults(defineProps<{
  active?: boolean
  as?: Component | string
  current?: 'page' | 'true' | 'step'
  class?: HTMLAttributes['class']
}>(), { active: false, as: 'button', current: 'true', class: undefined })
</script>

<template>
  <component
    :is="as"
    :type="as === 'button' ? 'button' : undefined"
    :aria-current="active ? current : undefined"
    data-slot="pane-item"
    :data-active="active || undefined"
    :class="cn(
      'block w-full rounded-xl px-3 py-2.5 text-left text-sm transition-colors outline-none',
      'hover:bg-card/70 focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-ring',
      active ? 'bg-card shadow-xs ring-1 ring-border hover:bg-card' : '',
      props.class,
    )"
  >
    <slot />
  </component>
</template>
