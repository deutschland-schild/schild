<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import { cn } from '@schild/ui/lib/utils'

/**
 * The website's dashboard panel: white rounded card with an optional header bar,
 * an optional tab strip (paper), a list on paper on the left and the detail on the right,
 * and an optional footer (e.g. EffectFooter). Below `md` the list stacks above the detail.
 */
const props = withDefaults(defineProps<{
  /** Accessible name of the list navigation. */
  listLabel?: string
  /** Small slate heading above the list. */
  listTitle?: string
  /** Hide the list below lg (e.g. while a detail is open on a phone). */
  hideListOnMobile?: boolean
  /** Tailwind width class pair for the list column. */
  listWidth?: 'sm' | 'md'
  /** Keep the list in view and scroll it on its own on wide screens. */
  stickyList?: boolean
  class?: HTMLAttributes['class']
}>(), { listLabel: undefined, listTitle: undefined, hideListOnMobile: false, listWidth: 'sm', stickyList: false, class: undefined })
</script>

<template>
  <section data-slot="split-pane" :class="cn('overflow-clip rounded-xl border bg-card text-card-foreground shadow-sm', props.class)">
    <header v-if="$slots.header" class="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b px-4 py-3 sm:px-5">
      <slot name="header" />
    </header>
    <slot name="tabs" />
    <div
      :class="cn('grid min-w-0', $slots.list ? (listWidth === 'md' ? 'lg:grid-cols-[minmax(16rem,22rem)_1fr]' : 'md:grid-cols-[15rem_1fr]') : '')"
    >
      <nav
        v-if="$slots.list"
        :aria-label="listLabel"
        :class="cn(
          'min-w-0 border-b bg-muted p-3',
          listWidth === 'md' ? 'lg:border-r lg:border-b-0' : 'md:border-r md:border-b-0',
          hideListOnMobile ? (listWidth === 'md' ? 'hidden lg:block' : 'hidden md:block') : '',
        )"
      >
        <div :class="stickyList ? (listWidth === 'md' ? 'lg:sticky lg:top-16 lg:max-h-[calc(100svh-6rem)] lg:overflow-y-auto' : 'md:sticky md:top-16 md:max-h-[calc(100svh-6rem)] md:overflow-y-auto') : ''">
          <p v-if="listTitle" class="px-1 pb-2 text-xs font-semibold text-muted-foreground">
            {{ listTitle }}
          </p>
          <slot name="list" />
        </div>
      </nav>
      <div class="min-w-0 p-4 sm:p-5">
        <slot />
      </div>
    </div>
    <slot name="footer" />
  </section>
</template>
