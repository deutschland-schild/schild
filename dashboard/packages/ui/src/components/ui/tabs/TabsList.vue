<script setup lang="ts">
import type { TabsListProps } from "reka-ui"
import type { HTMLAttributes } from "vue"
import { reactiveOmit } from "@vueuse/core"
import { cn } from "@schild/ui/lib/utils"
import { TabsList } from "reka-ui"

/**
 * `pill` (default): compact filter switch. `line`: the website's tab strip (paper band,
 * active tab as a white card that merges into the content below).
 */
const props = withDefaults(defineProps<TabsListProps & { class?: HTMLAttributes["class"], variant?: "pill" | "line" }>(), { variant: "pill", class: undefined })

const delegatedProps = reactiveOmit(props, "class", "variant")
</script>

<template>
  <TabsList
    data-slot="tabs-list"
    :data-variant="variant"
    v-bind="delegatedProps"
    :class="cn(
      'group/tabs-list text-muted-foreground',
      variant === 'line'
        ? 'flex w-full items-end gap-1 overflow-x-auto border-b bg-muted px-3 pt-2.5 sm:px-4'
        : 'inline-flex h-9 w-fit items-center justify-center rounded-full bg-muted p-0.5 ring-1 ring-border',
      props.class,
    )"
  >
    <slot />
  </TabsList>
</template>
