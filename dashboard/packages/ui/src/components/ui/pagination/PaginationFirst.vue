<script setup lang="ts">
import type { PaginationFirstProps } from "reka-ui"
import type { HTMLAttributes } from "vue"
import type { ButtonVariants } from '@schild/ui/components/ui/button'
import { ChevronLeftIcon } from "@lucide/vue"
import { reactiveOmit } from "@vueuse/core"
import { cn } from "@schild/ui/lib/utils"
import { PaginationFirst, useForwardProps } from "reka-ui"
import { buttonVariants } from '@schild/ui/components/ui/button'

const props = withDefaults(defineProps<PaginationFirstProps & {
  size?: ButtonVariants["size"]
  class?: HTMLAttributes["class"]
}>(), {
  size: "default",
})

const delegatedProps = reactiveOmit(props, "class", "size")
const forwarded = useForwardProps(delegatedProps)
</script>

<template>
  <PaginationFirst
    data-slot="pagination-first"
    aria-label="Zur ersten Seite"
    :class="cn(buttonVariants({ variant: 'ghost', size }), 'gap-1 px-2.5 sm:pr-2.5', props.class)"
    v-bind="forwarded"
  >
    <slot>
      <ChevronLeftIcon />
      <span class="hidden sm:block">Erste</span>
    </slot>
  </PaginationFirst>
</template>
