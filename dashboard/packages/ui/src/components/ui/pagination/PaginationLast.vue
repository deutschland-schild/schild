<script setup lang="ts">
import type { PaginationLastProps } from "reka-ui"
import type { HTMLAttributes } from "vue"
import type { ButtonVariants } from '@schild/ui/components/ui/button'
import { ChevronRightIcon } from "@lucide/vue"
import { reactiveOmit } from "@vueuse/core"
import { cn } from "@schild/ui/lib/utils"
import { PaginationLast, useForwardProps } from "reka-ui"
import { buttonVariants } from '@schild/ui/components/ui/button'

const props = withDefaults(defineProps<PaginationLastProps & {
  size?: ButtonVariants["size"]
  class?: HTMLAttributes["class"]
}>(), {
  size: "default",
})

const delegatedProps = reactiveOmit(props, "class", "size")
const forwarded = useForwardProps(delegatedProps)
</script>

<template>
  <PaginationLast
    data-slot="pagination-last"
    aria-label="Zur letzten Seite"
    :class="cn(buttonVariants({ variant: 'ghost', size }), 'gap-1 px-2.5 sm:pr-2.5', props.class)"
    v-bind="forwarded"
  >
    <slot>
      <span class="hidden sm:block">Letzte</span>
      <ChevronRightIcon />
    </slot>
  </PaginationLast>
</template>
