<script setup lang="ts">
import type { PaginationListItemProps } from "reka-ui"
import type { HTMLAttributes } from "vue"
import type { ButtonVariants } from '@schild/ui/components/ui/button'
import { reactiveOmit } from "@vueuse/core"
import { cn } from "@schild/ui/lib/utils"
import { PaginationListItem } from "reka-ui"
import { buttonVariants } from '@schild/ui/components/ui/button'

const props = withDefaults(defineProps<PaginationListItemProps & {
  size?: ButtonVariants["size"]
  class?: HTMLAttributes["class"]
  isActive?: boolean
}>(), {
  size: "icon",
})

const delegatedProps = reactiveOmit(props, "class", "size", "isActive")
</script>

<template>
  <PaginationListItem
    data-slot="pagination-item"
    :aria-label="`Seite ${props.value}`"
    v-bind="delegatedProps"
    :class="cn(
      buttonVariants({
        variant: isActive ? 'outline' : 'ghost',
        size,
      }),
      props.class)"
  >
    <slot />
  </PaginationListItem>
</template>
