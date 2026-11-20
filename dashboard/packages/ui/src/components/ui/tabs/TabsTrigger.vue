<script setup lang="ts">
import type { TabsTriggerProps } from "reka-ui"
import type { HTMLAttributes } from "vue"
import { reactiveOmit } from "@vueuse/core"
import { cn } from "@schild/ui/lib/utils"
import { TabsTrigger, useForwardProps } from "reka-ui"

const props = defineProps<TabsTriggerProps & { class?: HTMLAttributes["class"] }>()

const delegatedProps = reactiveOmit(props, "class")

const forwardedProps = useForwardProps(delegatedProps)
</script>

<template>
  <TabsTrigger
    data-slot="tabs-trigger"
    :class="cn(
      [
        'inline-flex items-center justify-center gap-1.5 text-[13px] font-semibold whitespace-nowrap transition-[color,background-color,box-shadow]',
        'text-muted-foreground hover:text-foreground data-[state=active]:text-foreground',
        'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring disabled:pointer-events-none disabled:opacity-50',
        '[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*=size-])]:size-4',
        // pill (default)
        'group-data-[variant=pill]/tabs-list:h-full group-data-[variant=pill]/tabs-list:flex-1 group-data-[variant=pill]/tabs-list:rounded-full group-data-[variant=pill]/tabs-list:px-3',
        'group-data-[variant=pill]/tabs-list:data-[state=active]:bg-card group-data-[variant=pill]/tabs-list:data-[state=active]:shadow-sm group-data-[variant=pill]/tabs-list:data-[state=active]:ring-1 group-data-[variant=pill]/tabs-list:data-[state=active]:ring-border',
        // line: website tab strip
        'group-data-[variant=line]/tabs-list:-mb-px group-data-[variant=line]/tabs-list:rounded-t-xl group-data-[variant=line]/tabs-list:border group-data-[variant=line]/tabs-list:border-b-0 group-data-[variant=line]/tabs-list:border-transparent group-data-[variant=line]/tabs-list:px-2.5 group-data-[variant=line]/tabs-list:py-2',
        'group-data-[variant=line]/tabs-list:data-[state=active]:border-border group-data-[variant=line]/tabs-list:data-[state=active]:bg-card',
      ],
      props.class,
    )"
    v-bind="forwardedProps"
  >
    <slot />
  </TabsTrigger>
</template>
