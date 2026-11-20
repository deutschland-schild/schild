<script setup lang="ts">
import type { Geo } from '@/api/types'
import { countryName, flagEmoji } from '@schild/ui'
import { Globe } from '@lucide/vue'
import { computed } from 'vue'
import { NET_CLASS } from '@/lib/labels'

/** Country with flag and network (ASN) for lists; full words, not only codes. */
const props = withDefaults(defineProps<{ geo?: Geo | null, compact?: boolean }>(), { geo: null, compact: false })
const net = computed(() => props.geo ? (NET_CLASS[props.geo.net_class] ?? props.geo.net_class) : '')
</script>

<template>
  <span v-if="geo" class="inline-flex min-w-0 flex-col leading-tight">
    <span class="truncate">
      <span v-if="flagEmoji(geo.country)" aria-hidden="true">{{ flagEmoji(geo.country) }}</span>
      <Globe v-else class="mr-0.5 inline size-3.5 align-[-2px] text-muted-foreground" aria-hidden="true" />
      {{ countryName(geo.country) }}<template v-if="geo.city && !compact">, {{ geo.city }}</template>
    </span>
    <span v-if="!compact" class="truncate text-xs text-muted-foreground">
      AS{{ geo.asn }}<template v-if="geo.as_org"> · {{ geo.as_org }}</template> · {{ net }}
    </span>
  </span>
  <span v-else class="text-muted-foreground">–</span>
</template>
