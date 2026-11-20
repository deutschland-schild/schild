<script setup lang="ts">
import { formatDateTime, formatRelative, toDate } from '@schild/ui/lib/format'
import { useIntervalFn, useNow } from '@vueuse/core'
import { computed } from 'vue'

/** "vor 3 Minuten" with the absolute time as tooltip and machine-readable datetime. Updates itself. */
const props = withDefaults(defineProps<{ value: Date | string | number, interval?: number }>(), { interval: 30_000 })
const now = useNow({ scheduler: update => useIntervalFn(update, props.interval) })
const date = computed(() => toDate(props.value))
const iso = computed(() => Number.isNaN(date.value.getTime()) ? undefined : date.value.toISOString())
const absolute = computed(() => formatDateTime(date.value))
const relative = computed(() => formatRelative(date.value, now.value))
</script>

<template>
  <time :datetime="iso" :title="absolute" class="whitespace-nowrap tabular-nums">{{ relative }}</time>
</template>
