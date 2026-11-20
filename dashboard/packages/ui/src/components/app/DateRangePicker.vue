<script setup lang="ts">
import type { DateRange } from 'reka-ui'
import { Button } from '@schild/ui/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@schild/ui/components/ui/popover'
import { RangeCalendar } from '@schild/ui/components/ui/range-calendar'
import { DateFormatter, getLocalTimeZone } from '@internationalized/date'
import { CalendarDays } from '@lucide/vue'
import { computed } from 'vue'

/** Date range picker (German locale, week starts Monday). */
withDefaults(defineProps<{ placeholder?: string }>(), { placeholder: 'Zeitraum wählen' })
const range = defineModel<DateRange>({ default: () => ({ start: undefined, end: undefined }) })
const df = new DateFormatter('de-DE', { dateStyle: 'medium' })
const tz = getLocalTimeZone()
const text = computed(() => {
  const { start, end } = range.value
  if (!start) return null
  return end ? `${df.format(start.toDate(tz))} – ${df.format(end.toDate(tz))}` : df.format(start.toDate(tz))
})
</script>

<template>
  <Popover>
    <PopoverTrigger as-child>
      <Button variant="outline" size="sm" class="justify-start font-normal" :class="!text && 'text-muted-foreground'">
        <CalendarDays aria-hidden="true" />
        {{ text ?? placeholder }}
      </Button>
    </PopoverTrigger>
    <PopoverContent class="w-auto p-0" align="start">
      <RangeCalendar v-model="range" locale="de-DE" :week-starts-on="1" :number-of-months="2" initial-focus />
    </PopoverContent>
  </Popover>
</template>
