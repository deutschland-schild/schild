<script setup lang="ts">
import type { SegmentOption } from '@schild/ui'
import type { WebsiteRangeKey } from '@/api/websites'
import { NativeSelect, NativeSelectOption, SegmentedControl } from '@schild/ui'
import { computed } from 'vue'
import { WEBSITE_RANGE_KEYS, WEBSITE_RANGES } from '@/api/websites'

/** Time range of the website overview (Echtzeit, 6 h, 24 h, 48 h, 7 and 14 days); a select on small screens. */
const range = defineModel<WebsiteRangeKey>({ required: true })
const options = computed<SegmentOption<WebsiteRangeKey>[]>(() => WEBSITE_RANGE_KEYS.map(k => ({ value: k, label: WEBSITE_RANGES[k].label, testid: `range-${k}` })))
</script>

<template>
  <SegmentedControl v-model="range" :options="options" label="Zeitraum" class="hidden md:inline-grid" />
  <div class="md:hidden">
    <NativeSelect v-model="range" aria-label="Zeitraum" data-testid="range-select">
      <NativeSelectOption v-for="k in WEBSITE_RANGE_KEYS" :key="k" :value="k">
        {{ WEBSITE_RANGES[k].label }}
      </NativeSelectOption>
    </NativeSelect>
  </div>
</template>
