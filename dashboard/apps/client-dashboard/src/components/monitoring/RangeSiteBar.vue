<script setup lang="ts">
import type { SegmentOption } from '@schild/ui'
import type { RangeKey, SiteNow } from '@/api/monitoring'
import { NativeSelect, NativeSelectOption, SegmentedControl } from '@schild/ui'
import { computed } from 'vue'
import { RANGE_KEYS, RANGES } from '@/api/monitoring'

/**
 * Time range (1 h, 6 h, 48 h, 14 d) and website switch of the monitoring pages, both kept
 * in the URL by the parent. On narrow screens the range is a select.
 */
const props = defineProps<{
  sites?: SiteNow[]
  /** Hide the website switch (server numbers are per server). */
  noSites?: boolean
}>()
const range = defineModel<RangeKey>('range', { required: true })
const site = defineModel<string>('site', { default: '' })

const options = computed<SegmentOption<RangeKey>[]>(() => RANGE_KEYS.map(k => ({ value: k, label: RANGES[k].label, testid: `range-${k}` })))
const siteOptions = computed(() => (props.sites ?? []).filter(s => s.site !== '_other'))
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
    <SegmentedControl v-model="range" :options="options" label="Zeitraum" class="hidden sm:inline-grid" />
    <div class="sm:hidden">
      <NativeSelect v-model="range" aria-label="Zeitraum" data-testid="range-select">
        <NativeSelectOption v-for="k in RANGE_KEYS" :key="k" :value="k">
          {{ RANGES[k].label }}
        </NativeSelectOption>
      </NativeSelect>
    </div>
    <NativeSelect v-if="!noSites && siteOptions.length > 1" v-model="site" aria-label="Website" data-testid="site-select">
      <NativeSelectOption value="">
        Alle Websites
      </NativeSelectOption>
      <NativeSelectOption v-for="s in siteOptions" :key="s.site" :value="s.site">
        {{ s.label ?? s.site }}
      </NativeSelectOption>
    </NativeSelect>
  </div>
</template>
