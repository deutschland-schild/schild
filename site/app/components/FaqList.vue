<script setup lang="ts">
// Grouped FAQ as native <details> disclosures: works without JavaScript.
// All questions are listed; each answer opens on its own.
// With a single group or without group titles there is no left group column.
export interface FaqItem { q: string, a: string }
export interface FaqGroup { group?: string, items: FaqItem[] }

const props = defineProps<{ groups: FaqGroup[] }>()

const withColumn = computed(() => props.groups.length > 1 && props.groups.every(g => !!g.group))
</script>

<template>
  <div class="grid gap-14">
    <div
      v-for="(g, gi) in groups"
      :key="g.group ?? gi"
      :class="withColumn ? 'grid gap-6 lg:grid-cols-[16rem_1fr]' : 'max-w-4xl'"
    >
      <h3 v-if="withColumn" class="text-lg font-semibold">{{ g.group }}</h3>
      <div>
        <div class="divide-y divide-line border-y border-line">
          <details v-for="item in g.items" :key="item.q" class="group py-1">
            <summary class="flex min-h-12 cursor-pointer list-none items-center justify-between gap-4 py-3 font-medium [&::-webkit-details-marker]:hidden">
              {{ item.q }}
              <svg class="size-4 shrink-0 text-slate transition group-open:rotate-45 motion-reduce:transition-none" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M8 3v10M3 8h10" /></svg>
            </summary>
            <p class="max-w-3xl pb-4 text-sm leading-relaxed text-slate">{{ item.a }}</p>
          </details>
        </div>
      </div>
    </div>
  </div>
</template>
