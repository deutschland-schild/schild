<script setup lang="ts">
// Markdown tables in the docs: scroll horizontally inside the content column instead of overflowing it.
// Wide tables get a minimum width estimated from their content (data-min-rem, set in nuxt.config.ts),
// so cells don't become tall narrow strips.
const props = defineProps<{ dataMinRem?: number | string }>()
const minWidth = computed(() => Number(props.dataMinRem) ? `${props.dataMinRem}rem` : undefined)
</script>

<template>
  <div class="doku-table not-prose my-6 overflow-x-auto rounded-lg border border-line" tabindex="0" role="region" aria-label="Tabelle (horizontal scrollbar)">
    <table :style="{ minWidth }"><slot /></table>
  </div>
</template>
