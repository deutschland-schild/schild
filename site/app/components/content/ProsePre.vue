<script setup lang="ts">
const props = defineProps<{ code?: string, language?: string | null, filename?: string | null, highlights?: number[], meta?: string | null, class?: string | null, svg?: string, diagram?: string }>()
const copied = ref(false)

async function copy() {
  await navigator.clipboard.writeText(props.code ?? '')
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}
</script>

<template>
  <MermaidDiagram v-if="language === 'mermaid'" :code="code ?? ''" :svg="svg" :diagram="diagram" />
  <div v-else class="not-prose group relative my-6 codeblock">
    <div class="codeblock-title flex items-center justify-between gap-3">
      <span>{{ filename || language || 'text' }}</span>
      <button class="rounded-md border border-line bg-white px-2 py-0.5 text-[11px] font-semibold text-ink" @click="copy">{{ copied ? 'Kopiert' : 'Kopieren' }}</button>
    </div>
    <pre :class="props.class"><slot /></pre>
  </div>
</template>
