<script setup lang="ts">
// Renders ```mermaid blocks from docs/, themed with the brand tokens.
// Normally `svg` is set: the build inlines the pre-rendered SVG (site/diagrams/<hash>.svg, see scripts/diagrams.mjs),
// so the page needs no Mermaid JavaScript at all. Without it (diagram changed, SVG not yet re-rendered) Mermaid is
// loaded and renders in the browser once the diagram comes near the viewport. `?mermaid=live` forces that path;
// scripts/diagrams.mjs uses it to capture the SVGs.
const props = defineProps<{ code: string, svg?: string, diagram?: string }>()
const live = ref('')
const failed = ref(false)
const el = ref<HTMLElement>()
const forceLive = ref(false)
const shown = computed(() => live.value || (forceLive.value ? '' : props.svg ?? ''))
// Natural width of the diagram (Mermaid writes it as max-width). On phones the diagram keeps up to 36rem of it and the
// figure scrolls sideways, instead of shrinking the labels to an unreadable size.
const naturalWidth = computed(() => shown.value.match(/max-width:\s*([\d.]+)px/)?.[1])
let seq = 0

async function render() {
  try {
    const { default: mermaid } = await import('mermaid')
    // Text is measured for the layout: wait for the web fonts.
    await document.fonts.ready
    // Mermaid needs concrete colours; take them from the active brand palette.
    const css = getComputedStyle(document.documentElement)
    const c = (name: string) => css.getPropertyValue(`--color-${name}`).trim()
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: 'base',
      fontFamily: 'Inter Variable, sans-serif',
      flowchart: { curve: 'basis', padding: 14, htmlLabels: true, wrappingWidth: 320, nodeSpacing: 36, rankSpacing: 44 },
      themeVariables: {
        fontSize: '15px',
        primaryColor: '#FFFFFF',
        primaryBorderColor: c('ink'),
        primaryTextColor: c('ink'),
        lineColor: c('slate'),
        secondaryColor: c('signal-tint'),
        tertiaryColor: c('paper'),
        clusterBkg: c('paper'),
        edgeLabelBackground: c('paper'),
      },
    })
    // Stable id per diagram, so captured SVGs (scoped styles use it) don't change between runs.
    const id = props.diagram ? `mmd-${props.diagram}` : `mmd-${Math.random().toString(36).slice(2)}-${seq++}`
    live.value = (await mermaid.render(id, props.code.trim())).svg
  } catch (e) {
    console.error(e)
    failed.value = true
  }
}

onMounted(() => {
  forceLive.value = new URLSearchParams(location.search).get('mermaid') === 'live'
  if (props.svg && !forceLive.value) return
  if (forceLive.value) return render()
  const { stop } = useIntersectionObserver(el, ([entry]) => {
    if (!entry?.isIntersecting) return
    stop()
    render()
  }, { rootMargin: '600px 0px' })
})
</script>

<template>
  <figure ref="el" class="not-prose my-8 overflow-x-auto rounded-card border border-line bg-paper p-5 sm:p-8" :data-diagram="diagram">
    <div v-if="shown" class="mermaid-svg flex justify-center-safe [&_svg]:h-auto [&_svg]:max-w-full" :style="naturalWidth ? { '--mmd-w': `${naturalWidth}px` } : undefined" v-html="shown" />
    <pre v-else-if="failed" class="font-mono text-sm whitespace-pre-wrap text-slate">{{ code }}</pre>
    <div v-else class="h-80 animate-pulse rounded-lg bg-sand" aria-label="Diagramm wird geladen" />
  </figure>
</template>

<style>
/* Last node of a chain (double circle) and decisions get the brand accent. */
.mermaid-svg .node circle, .mermaid-svg .node polygon { fill: var(--color-signal-tint) !important; stroke: var(--color-signal-deep) !important; }
.mermaid-svg .node rect { rx: 10px; ry: 10px; stroke-width: 1.5px; }
.mermaid-svg .edgeLabel { font-size: 13px; color: var(--color-slate); }
@media (max-width: 639px) {
  .mermaid-svg svg { min-width: min(var(--mmd-w, 0px), 36rem); }
}
</style>
