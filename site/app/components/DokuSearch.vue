<script setup lang="ts">
// "/" or Cmd/Ctrl+K: client-side search over titles, headings and text of all /doku pages (static-friendly).

const open = defineModel<boolean>({ default: false })
const query = ref('')
const active = ref(0)
const input = ref<HTMLInputElement>()
const router = useRouter()

// Prebuilt index (server/routes/doku-search.json.ts), loaded on first open.
type Section = { id: string, title: string, titles: string[], content: string }
const { data: sections, execute } = useLazyAsyncData('doku-search', () => $fetch<Section[]>('/doku-search.json'), { immediate: false, server: false })

watch(open, async (v) => {
  if (!v) return
  query.value = ''
  active.value = 0
  if (!sections.value) execute()
  await nextTick()
  input.value?.focus()
})

const results = computed(() => {
  const terms = query.value.toLowerCase().split(/\s+/).filter(Boolean)
  if (!terms.length || !sections.value) return []
  return sections.value
    .map((s) => {
      const content = s.content
      const titles = s.titles.join(' ').toLowerCase()
      const title = s.title.toLowerCase()
      const hay = `${titles} ${title} ${content.toLowerCase()}`
      if (!terms.every(t => hay.includes(t))) return null
      const score = terms.reduce((n, t) => n + (title.includes(t) ? 10 : 0) + (titles.includes(t) ? 3 : 0), 0)
      const i = content.toLowerCase().indexOf(terms[0]!)
      const snippet = i < 0 ? content.slice(0, 120) : `${i > 40 ? '…' : ''}${content.slice(Math.max(0, i - 40), i + 100)}…`
      return { ...s, score, snippet }
    })
    .filter(r => r !== null)
    .sort((a, b) => b.score - a.score)
    .slice(0, 12)
})
watch(query, () => (active.value = 0))

function go(id: string) {
  open.value = false
  router.push(id)
}

function onKey(e: KeyboardEvent) {
  if (e.key === 'ArrowDown') { active.value = Math.min(active.value + 1, results.value.length - 1); e.preventDefault() }
  if (e.key === 'ArrowUp') { active.value = Math.max(active.value - 1, 0); e.preventDefault() }
  if (e.key === 'Enter' && results.value[active.value]) go(results.value[active.value]!.id)
  if (e.key === 'Escape') open.value = false
}

if (import.meta.client) {
  useEventListener(window, 'keydown', (e: KeyboardEvent) => {
    const typing = /INPUT|TEXTAREA|SELECT/.test((e.target as HTMLElement)?.tagName)
    if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !typing)) {
      e.preventDefault()
      open.value = true
    }
  })
}

function highlight(text: string) {
  const esc = text.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)
  const terms = query.value.split(/\s+/).filter(Boolean).map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  return terms.length ? esc.replace(new RegExp(`(${terms.join('|')})`, 'gi'), '<mark class="rounded-sm bg-signal-tint text-signal-deep">$1</mark>') : esc
}
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="fixed inset-0 z-50 flex items-start justify-center bg-ink/40 p-4 pt-[10vh]" @click.self="open = false">
      <div class="w-full max-w-2xl overflow-hidden rounded-xl border border-line bg-white shadow-2xl" role="dialog" aria-modal="true" aria-label="Dokumentation durchsuchen">
        <div class="flex items-center gap-3 border-b border-line px-4">
          <svg class="size-5 text-slate" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
          <input ref="input" v-model="query" placeholder="Dokumentation durchsuchen …" aria-label="Suchbegriff" class="h-13 flex-1 bg-transparent text-base outline-none focus-visible:shadow-none focus-visible:outline-none" @keydown="onKey">
          <button class="rounded border border-line px-1.5 font-mono text-xs text-slate" @click="open = false">Esc</button>
        </div>
        <ul v-if="results.length" class="max-h-[60vh] overflow-y-auto p-2">
          <li v-for="(r, i) in results" :key="r.id">
            <button class="w-full rounded-lg px-3 py-2.5 text-left" :class="i === active ? 'bg-paper' : ''" @mouseenter="active = i" @click="go(r.id)">
              <p class="truncate text-xs text-slate">{{ r.titles.join(' › ') }}</p>
              <p class="mt-0.5 font-semibold" v-html="highlight(r.title)" />
              <p class="mt-1 line-clamp-2 text-sm text-slate" v-html="highlight(r.snippet)" />
            </button>
          </li>
        </ul>
        <p v-else-if="query && sections" class="px-6 py-10 text-center text-slate">Nichts gefunden für „{{ query }}“.</p>
        <p v-else-if="query" class="px-6 py-10 text-center text-slate">Suche wird geladen …</p>
        <p v-else class="px-6 py-10 text-center text-sm text-slate">Suche nach Begriffen wie <em>Beirat</em>, <em>Rollback</em> oder <em>Poisoning</em>.</p>
      </div>
    </div>
  </Teleport>
</template>
