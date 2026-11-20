<script setup lang="ts">
import { sourceFile } from '~/utils/hub'
import { ISSUES_URL, sourceUrl } from '~/utils/release'

// One page of the documentation hub: Markdown in the middle, "on this page" right (xl+),
// discussion note with the source file, prev/next in reading order.
const props = defineProps<{ page: any, path: string }>()
const { neighbours } = useHub()
const nav = computed(() => neighbours(props.path))
const toc = computed(() => props.page?.body?.toc?.links ?? [])
const file = computed(() => sourceFile(props.path))
// Pages of a planned part (labs, relays) say so before the text, so the target picture is not read as a product.
const planned = computed(() => nav.value.section?.status === 'planned' ? nav.value.section : undefined)

const activeId = ref('')
onMounted(() => {
  const obs = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) activeId.value = e.target.id
  }, { rootMargin: '-80px 0px -70% 0px' })
  document.querySelectorAll('article h2[id]').forEach(h => obs.observe(h))
  onBeforeUnmount(() => obs.disconnect())
})
</script>

<template>
  <div class="flex gap-10 py-8 lg:py-10">
    <article class="min-w-0 flex-1">
      <nav class="flex flex-wrap items-center gap-x-2 text-sm text-slate" aria-label="Brotkrumen">
        <NuxtLink to="/doku" class="hover:text-ink">Dokumentation</NuxtLink>
        <span aria-hidden="true">/</span>
        <NuxtLink v-if="nav.section" :to="`/doku#${nav.section.id}`" class="hover:text-ink">{{ nav.section.label }}</NuxtLink>
      </nav>

      <aside v-if="planned" class="mt-4 max-w-[75ch] rounded-lg border border-mist-line bg-mist px-5 py-4 text-sm leading-relaxed text-slate" aria-label="Geplant">
        <p class="flex items-center gap-2 font-semibold text-ink"><StatusBadge status="planned" /> {{ planned.label }} gibt es noch nicht im Betrieb.</p>
        <p class="mt-2">
          Diese Seite beschreibt das Zielbild. Ein erster Prototyp läuft bisher nur im Testlabor.
          Das Schild Gateway braucht keine Labs und Relays, damit kannst du heute schon loslegen:
          <NuxtLink to="/doku/gateway/01-funktionen" class="font-semibold text-link hover:underline">Funktionen des Gateways →</NuxtLink>
        </p>
      </aside>

      <ContentRenderer :value="page" class="doku-prose prose prose-slate mt-4 max-w-none" />

      <PersonaQuote v-if="page.quote" class="mt-8 max-w-[75ch]" :persona="page" :link="false" :outdent="false" />

      <aside class="mt-14 max-w-[75ch] rounded-lg border border-line bg-paper px-5 py-4 text-sm leading-relaxed text-slate" aria-label="Diskutieren">
        <p class="font-semibold text-ink">Diskutieren</p>
        <p class="mt-1">
          Per <a :href="ISSUES_URL" target="_blank" rel="noopener" class="font-semibold text-link hover:underline">Issue</a> oder Pull Request auf GitHub.
          <span v-if="file" class="mt-1 block">Datei: <a :href="sourceUrl(file)" target="_blank" rel="noopener" class="hover:underline"><code class="code [overflow-wrap:anywhere]">{{ file }}</code></a></span>
        </p>
      </aside>

      <nav class="mt-8 grid max-w-[75ch] gap-4 sm:grid-cols-2" aria-label="Kapitel blättern">
        <NuxtLink v-if="nav.prev" :to="nav.prev.path" class="rounded-lg border border-line p-4 transition hover:border-ink">
          <span class="text-sm text-slate">← Zurück</span>
          <p class="font-semibold">{{ nav.prev.short }}</p>
        </NuxtLink>
        <span v-else />
        <NuxtLink v-if="nav.next" :to="nav.next.path" class="rounded-lg border border-line p-4 text-right transition hover:border-ink">
          <span class="text-sm text-slate">Weiter →</span>
          <p class="font-semibold">{{ nav.next.short }}</p>
        </NuxtLink>
      </nav>
    </article>

    <aside class="hidden w-56 shrink-0 xl:block">
      <div v-if="toc.length" class="sticky top-[calc(var(--doku-header,3.5rem)+1rem)] max-h-[calc(100vh-var(--doku-header,3.5rem)-2rem)] overflow-y-auto overscroll-contain">
        <p class="mb-3 text-xs font-semibold tracking-wide text-ink uppercase">Auf dieser Seite</p>
        <ul class="space-y-0.5 border-l border-line text-sm">
          <li v-for="l in toc" :key="l.id">
            <a :href="`#${l.id}`" class="-ml-px block rounded-r-md border-l-2 py-1 pr-2 pl-3 leading-snug transition" :class="activeId === l.id ? 'border-ink-800 bg-mist font-semibold text-ink' : 'border-transparent text-slate hover:bg-mist hover:text-ink'">{{ l.text }}</a>
          </li>
        </ul>
      </div>
    </aside>
  </div>
</template>
