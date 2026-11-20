<script setup lang="ts">
// Docs layout for /doku: slim header, sticky section navigation left (drawer on mobile), content right.
// Pages add their own "on this page" column.
const navOpen = useState('doku-nav-open', () => false)
const searchOpen = useState('doku-search-open', () => false)
const route = useRoute()
watch(() => route.fullPath, () => (navOpen.value = false))
onKeyStroke('Escape', () => (navOpen.value = false))

// Keep the active chapter visible in the (independently scrolling) sidebar.
const sidebar = ref<HTMLElement>()
function revealActive() {
  const el = sidebar.value
  const link = el?.querySelector<HTMLElement>('[aria-current="page"]')
  if (!el || !link) return
  const top = link.getBoundingClientRect().top - el.getBoundingClientRect().top
  if (top < 0 || top > el.clientHeight - 40) el.scrollTop += top - el.clientHeight / 3
}
onMounted(revealActive)

// The sticky header height feeds the sticky sidebar,
// the page TOC (HubChapter) and the anchor offset via --doku-header.
const header = ref<HTMLElement>()
useResizeObserver(header, ([entry]) => {
  const h = Math.ceil(entry!.borderBoxSize?.[0]?.blockSize ?? entry!.contentRect.height)
  document.documentElement.style.setProperty('--doku-header', `${h}px`)
  document.documentElement.style.scrollPaddingTop = `${h + 16}px`
})
onBeforeUnmount(() => {
  document.documentElement.style.removeProperty('--doku-header')
  document.documentElement.style.scrollPaddingTop = ''
})
watch(() => route.path, () => nextTick(revealActive))
</script>

<template>
  <div class="flex min-h-screen flex-col bg-white">
    <a href="#inhalt" class="skip-link">Zum Inhalt springen</a>

    <header ref="header" class="sticky top-0 z-40 border-b border-line bg-white/95 backdrop-blur">
      <div class="mx-auto flex h-14 max-w-[90rem] items-center gap-3 px-4 sm:px-6 lg:px-8">
        <button
          class="-ml-2 rounded-lg p-2 text-ink lg:hidden" :aria-expanded="navOpen" aria-controls="doku-drawer"
          aria-label="Kapitel anzeigen" @click="navOpen = !navOpen"
        >
          <svg class="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" /></svg>
        </button>
        <NuxtLink to="/doku" class="flex min-w-0 items-center gap-2.5" aria-label="Dokumentation – Überblick">
          <BrandMark class="size-7 shrink-0" />
          <span class="truncate text-sm font-bold tracking-tight text-ink max-sm:hidden">Deutschland-Schild</span>
          <AlphaBadge />
          <span class="h-4 w-px bg-line max-sm:hidden" aria-hidden="true" />
          <span class="text-sm font-semibold text-slate">Dokumentation</span>
        </NuxtLink>
        <div class="ml-auto flex items-center gap-2">
          <button
            class="flex items-center gap-2 rounded-lg border border-line px-2.5 py-1.5 text-sm text-slate transition hover:border-ink hover:text-ink"
            aria-label="Dokumentation durchsuchen" @click="searchOpen = true"
          >
            <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
            <span class="max-md:hidden">Suchen</span>
            <kbd class="rounded border border-line px-1 font-mono text-[11px] max-md:hidden">/</kbd>
          </button>
          <NuxtLink to="/api" class="rounded-lg px-2.5 py-1.5 text-sm font-semibold text-ink hover:bg-mist">API</NuxtLink>
          <NuxtLink to="/" class="rounded-lg px-2.5 py-1.5 text-sm font-semibold text-ink hover:bg-mist">
            <span aria-hidden="true">←</span> <span class="max-sm:hidden">Zur </span>Website
          </NuxtLink>
        </div>
      </div>
    </header>

    <div class="mx-auto flex w-full max-w-[90rem] flex-1 gap-10 px-4 sm:px-6 lg:px-8">
      <aside class="hidden w-64 shrink-0 lg:block">
        <div ref="sidebar" class="sticky top-[var(--doku-header,3.5rem)] h-[calc(100vh-var(--doku-header,3.5rem))] overflow-y-auto overscroll-contain py-8 pr-3">
          <DokuNav />
        </div>
      </aside>
      <main id="inhalt" class="min-w-0 flex-1" tabindex="-1"><slot /></main>
    </div>

    <footer class="border-t border-line text-sm text-slate">
      <div class="mx-auto flex max-w-[90rem] flex-wrap items-center gap-x-5 gap-y-2 px-4 py-6 sm:px-6 lg:px-8">
        <span>Deutschland-Schild · Dokumentation (Entwurf)</span>
        <NuxtLink to="/impressum" class="ml-auto hover:text-ink">Impressum</NuxtLink>
        <NuxtLink to="/datenschutz" class="hover:text-ink">Datenschutz</NuxtLink>
      </div>
    </footer>

    <!-- Mobile drawer with the same navigation -->
    <div v-if="navOpen" class="fixed inset-0 z-50 lg:hidden">
      <div class="absolute inset-0 bg-ink/40" aria-hidden="true" @click="navOpen = false" />
      <div id="doku-drawer" class="absolute inset-y-0 left-0 flex w-[min(20rem,85vw)] flex-col bg-white shadow-xl" role="dialog" aria-modal="true" aria-label="Kapitel">
        <div class="flex h-14 shrink-0 items-center justify-between border-b border-line px-4">
          <span class="text-sm font-semibold">Kapitel</span>
          <button class="rounded-lg p-2" aria-label="Schließen" @click="navOpen = false">
            <svg class="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" /></svg>
          </button>
        </div>
        <div class="flex-1 overflow-y-auto overscroll-contain px-4 py-6"><DokuNav /></div>
      </div>
    </div>

    <DokuSearch v-model="searchOpen" />
  </div>
</template>
