<script setup lang="ts">
// Real screenshots of the gateway dashboard (dashboard), 1440×900: the real UI with its mock data (.example domains,
// the header shows "Testdaten").
// Files: public/img/dashboards/<name>.webp (2160 wide) plus <name>-720/-1100/-1600.webp for smaller screens.
export interface DashboardShot {
  src: string
  title: string
  summary?: string
  text: string
  benefit?: string
  alt: string
  // Label of the window bar when the shot is not a dashboard view (block page, login page): the address a visitor sees.
  frame?: string
}

const WIDTHS = [720, 1100, 1600]
const srcset = (src: string) => [...WIDTHS.map(w => `${src.replace(/\.webp$/, `-${w}.webp`)} ${w}w`), `${src} 2160w`].join(', ')
const SIZES = '(min-width: 1152px) 1086px, (min-width: 640px) calc(100vw - 66px), calc(100vw - 42px)'

const props = defineProps<{ shots: DashboardShot[], label: string, caption?: string, eager?: boolean }>()
const active = ref(0)
const current = computed(() => props.shots[active.value]!)
const frame = computed(() => current.value.frame ?? `Schild Dashboard · ${current.value.title}`)
const uid = useId()

// Phones: keep the active tab visible in the sideways scrolling row (also for the arrow keys).
watch(active, i => nextTick(() => {
  const tab = document.getElementById(`${uid}-tab-${i}`)
  tab?.focus({ preventScroll: true })
  tab?.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'smooth' })
}))
</script>

<template>
  <figure class="min-w-0">
    <!-- Phones: one row of compact tabs that scrolls sideways, so the screenshot stays near the top. -->
    <div role="tablist" :aria-label="label" class="flex gap-2 overflow-x-auto [scrollbar-width:none] max-sm:-mx-5 max-sm:px-5 max-sm:pb-1 sm:grid sm:gap-3" :class="shots.length === 3 ? 'sm:grid-cols-3' : 'sm:grid-cols-2 lg:grid-cols-4'">
      <button
        v-for="(s, i) in shots" :id="`${uid}-tab-${i}`" :key="s.src" role="tab" type="button"
        :aria-selected="active === i" :aria-controls="`${uid}-panel`" :tabindex="active === i ? 0 : -1"
        class="shrink-0 rounded-full border px-3.5 py-2 text-left whitespace-nowrap transition sm:rounded-xl sm:p-4 sm:whitespace-normal"
        :class="active === i ? 'border-ink bg-ink text-white shadow-sm' : 'border-line bg-white text-ink hover:border-ink/40'"
        @click="active = i"
        @keydown.right.prevent="active = (i + 1) % shots.length"
        @keydown.left.prevent="active = (i - 1 + shots.length) % shots.length"
      >
        <span class="block text-sm font-semibold">{{ s.title }}</span>
        <span
          v-if="s.summary"
          class="mt-1 block text-xs leading-snug max-sm:hidden"
          :class="active === i ? 'text-white/80' : 'text-slate'"
        >{{ s.summary }}</span>
      </button>
    </div>

    <div :id="`${uid}-panel`" role="tabpanel" :aria-labelledby="`${uid}-tab-${active}`" class="mt-4 overflow-hidden rounded-xl sm:mt-5 border border-line bg-white shadow-lg">
      <div class="flex items-center justify-between gap-3 border-b border-line bg-mist px-4 py-2.5">
        <div class="flex min-w-0 items-center gap-2">
          <span class="flex items-center gap-1.5" aria-hidden="true">
            <span class="size-2.5 rounded-full bg-line" />
            <span class="size-2.5 rounded-full bg-line" />
            <span class="size-2.5 rounded-full bg-line" />
          </span>
          <span class="ml-2 truncate text-xs font-medium text-slate">{{ frame }}</span>
        </div>
        <a :href="current.src" target="_blank" rel="noopener" class="shrink-0 text-xs font-semibold text-link hover:underline">
          Vollbild <span aria-hidden="true">↗</span>
        </a>
      </div>
      <a :href="current.src" target="_blank" rel="noopener" class="block" title="In voller Größe öffnen">
        <img
          :src="current.src" :srcset="srcset(current.src)" :sizes="SIZES" :alt="current.alt" width="2160" height="1350"
          :loading="eager ? 'eager' : 'lazy'" :fetchpriority="eager ? 'high' : undefined" decoding="async" class="block h-auto w-full"
        >
      </a>
      <div class="grid gap-3 border-t border-line bg-paper px-5 py-4 text-sm sm:grid-cols-2">
        <p class="leading-relaxed text-ink">
          {{ current.text }}
        </p>
        <p v-if="current.benefit" class="leading-relaxed text-slate">
          {{ current.benefit }}
        </p>
      </div>
    </div>

    <figcaption class="mt-3 text-xs text-slate">
      {{ caption ?? 'Echte Screenshots aus dem Gateway-Dashboard mit Testdaten (nur IP-Adressen aus Dokumentationsbereichen).' }}
    </figcaption>
  </figure>
</template>
