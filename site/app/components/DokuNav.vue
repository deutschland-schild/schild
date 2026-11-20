<script setup lang="ts">

import type { HubSection } from '~/composables/useHub'

// Section navigation of /doku: overview, the parts of Deutschland-Schild, then "Allgemeines" (system and project),
// each section a collapsible group.
const { sections } = useHub()
const groups = computed(() => [
  { label: '', sections: sections.value.filter(s => !s.general) },
  { label: 'Allgemeines', sections: sections.value.filter(s => s.general) },
])
const route = useRoute()
const current = computed(() => route.path.replace(/\/+$/, ''))

// Collapsed state per section; "Allgemeines" starts collapsed, the section of the current page is always open.
const collapsed = useState<Record<string, boolean>>('doku-nav-collapsed', () => ({}))
const hasCurrent = (s: HubSection) => s.chapters.some(c => c.path === current.value)
const isOpen = (s: HubSection) => hasCurrent(s) || !(collapsed.value[s.id] ?? !!s.general)
function toggle(s: HubSection) {
  collapsed.value[s.id] = isOpen(s)
}
</script>

<template>
  <nav aria-label="Dokumentation" class="text-sm">
    <ul class="mb-6 space-y-0.5">
      <li>
        <NuxtLink to="/doku" class="block rounded-md px-2 py-1.5 transition" :class="current === '/doku' ? 'bg-mist font-semibold text-ink' : 'text-slate hover:text-ink'">Überblick</NuxtLink>
      </li>
      <li>
        <NuxtLink to="/doku/gateway/00-installieren" class="block rounded-md px-2 py-1.5 transition" :class="current === '/doku/gateway/00-installieren' ? 'bg-mist font-semibold text-ink' : 'text-slate hover:text-ink'">Gateway installieren</NuxtLink>
      </li>
    </ul>

    <template v-for="g in groups" :key="g.label">
      <p v-if="g.label" class="border-t border-line px-2 pt-5 pb-1 text-xs font-semibold text-slate">{{ g.label }}</p>
      <div v-for="s in g.sections" :key="s.id" :class="g.label ? 'py-1.5' : 'border-t border-line py-3'">
        <button
          class="flex w-full items-center justify-between gap-2 px-2 py-1 text-left text-xs font-semibold tracking-wide text-ink uppercase"
          :aria-expanded="isOpen(s)"
          @click="toggle(s)"
        >
          <span class="flex items-center gap-2">
            {{ s.label }}
            <StatusBadge v-if="s.status" :status="s.status" short />
          </span>
          <svg
            class="size-3.5 shrink-0 text-slate transition" :class="isOpen(s) ? 'rotate-90' : ''"
            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"
          ><path d="m9 6 6 6-6 6" /></svg>
        </button>
        <ul v-show="isOpen(s)" class="mt-1.5 space-y-px">
          <li v-for="c in s.chapters" :key="c.path">
            <NuxtLink
              :to="c.path" class="flex gap-2 rounded-md border-l-2 px-2 py-1 transition"
              :class="current === c.path ? 'border-ink-800 bg-mist font-semibold text-ink' : 'border-transparent text-slate hover:bg-mist hover:text-ink'"
              :aria-current="current === c.path ? 'page' : undefined"
            >
              <span class="leading-5">{{ c.short }}</span>
            </NuxtLink>
          </li>
        </ul>
      </div>
    </template>
  </nav>
</template>
