<script setup lang="ts">
import { REPO_URL } from '~/utils/release'

const open = ref(false)
const menu = ref<string | null>(null)
const route = useRoute()
watch(() => route.fullPath, () => { open.value = false; menu.value = null })
onKeyStroke('Escape', () => { open.value = false; menu.value = null })
// No border: at the top the bar merges with the light blue hero; once the page moves it turns white with a shadow.
const { y } = useWindowScroll()
const nav = ref<HTMLElement>()
onClickOutside(nav, () => (menu.value = null))

// Start page chapters (hash links) and the project pages. Groups open a small menu.
// Hash links stay plain <a>: NuxtLink marks every hash link on the same page with aria-current="page".
// Top-level page links (none at the moment) are NuxtLinks with an active state.
// Inside the documentation the install button stays in the documentation.
const installTo = computed(() => route.path.startsWith('/doku') ? '/doku/gateway/00-installieren' : '/#installieren')

type NavLink = { to: string, label: string, text?: string }
type NavGroup = { label: string, to?: string, items?: NavLink[] }
const groups: NavGroup[] = [
  {
    label: 'Gateway',
    items: [
      { to: '/#funktionen', label: 'Funktionen', text: 'Was das Gateway mitbringt' },
      { to: '/#dashboard', label: 'Dashboard', text: 'Ansichten mit Testdaten' },
      { to: '/#installieren', label: 'Installieren', text: 'Docker oder Binary, als dein Caddy oder dahinter' },
      { to: '/#faq', label: 'FAQ', text: 'Fragen und Antworten' },
      { to: '/api', label: 'Gateway API', text: 'Referenz für Agenten und Skripte' },
    ],
  },
  {
    label: 'Projekt',
    items: [
      { to: '/#vergleich', label: 'Vergleich', text: 'fail2ban, CrowdSec, Cloudflare' },
      { to: '/netz', label: 'Das Schild-Netz', text: 'Labs und Relays, geplant' },
      { to: '/netz#fahrplan', label: 'Fahrplan', text: 'Klein anfangen, dann wachsen' },
    ],
  },
]
const isHash = (to: string) => to.includes('#')
// Resolved in script: resolveComponent() inside the template is not in scope and rendered a dead <nuxtlink> tag.
const NuxtLink = resolveComponent('NuxtLink')
const linkActive = (to: string) => !isHash(to) && route.path === to
const groupActive = (g: NavGroup) => !!g.items?.some(l => !isHash(l.to) && route.path === l.to)
const toggle = (label: string) => (menu.value = menu.value === label ? null : label)
</script>

<template>
  <header class="sticky top-0 z-40 text-ink backdrop-blur transition-[background-color,box-shadow] duration-200" :class="y > 0 ? 'bg-white/95 shadow-md' : 'bg-mist/90'">
    <div class="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-5 sm:px-8">
      <div class="flex shrink-0 items-center gap-2.5">
        <BrandLogo />
        <AlphaBadge />
      </div>
      <nav ref="nav" class="flex items-center gap-1 text-sm" aria-label="Hauptnavigation">
        <template v-for="g in groups" :key="g.label">
          <component
            :is="isHash(g.to!) ? 'a' : NuxtLink" v-if="g.to" v-bind="isHash(g.to!) ? { href: g.to } : { to: g.to }"
            class="rounded-lg px-3 py-2 transition max-lg:hidden" :class="linkActive(g.to!) ? 'font-semibold text-ink' : 'text-ink hover:bg-ink/5'"
          >
            {{ g.label }}
          </component>
          <div v-else class="relative max-lg:hidden">
            <button
              class="flex items-center gap-1 rounded-lg px-3 py-2 transition hover:bg-ink/5" :class="menu === g.label || groupActive(g) ? 'font-semibold text-ink' : 'text-ink'"
              :aria-expanded="menu === g.label" :aria-controls="`menu-${g.label}`" @click="toggle(g.label)"
            >
              {{ g.label }}
              <svg class="size-3.5 transition" :class="menu === g.label ? 'rotate-180' : ''" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="m6 9 6 6 6-6" /></svg>
            </button>
            <ul v-if="menu === g.label" :id="`menu-${g.label}`" class="absolute top-full left-0 mt-2 w-72 rounded-xl border border-line bg-white p-2 shadow-lg">
              <li v-for="l in g.items" :key="l.to">
                <component :is="isHash(l.to) ? 'a' : NuxtLink" v-bind="isHash(l.to) ? { href: l.to } : { to: l.to }" class="block rounded-lg px-3 py-2.5 transition hover:bg-mist" @click="menu = null">
                  <span class="block font-semibold text-ink">{{ l.label }}</span>
                  <span class="mt-0.5 block text-xs text-slate">{{ l.text }}</span>
                </component>
              </li>
            </ul>
          </div>
        </template>
        <NuxtLink to="/ueber" class="rounded-lg px-3 py-2 transition max-lg:hidden" :class="route.path === '/ueber' ? 'font-semibold text-ink' : 'text-ink hover:bg-ink/5'">Über</NuxtLink>
        <NuxtLink to="/doku" class="rounded-lg px-3 py-2 transition max-lg:hidden" :class="route.path.startsWith('/doku') ? 'font-semibold text-ink' : 'text-ink hover:bg-ink/5'">Dokumentation</NuxtLink>
        <a :href="REPO_URL" target="_blank" rel="noopener" class="rounded-lg p-2 text-ink transition hover:bg-ink/5 max-[440px]:hidden" aria-label="Schild auf GitHub"><svg class="size-5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2.15c-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.78 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.38-5.25 5.67.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" /></svg></a>
        <!-- Ghost style: the page's own primary action in the hero stays the only filled button. -->
        <NuxtLink :to="installTo" class="btn-ghost ml-2 px-4 py-2 text-sm max-sm:hidden">Jetzt installieren</NuxtLink>
        <button class="rounded-lg p-2 lg:hidden" :aria-expanded="open" aria-controls="mobil-menue" aria-label="Menü" @click="open = !open">
          <svg class="size-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path :d="open ? 'M6 6l12 12M18 6 6 18' : 'M4 7h16M4 12h16M4 17h16'" /></svg>
        </button>
      </nav>
    </div>
    <nav v-if="open" id="mobil-menue" class="max-h-[calc(100svh-4rem)] overflow-y-auto border-t border-line px-5 py-4 lg:hidden" aria-label="Hauptnavigation mobil">
      <div class="grid gap-x-6 gap-y-5 sm:grid-cols-2">
        <div>
          <component :is="isHash(g.to!) ? 'a' : NuxtLink" v-for="g in groups.filter(x => x.to)" :key="g.label" v-bind="isHash(g.to!) ? { href: g.to } : { to: g.to }" class="block rounded-lg px-2 py-2 text-base font-semibold" :class="linkActive(g.to!) ? 'text-signal-deep' : ''" @click="open = false">{{ g.label }}</component>
          <NuxtLink to="/ueber" class="block rounded-lg px-2 py-2 text-base font-semibold" @click="open = false">Über</NuxtLink>
          <NuxtLink to="/doku" class="block rounded-lg px-2 py-2 text-base font-semibold" @click="open = false">Dokumentation</NuxtLink>
          <a :href="REPO_URL" target="_blank" rel="noopener" class="block rounded-lg px-2 py-2 text-base font-semibold">GitHub</a>
        </div>
        <div v-for="g in groups.filter(x => x.items)" :key="g.label">
          <p class="px-2 text-xs font-semibold tracking-widest text-slate uppercase">{{ g.label }}</p>
          <component :is="isHash(l.to) ? 'a' : NuxtLink" v-for="l in g.items" :key="l.to" v-bind="isHash(l.to) ? { href: l.to } : { to: l.to }" class="block rounded-lg px-2 py-2 text-base font-semibold" @click="open = false">{{ l.label }}</component>
        </div>
      </div>
      <NuxtLink :to="installTo" class="btn-ghost mt-4 w-full justify-center" @click="open = false">Jetzt installieren</NuxtLink>
    </nav>
  </header>
</template>
