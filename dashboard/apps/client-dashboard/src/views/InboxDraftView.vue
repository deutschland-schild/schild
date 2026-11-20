<script setup lang="ts">
import type { InboxItem, InboxKind } from '@/lib/inbox-draft'
import { Button, Input, NativeSelect, NativeSelectOption, PageHeader, StatusDot, StatusPill, Tag, toast } from '@schild/ui'
import { ArrowRight, ChevronDown, Globe, Inbox, Server, ShieldAlert, ShieldCheck, TriangleAlert } from '@lucide/vue'
import { computed, nextTick, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useOverview } from '@/api/queries'
import { useWebsites } from '@/api/websites'
import ServersCard from '@/components/ServersCard.vue'
import WebsiteCard from '@/components/websites/WebsiteCard.vue'
import { draftNav, multiInstance, openFor, SIDEBAR_SITES_MAX, withDemoSites } from '@/lib/draft-nav'
import { DEMO_SITES, DRAFT_SITES, inbox, manyDemo } from '@/lib/inbox-draft'
import { websitePath } from '@/lib/nav'
import { STATUS, websiteName } from '@/lib/websites'

/**
 * DRAFT, mock builds only: the start page as an inbox (initiator, 2026-11-03). Every item has one default
 * action; "Erweitert" changes it where there is a choice. Nothing here is a contract.
 *
 * Many websites and items: the inbox shows the most urgent first, PAGE at a time, and a website select
 * once there are more than PAGE items; the websites become a searchable list from SIDEBAR_SITES_MAX on.
 */
const PAGE = 8

const KIND: Record<InboxKind, { icon: typeof Inbox, tone: string, rank: number }> = {
  server: { icon: Server, tone: 'text-status-warning', rank: 0 },
  false_positive: { icon: TriangleAlert, tone: 'text-status-warning', rank: 1 },
  domain: { icon: Globe, tone: 'text-muted-foreground', rank: 2 },
}

// "Erweitert": open per item; for a new domain another website than the suggested one.
const advanced = reactive<Record<string, boolean>>({})
const target = reactive<Record<string, string>>({})
const targetOf = (it: InboxItem) => target[it.id] ?? it.suggest ?? ''
const domainOf = (it: InboxItem) => it.title.split(': ')[1] ?? ''

function remove(it: InboxItem, message: string) {
  const at = inbox.items.indexOf(it)
  inbox.items.splice(at, 1)
  toast.success(message, { action: { label: 'Rückgängig', onClick: () => inbox.items.splice(at, 0, it) } })
}

// Website filter, kept in the URL (?website=) so a website can link to its own open items.
const route = useRoute()
const router = useRouter()
const siteFilter = computed({
  get: () => typeof route.query.website === 'string' ? route.query.website : '',
  set: v => void router.replace({ query: { ...route.query, website: v || undefined } }),
})
const sorted = computed(() => [...inbox.items].sort((a, b) => KIND[a.kind].rank - KIND[b.kind].rank))
const filtered = computed(() => siteFilter.value ? sorted.value.filter(i => i.site === siteFilter.value || (i.kind === 'domain' && i.suggest === siteFilter.value)) : sorted.value)
const shownCount = ref(PAGE)
watch(siteFilter, () => (shownCount.value = PAGE))
const shown = computed(() => filtered.value.slice(0, shownCount.value))
const sitesWithItems = computed(() => [...new Set(inbox.items.map(i => i.site || i.suggest || '').filter(Boolean))].sort())

const news = [
  { id: 'n1', icon: ShieldAlert, title: 'Welle abgewehrt auf verein.example', text: '1.240 versuchte Anmeldungen in 20 Minuten, alle gestoppt.', to: websitePath('verein.example', 'events'), when: 'vor 2 Stunden' },
  { id: 'n2', icon: Globe, title: 'Versuchter Dateizugriff auf 3 Websites', text: 'Die Adresse ist für alle Websites auf diesem Server gesperrt.', to: '/incidents', when: 'vor 6 Stunden' },
]

const websitesQ = useWebsites()
const list = computed(() => withDemoSites(websitesQ.data.value?.websites ?? []))
const many = computed(() => list.value.length > SIDEBAR_SITES_MAX)
// Many websites: a list with search, the ones that need a look first.
const query = ref('')
const siteRank = (id: string, status: string) => (status === 'disrupted' ? 0 : status === 'attention' ? 1 : 2) * 1000 - openFor(id)
const listed = computed(() => {
  const q = query.value.trim().toLowerCase()
  return list.value
    .filter(w => !q || [websiteName(w), w.id, ...w.hosts].some(t => t.toLowerCase().includes(q)))
    .sort((a, b) => siteRank(a.id, a.status) - siteRank(b.id, b.status) || a.id.localeCompare(b.id))
})
const sitesShown = ref(12)
const siteOptions = computed(() => manyDemo.value ? [...DRAFT_SITES, ...DEMO_SITES] : DRAFT_SITES)

const overview = useOverview()
// Opening the draft switches the draft sidebar on; the button at the top switches it off again.
draftNav.value = true

// "Alle N Websites" in the sidebar links to #websites.
const sitesSection = ref<HTMLElement>()
watch(() => route.hash, async (h) => {
  if (h !== '#websites') return
  await nextTick()
  sitesSection.value?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}, { immediate: true })
</script>

<template>
  <div class="max-w-5xl">
    <PageHeader title="Übersicht" description="Was auf dich wartet, was passiert ist und wie es deinen Websites geht.">
      <template #eyebrow>
        Entwurf · nur im Mock
      </template>
      <template #actions>
        <Button v-if="draftNav" size="sm" variant="ghost" @click="manyDemo = !manyDemo">
          {{ manyDemo ? 'Nur 4 Websites' : 'Viele Websites simulieren' }}
        </Button>
        <Button v-if="draftNav" size="sm" variant="ghost" @click="multiInstance = !multiInstance">
          {{ multiInstance ? 'Nur eine Instanz' : 'Mehrere Instanzen simulieren' }}
        </Button>
        <Button size="sm" variant="outline" @click="draftNav = !draftNav">
          {{ draftNav ? 'Alte Seitenleiste zeigen' : 'Neue Seitenleiste zeigen' }}
        </Button>
      </template>
    </PageHeader>

    <div class="mb-6 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border bg-card px-4 py-3 text-sm">
      <StatusPill tone="success" size="sm">
        Grundschutz aktiv
      </StatusPill>
      <span class="min-w-0 flex-1 basis-56 text-muted-foreground">
        {{ list.length }} Websites. Heute 312 Angriffsversuche gestoppt.
      </span>
      <Button as-child variant="link" size="sm" class="h-auto p-0">
        <RouterLink to="/settings">
          Details
          <ArrowRight aria-hidden="true" />
        </RouterLink>
      </Button>
    </div>

    <section aria-labelledby="inbox-title" class="mb-8">
      <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 id="inbox-title" class="flex items-center gap-2 text-base font-semibold">
          Zu entscheiden
          <Tag v-if="inbox.items.length" class="rounded-md bg-secondary text-secondary-foreground">
            {{ inbox.items.length }}
          </Tag>
        </h2>
        <!-- Only when the list gets long: a plain select box, no chips. -->
        <NativeSelect v-if="inbox.items.length > PAGE || siteFilter" v-model="siteFilter" aria-label="Nach Website filtern" class="w-56">
          <NativeSelectOption value="">
            Alle Websites
          </NativeSelectOption>
          <NativeSelectOption v-for="s in sitesWithItems" :key="s" :value="s">
            {{ s }}
          </NativeSelectOption>
        </NativeSelect>
      </div>

      <div v-if="!filtered.length" class="flex items-center gap-3 rounded-xl border bg-card px-4 py-5 text-sm text-muted-foreground">
        <ShieldCheck class="size-5 text-status-success" aria-hidden="true" />
        Nichts zu tun{{ siteFilter ? ` für ${siteFilter}` : '' }}. Grundschutz aktiv.
      </div>

      <template v-else>
        <ul class="divide-y rounded-xl border bg-card">
          <li v-for="it in shown" :key="it.id" class="px-4 py-3">
            <div class="flex flex-wrap items-start gap-x-3 gap-y-2">
              <component :is="KIND[it.kind].icon" class="mt-0.5 size-4 shrink-0" :class="KIND[it.kind].tone" aria-hidden="true" />
              <div class="min-w-0 flex-1 basis-72">
                <p class="text-sm font-medium">
                  {{ it.title }}
                  <span v-if="it.site" class="font-normal text-muted-foreground">· {{ it.site }}</span>
                </p>
                <p class="text-sm text-muted-foreground">
                  {{ it.text }}
                </p>
                <button
                  v-if="it.kind === 'domain'"
                  type="button"
                  class="mt-1 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                  :aria-expanded="!!advanced[it.id]"
                  @click="advanced[it.id] = !advanced[it.id]"
                >
                  <ChevronDown class="size-3.5 transition-transform" :class="advanced[it.id] ? '' : '-rotate-90'" aria-hidden="true" />
                  Erweitert
                </button>
              </div>
              <div class="ml-7 flex shrink-0 items-center gap-1 sm:ml-0">
                <template v-if="it.kind === 'false_positive'">
                  <Button size="sm" variant="ghost" @click="remove(it, 'Markiert als echter Angriffsversuch.')">
                    Kein Fehlalarm
                  </Button>
                  <Button size="sm" @click="remove(it, `Ausnahme für ${it.site} angelegt.`)">
                    Ausnahme anlegen
                  </Button>
                </template>
                <template v-else-if="it.kind === 'domain'">
                  <Button size="sm" variant="ghost" @click="remove(it, `${domainOf(it)} wird weiter abgewiesen.`)">
                    Abweisen
                  </Button>
                  <Button size="sm" @click="remove(it, `${domainOf(it)} gehört jetzt zu ${targetOf(it)}.`)">
                    Zu {{ targetOf(it) }}
                  </Button>
                </template>
                <Button v-else as-child size="sm" variant="outline">
                  <RouterLink to="/server/check">
                    Ansehen
                  </RouterLink>
                </Button>
              </div>
            </div>

            <!-- Erweitert: another website for the domain -->
            <div v-if="advanced[it.id] && it.kind === 'domain'" class="mt-3 ml-7 flex flex-wrap items-center gap-2 rounded-lg bg-muted/40 p-3 text-sm">
              <label :for="`target-${it.id}`">Andere Website:</label>
              <NativeSelect :id="`target-${it.id}`" :model-value="targetOf(it)" class="w-56" @update:model-value="v => (target[it.id] = String(v))">
                <NativeSelectOption v-for="s in siteOptions" :key="s" :value="s">
                  {{ s }}
                </NativeSelectOption>
              </NativeSelect>
            </div>
          </li>
        </ul>
        <div v-if="filtered.length > shown.length" class="mt-2 flex items-center gap-3 text-sm text-muted-foreground">
          <Button size="sm" variant="outline" @click="shownCount += PAGE">
            Weitere {{ Math.min(PAGE, filtered.length - shown.length) }} anzeigen
          </Button>
          <span>{{ shown.length }} von {{ filtered.length }}</span>
        </div>
      </template>
    </section>

    <section aria-labelledby="news-title" class="mb-8">
      <h2 id="news-title" class="mb-3 text-base font-semibold">
        Was passiert ist
      </h2>
      <ul class="divide-y rounded-xl border bg-card">
        <li v-for="n in news" :key="n.id">
          <RouterLink :to="n.to" class="flex items-start gap-3 px-4 py-3 hover:bg-muted/40">
            <component :is="n.icon" class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <span class="min-w-0 flex-1 text-sm">
              <span class="font-medium">{{ n.title }}</span>
              <span class="block text-muted-foreground">{{ n.text }}</span>
            </span>
            <span class="shrink-0 text-xs text-muted-foreground">{{ n.when }}</span>
          </RouterLink>
        </li>
      </ul>
    </section>

    <section id="websites" ref="sitesSection" aria-labelledby="sites-title" class="scroll-mt-16">
      <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 id="sites-title" class="text-base font-semibold">
          Websites <span class="font-normal text-muted-foreground">· {{ list.length }}</span>
        </h2>
        <Input v-if="many" v-model="query" type="search" placeholder="Website suchen …" aria-label="Websites suchen" class="w-56" />
      </div>

      <!-- Few websites: cards. -->
      <div v-if="!many" class="grid gap-4 md:grid-cols-2">
        <div v-for="w in list" :key="w.id" class="relative">
          <Tag v-if="openFor(w.id)" class="absolute top-3 right-3 z-10 rounded-md bg-secondary text-secondary-foreground">
            {{ openFor(w.id) }} offen
          </Tag>
          <WebsiteCard :website="w" />
        </div>
      </div>

      <!-- Many websites: one line each, the ones that need a look first. -->
      <template v-else>
        <ul class="divide-y rounded-xl border bg-card">
          <li v-for="w in listed.slice(0, sitesShown)" :key="w.id">
            <RouterLink :to="websitePath(w.id)" class="flex items-center gap-3 px-4 py-2.5 text-sm hover:bg-muted/40">
              <StatusDot :tone="STATUS[w.status].tone" :label="STATUS[w.status].label" />
              <span class="min-w-0 flex-1 truncate font-medium">{{ websiteName(w) }}</span>
              <span class="text-xs text-muted-foreground">{{ STATUS[w.status].label }}</span>
              <Tag v-if="openFor(w.id)" class="rounded-md bg-secondary text-secondary-foreground">
                {{ openFor(w.id) }} offen
              </Tag>
            </RouterLink>
          </li>
          <li v-if="!listed.length" class="px-4 py-3 text-sm text-muted-foreground">
            Keine Website passt.
          </li>
        </ul>
        <div v-if="listed.length > sitesShown" class="mt-2 flex items-center gap-3 text-sm text-muted-foreground">
          <Button size="sm" variant="outline" @click="sitesShown += 12">
            Weitere anzeigen
          </Button>
          <span>{{ Math.min(sitesShown, listed.length) }} von {{ listed.length }}</span>
        </div>
      </template>
    </section>

    <section v-if="overview.data.value?.servers" aria-labelledby="servers-title" class="mt-8">
      <h2 id="servers-title" class="mb-3 text-base font-semibold">
        Server
      </h2>
      <ServersCard :servers="overview.data.value.servers" />
    </section>
  </div>
</template>
