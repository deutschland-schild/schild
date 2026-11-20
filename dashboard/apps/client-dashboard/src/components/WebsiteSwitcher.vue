<script setup lang="ts">
import type { WebsiteSummary } from '@/api/websites'
import type { ServerEntry, WebsiteSubpage } from '@/lib/nav'
import { Input, Popover, PopoverContent, PopoverTrigger, SidebarMenu, SidebarMenuButton, SidebarMenuItem, StatusDot, useSidebar } from '@schild/ui'
import { Check, ChevronsUpDown, LayoutGrid, Plus, Server } from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { NAV_COPY, serverWarning, WEBSITE_FILTER_FROM, websitePath } from '@/lib/nav'
import { FEATURES } from '@/lib/hosts'
import { STATUS, websiteName } from '@/lib/websites'

/**
 * One server or one website at a time (D36 amendment 2026-10-31; servers 2026-11-02). The list holds the
 * servers (the gateway, then its agents) and below them the websites, side by side: a website belongs to
 * no one server. Switching websites keeps the sub-page. A warning dot stands for another server or website
 * that needs a look.
 */
const props = defineProps<{ websites: WebsiteSummary[], servers: ServerEntry[], site: string, server: string, subpage: WebsiteSubpage | null }>()
const { isMobile, setOpenMobile } = useSidebar()

const open = ref(false)
const query = ref('')
watch(open, (v) => {
  if (!v) query.value = ''
})
const current = computed(() => props.server ? undefined : props.websites.find(w => w.id === props.site))
const currentServer = computed(() => props.server ? props.servers.find(s => s.id === props.server) : undefined)
const title = computed(() => props.server ? currentServer.value?.label ?? NAV_COPY.server : props.site ? websiteName(current.value, props.site) : NAV_COPY.all)
const rank = (w: WebsiteSummary) => w.status === 'disrupted' ? 2 : w.status === 'attention' ? 1 : 0
const others = computed(() => props.websites.filter(w => (props.server || w.id !== props.site) && rank(w) > 0).sort((a, b) => rank(b) - rank(a)))
const serverHint = computed(() => serverWarning(props.servers.filter(s => s.id !== props.server)))
/** The dot on the closed switcher: the most urgent other server or website. */
const warning = computed(() => {
  const w = others.value[0]
  const n = others.value.length
  const web = w ? { tone: STATUS[w.status].tone, label: n === 1 ? '1 weitere Website braucht einen Blick' : `${n} weitere Websites brauchen einen Blick` } : null
  const srv = serverHint.value
  if (srv && (srv.tone === 'danger' || !web || web.tone !== 'danger')) return web ? { tone: srv.tone, label: `${srv.label}, ${web.label}` } : srv
  return web
})
const subline = computed(() => {
  if (props.server) return currentServer.value?.hint ? `${NAV_COPY.server} · ${currentServer.value.hint}` : NAV_COPY.server
  if (props.site) return current.value ? STATUS[current.value.status].label : ''
  return props.websites.length === 1 ? '1 Website' : `${props.websites.length} Websites`
})
const shown = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return props.websites
  return props.websites.filter(w => [websiteName(w), w.id, ...w.hosts].some(t => t.toLowerCase().includes(q)))
})
function close() {
  open.value = false
  if (isMobile.value) setOpenMobile(false)
}
</script>

<template>
  <SidebarMenu>
    <SidebarMenuItem>
      <Popover v-model:open="open">
        <PopoverTrigger as-child>
          <SidebarMenuButton size="lg" class="border bg-card" :tooltip="title" data-testid="website-switcher">
            <span class="sr-only">{{ NAV_COPY.switcher }}:</span>
            <span class="flex size-4 shrink-0 items-center justify-center">
              <Server v-if="server" class="size-4" aria-hidden="true" />
              <StatusDot v-else-if="current" :tone="STATUS[current.status].tone" :label="STATUS[current.status].label" />
              <LayoutGrid v-else class="size-4" aria-hidden="true" />
            </span>
            <span class="grid min-w-0 flex-1 text-left leading-tight">
              <span class="truncate font-medium" data-testid="switcher-title">{{ title }}</span>
              <span v-if="subline" class="truncate text-xs text-muted-foreground tabular-nums">{{ subline }}</span>
            </span>
            <StatusDot v-if="warning" :tone="warning.tone" :label="warning.label" data-testid="switcher-others" />
            <ChevronsUpDown class="ml-auto size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          </SidebarMenuButton>
        </PopoverTrigger>
        <PopoverContent align="start" class="w-80 max-w-[calc(100vw-2rem)] p-1.5" data-testid="switcher-list">
          <Input
            v-if="websites.length >= WEBSITE_FILTER_FROM"
            v-model="query"
            type="search"
            class="mb-1.5"
            :placeholder="NAV_COPY.filterPlaceholder"
            :aria-label="NAV_COPY.filterLabel"
            data-testid="switcher-filter"
          />
          <nav :aria-label="NAV_COPY.switcher" class="max-h-[60vh] overflow-y-auto">
            <p v-if="!query" class="px-2 pt-1 pb-0.5 text-xs font-medium text-muted-foreground" data-testid="switcher-servers">
              {{ NAV_COPY.servers }}
            </p>
            <template v-if="!query">
              <RouterLink
                v-for="s in servers"
                :key="s.id"
                :to="s.to"
                class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring"
                :aria-current="s.id === server ? 'true' : undefined"
                data-testid="server-item"
                @click="close"
              >
                <span class="flex size-4 shrink-0 items-center justify-center">
                  <StatusDot v-if="s.tone" :tone="s.tone" :label="s.hint" />
                  <Server v-else class="size-4" aria-hidden="true" />
                </span>
                <span class="min-w-0 flex-1 truncate">{{ s.label }}</span>
                <Check v-if="s.id === server" class="size-4 shrink-0" aria-hidden="true" />
              </RouterLink>
              <RouterLink v-if="FEATURES.hostAgents" to="/server/check?new=1" class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground focus-visible:outline-2 focus-visible:outline-ring" data-testid="server-add" @click="close">
                <Plus class="size-4 shrink-0" aria-hidden="true" />
                {{ NAV_COPY.addServer }}
              </RouterLink>
              <div class="my-1.5 border-t" role="separator" />
              <p class="px-2 pt-1 pb-0.5 text-xs font-medium text-muted-foreground">
                {{ NAV_COPY.websites }}
              </p>
            </template>
            <RouterLink to="/" class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring" data-testid="switcher-all" @click="close">
              <LayoutGrid class="size-4 shrink-0" aria-hidden="true" />
              <span class="min-w-0 flex-1 truncate font-medium">{{ NAV_COPY.all }}</span>
              <Check v-if="!site && !server" class="size-4 shrink-0" aria-hidden="true" />
            </RouterLink>
            <RouterLink
              v-for="w in shown"
              :key="w.id"
              :to="websitePath(w.id, subpage ?? '')"
              class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring"
              :aria-current="w.id === site && !server ? 'true' : undefined"
              data-testid="switcher-item"
              @click="close"
            >
              <span class="flex size-4 shrink-0 items-center justify-center">
                <StatusDot :tone="STATUS[w.status].tone" :label="STATUS[w.status].label" />
              </span>
              <span class="min-w-0 flex-1 break-all">{{ websiteName(w) }}</span>
              <Check v-if="w.id === site && !server" class="size-4 shrink-0" aria-hidden="true" />
            </RouterLink>
            <p v-if="!shown.length" class="px-2 py-1.5 text-xs text-muted-foreground">
              {{ NAV_COPY.filterEmpty }}
            </p>
          </nav>
        </PopoverContent>
      </Popover>
    </SidebarMenuItem>
  </SidebarMenu>
</template>
