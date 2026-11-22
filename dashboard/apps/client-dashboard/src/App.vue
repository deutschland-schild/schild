<script setup lang="ts">
import type { BreadcrumbEntry, CommandEntry, NavGroup } from '@schild/ui'
import { RouterShell } from '@schild/app-kit'
import { Button, toast, Toaster, TooltipProvider, useTheme } from '@schild/ui'
import { Activity, Download, Keyboard, LayoutGrid, LogOut, Moon, Network, Radio, Search, Server, ServerCog, ShieldAlert, SlidersHorizontal, UserCheck } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import type { Component } from 'vue'
import { computed, defineAsyncComponent, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, csrf, errorMessage, session } from './api/client'
import { deleteAllowlistEntry, keys, useAllowMyIp, useOverview } from './api/queries'
import GroupModePill from './components/GroupModePill.vue'
import TestProfileBanner from './components/TestProfileBanner.vue'
import { useGroupStatus } from './api/group'
import { useHosts } from './api/hosts'
import { useWebsites } from './api/websites'
import RequestContextSheet from './components/requests/RequestContextSheet.vue'
import ShortcutHelp from './components/ShortcutHelp.vue'
import WebsiteSwitcher from './components/WebsiteSwitcher.vue'
import { useCurrentWebsite } from './composables/useCurrentWebsite'
import { handleKeydown, useShortcuts } from './composables/useShortcuts'
import { FEATURES } from './lib/hosts'
import { versionText } from './lib/labels'
import { buildNav, NAV_COPY, serverEntries, websitePath } from './lib/nav'
import { RULES_PATH } from './lib/rules'
import { STATUS, websiteName } from './lib/websites'
import { APP_NAME } from './router'

const isMock = import.meta.env.VITE_MOCK === 'true'
// The draft sidebar and overview (lib/draft-nav.ts, InboxDraftView.vue) exist in dev and mock builds only.
// Loaded on demand: the production build drops this branch and ships none of it.
const draft = shallowRef<typeof import('./lib/draft-nav')>()
let InstanceSwitcher: Component | undefined
if (import.meta.env.DEV || isMock) {
  void import('./lib/draft-nav').then(m => (draft.value = m))
  InstanceSwitcher = defineAsyncComponent(() => import('./components/InstanceSwitcher.vue'))
}
const draftNav = computed(() => !!draft.value?.draftNav.value)
const multiInstance = computed(() => !!draft.value?.multiInstance.value)
const route = useRoute()
const router = useRouter()
const qc = useQueryClient()
const isPublic = computed(() => route.meta.public === true)
const authed = computed(() => !!session.value?.authenticated && !isPublic.value)

const overview = useOverview(authed)
const ov = computed(() => authed.value ? overview.data.value : undefined)
// The mode this gateway runs in (alone or a node of a group, MVP-27), in the top bar of every page.
const groupQ = useGroupStatus(authed)
const group = computed(() => authed.value ? groupQ.data.value : undefined)
// The running gateway's version at the foot of the sidebar: "0.1.0", a test build marked short, explained on hover.
const version = computed(() => {
  const v = ov.value?.version ?? ''
  const number = v.replace(/^schild\s+/, '').replace(/\s*\(.*\)$/, '')
  return number ? { number, test: /\(non-release/i.test(v), full: versionText(v) } : undefined
})

// The sidebar holds one server or one website with its pages, or "Alle Websites" with Schutz and Einstellungen
// (lib/nav.ts). The switcher lists the servers (the gateway and its agents) and the websites side by side.
const websitesQ = useWebsites(authed)
const websites = computed(() => websitesQ.data.value?.websites ?? [])
const node = computed(() => websitesQ.data.value?.node ?? '')
const hostsQ = useHosts(authed)
const servers = computed(() => serverEntries(node.value, websitesQ.data.value?.server, hostsQ.data.value?.items))
const { site, subpage, last } = useCurrentWebsite()
const current = computed(() => websites.value.find(w => w.id === site.value))
// On a server page the switcher holds that server: the gateway, or the agent of ?server= on the Server-Check.
const heldServer = computed(() => {
  if (!route.path.startsWith('/server')) return ''
  const q = route.name === 'server-check' && typeof route.query.server === 'string' ? route.query.server : ''
  return q && servers.value.some(s => s.id === q) ? q : 'local'
})
// Otherwise it holds the website in the URL. Every other page holds none: the start page, the events of all
// websites (D68), the incidents and the settings, which hold for all websites (initiator 2026-11-15).
const held = computed(() => heldServer.value || !route.meta.website ? '' : site.value)
const nav = computed<NavGroup[]>(() => {
  const d = draft.value
  if (d?.draftNav.value)
    return d.buildDraftNav({ websites: d.withDemoSites(websites.value), servers: servers.value, site: site.value, subpage: subpage.value, serverPage: route.path.startsWith('/server') ? String(route.name) : '', path: route.path })
  const groups = buildNav({ site: held.value, server: heldServer.value, path: route.path, group: group.value?.mode === 'group' })
  return d ? [d.draftGroup(), ...groups] : groups
})
/** A page of the open (or last) website, else of the top website; without any website the start page. */
const sitePage = (sub: string) => websitePath(site.value || last.value || websites.value[0]?.id || '', sub)

const SERVER_TABS: Record<string, string> = { 'server-load': 'Auslastung', 'server-check': 'Server-Check', 'server-group': 'Cluster' }
const breadcrumbs = computed<BreadcrumbEntry[] | undefined>(() => {
  // An agent's Server-Check carries its own name; the gateway its node name.
  const agent = heldServer.value && heldServer.value !== 'local' ? servers.value.find(s => s.id === heldServer.value) : undefined
  if (agent) return [{ label: agent.label }, { label: 'Server-Check' }]
  const serverName = node.value || 'Server'
  const draftHome = draftNav.value ? draft.value!.DRAFT_HOME : null
  if (route.path === draftHome) return [{ label: node.value || 'Instanz' }, { label: 'Übersicht' }]
  if (route.name === 'server') return [{ label: serverName }]
  // A rule repository is a page below Regeln (D62).
  if (route.meta.repository) return [{ label: 'Regeln', to: RULES_PATH }, { label: route.meta.title ?? '' }]
  const tab = SERVER_TABS[String(route.name)]
  if (tab) return [{ label: serverName, to: '/server' }, { label: tab }]
  if (!route.meta.website || !site.value) return undefined
  const name = websiteName(current.value, site.value)
  const crumbs: BreadcrumbEntry[] = [draftHome ? { label: node.value || 'Instanz', to: draftHome } : { label: NAV_COPY.all, to: '/' }]
  if (route.name === 'website') crumbs.push({ label: name })
  else crumbs.push({ label: name, to: websitePath(site.value) }, { label: route.meta.title ?? '' })
  return crumbs
})

const helpOpen = ref(false)
const theme = useTheme()
const isDark = computed(() => theme.value === 'dark' || (theme.value === 'auto' && theme.system.value === 'dark'))

const allowMine = useAllowMyIp()
async function allowMyIpNow() {
  try {
    const entry = await allowMine.mutateAsync({ label: 'Meine IP', ttl: '7d' })
    toast.success(`Deine IP ${entry.ip ?? ''} ist für 7 Tage freigeschaltet`, {
      description: 'Schild sperrt sie nicht. Ändern kannst du das unter „Eigene IPs“.',
      action: {
        label: 'Rückgängig',
        onClick: async () => {
          await deleteAllowlistEntry(entry.id)
          void qc.invalidateQueries({ queryKey: keys.allowlist })
          void qc.invalidateQueries({ queryKey: keys.myip })
          toast('Freischaltung zurückgenommen')
        },
      },
    })
  }
  catch (err) {
    toast.error('Freischalten hat nicht geklappt', { description: errorMessage(err) })
  }
}

async function logout() {
  try {
    await api.POST('/auth/logout', { params: { header: csrf() } })
  }
  finally {
    session.value = { authenticated: false, first_run: false }
    qc.clear()
    await router.push({ name: 'login' })
    toast('Du bist abgemeldet')
  }
}

const commands = computed<CommandEntry[]>(() => [...placeCommands.value, ...allCommands.value])
/** ⌘K lists the server and every website (with status and requests per second) before the pages. */
const placeCommands = computed<CommandEntry[]>(() => [
  { id: 'all-websites', label: NAV_COPY.all, group: 'Websites', icon: LayoutGrid, keywords: ['start', 'überblick', 'websites'], to: '/' },
  ...servers.value.map(s => ({
    id: `server:${s.id}`,
    label: s.label,
    group: 'Server',
    to: s.to,
    ...(s.tone ? { dot: s.tone, hint: s.hint } : { icon: Server }),
    keywords: ['server', 'start', 'überblick', 'auslastung', 'server-check'],
  })),
  ...websites.value.map(w => ({
    id: `website:${w.id}`,
    label: websiteName(w),
    group: 'Websites',
    to: websitePath(w.id, subpage.value ?? ''),
    dot: STATUS[w.status].tone,
    hint: STATUS[w.status].label,
    keywords: [w.id, ...w.hosts],
  })),
])
const allCommands = computed<CommandEntry[]>(() => [
  { id: 'allow-mine', label: 'Meine IP freischalten', group: 'Aktionen', icon: UserCheck, keywords: ['allowlist', 'eigene ip', 'aussperren'], run: allowMyIpNow },
  { id: 'allow-ip', label: 'IP, Bereich oder DynDNS freischalten …', group: 'Aktionen', icon: Network, keywords: ['allowlist', 'ausnahme'], to: '/own-ips?new=1' },
  { id: 'incident', label: 'Vorfall suchen …', group: 'Aktionen', icon: ShieldAlert, keywords: ['vorfallnummer', 'entsperren', 'freischalten'], to: '/blocks?view=requests' },
  { id: 'live', label: 'Live-Ansicht starten', group: 'Aktionen', icon: Radio, keywords: ['echtzeit', 'stream'], to: '/events?live=1' },
  { id: 'blocked', label: 'Gesperrte Anfragen der letzten 24 Stunden', group: 'Aktionen', icon: Activity, keywords: ['blockiert', 'gesperrt'], to: '/events?outcome=blocked&time=24h' },
  { id: 'privacy', label: 'Daten zu einer IP finden, exportieren oder löschen', group: 'Aktionen', icon: Download, keywords: ['dsgvo', 'auskunft', 'löschen'], to: '/privacy' },
  { id: 'events', label: 'Ereignisse aller Websites', group: 'Aktionen', icon: Activity, keywords: ['events', 'log', 'anfragen', 'alle ereignisse', 'alarme'], to: '/events' },
  { id: 'traffic', label: 'Diagramme der letzten Stunde', group: 'Aktionen', icon: Activity, keywords: ['traffic', 'anfragen pro sekunde', 'monitoring', 'antwortzeit', 'statuscodes'], to: `${sitePage('charts')}?time=1h` },
  { id: 'load', label: 'Auslastung des Servers ansehen', group: 'Aktionen', icon: Server, keywords: ['cpu', 'arbeitsspeicher', 'festplatte', 'netzwerk', 'last'], to: '/server/load' },
  { id: 'servers', label: 'Server-Check ansehen', group: 'Aktionen', icon: Server, keywords: ['server', 'hosts', 'updates', 'ports', 'ssh', 'firewall', 'befunde'], to: '/server/check' },
  ...(FEATURES.hostAgents ? [{ id: 'add-server', label: 'Server hinzufügen (Agent) …', group: 'Aktionen', icon: ServerCog, keywords: ['agent', 'app-server', 'vm', 'code', 'einbinden'], to: '/server/check?new=1' }] : []),
  { id: 'rules', label: 'Regelquellen ein- und ausschalten', group: 'Aktionen', icon: SlidersHorizontal, keywords: ['modus', 'beobachten', 'erkennen', 'sperren', 'crs', 'crowdsec'], to: RULES_PATH },
  { id: 'search-events', label: 'Ereignisse durchsuchen', group: 'Aktionen', icon: Search, keywords: ['suche', 'filter'], to: '/events?focus=search' },
  { id: 'theme', label: isDark.value ? 'Helles Design' : 'Dunkles Design', group: 'Einstellungen', icon: Moon, keywords: ['dark mode', 'darstellung'], run: () => (theme.value = isDark.value ? 'light' : 'dark') },
  { id: 'shortcuts', label: 'Tastenkürzel anzeigen', group: 'Einstellungen', icon: Keyboard, shortcut: '?', run: () => (helpOpen.value = true) },
  { id: 'logout', label: 'Abmelden', group: 'Einstellungen', icon: LogOut, run: logout },
])

const go = (to: string) => () => void router.push(to)
useShortcuts([
  { keys: '?', label: 'Tastenkürzel anzeigen', group: 'Überall', run: () => (helpOpen.value = true) },
  { keys: 'g w', label: 'Zu allen Websites', group: 'Navigation', run: go('/') },
  { keys: 'g u', label: 'Zu den Zugriffen der Website', group: 'Navigation', run: () => void router.push(sitePage('')) },
  { keys: 'g a', label: 'Zu den Ereignissen der Website', group: 'Navigation', run: () => void router.push(sitePage('events')) },
  { keys: 'g e', label: 'Zu den Ereignissen aller Websites', group: 'Navigation', run: go('/events') },
  { keys: 'g t', label: 'Zu den Diagrammen der Website', group: 'Navigation', run: () => void router.push(sitePage('charts')) },
  { keys: 'g v', label: 'Zu den Sperren', group: 'Navigation', run: go('/blocks') },
  { keys: 'g h', label: 'Zur Auslastung des Servers', group: 'Navigation', run: go('/server/load') },
  { keys: 'g r', label: 'Zu den Regeln', group: 'Navigation', run: go('/settings/rules') },
  { keys: 'g i', label: 'Zu den eigenen IPs', group: 'Navigation', run: go('/own-ips') },
  { keys: 'g d', label: 'Zum Datenschutz', group: 'Navigation', run: go('/privacy') },
  { keys: 'g ,', label: 'Zu den Einstellungen', group: 'Navigation', run: go('/settings') },
])
function onKey(e: KeyboardEvent) {
  if (authed.value) handleKeydown(e)
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
</script>

<template>
  <TooltipProvider :delay-duration="300">
    <template v-if="isPublic">
      <RouterView />
      <Toaster position="bottom-right" rich-colors close-button />
    </template>
    <RouterShell v-else :app-name="APP_NAME" app-subtitle="Dashboard" :nav="nav" :commands="commands" :breadcrumbs="breadcrumbs">
      <template #sidebar-header>
        <template v-if="draftNav">
          <component :is="InstanceSwitcher" v-if="InstanceSwitcher && multiInstance" :name="node || 'Instanz'" />
        </template>
        <WebsiteSwitcher v-else :websites="websites" :servers="servers" :site="held" :server="heldServer" :subpage="subpage" />
      </template>
      <template v-if="group" #status>
        <GroupModePill :status="group" />
      </template>
      <template #sidebar-footer>
        <p v-if="version" class="truncate border-b px-2 pt-1 pb-2 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden" data-testid="sidebar-version" :title="version.full">
          Version {{ version.number }}<template v-if="version.test"> · Testversion</template>
        </p>
        <div class="flex items-center gap-2 px-2 py-1 text-sm group-data-[collapsible=icon]:hidden">
          <span class="min-w-0 flex-1 truncate text-muted-foreground">
            {{ session.value?.user ?? 'admin' }}<template v-if="session.value?.via === 'localhost'"> · lokal</template>
          </span>
          <Button variant="ghost" size="sm" data-testid="logout" @click="logout">
            <LogOut aria-hidden="true" />
            Abmelden
          </Button>
        </div>
      </template>
      <TestProfileBanner v-if="ov?.profile === 'test'" />
      <RouterView />
    </RouterShell>
    <ShortcutHelp v-model:open="helpOpen" />
    <!-- MVP-22: "Kontext" of an event, opened from any page with ?context=<event id>. -->
    <RequestContextSheet v-if="authed" />
  </TooltipProvider>
</template>
