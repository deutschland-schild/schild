import type { RouteRecordRaw } from 'vue-router'
import { syncDocumentTitle } from '@schild/app-kit'
import {
  BadgeCheck,
  BookOpenCheck,
  FileClock,
  LayoutDashboard,
  Lightbulb,
  Network,
  Settings,
  Waypoints,
} from '@lucide/vue'
import { createRouter, createWebHashHistory, RouterView } from 'vue-router'

export const APP_NAME = 'Schild-Lab'

// Sections of the lab dashboard (MVP-10). Sections with a detail page use child routes:
// the list child has no own title (it inherits the section title), the detail child adds a breadcrumb.
export const routes: RouteRecordRaw[] = [
  { path: '/', name: 'overview', component: () => import('./views/OverviewView.vue'), meta: { title: 'Überblick', nav: { group: 'Lab', icon: LayoutDashboard, keywords: ['start', 'status', 'eingang', 'queue', 'ack'] } } },
  {
    path: '/signals',
    component: RouterView,
    meta: { title: 'Signale & Muster', nav: { group: 'Lab', icon: Waypoints, keywords: ['signals', 'patterns', 'muster', 'bürgen'] } },
    children: [
      { path: '', name: 'signals', component: () => import('./views/SignalsView.vue') },
      { path: ':patternId', name: 'pattern', component: () => import('./views/PatternView.vue'), props: true, meta: { title: 'Muster' } },
    ],
  },
  {
    path: '/proposals',
    component: RouterView,
    meta: { title: 'Vorschläge', nav: { group: 'Lab', icon: Lightbulb, keywords: ['proposals', 'regeln', 'freigabe', 'review'] } },
    children: [
      { path: '', name: 'proposals', component: () => import('./views/ProposalsView.vue') },
      { path: ':id', name: 'proposal', component: () => import('./views/ProposalsView.vue'), props: true, meta: { title: 'Vorschlag' } },
    ],
  },
  {
    path: '/published',
    component: RouterView,
    meta: { title: 'Veröffentlicht', nav: { group: 'Lab', icon: BadgeCheck, keywords: ['published', 'feed', 'bundle', 'bündel', 'signaturen', 'withdraw', 'zurückziehen', 'rückzug', 'alle netzregeln zurückziehen', 'mitzeichnen'] } },
    children: [
      { path: '', name: 'published', component: () => import('./views/PublishedView.vue') },
      { path: 'withdrawals', name: 'withdrawals', component: () => import('./views/WithdrawalsView.vue'), meta: { title: 'Rückzüge' } },
      { path: ':version(\\d+)', name: 'bundle', component: () => import('./views/BundleView.vue'), props: route => ({ version: Number(route.params.version) }), meta: { title: 'Bündel' } },
    ],
  },
  { path: '/relays', name: 'relays', component: () => import('./views/RelaysView.vue'), meta: { title: 'Relays & Peers', nav: { group: 'Netz', icon: Network, keywords: ['relay', 'peers', 'verteiler', 'eingefroren'] } } },
  { path: '/clients', name: 'clients', component: () => import('./views/ClientsView.vue'), meta: { title: 'Clients & Bürgen', nav: { group: 'Netz', icon: BookOpenCheck, keywords: ['clients', 'issuer', 'bürgen', 'sperren', 'kontingent'] } } },
  { path: '/log', name: 'public-log', component: () => import('./views/PublicLogView.vue'), meta: { title: 'Öffentliches Log', nav: { group: 'Netz', icon: FileClock, keywords: ['transparency', 'log', 'checkpoint', 'hash', 'prüfen'] } } },
  { path: '/settings', name: 'settings', component: () => import('./views/SettingsView.vue'), meta: { title: 'Einstellungen', nav: { group: 'Verwaltung', icon: Settings, keywords: ['settings', 'schwellen', 'aufbewahrung', 'konto'] } } },
  { path: '/:pathMatch(.*)*', name: 'not-found', component: () => import('./views/NotFoundView.vue'), meta: { title: 'Nicht gefunden' } },
]

export function createAppRouter() {
  // Hash history: works at root and under any sub-path when served via go:embed.
  const router = createRouter({
    history: createWebHashHistory(),
    routes,
    scrollBehavior: (_to, _from, saved) => saved ?? { top: 0 },
  })
  syncDocumentTitle(router, APP_NAME)
  return router
}
