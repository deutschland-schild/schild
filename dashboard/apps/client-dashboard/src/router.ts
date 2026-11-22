import type { Router, RouteRecordRaw, RouterHistory } from 'vue-router'
import type { RuleRepositoryId } from './api/types'
import { syncDocumentTitle, unwrap } from '@schild/app-kit'
import { createRouter, createWebHashHistory } from 'vue-router'
import { api, session, setUnauthorizedHandler } from './api/client'
import { websitePath } from './lib/nav'
import { REPOSITORIES, REPOSITORY_IDS } from './lib/rules'

export const APP_NAME = 'Schild'

declare module 'vue-router' {
  interface RouteMeta {
    /** Rendered without the app shell and reachable without a session (login, first-run setup). */
    public?: boolean
    /** A page of one website (/w/:site/...). */
    website?: boolean
    /** The page of one rule repository (/settings/rules/<id>, D73). */
    repository?: RuleRepositoryId
  }
}

const view = {
  websites: () => import('./views/WebsitesView.vue'),
  server: () => import('./views/ServerOverviewView.vue'),
  load: () => import('./views/ServerLoadView.vue'),
  check: () => import('./views/ServersView.vue'),
  group: () => import('./views/GroupView.vue'),
  requests: () => import('./views/WebsiteRequestsView.vue'),
  events: () => import('./views/WebsiteEventsView.vue'),
  access: () => import('./views/WebsiteAccessView.vue'),
  crawlers: () => import('./views/WebsiteCrawlersView.vue'),
  charts: () => import('./views/TrafficView.vue'),
}

/**
 * Sections of the built-in gateway dashboard (MVP-09). One gateway is one server (initiator decision
 * 2026-10-29): "/" lists its websites (D36 amendment 2026-10-31), they live under /w/<website-id>/...,
 * the server under /server (reached at the top right), the sidebar is built in lib/nav.ts. The central dashboard (MVP-20) turns this around for many servers.
 */
export const routes: RouteRecordRaw[] = [
  // ---------------------------------------------------------------- start page and server
  { path: '/', name: 'websites', component: view.websites, meta: { title: 'Alle Websites' } },
  { path: '/server/load', name: 'server-load', component: view.load, meta: { title: 'Auslastung' } },
  { path: '/server/check', name: 'server-check', component: view.check, meta: { title: 'Server-Check' } },
  { path: '/server/group', name: 'server-group', component: view.group, meta: { title: 'Cluster' } },
  { path: '/server', name: 'server', component: view.server, meta: { title: 'Server' } },

  // ---------------------------------------------------------------- websites (below the server)
  // D68: two pages per website. Zugriffe is its start page (with what was Überblick), Ereignisse holds what
  // was Alarme and the event list of the website.
  { path: '/w/:site', name: 'website', component: view.requests, meta: { title: 'Zugriffe', website: true } },
  { path: '/w/:site/events', name: 'website-events', component: view.events, meta: { title: 'Ereignisse', website: true } },
  // The exceptions of all websites are one list, under Regeln (D84).
  { path: '/w/:site/exceptions', redirect: { path: '/settings/rules/local', query: { view: 'exceptions' } } },
  { path: '/w/:site/charts', name: 'website-charts', component: view.charts, meta: { title: 'Diagramme', website: true } },
  { path: '/w/:site/access', name: 'website-access', component: view.access, meta: { title: 'Zugriffsschutz', website: true } },
  { path: '/w/:site/ai-crawlers', name: 'website-crawlers', component: view.crawlers, meta: { title: 'KI-Crawler', website: true } },

  // ---------------------------------------------------------------- events and incidents (all websites, filter website=)
  {
    path: '/events',
    name: 'events',
    component: () => import('./views/EventsView.vue'),
    meta: { title: 'Ereignisse' },
    // The events of one website live on its own Ereignisse page (D68): a website filter opens it.
    beforeEnter: (to) => {
      const { website, ...query } = to.query
      return typeof website === 'string' && website ? { path: websitePath(website, 'events'), query, replace: true } : true
    },
  },
  // The list of incidents is the tab "Gestoppte Anfragen" of Sperren (2026-11-18); one incident keeps its page.
  { path: '/incidents', redirect: to => ({ path: '/blocks', query: { ...to.query, view: 'requests' } }) },
  { path: '/incidents/:incident', name: 'incident', component: () => import('./views/IncidentsView.vue'), meta: { title: 'Vorfälle' } },

  // ---------------------------------------------------------------- Einstellungen
  { path: '/settings', name: 'settings', component: () => import('./views/SettingsView.vue'), meta: { title: 'Einstellungen' } },
  // Schutzstatus is part of Allgemein since 2026-11-18; old links keep working.
  { path: '/status', redirect: '/settings' },
  // Verhalten & Limits is split (2026-11-18): scenarios and limits below Regeln, hits and waves on Sperren.
  {
    path: '/blocks',
    name: 'blocks',
    component: () => import('./views/BehaviourView.vue'),
    meta: { title: 'Sperren', part: 'blocks' },
    // Old links to the waves tab (D97).
    beforeEnter: to => to.query.view === 'waves' ? { path: '/settings/rules/behaviour', query: { ...to.query, view: 'detectors' } } : true,
  },
  {
    path: '/behaviour',
    redirect: (to) => {
      const view = String(to.query.view ?? '')
      if (view === 'scenarios' || view === 'limits' || view === 'detectors')
        return { path: '/settings/rules/behaviour', query: view === 'scenarios' ? {} : { view } }
      // Waves moved next to their detectors (D97).
      if (view === 'waves')
        return { path: '/settings/rules/behaviour', query: { ...to.query, view: 'detectors' } }
      return { path: '/blocks', query: { ...to.query, view: 'hits' } }
    },
  },
  { path: '/own-ips', name: 'own-ips', component: () => import('./views/OwnIpsView.vue'), meta: { title: 'Eigene IPs' } },
  { path: '/privacy', name: 'privacy', component: () => import('./views/PrivacyView.vue'), meta: { title: 'Datenschutz' } },
  // D62, D73: Regeln lists its sources, each one is a page of its own with the repository id as segment.
  { path: '/settings/rules', name: 'rules', component: () => import('./views/RulesView.vue'), meta: { title: 'Regeln' } },
  { path: '/settings/rules/behaviour', name: 'rules-behaviour', component: () => import('./views/BehaviourView.vue'), meta: { title: 'Szenarien und Limits', part: 'rules' } },
  ...REPOSITORY_IDS.map(id => ({ path: `/settings/rules/${id}`, name: `rules-${id}`, component: () => import('./views/RuleRepositoryView.vue'), meta: { title: REPOSITORIES[id].name, repository: id } })),

  // The styleguide is a development page: only in development and mock builds (never in the build the
  // gateway serves), and behind the login like every other page (D36 re-measurement D: /#/styleguide
  // opened without login).
  ...(import.meta.env.DEV || import.meta.env.VITE_MOCK === 'true'
    ? [
        { path: '/styleguide', name: 'styleguide', component: () => import('./styleguide/StyleguideView.vue'), meta: { title: 'Styleguide' } },
        // Draft (initiator 2026-11-03), mock only, no contract behind it yet: the start page as an inbox.
        { path: '/draft/inbox', name: 'inbox-draft', component: () => import('./views/InboxDraftView.vue'), meta: { title: 'Übersicht (Entwurf)' } },
      ]
    : []),
  { path: '/login', name: 'login', component: () => import('./views/LoginView.vue'), meta: { title: 'Anmelden', public: true } },
  { path: '/setup', name: 'setup', component: () => import('./views/SetupView.vue'), meta: { title: 'Einrichtung', public: true } },
  { path: '/:pathMatch(.*)*', name: 'not-found', component: () => import('./views/NotFoundView.vue'), meta: { title: 'Nicht gefunden' } },
]

/** Load GET /auth/session once (or again with force). Network errors leave the session unknown. */
export async function loadSession(force = false) {
  if (session.loaded && !force) return session.value
  try {
    session.value = await unwrap(api.GET('/auth/session'))
  }
  catch {
    session.value = null
  }
  session.loaded = true
  return session.value
}

/** Login and setup gate: first run -> setup, no session -> login (with return path). */
export function installAuthGuard(router: Router) {
  router.beforeEach(async (to) => {
    const s = await loadSession()
    if (s?.first_run) return to.name === 'setup' ? true : { name: 'setup' }
    if (!s?.authenticated) {
      if (to.name === 'login') return true
      return { name: 'login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} }
    }
    if (to.name === 'login') return typeof to.query.next === 'string' && to.query.next.startsWith('/') ? to.query.next : { path: '/' }
    return true
  })
  setUnauthorizedHandler(() => {
    if (!session.value?.authenticated) return
    session.value = { authenticated: false, first_run: false }
    const current = router.currentRoute.value
    if (!current.meta.public) void router.push({ name: 'login', query: { next: current.fullPath, expired: '1' } })
  })
}

export function createAppRouter(history: RouterHistory = createWebHashHistory()) {
  // Hash history: works at root and under any sub-path when served via go:embed, no server rewrites needed.
  const router = createRouter({
    history,
    routes,
    scrollBehavior: (to, from, saved) => {
      if (saved) return saved
      // Filter changes on the same page keep the scroll position.
      if (to.path === from.path) return false
      return { top: 0 }
    },
  })
  installAuthGuard(router)
  syncDocumentTitle(router, APP_NAME)
  return router
}
