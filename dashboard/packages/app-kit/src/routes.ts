import type { Component } from 'vue'
import type { RouteLocationNormalizedLoaded, RouteRecordRaw, Router } from 'vue-router'
import type { BreadcrumbEntry, NavGroup } from '@schild/ui'

declare module 'vue-router' {
  interface RouteMeta {
    /** German page title, also used for breadcrumb and document title. */
    title?: string
    /** Sidebar group label; routes without `nav` are not listed. */
    nav?: { group?: string, icon?: Component, order?: number, keywords?: string[], devOnly?: boolean }
  }
}

/** Build sidebar groups from route records (keeps declaration order within a group). */
export function navFromRoutes(routes: readonly RouteRecordRaw[], opts: { dev?: boolean } = {}): NavGroup[] {
  const groups = new Map<string, NavGroup>()
  for (const r of routes) {
    const nav = r.meta?.nav
    if (!nav || !r.meta?.title) continue
    if (nav.devOnly && !opts.dev) continue
    const key = nav.group ?? ''
    if (!groups.has(key)) groups.set(key, { label: nav.group, items: [] })
    groups.get(key)!.items.push({ to: r.path, label: r.meta.title, icon: nav.icon, keywords: nav.keywords })
  }
  return [...groups.values()]
}

/** Breadcrumb: app root, then every matched route with a title. */
export function breadcrumbsFor(route: RouteLocationNormalizedLoaded, appName: string): BreadcrumbEntry[] {
  const crumbs: BreadcrumbEntry[] = [{ label: appName, to: '/' }]
  for (const m of route.matched) {
    if (!m.meta.title || m.path === '/') continue
    crumbs.push({ label: m.meta.title, to: m.path.includes(':') ? undefined : m.path })
  }
  if (crumbs.length === 1 && route.meta.title) crumbs.push({ label: route.meta.title })
  return crumbs
}

/** Keep document.title in sync: "<Seite> · <App>". */
export function syncDocumentTitle(router: Router, appName: string): void {
  router.afterEach((to) => {
    document.title = to.meta.title ? `${to.meta.title} · ${appName}` : appName
  })
}
