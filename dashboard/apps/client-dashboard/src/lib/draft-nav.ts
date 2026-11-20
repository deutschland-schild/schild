import type { NavGroup, NavItem } from '@schild/ui'
import type { ServerEntry } from './nav'
import type { WebsiteSummary } from '@/api/websites'
import { Gauge, Inbox, LayoutDashboard, Lock, Network, Settings } from '@lucide/vue'
import { ref, watch } from 'vue'
import { DEMO_SITES, demoStatus, inbox, manyDemo } from './inbox-draft'
import { rulesNavItem, websitePath } from './nav'
import { STATUS, websiteName } from './websites'

/**
 * DRAFT, dev and mock builds only (initiator, 2026-11-03): the sidebar as a tree below the instance.
 *
 *   [web-1 ▾]             the instance as a plain select box, only with several instances (central dashboard)
 *   Übersicht             inbox, websites, servers of the instance
 *   Websites              each website, a click opens its Zugriffe (D68); the open one lists its other pages
 *   Server                each server, a click opens it; the open one lists Auslastung and Server-Check
 *   Schutz                for the whole instance
 *   Einstellungen         Allgemein, Datenschutz
 *
 * Switched on by opening /draft/inbox, off by the button on that page; kept in localStorage so the
 * e2e tests (mock mode, fresh storage) keep the old navigation.
 */
export const DRAFT_HOME = '/draft/inbox'
const KEY = 'schild.draftNav'
const allowed = import.meta.env.DEV || import.meta.env.VITE_MOCK === 'true'
export const draftNav = ref(allowed && typeof localStorage !== 'undefined' && localStorage.getItem(KEY) === '1')
watch(draftNav, v => v ? localStorage.setItem(KEY, '1') : localStorage.removeItem(KEY))
/** Simulates the central dashboard with several instances: only then the sidebar shows the instance select. */
export const multiInstance = ref(false)

const SITE_PAGES = [
  ['events', 'Ereignisse'],
  ['access', 'Zugriffsschutz'],
  ['ai-crawlers', 'KI-Crawler'],
] as const

/** The group above the normal sidebar that leads to the draft overview (the draft sidebar reaches it through the instance). */
export function draftGroup(): NavGroup {
  return { label: 'Entwurf', items: [{ to: DRAFT_HOME, label: 'Übersicht', icon: Inbox, ...(inbox.items.length ? { badge: inbox.items.length } : {}), keywords: ['posteingang', 'inbox', 'entscheiden'] }] }
}

export const openFor = (site: string) => inbox.items.filter(i => i.site === site).length

/** From this many websites the sidebar lists only those that need a look, plus "Alle N Websites". */
export const SIDEBAR_SITES_MAX = 8
/** With many websites: at most this many with a problem in the sidebar, the worst first. */
const SIDEBAR_PROBLEMS_MAX = 6

/** The websites of the mock plus, with the demo on, 44 made-up ones (only what the sidebar and list need). */
export function withDemoSites(list: WebsiteSummary[]): WebsiteSummary[] {
  if (!manyDemo.value) return list
  return [...list, ...DEMO_SITES.map(id => ({ id, label: id, hosts: [id], status: demoStatus(id) }) as unknown as WebsiteSummary)]
}

export function buildDraftNav(i: { websites: WebsiteSummary[], servers: ServerEntry[], site: string, subpage: string | null, serverPage: string, path: string }): NavGroup[] {
  // Many websites: the sidebar keeps only those with a problem or open items and the open one; all of
  // them are on the overview (with search) and in ⌘K. A sidebar of 50 websites hides Schutz and Einstellungen.
  // Open items do not count here: they are on the Übersicht badge, and with many websites nearly every one has some.
  const many = i.websites.length > SIDEBAR_SITES_MAX
  const rank = (w: WebsiteSummary) => w.status === 'disrupted' ? 0 : w.status === 'attention' ? 1 : 2
  const problems = i.websites.filter(w => w.status === 'disrupted' || w.status === 'attention').sort((a, b) => rank(a) - rank(b)).slice(0, SIDEBAR_PROBLEMS_MAX)
  const current = i.websites.find(w => w.id === i.site)
  const shownSites = !many ? i.websites : current && !problems.includes(current) ? [current, ...problems] : problems
  const websites: NavItem[] = shownSites.map((w) => {
    const open = w.id === i.site
    return {
      to: websitePath(w.id),
      label: websiteName(w),
      dot: STATUS[w.status].tone,
      dotLabel: STATUS[w.status].label,
      exact: true,
      selected: open && !!i.subpage,
      // Only status and open items: requests per second change all the time and ask for nothing.
      ...(openFor(w.id) ? { badge: openFor(w.id) } : {}),
      keywords: [w.id, ...w.hosts, 'zugriffe', 'überblick'],
      ...(open ? { children: SITE_PAGES.map(([sub, label]) => ({ to: websitePath(w.id, sub), label })) } : {}),
    }
  })
  const servers: NavItem[] = i.servers.map(s => ({
    to: s.to,
    label: s.label,
    ...(s.tone ? { dot: s.tone, dotLabel: s.hint } : {}),
    exact: true,
    selected: s.id === 'local' && (i.serverPage === 'server-load' || i.serverPage === 'server-check'),
    ...(i.serverPage && s.id === 'local'
      ? { children: [{ to: '/server/load', label: 'Auslastung' }, { to: '/server/check', label: 'Server-Check' }] }
      : {}),
  }))
  if (many) websites.push({ to: `${DRAFT_HOME}#websites`, label: `Alle ${i.websites.length} Websites`, keywords: ['websites', 'liste', 'suchen'], hideInPalette: true })
  return [
    { items: [{ to: DRAFT_HOME, label: 'Übersicht', icon: LayoutDashboard, ...(inbox.items.length ? { badge: inbox.items.length } : {}), keywords: ['posteingang', 'start', 'entscheiden'] }] },
    { label: many ? 'Websites · brauchen einen Blick' : 'Websites', items: websites },
    { label: 'Server', items: servers },
    {
      label: 'Schutz',
      items: [
        rulesNavItem(i.path),
        { to: '/blocks', label: 'Sperren', icon: Gauge },
        { to: '/own-ips', label: 'Eigene IPs', icon: Network },
      ],
    },
    {
      label: 'Einstellungen',
      items: [
        { to: '/settings', label: 'Allgemein', icon: Settings, exact: true },
        { to: '/privacy', label: 'Datenschutz', icon: Lock },
      ],
    },
  ]
}
