import type { NavGroup, NavItem, StatusTone } from '@schild/ui'
import type { HostSummary } from '@/api/hosts'
import type { ServerHealth } from '@/api/websites'
import { Activity, Ban, Bot, ChartArea, ClipboardCheck, KeyRound, LayoutDashboard, Lock, Network, ScrollText, Settings, ShieldAlert, Waypoints } from '@lucide/vue'
import { FEATURES, hostStatusText, hostTone } from './hosts'
import { REPOSITORIES, REPOSITORY_IDS, RULES_PATH, rulesPath } from './rules'
import { STATUS, WEBSITE_COPY } from './websites'

/**
 * Sidebar of the built-in gateway dashboard (D36 amendment 2026-10-31, servers 2026-11-02): one server or
 * one website at a time.
 *
 *   [● app-a.example ▾]  switcher (WebsiteSwitcher.vue): Server (gateway, agents), then Websites
 *     a website:  Zugriffe · Ereignisse · Zugriffsschutz · KI-Crawler (D68: Zugriffe is its start page)
 *     a server:   Überblick · Auslastung · Server-Check (an agent: Server-Check)
 *     none:       Ereignisse of all websites ("Alle Websites"), and below them what holds for all websites:
 *       Schutz         Regeln (with OWASP CRS, CrowdSec Hub, Eigene & Ausnahmen, Szenarien und Limits below it,
 *                      D62/D73/D84), Sperren (blocked addresses and stopped requests, D87), Eigene IPs
 *       Einstellungen  Allgemein (with what was Schutzstatus, 2026-11-18), Datenschutz
 *   A website or a server lists only its own pages (initiator 2026-11-15): the settings of the whole gateway
 *   beside a website's pages read as if they were that website's.
 *
 * Servers and websites stand side by side, not one below the other (initiator 2026-11-02): later several
 * ingress servers behind a load balancer serve the same domain, so a website belongs to no one server.
 */
export interface NavInput {
  /** Website the switcher holds, whose pages the sidebar lists; '' on "Alle Websites" or a server. */
  site: string
  /** Server the switcher holds ('local' or an agent id), whose pages the sidebar lists; '' otherwise. */
  server?: string
  /** Current path: the rule pages are listed below Regeln while one of them is open. */
  path?: string
  /** This gateway is a node of a group (MVP-27): the server lists the page "Gruppe". */
  group?: boolean
}

/** Scenarios and limits, below Regeln (2026-11-18): what schild does across requests. */
export const BEHAVIOUR_RULES_PATH = '/settings/rules/behaviour'

/** Regeln with its sources below it (D62): the sources show while a rule page is open. */
export function rulesNavItem(path = ''): NavItem {
  const open = path === RULES_PATH || path.startsWith(`${RULES_PATH}/`)
  return {
    to: RULES_PATH,
    label: 'Regeln',
    icon: ScrollText,
    exact: true,
    selected: path.startsWith(`${RULES_PATH}/`),
    keywords: ['rules', 'waf', 'regelquellen', 'freigeben', 'ausschalten', 'crs', 'owasp', 'crowdsec', 'hub', 'cve', 'eigene regeln', 'rules.d'],
    ...(open
      ? { children: [
          ...REPOSITORY_IDS.map(id => ({ to: rulesPath(id), label: REPOSITORIES[id].nav ?? REPOSITORIES[id].name, keywords: REPOSITORIES[id].keywords })),
          { to: BEHAVIOUR_RULES_PATH, label: 'Szenarien und Limits', keywords: ['behaviour', 'verhalten', 'brute force', 'passwort-raten', 'rate limit', 'limits', 'szenarien'] },
        ] }
      : {}),
  }
}

/** From this many websites the switcher shows a filter field above the list. */
export const WEBSITE_FILTER_FROM = 9

export const NAV_COPY = {
  server: 'Server',
  servers: 'Server',
  websites: 'Websites',
  addServer: 'Server hinzufügen',
  all: 'Alle Websites',
  protection: 'Schutz · alle Websites',
  filterPlaceholder: 'Website filtern …',
  filterLabel: 'Websites filtern',
  filterEmpty: 'Keine Website passt.',
  switcher: 'Server oder Website wechseln',
} as const

/** Path of a website page: /w/<id>/<sub>. Without a website: the server overview. */
export function websitePath(site: string, sub = ''): string {
  if (!site) return '/'
  return sub ? `/w/${encodeURIComponent(site)}/${sub}` : `/w/${encodeURIComponent(site)}`
}

/** Sub-page of a website path ("events"), or '' for its start page (Zugriffe). */
export const WEBSITE_SUBPAGES = ['events', 'charts', 'access', 'ai-crawlers'] as const
export type WebsiteSubpage = typeof WEBSITE_SUBPAGES[number] | ''

/** Sub-page of a website URL (/w/<id>/...), null outside the website pages. */
export function subpageOf(path: string): WebsiteSubpage | null {
  const m = /^\/w\/[^/]+(?:\/([^/]+))?\/?$/.exec(path)
  if (!m) return null
  return (WEBSITE_SUBPAGES as readonly string[]).includes(m[1] ?? '') ? (m[1] as WebsiteSubpage) : ''
}


/**
 * The pages of one website, shown below it when it is selected. Two pages instead of three (D68):
 * Zugriffe (the start page, with what was Überblick) and Ereignisse (what was Alarme, with the event list).
 */
export function websitePages(site: string): NavItem[] {
  return [
    { to: websitePath(site), label: WEBSITE_COPY.requests, icon: ChartArea, exact: true, keywords: ['überblick', 'besucher', 'seitenaufrufe', 'anfragen', 'zugriffsprotokoll', 'log'] },
    { to: websitePath(site, 'events'), label: WEBSITE_COPY.events, icon: ShieldAlert, keywords: ['alarme', 'angriffe', 'vorfälle', 'gesperrt', 'sperren', 'wellen', 'incidents', 'events'] },
    { to: websitePath(site, 'access'), label: WEBSITE_COPY.access, icon: KeyRound, keywords: ['passwortschutz', 'passwort', 'wartung', 'wartungsseite', 'sperren', 'lücke', 'zugang', 'ip'] },
    { to: websitePath(site, 'ai-crawlers'), label: WEBSITE_COPY.crawlers, icon: Bot, keywords: ['crawler', 'bots', 'ki-training', 'gptbot', 'robots.txt', 'blocken', 'falsche crawler'] },
  ]
}

/** "Alle Websites" (no website or server held): the event list of every website (D68). */
export function allWebsitesPages(): NavItem[] {
  return [{ to: '/events', label: WEBSITE_COPY.events, icon: ShieldAlert, keywords: ['alle websites', 'alarme', 'angriffe', 'gesperrt', 'events', 'log'] }]
}

/** The page of the group (MVP-27): every gateway with its state and load. */
export const GROUP_PATH = '/server/group'

/** The pages of one server: the gateway has Überblick, Auslastung and Server-Check; an agent only its check. */
export function serverPages(server: string, group = false): NavItem[] {
  if (server && server !== 'local') {
    return [{ to: `/server/check?server=${encodeURIComponent(server)}`, activeOn: ['/server/check'], label: 'Server-Check', icon: ClipboardCheck, keywords: ['updates', 'ports', 'ssh', 'firewall', 'befunde', 'agent'] }]
  }
  return [
    { to: '/server', label: WEBSITE_COPY.overview, icon: LayoutDashboard, exact: true, keywords: ['server', 'websites', 'zustand'] },
    { to: '/server/load', label: 'Auslastung', icon: Activity, keywords: ['cpu', 'arbeitsspeicher', 'festplatte', 'netzwerk', 'last'] },
    { to: '/server/check', label: 'Server-Check', icon: ClipboardCheck, keywords: ['updates', 'ports', 'ssh', 'firewall', 'befunde', 'agenten'] },
    ...(group ? [{ to: GROUP_PATH, label: 'Gruppe', icon: Waypoints, keywords: ['cluster', 'knoten', 'nodes', 'loadbalancer', 'abgleich', 'hochverfügbar'] }] : []),
  ]
}

/** One line of the server list: the gateway first, then its agents. No tone while the state is unknown. */
export interface ServerEntry {
  id: string
  label: string
  to: string
  tone?: StatusTone
  hint?: string
}

/** The gateway under its node name, then the agents by name. Withdrawn agents stay on the Server-Check only. */
export function serverEntries(node: string, server: ServerHealth | undefined, hosts: HostSummary[] = []): ServerEntry[] {
  const agents = hosts.filter(h => FEATURES.hostAgents && h.role === 'agent' && h.status !== 'revoked').sort((a, b) => a.hostname.localeCompare(b.hostname))
  return [
    { id: 'local', label: node || NAV_COPY.server, to: '/server', ...(server ? { tone: STATUS[server.status].tone, hint: STATUS[server.status].label } : {}) },
    ...agents.map(h => ({ id: h.id, label: h.hostname, to: `/server/check?server=${encodeURIComponent(h.id)}`, tone: hostTone(h), hint: hostStatusText(h) })),
  ]
}

/** The most urgent state among the servers, for the dot on the icon; null when none needs a look. */
export function serverWarning(servers: ServerEntry[]): { tone: StatusTone, label: string } | null {
  const hit = (tone: StatusTone) => servers.filter(s => s.tone === tone).length
  const tone = hit('danger') ? 'danger' : hit('warning') ? 'warning' : null
  if (!tone) return null
  const n = hit('danger') + hit('warning')
  return { tone, label: n === 1 ? '1 Server braucht einen Blick' : `${n} Server brauchen einen Blick` }
}

export function buildNav(i: NavInput): NavGroup[] {
  const protection: NavItem[] = [
    rulesNavItem(i.path),
    { to: '/blocks', label: 'Sperren', icon: Ban, keywords: ['gesperrte ips', 'gesperrt', 'sperre', 'firewall', 'nftables', 'vorfälle', 'vorfallnummer', 'entsperren', 'wellen', 'treffer'] },
    { to: '/own-ips', label: 'Eigene IPs', icon: Network, keywords: ['allowlist', 'ip', 'freischalten', 'dyndns'] },
  ]
  const settings: NavItem[] = [
    { to: '/settings', label: 'Allgemein', icon: Settings, exact: true, keywords: ['settings', 'schutzstatus', 'grundschutz', 'version', 'aufbewahrung', 'passwort'] },
    { to: '/privacy', label: 'Datenschutz', icon: Lock, keywords: ['privacy', 'dsgvo', 'löschen', 'export'] },
  ]
  if (i.server)
    return [{ items: serverPages(i.server, i.group) }]
  if (i.site)
    return [{ items: websitePages(i.site) }]
  return [
    { items: allWebsitesPages() },
    { label: NAV_COPY.protection, items: protection },
    { label: WEBSITE_COPY.navSettings, items: settings },
  ]
}
