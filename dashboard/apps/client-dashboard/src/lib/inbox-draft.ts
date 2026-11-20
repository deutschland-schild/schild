import { reactive, ref, watch } from 'vue'

/**
 * DRAFT, mock builds only: the items of the inbox start page (initiator, 2026-11-03). Local state, no
 * contract behind it. Each item has one default action; changing its reach ("Erweitert") is optional.
 */
export type InboxKind = 'false_positive' | 'domain' | 'server'

export interface InboxItem {
  id: string
  kind: InboxKind
  title: string
  text: string
  /** Website the item belongs to, '' when it is about all of them or none yet. */
  site: string
  /** New domain: the suggested website. */
  suggest?: string
  since: string
}

const BASE_SITES = ['verein.example', 'praxis.example', 'shop.example', 'blog.example']
/** Websites a new domain can be assigned to; grows with the demo below. */
export const DRAFT_SITES = BASE_SITES

export const inbox = reactive<{ items: InboxItem[] }>({
  items: [
    {
      id: 'fp-942100',
      kind: 'false_positive',
      title: 'Möglicher Fehlalarm im Checkout',
      text: 'Regel 942100 schlägt 18-mal bei normalen Besuchern auf /checkout an. Die Ausnahme gilt nur für diese Seite.',
      site: 'shop.example',
      since: 'vor 40 Minuten',
    },
    {
      id: 'domain-www-blog',
      kind: 'domain',
      title: 'Neue Domain gesehen: www.blog.example',
      text: '212 Anfragen in 24 Stunden. Bis sie zugeordnet ist, weist Schild sie ab.',
      site: '',
      suggest: 'blog.example',
      since: 'vor 5 Stunden',
    },
    {
      id: 'server-updates',
      kind: 'server',
      title: 'web-1: 2 Sicherheitsupdates offen',
      text: 'Betrifft den Server, auf dem alle Websites laufen.',
      site: '',
      since: 'vor 2 Tagen',
    },
  ],
})

/**
 * "Viele Websites simulieren": 48 made-up websites and about 40 open items, to see how the sidebar, the
 * inbox and the website list hold up. Off by default; the generated items are removed again when off.
 */
export const manyDemo = ref(false)
export const DEMO_SITES = Array.from({ length: 44 }, (_, n) => `kunde-${String(n + 1).padStart(2, '0')}.example`)
/** Status of a made-up website: a few need a look, one is down. */
export const demoStatus = (site: string): 'ok' | 'attention' | 'disrupted' => {
  const n = Number(site.slice(6, 8))
  return n === 7 ? 'disrupted' : n % 9 === 0 ? 'attention' : 'ok'
}
function demoItems(): InboxItem[] {
  const out: InboxItem[] = []
  DEMO_SITES.forEach((site, n) => {
    if (n % 3 === 0) {
      out.push({ id: `demo-fp-${site}`, kind: 'false_positive', title: 'Möglicher Fehlalarm im Kontaktformular', text: `Regel 941100 schlägt ${4 + n}-mal bei normalen Besuchern auf /kontakt an. Die Ausnahme gilt nur für diese Seite.`, site, since: `vor ${n + 1} Stunden` })
    }
    if (n % 4 === 1) {
      out.push({ id: `demo-domain-${site}`, kind: 'domain', title: `Neue Domain gesehen: www.${site}`, text: `${30 + n} Anfragen in 24 Stunden. Bis sie zugeordnet ist, weist Schild sie ab.`, site: '', suggest: site, since: 'gestern' })
    }
  })
  return out
}
watch(manyDemo, (on) => {
  if (on) inbox.items.push(...demoItems())
  else inbox.items = inbox.items.filter(i => !i.id.startsWith('demo-'))
})
