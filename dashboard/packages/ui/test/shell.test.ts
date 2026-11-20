import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import AppShell from '../src/components/app/AppShell.vue'

const nav = [
  { label: 'Schutz', items: [{ to: '/', label: 'Überblick' }, { to: '/events', label: 'Ereignisse', badge: 3 }] },
  { items: [{ to: '/settings', label: 'Einstellungen' }] },
]

describe('AppShell', () => {
  it('renders nav with aria-current, breadcrumb, skip link and main landmark', async () => {
    const w = mount(AppShell, {
      props: { appName: 'Schild', nav, currentPath: '/events/abc', breadcrumbs: [{ label: 'Schild', to: '/' }, { label: 'Ereignisse' }] },
      slots: { default: '<p>Inhalt</p>' },
      attachTo: document.body,
    })
    await flushPromises()
    const current = w.findAll('a[aria-current="page"]')
    expect(current).toHaveLength(1)
    expect(current[0]!.text()).toContain('Ereignisse')
    expect(current[0]!.attributes('href')).toBe('/events')
    expect(w.find('a[href="#main"]').text()).toBe('Zum Inhalt springen')
    expect(w.get('main#main').text()).toBe('Inhalt')
    expect(w.find('nav[aria-label="Hauptnavigation"]').exists()).toBe(true)
    expect(w.text()).toContain('3')
    w.unmount()
  })

  it('opens the command palette with Ctrl+K and navigates', async () => {
    const w = mount(AppShell, { props: { appName: 'Schild', nav, currentPath: '/' }, attachTo: document.body })
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))
    await flushPromises()
    const items = [...document.querySelectorAll<HTMLElement>('[data-slot="command-item"]')]
    expect(items.map(i => i.textContent?.trim())).toContain('Einstellungen')
    items.find(i => i.textContent?.includes('Einstellungen'))!.click()
    await flushPromises()
    expect(w.emitted('navigate')?.[0]).toEqual(['/settings'])
    w.unmount()
  })

  // Messung 2026-10-29 abend 4.5: a fixed min-w-32 breadcrumb pushed mode pill, search and theme toggle
  // off screen at 360-430 px and clipped the page name to 128 px on desktop. jsdom can't measure layout,
  // so this guards the flex classes that make the header fit (checked in Chromium at 360/390/430/1440 px).
  it('keeps the header responsive: breadcrumb shrinks, context takes leftover space, actions never shrink', async () => {
    const w = mount(AppShell, {
      props: { appName: 'Schild', nav, currentPath: '/events', breadcrumbs: [{ label: 'Websites', to: '/' }, { label: 'shop.example', to: '/w/shop' }, { label: 'Verhalten & Limits' }] },
      slots: { context: 'Läuft: Grundregeln (CRS) 4.25.0 · schild 0.1.0-alpha' },
      attachTo: document.body,
    })
    await flushPromises()
    const crumb = w.get('[data-slot="shell-breadcrumb"]').classes()
    expect(crumb).toEqual(expect.arrayContaining(['min-w-0', 'shrink', 'overflow-hidden']))
    expect(crumb.filter(c => c.startsWith('min-w-') && c !== 'min-w-0')).toEqual([])
    expect(crumb).not.toContain('flex-1')
    const ctx = w.get('[data-slot="shell-context"]').classes()
    expect(ctx).toEqual(expect.arrayContaining(['min-w-0', 'flex-1', 'basis-0', 'truncate', 'hidden', 'xl:block']))
    expect(w.get('[data-slot="shell-actions"]').classes()).toEqual(expect.arrayContaining(['shrink-0', 'ml-auto']))
    // Only the current page stays visible on small screens, and it truncates instead of overflowing.
    const items = w.findAll('[data-slot="breadcrumb-item"]')
    expect(items.length).toBe(3)
    expect(items.slice(0, -1).every(i => i.classes().includes('hidden'))).toBe(true)
    expect(items.at(-1)!.classes()).toContain('min-w-0')
    expect(w.get('[data-slot="breadcrumb-page"]').classes()).toContain('truncate')
    w.unmount()
  })
})
