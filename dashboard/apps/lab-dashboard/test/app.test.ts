import type { Router } from 'vue-router'
import { navFromRoutes } from '@schild/app-kit'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { flushPromises, mount } from '@vue/test-utils'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'
import App from '../src/App.vue'
import { live } from '../src/lib/live'
import { labHandlers } from '../src/mock/handlers'
import { LabMock, memorySessionStore } from '../src/mock/state'
import { routes } from '../src/router'

const SECTIONS = ['Überblick', 'Signale & Muster', 'Vorschläge', 'Veröffentlicht', 'Relays & Peers', 'Clients & Bürgen', 'Öffentliches Log', 'Einstellungen']

let mock: LabMock
const server = setupServer()
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => {
  mock = new LabMock(memorySessionStore(), { peerDelayMs: 0 })
  server.resetHandlers(...labHandlers(mock, '/api/v0', 0))
})
afterEach(() => {
  mock.dispose()
  live.paused = true // no background polling between tests
})

async function until(fn: () => boolean, ms = 3000) {
  const start = Date.now()
  while (!fn()) {
    if (Date.now() - start > ms) throw new Error(`timeout waiting for condition; page: ${(document.body.textContent ?? '').slice(0, 600)}`)
    await flushPromises()
    await new Promise(r => setTimeout(r, 10))
  }
}

async function mountApp(path: string, login = true) {
  live.paused = false
  if (login) mock.login({ user: 'm.muster', password: 'x' })
  const router: Router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const w = mount(App, { global: { plugins: [router, [VueQueryPlugin, { queryClient: qc }]] }, attachTo: document.body })
  return { w, router }
}

const text = () => document.body.textContent ?? ''

describe('lab dashboard', () => {
  it('has a route for every section, in order', () => {
    expect(navFromRoutes(routes).flatMap(g => g.items.map(i => i.label))).toEqual(SECTIONS)
  })

  it('asks for login first, then shows ingest health with ack p99 against the target', async () => {
    const { w } = await mountApp('/', false)
    await until(() => text().includes('Anmelden'))
    expect(w.find('h1').text()).toBe('Anmelden')
    await w.find('input[type=password]').setValue('geheim')
    await w.find('form').trigger('submit')
    await until(() => text().includes('liegt unter dem Ziel von 50 ms'))
    expect(w.find('h1').text()).toBe('Überblick')
    expect(text()).toContain('Ack-Latenz p99')
    expect(text()).toContain('Warteschlange nach Priorität')
    w.unmount()
  })

  it('shows a wrong password calmly and stays on the login', async () => {
    const { w } = await mountApp('/', false)
    await until(() => text().includes('Anmelden'))
    await w.find('input[type=password]').setValue('falsch')
    await w.find('form').trigger('submit')
    await until(() => text().includes('Passwort stimmen nicht'))
    w.unmount()
  })

  it('explains why a proposal cannot block yet and never offers block in the approval', async () => {
    const { w } = await mountApp('/proposals/prop-0007')
    await until(() => text().includes('Sperren ist noch nicht möglich'))
    expect(text()).toContain('Reproduziert hat bisher 1 Lab-Betreiber, nötig sind 2 verschiedene.')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }))
    await until(() => !!document.querySelector('[data-testid="approve-person"]'))
    expect(document.querySelector('[data-testid="approve-person"]')!.textContent).toContain('m.muster')
    const block = document.querySelector<HTMLInputElement>('input[type=radio][data-value="block"]')!
    const challenge = document.querySelector<HTMLInputElement>('input[type=radio][data-value="challenge"]')!
    expect(block.disabled).toBe(true)
    expect(challenge.disabled).toBe(false)
    w.unmount()
  })

  it('needs ALLE ZURÜCKZIEHEN and the password to withdraw all network rules; stray keys never trigger it', async () => {
    const { w, router } = await mountApp('/published/withdrawals')
    await until(() => !!document.querySelector('[data-testid="open-withdraw-all"]'))
    expect(router.currentRoute.value.path).toBe('/published/withdrawals')
    expect(text()).not.toMatch(/not-?aus/i)
    const before = mock.state.withdrawals.length
    for (const key of ['n', 'a', 'Enter', ' ', 'g', 'n', 'r', 'e', 'j', 'k']) window.dispatchEvent(new KeyboardEvent('keydown', { key }))
    await flushPromises()
    expect(mock.state.withdrawals.length).toBe(before)
    ;(document.querySelector('[data-testid="open-withdraw-all"]') as HTMLButtonElement).click()
    await until(() => !!document.querySelector('[data-testid="withdraw-all-submit"]'))
    const submit = () => document.querySelector<HTMLButtonElement>('[data-testid="withdraw-all-submit"]')!
    const phrase = document.querySelector<HTMLInputElement>('[data-testid="withdraw-all-phrase"]')!
    const pw = document.querySelector<HTMLInputElement>('[data-testid="withdraw-all-password"]')!
    expect(submit().disabled).toBe(true)
    phrase.value = 'NOT-AUS'
    phrase.dispatchEvent(new Event('input'))
    pw.value = 'x'
    pw.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(submit().disabled).toBe(true)
    phrase.value = 'ALLE ZURÜCKZIEHEN'
    phrase.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(submit().disabled).toBe(false)
    submit().click()
    await until(() => text().includes('noch 1 Mitzeichnung fehlt') && !!document.querySelector('[data-testid="withdraw-all-status"]'))
    expect(mock.state.withdrawals.length).toBe(before + 1)
    expect(mock.state.withdrawals[0]).toMatchObject({ scope: 'all', status: 'collecting' })
    w.unmount()
  })

  it('never renders an IP address on any section', async () => {
    const ipv4 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
    const { w, router } = await mountApp('/')
    for (const r of ['/', '/signals', '/proposals', '/published', '/published/withdrawals', '/relays', '/clients', '/log', '/settings']) {
      await router.push(r)
      await until(() => !document.querySelector('[aria-busy="true"]'))
      expect(text()).not.toMatch(ipv4)
    }
    w.unmount()
  })
})
