import type { CreateStateOptions, MockState } from '../src/mock/data'
import { createQueryClient } from '@schild/app-kit'
import { VueQueryPlugin } from '@tanstack/vue-query'
import { flushPromises, mount } from '@vue/test-utils'
import { setupServer } from 'msw/node'
import { createMemoryHistory } from 'vue-router'
import { session } from '../src/api/client'
import App from '../src/App.vue'
import { createState } from '../src/mock/data'
import { createHandlers } from '../src/mock/handlers'
import { createAppRouter } from '../src/router'

/** Stateful mock backend for tests: the same MSW handlers as mock mode, served in Node. */
export function mockServer(opts: CreateStateOptions = {}) {
  const ctx: { state: MockState } = { state: createState(opts) }
  const server = setupServer(...createHandlers(ctxProxy(ctx), { latency: 0, liveIntervalMs: 40, monitoringTickMs: 100 }))
  return {
    server,
    get state() {
      return ctx.state
    },
    reset(o: CreateStateOptions = opts) {
      ctx.state = createState(o)
    },
  }
}

/** Handlers keep a reference; proxy so reset() swaps the state underneath. */
function ctxProxy(ctx: { state: MockState }): MockState {
  return new Proxy({} as MockState, {
    get: (_t, k) => Reflect.get(ctx.state, k),
    set: (_t, k, v) => Reflect.set(ctx.state, k, v),
  })
}

const mounted: { unmount: () => void }[] = []

/** Unmount every app mounted by mountApp (call in afterEach so failed tests do not leak). */
export function cleanup() {
  while (mounted.length) {
    try {
      mounted.pop()!.unmount()
    }
    catch { /* already unmounted */ }
  }
}

export async function mountApp(path: string) {
  session.value = null
  session.loaded = false
  const router = createAppRouter(createMemoryHistory())
  router.push(path)
  await router.isReady()
  const queryClient = createQueryClient()
  const wrapper = mount(App, { global: { plugins: [router, [VueQueryPlugin, { queryClient }]] }, attachTo: document.body })
  mounted.push(wrapper)
  await settle()
  return { wrapper, router, queryClient }
}

/** Let fetches, vue-query and re-renders finish. */
export async function settle(rounds = 6) {
  for (let i = 0; i < rounds; i++) {
    await flushPromises()
    await new Promise(r => setTimeout(r, 5))
  }
}

export async function waitFor(fn: () => boolean, timeout = 2000) {
  const start = Date.now()
  while (!fn()) {
    if (Date.now() - start > timeout) throw new Error('waitFor timed out')
    await settle(1)
  }
}

/** Text of the whole document (dialogs and sheets render into portals). */
export function bodyText() {
  return document.body.textContent ?? ''
}

export function byTestId<T extends HTMLElement = HTMLElement>(id: string): T | null {
  return document.querySelector<T>(`[data-testid="${id}"]`)
}

export async function click(el: Element | null) {
  if (!el) throw new Error('element not found')
  ;(el as HTMLElement).click()
  await settle()
}

export async function type(el: Element | null, value: string) {
  if (!el) throw new Error('element not found')
  const input = el as HTMLInputElement
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await settle(2)
}

/** The action button of the toast whose text contains `text`. */
export function toastAction(text: string, label = 'Rückgängig'): HTMLButtonElement | null {
  const toast = [...document.querySelectorAll('[data-sonner-toast]')].find(t => t.textContent?.includes(text))
  return toast ? [...toast.querySelectorAll('button')].find(b => b.textContent?.trim() === label) ?? null : null
}
