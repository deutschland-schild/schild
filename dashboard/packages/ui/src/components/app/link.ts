import type { Component } from 'vue'
import { getCurrentInstance } from 'vue'

/** Use RouterLink when the app registered vue-router, else a plain anchor. */
export function useLinkComponent(override?: Component | string): { is: Component | string, props: (to: string) => Record<string, string> } {
  const routerLink = getCurrentInstance()?.appContext.components.RouterLink
  const is = override ?? routerLink ?? 'a'
  const isAnchor = is === 'a'
  return { is, props: (to): Record<string, string> => (isAnchor ? { href: to } : { to }) }
}

export function isActivePath(current: string, to: string): boolean {
  if (to === '/') return current === '/'
  return current === to || current.startsWith(`${to}/`)
}
