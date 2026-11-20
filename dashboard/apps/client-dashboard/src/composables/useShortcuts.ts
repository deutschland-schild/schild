import { onScopeDispose, reactive } from 'vue'

/**
 * Keyboard shortcuts: single keys ("?", "a") and two-key sequences ("g e").
 * Pages register their own shortcuts while mounted; the help overlay lists everything active.
 * Ignored while typing in a field, with Ctrl/Cmd/Alt held, or while a dialog is open.
 */
export interface Shortcut {
  /** "?" | "a" | "g e" (space separates a sequence). */
  keys: string
  label: string
  group: string
  run: (e: KeyboardEvent) => void
}

export const registry = reactive<{ items: Shortcut[] }>({ items: [] })

export function registerShortcuts(list: Shortcut[]): () => void {
  registry.items.push(...list)
  return () => {
    registry.items = registry.items.filter(s => !list.includes(s))
  }
}

/** Register shortcuts for the lifetime of the calling component/scope. */
export function useShortcuts(list: Shortcut[]) {
  const off = registerShortcuts(list)
  onScopeDispose(off)
}

function isTyping(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null
  if (!el || !el.tagName) return false
  if (el.isContentEditable) return true
  const tag = el.tagName
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true
  if (tag === 'INPUT') {
    const type = (el as HTMLInputElement).type
    return !['checkbox', 'radio', 'button', 'submit', 'reset'].includes(type)
  }
  return false
}

function dialogOpen(): boolean {
  return !!document.querySelector('[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"]')
}

let pending: string | null = null
let pendingTimer: ReturnType<typeof setTimeout> | null = null

export function handleKeydown(e: KeyboardEvent): boolean {
  if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) return false
  if (isTyping(e.target) || dialogOpen()) return false
  const key = e.key
  const items = registry.items
  if (pending) {
    const combo = `${pending} ${key}`
    pending = null
    if (pendingTimer) clearTimeout(pendingTimer)
    const hit = [...items].reverse().find(s => s.keys === combo)
    if (hit) {
      e.preventDefault()
      hit.run(e)
      return true
    }
    return false
  }
  if (items.some(s => s.keys.startsWith(`${key} `))) {
    pending = key
    pendingTimer = setTimeout(() => (pending = null), 1200)
    e.preventDefault()
    return true
  }
  // Last registered wins: page shortcuts override global ones with the same key.
  const hit = [...items].reverse().find(s => s.keys === key)
  if (hit) {
    e.preventDefault()
    hit.run(e)
    return true
  }
  return false
}

/** Human readable key label for the help overlay. */
export function keyLabels(keys: string): string[] {
  return keys.split(' ').map(k => (k === ' ' ? 'Leertaste' : k === 'Escape' ? 'Esc' : k.length === 1 ? k.toUpperCase() : k))
}
