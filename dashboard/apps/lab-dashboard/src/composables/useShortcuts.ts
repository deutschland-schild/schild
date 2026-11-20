import { onScopeDispose } from 'vue'

export interface Shortcut {
  /** Single key ("j", "?", "/") or a two-key sequence ("g o"). */
  keys: string
  description: string
  group?: string
  run: (e: KeyboardEvent) => void
  /** Allowed while focus is in a text field (default false). */
  inInputs?: boolean
}

const registry = new Set<Shortcut>()

/** All registered shortcuts (for the help dialog). */
export function listShortcuts(): Shortcut[] {
  return [...registry]
}

export function isTypingTarget(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null
  if (!el || !el.tagName) return false
  return el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName)
}

/** True while a modal dialog is open; page shortcuts must not fire behind it. */
function modalOpen(): boolean {
  return !!document.querySelector('[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"]')
}

let pending: string | null = null
let pendingTimer: ReturnType<typeof setTimeout> | undefined
let installed = false

function onKey(e: KeyboardEvent) {
  if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return
  const typing = isTypingTarget(e.target)
  const key = e.key.length === 1 ? e.key.toLowerCase() : e.key
  const seq = pending ? `${pending} ${key}` : key
  const all = [...registry]
  const exact = all.find(s => s.keys === seq && (!typing || s.inInputs) && (s.keys === 'Escape' || !modalOpen()))
  if (exact) {
    pending = null
    e.preventDefault()
    exact.run(e)
    return
  }
  if (!typing && !modalOpen() && all.some(s => s.keys.startsWith(`${key} `))) {
    pending = key
    clearTimeout(pendingTimer)
    pendingTimer = setTimeout(() => (pending = null), 1200)
    return
  }
  pending = null
}

/**
 * Register keyboard shortcuts for the lifetime of the calling component.
 * Shortcuts never fire while typing (unless inInputs) or behind an open dialog,
 * and never trigger irreversible actions directly: they open dialogs or move focus.
 */
export function useShortcuts(list: Shortcut[]): void {
  if (!installed && typeof window !== 'undefined') {
    installed = true
    // One global listener for the app's lifetime; shortcuts come and go with their components.
    window.addEventListener('keydown', onKey)
  }
  for (const s of list) registry.add(s)
  onScopeDispose(() => {
    for (const s of list) registry.delete(s)
  })
}

/** Test helper. */
export function resetShortcuts(): void {
  registry.clear()
  pending = null
}
