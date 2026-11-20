// Dev-only client for modules/inline-edit: Alt+click (Option+click) on a text makes that one text node editable.
// Enter saves (POST to the dev server, which writes the source file), Escape or clicking elsewhere cancels.
import { defineNuxtPlugin } from '#app'

const ENDPOINT = '/__inline-edit'

function textNodeAt(x: number, y: number): Text | null {
  const doc = document as Document & {
    caretPositionFromPoint?: (x: number, y: number) => { offsetNode: Node } | null
    caretRangeFromPoint?: (x: number, y: number) => Range | null
  }
  const node = doc.caretPositionFromPoint?.(x, y)?.offsetNode ?? doc.caretRangeFromPoint?.(x, y)?.startContainer ?? null
  return node && node.nodeType === Node.TEXT_NODE && node.textContent?.trim() ? node as Text : null
}

// Source files of the Vue components that rendered this node, innermost first (dev builds set type.__file).
function componentFiles(node: Node): string[] {
  type Instance = { type?: { __file?: string }, parent?: Instance | null }
  let el: Element | null = node.parentElement
  while (el && !(el as Element & { __vueParentComponent?: Instance }).__vueParentComponent) el = el.parentElement
  const files: string[] = []
  let inst = (el as (Element & { __vueParentComponent?: Instance }) | null)?.__vueParentComponent ?? null
  while (inst) {
    const f = inst.type?.__file
    if (f && !files.includes(f)) files.push(f)
    inst = inst.parent ?? null
  }
  return files
}

let toastEl: HTMLDivElement | null = null
let toastTimer: ReturnType<typeof setTimeout> | undefined
function toast(message: string, kind: 'info' | 'ok' | 'error' = 'info') {
  if (!toastEl) {
    toastEl = document.createElement('div')
    toastEl.setAttribute('role', 'status')
    toastEl.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647;max-width:28rem;padding:10px 14px;border-radius:8px;font:13px/1.4 system-ui,sans-serif;color:#fff;box-shadow:0 4px 16px rgba(0,0,0,.25);white-space:pre-line'
    document.body.appendChild(toastEl)
  }
  toastEl.style.background = kind === 'error' ? '#B91C1C' : kind === 'ok' ? '#047857' : '#0A1A33'
  toastEl.textContent = message
  toastEl.style.display = 'block'
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { if (toastEl) toastEl.style.display = 'none' }, kind === 'error' ? 9000 : 4000)
}

export default defineNuxtPlugin(() => {
  if (!import.meta.dev) return
  let editing: { node: Text, span: HTMLSpanElement } | null = null

  function finish(save: boolean) {
    if (!editing) return
    const { node, span } = editing
    editing = null
    const oldRaw = node.data
    const edited = span.textContent ?? ''
    // Put Vue's original text node back, so the virtual DOM stays consistent.
    span.replaceWith(node)
    if (!save || edited.replace(/\s+/g, ' ').trim() === oldRaw.replace(/\s+/g, ' ').trim()) return
    const lead = oldRaw.match(/^\s*/)![0]
    const trail = oldRaw.match(/\s*$/)![0]
    node.data = lead + edited.replace(/\s+/g, ' ').trim() + trail
    toast('Speichere …')
    fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-inline-edit': '1' },
      body: JSON.stringify({ oldText: oldRaw, newText: edited, page: location.pathname, files: componentFiles(node) }),
    })
      .then(async (r) => {
        const res = await r.json().catch(() => ({ error: `HTTP ${r.status}` }))
        if (!r.ok) {
          node.data = oldRaw
          const where = res.matches?.length ? `\n${res.matches.map((m: { file: string, line: number }) => `${m.file}:${m.line}`).join('\n')}` : ''
          toast(`Nicht gespeichert: ${res.error}${where}`, 'error')
          return
        }
        toast(`Gespeichert: ${res.file}:${res.line}`, 'ok')
      })
      .catch((e) => {
        node.data = oldRaw
        toast(`Nicht gespeichert: ${e}`, 'error')
      })
  }

  function start(node: Text, x: number, y: number) {
    const span = document.createElement('span')
    span.textContent = node.data
    span.setAttribute('contenteditable', 'plaintext-only')
    span.setAttribute('data-inline-edit', '')
    span.style.cssText = 'outline:2px dashed #F59E0B;outline-offset:2px;background:#FFFBEB;color:#0A1A33;border-radius:2px;cursor:text'
    node.replaceWith(span)
    editing = { node, span }
    span.focus()
    // Caret where the user clicked.
    const range = (document as any).caretRangeFromPoint?.(x, y) as Range | null
    if (range && span.contains(range.startContainer)) {
      const sel = getSelection()
      sel?.removeAllRanges()
      sel?.addRange(range)
    }
    span.addEventListener('keydown', (e) => {
      e.stopPropagation()
      if (e.key === 'Enter') { e.preventDefault(); finish(true) }
      if (e.key === 'Escape') { e.preventDefault(); finish(false) }
    })
    span.addEventListener('keyup', e => e.stopPropagation())
    span.addEventListener('blur', () => finish(false))
    toast('Bearbeiten: Enter speichert, Esc bricht ab.')
  }

  // Capture phase on window: runs before links, buttons and Vue handlers.
  const guard = (e: MouseEvent) => {
    const inEditor = editing && e.target instanceof Node && editing.span.contains(e.target)
    if (e.altKey || inEditor) {
      e.preventDefault()
      e.stopImmediatePropagation()
    }
  }
  window.addEventListener('mousedown', (e) => {
    if (!e.altKey || e.button !== 0) return
    const node = textNodeAt(e.clientX, e.clientY)
    if (!node) return
    e.preventDefault()
    e.stopImmediatePropagation()
    finish(false)
    start(node, e.clientX, e.clientY)
  }, true)
  window.addEventListener('click', guard, true)
  window.addEventListener('auxclick', guard, true)
})
