import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { resetShortcuts, useShortcuts } from '../src/composables/useShortcuts'

function press(key: string, target: EventTarget = window) {
  target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }))
}

function host(list: Parameters<typeof useShortcuts>[0]) {
  return mount(defineComponent({ setup: () => { useShortcuts(list); return () => h('div', [h('input', { id: 'field' })]) } }), { attachTo: document.body })
}

afterEach(() => resetShortcuts())

describe('keyboard shortcuts', () => {
  it('runs single keys and two-key sequences', () => {
    const a = vi.fn()
    const go = vi.fn()
    const w = host([{ keys: 'a', description: 'a', run: a }, { keys: 'g o', description: 'go', run: go }])
    press('a')
    press('g')
    press('o')
    expect(a).toHaveBeenCalledTimes(1)
    expect(go).toHaveBeenCalledTimes(1)
    w.unmount()
  })

  it('ignores keys typed into inputs', () => {
    const a = vi.fn()
    const w = host([{ keys: 'a', description: 'a', run: a }])
    press('a', w.get('#field').element)
    expect(a).not.toHaveBeenCalled()
    w.unmount()
  })

  it('does not fire behind an open dialog', () => {
    const a = vi.fn()
    const w = host([{ keys: 'a', description: 'a', run: a }])
    const dlg = document.createElement('div')
    dlg.setAttribute('role', 'dialog')
    dlg.dataset.state = 'open'
    document.body.append(dlg)
    press('a')
    expect(a).not.toHaveBeenCalled()
    dlg.remove()
    press('a')
    expect(a).toHaveBeenCalledTimes(1)
    w.unmount()
  })

  it('unregisters with the component', () => {
    const a = vi.fn()
    host([{ keys: 'a', description: 'a', run: a }]).unmount()
    press('a')
    expect(a).not.toHaveBeenCalled()
  })
})
