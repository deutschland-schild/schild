import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import EffectFooter from '../src/components/app/EffectFooter.vue'
import MetaLine from '../src/components/app/MetaLine.vue'
import PaneItem from '../src/components/app/PaneItem.vue'
import SegmentedControl from '../src/components/app/SegmentedControl.vue'
import SplitPane from '../src/components/app/SplitPane.vue'
import Tag from '../src/components/app/Tag.vue'

const OPTIONS = [
  { value: 'block', label: 'Sperren', tone: 'ink' as const, testid: 'seg-block', mark: 'empfohlen' },
  { value: 'later', label: 'Später', disabled: true, reason: 'Kommt später.', testid: 'seg-later' },
  { value: 'observe', label: 'Beobachten', testid: 'seg-observe' },
]

function mountSegmented(start = 'block') {
  const model = ref(start)
  const Host = defineComponent({
    setup: () => () => h(SegmentedControl, { 'options': OPTIONS, 'label': 'Wirkung', 'modelValue': model.value, 'onUpdate:modelValue': (v: string) => (model.value = v) }),
  })
  return { w: mount(Host, { attachTo: document.body }), model }
}

describe('SegmentedControl', () => {
  it('is a labelled radio group with one checked segment', () => {
    const { w } = mountSegmented()
    const group = w.get('[role="radiogroup"]')
    expect(group.attributes('aria-label')).toBe('Wirkung')
    const radios = w.findAll('[role="radio"]')
    expect(radios.map(r => r.text())).toEqual(['Sperren empfohlen', 'Später', 'Beobachten'])
    expect(w.get('[data-testid="seg-block"] [data-slot="segment-mark"]').text()).toBe('empfohlen')
    expect(w.get('[data-testid="seg-block"]').attributes('aria-checked')).toBe('true')
    w.unmount()
  })

  it('keeps disabled options visible with a reason that screen readers get too', () => {
    const { w } = mountSegmented()
    const later = w.get('[data-testid="seg-later"]')
    expect(later.attributes('disabled')).toBeDefined()
    const reasonId = later.attributes('aria-describedby')!
    expect(document.getElementById(reasonId)?.textContent).toContain('Kommt später.')
    expect(w.text()).toContain('Später: Kommt später.')
    w.unmount()
  })

  it('changes the model on click, never to a disabled option', async () => {
    const { w, model } = mountSegmented()
    await w.get('[data-testid="seg-later"]').trigger('click')
    expect(model.value).toBe('block')
    await w.get('[data-testid="seg-observe"]').trigger('click')
    await flushPromises()
    expect(model.value).toBe('observe')
    w.unmount()
  })
})

describe('MetaLine', () => {
  it('joins parts with a middle dot, marks verified facts with a check and drops empty parts', () => {
    const w = mount(MetaLine, { props: { items: ['Quelle: Netz', { text: 'signiert von 3 Labs', tone: 'signal' }, '', false, '24 h: 97 Treffer'] } })
    expect(w.text().replace(/\s+/g, ' ')).toBe('Quelle: Netz · , signiert von 3 Labs · , 24 h: 97 Treffer')
    expect(w.find('.text-status-signal-text svg').exists()).toBe(true)
  })
})

describe('EffectFooter, Tag, SplitPane, PaneItem', () => {
  it('renders summary, actions and footnote', () => {
    const w = mount(EffectFooter, { props: { live: true }, slots: { default: 'Probelauf: 97 Treffer', actions: '<button>Anwenden</button>', note: 'Rücknehmbar.' } })
    expect(w.get('[aria-live="polite"]').text()).toBe('Probelauf: 97 Treffer')
    expect(w.text()).toContain('Anwenden')
    expect(w.text()).toContain('Rücknehmbar.')
  })

  it('tags carry their tone', () => {
    const w = mount(Tag, { props: { tone: 'warning' }, slots: { default: 'Probelauf' } })
    expect(w.attributes('data-tone')).toBe('warning')
    expect(w.text()).toBe('Probelauf')
  })

  it('split pane names the list and marks the active item', () => {
    const w = mount(SplitPane, {
      props: { listLabel: 'Herkunft', listTitle: 'Herkunft' },
      slots: {
        list: () => [h(PaneItem, { active: true }, () => 'Aus dem Netz'), h(PaneItem, null, () => 'Lokal')],
        default: () => 'Details',
      },
    })
    expect(w.get('nav').attributes('aria-label')).toBe('Herkunft')
    const items = w.findAll('[data-slot="pane-item"]')
    expect(items[0]!.attributes('aria-current')).toBe('true')
    expect(items[1]!.attributes('aria-current')).toBeUndefined()
    expect(items[0]!.attributes('type')).toBe('button')
    expect(w.text()).toContain('Details')
  })
})
