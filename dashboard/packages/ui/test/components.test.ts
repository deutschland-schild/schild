import type { ColumnDef } from '@tanstack/vue-table'
import { TooltipProvider } from 'reka-ui'
import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent, h, nextTick } from 'vue'
import { describe, expect, it, vi } from 'vitest'
import AreaChart from '../src/components/app/AreaChart.vue'
import BarList from '../src/components/app/BarList.vue'
import ConfirmDialog from '../src/components/app/ConfirmDialog.vue'
import DataTable from '../src/components/app/DataTable.vue'
import EmptyState from '../src/components/app/EmptyState.vue'
import ErrorState from '../src/components/app/ErrorState.vue'
import FilterBar from '../src/components/app/FilterBar.vue'
import IpAddress from '../src/components/app/IpAddress.vue'
import JsonView from '../src/components/app/JsonView.vue'
import LiveIndicator from '../src/components/app/LiveIndicator.vue'
import PageHeader from '../src/components/app/PageHeader.vue'
import RelativeTime from '../src/components/app/RelativeTime.vue'
import Sparkline from '../src/components/app/Sparkline.vue'
import StatCard from '../src/components/app/StatCard.vue'
import StatusPill from '../src/components/app/StatusPill.vue'
import { NativeSelect } from '../src/components/ui/native-select'

describe('BarList', () => {
  it('keeps text off the tinted bar (hint contrast) and scales bars to the maximum', () => {
    const w = mount(BarList, { props: { label: 'Länder', items: [{ id: 'nl', label: 'NL', value: 10, hint: 'AS64500' }, { id: 'de', label: 'DE', value: 5 }] } })
    const hint = w.get('[data-slot="bar-hint"]')
    expect(hint.text()).toBe('AS64500')
    // The hint is never inside the coloured bar or its track.
    expect(hint.element.closest('[data-slot="bar-track"]')).toBeNull()
    const bars = w.findAll('[data-slot="bar"]')
    expect(bars[0]!.attributes('style')).toContain('width: 100%')
    expect(bars[1]!.attributes('style')).toContain('width: 50%')
    expect(w.get('ul').attributes('aria-label')).toBe('Länder')
  })
})

describe('NativeSelect', () => {
  it('emits update:modelValue with the selected value and never renders modelValue as an attribute', async () => {
    const w = mount(NativeSelect, { props: { modelValue: 'a' }, slots: { default: '<option value="a">A</option><option value="b">B</option>' } })
    const sel = w.get('select')
    expect(sel.attributes('modelvalue')).toBeUndefined()
    await sel.setValue('b')
    expect(w.emitted('update:modelValue')?.[0]).toEqual(['b'])
  })
})

describe('StatusPill', () => {
  it('renders label, tone and decorative dot', () => {
    const w = mount(StatusPill, { props: { tone: 'signal', pulse: true }, slots: { default: 'Grundschutz aktiv' } })
    expect(w.text()).toBe('Grundschutz aktiv')
    expect(w.attributes('data-tone')).toBe('signal')
    expect(w.find('[aria-hidden="true"]').exists()).toBe(true)
    expect(w.html()).toContain('motion-safe:animate-ping')
  })
})

describe('LiveIndicator', () => {
  it('announces state politely', () => {
    const w = mount(LiveIndicator, { props: { state: 'offline' } })
    expect(w.attributes('role')).toBe('status')
    expect(w.text()).toBe('Keine Verbindung')
  })
})

describe('PageHeader / EmptyState / ErrorState', () => {
  it('renders a single h1 with actions', () => {
    const w = mount(PageHeader, { props: { title: 'Ereignisse', description: 'Alles, was Schild notiert.' }, slots: { actions: '<button>Export</button>' } })
    expect(w.find('h1').text()).toBe('Ereignisse')
    expect(w.find('button').text()).toBe('Export')
  })
  it('empty state is a status region', () => {
    const w = mount(EmptyState, { props: { title: 'Noch keine Vorfälle' } })
    expect(w.attributes('role')).toBe('status')
    expect(w.text()).toContain('Noch keine Vorfälle')
  })
  it('error state emits retry', async () => {
    const w = mount(ErrorState, { props: { detail: 'HTTP 502' } })
    expect(w.attributes('role')).toBe('alert')
    await w.find('button').trigger('click')
    expect(w.emitted('retry')).toHaveLength(1)
  })
})

describe('Sparkline / StatCard / AreaChart', () => {
  it('sparkline has an accessible summary', () => {
    const w = mount(Sparkline, { props: { values: [1, 4, 2], label: 'Abgewehrt' } })
    expect(w.attributes('role')).toBe('img')
    expect(w.attributes('aria-label')).toBe('Abgewehrt: von 1 auf 2, Höchstwert 4')
  })
  it('sparkline keeps a restart gap as a gap (no line through it)', () => {
    const w = mount(Sparkline, { props: { values: [1, 2, 3, null, null, 2, 4], label: 'Anfragen' } })
    const line = w.findAll('path').at(-1)!.attributes('d')!
    // Two segments, each starting with a move; nothing joins step 2 and step 5.
    expect(line.match(/M/g)).toHaveLength(2)
    const fill = w.findAll('path')[0]!.attributes('d')!
    expect(fill.match(/Z/g)).toHaveLength(2)
  })
  it('stat card formats value and delta', () => {
    const w = mount(StatCard, { props: { label: 'Anfragen', value: 12345, delta: 0.1, trend: [1, 2, 3] } })
    expect(w.get('[data-testid="stat-value"]').text()).toBe('12.345')
    expect(w.text()).toMatch(/\+10\s?%/)
    expect(w.find('svg[role="img"]').exists()).toBe(true)
  })
  it('stat card shows skeleton while loading', () => {
    const w = mount(StatCard, { props: { label: 'Anfragen', value: null, loading: true } })
    expect(w.find('[data-testid="stat-value"]').exists()).toBe(false)
    expect(w.attributes('aria-busy')).toBe('true')
  })
  it('area chart: legend for 2 series, sr table, keyboard crosshair', async () => {
    const w = mount(AreaChart, {
      props: {
        label: 'Anfragen pro Stunde',
        labels: ['10:00', '11:00', '12:00'],
        series: [{ id: 'ok', label: 'Durchgelassen', values: [5, 8, 3] }, { id: 'blocked', label: 'Abgewehrt', values: [1, 0, 2] }],
      },
    })
    expect(w.findAll('table tbody tr')).toHaveLength(3)
    expect(w.text()).toContain('Durchgelassen')
    const svg = w.get('svg[role="img"]')
    await svg.trigger('keydown', { key: 'End' })
    expect(w.text()).toContain('12:00')
    expect(w.findAll('circle')).toHaveLength(2)
  })
})

describe('RelativeTime', () => {
  it('renders a time element with ISO datetime', () => {
    const d = new Date(Date.now() - 5 * 60_000)
    const w = mount(RelativeTime, { props: { value: d } })
    expect(w.element.tagName).toBe('TIME')
    expect(w.attributes('datetime')).toBe(d.toISOString())
    expect(w.text()).toBe('vor 5 Minuten')
  })
})

describe('IpAddress', () => {
  it('shows flag, plaintext ip, and copies it', async () => {
    const w = mount({ render: () => h(TooltipProvider, () => h(IpAddress, { ip: '203.0.113.7', country: 'DE', asn: 3320, asnOrg: 'Deutsche Telekom' })) }, { attachTo: document.body })
    expect(w.text()).toContain('🇩🇪')
    expect(w.get('[data-testid="ip"]').text()).toBe('203.0.113.7')
    expect(w.html()).toContain('AS3320')
    await w.get('button').trigger('click')
    await flushPromises()
    expect(w.get('button').attributes('aria-label')).toBe('Kopiert')
    w.unmount()
  })
})

describe('JsonView', () => {
  it('renders a collapsible tree', async () => {
    const w = mount(JsonView, { props: { value: { a: 1, b: { c: 'x' }, d: [true, null] }, expandDepth: 1 } })
    expect(w.text()).toContain('"a"')
    expect(w.text()).toContain('1 Felder')
    const toggle = w.findAll('button').find(b => b.text().includes('"b"'))!
    expect(toggle.attributes('aria-expanded')).toBe('false')
    expect(toggle.text()).toContain('aufklappen')
    await toggle.trigger('click')
    expect(w.text()).toContain('"x"')
  })
})

describe('FilterBar', () => {
  it('removes chips and clears all', async () => {
    const chips = [{ key: 'country', label: 'Land', value: 'DE' }, { key: 'rule', label: 'Regel', value: '942100' }]
    const w = mount(FilterBar, { props: { 'chips': chips, 'onUpdate:chips': (v: unknown) => w.setProps({ chips: v as typeof chips }) } })
    expect(w.findAll('[data-testid="filter-chip"]')).toHaveLength(2)
    await w.get('button[aria-label="Filter Land: DE entfernen"]').trigger('click')
    expect(w.emitted('remove')![0]).toEqual([chips[0]])
    expect(w.findAll('[data-testid="filter-chip"]')).toHaveLength(1)
    await w.findAll('button').find(b => b.text() === 'Alle Filter entfernen')!.trigger('click')
    expect(w.emitted('clear')).toHaveLength(1)
  })
})

describe('ConfirmDialog', () => {
  it('requires the typed phrase before confirming', async () => {
    const w = mount(ConfirmDialog, {
      props: { open: true, title: 'Alle Netzregeln zurückziehen?', confirmPhrase: 'ALLE ZURÜCKZIEHEN', destructive: true, confirmLabel: 'Zurückziehen' },
      attachTo: document.body,
    })
    await flushPromises()
    const action = document.querySelector<HTMLButtonElement>('[data-testid="confirm-action"]')!
    const input = document.querySelector<HTMLInputElement>('[data-testid="confirm-input"]')!
    expect(action.disabled).toBe(true)
    input.value = 'alle zurückziehen'
    input.dispatchEvent(new Event('input'))
    await nextTick()
    expect(action.disabled).toBe(true)
    input.value = 'ALLE ZURÜCKZIEHEN'
    input.dispatchEvent(new Event('input'))
    await nextTick()
    expect(action.disabled).toBe(false)
    action.click()
    await nextTick()
    expect(w.emitted('confirm')).toHaveLength(1)
    w.unmount()
  })
})

interface Row { id: string, rule: string, hits: number }
const rows: Row[] = Array.from({ length: 30 }, (_, i) => ({ id: `r${i}`, rule: `rule-${String(i).padStart(2, '0')}`, hits: (i * 7) % 11 }))
const columns: ColumnDef<Row, any>[] = [
  { accessorKey: 'rule', header: 'Regel', meta: { label: 'Regel' } },
  { accessorKey: 'hits', header: 'Treffer', meta: { label: 'Treffer', class: 'text-right' } },
]

describe('DataTable', () => {
  function mountTable(extra: Record<string, unknown> = {}) {
    return mount(DataTable as any, {
      props: { columns, data: rows, label: 'Regeln', getRowId: (r: Row) => r.id, ...extra },
      attachTo: document.body,
    })
  }

  it('virtualizes large row sets: only a window of rows in the DOM, absolute row indexes', async () => {
    // jsdom has no ResizeObserver; the table only virtualizes where it exists.
    class RO { observe() {} unobserve() {} disconnect() {} }
    vi.stubGlobal('ResizeObserver', RO)
    // jsdom lays nothing out: give the scroll area a 600 px tall viewport.
    const rect = vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(600)
    const many: Row[] = Array.from({ length: 5000 }, (_, i) => ({ id: `m${i}`, rule: `rule-${i}`, hits: i }))
    const w = mountTable({ data: many, cursor: true, hasMore: true })
    await flushPromises()
    const trs = w.findAll('tbody tr[data-row]')
    expect(trs.length).toBeGreaterThan(0)
    expect(trs.length).toBeLessThan(100)
    expect(trs[0]!.attributes('aria-rowindex')).toBe('2')
    expect(w.findAll('tbody tr[data-slot="virtual-pad"]').length).toBeGreaterThan(0)
    expect(w.get('table').attributes('aria-rowcount')).toBe('-1')
    expect(w.text()).toContain('5.000 geladen')
    w.unmount()
    rect.mockRestore()
    vi.unstubAllGlobals()
  })

  it('hides the pager when everything fits on one page', () => {
    const w = mountTable({ data: rows.slice(0, 3) })
    expect(w.text()).toContain('3 Einträge')
    expect(w.find('select[aria-label="Einträge pro Seite"]').exists()).toBe(false)
    w.unmount()
  })

  it('paginates and labels the table', () => {
    const w = mountTable()
    expect(w.get('table').attributes('aria-label')).toBe('Regeln')
    expect(w.findAll('tbody tr[data-row]')).toHaveLength(25)
    expect(w.text()).toContain('1–25 von 30')
    w.unmount()
  })

  it('sorts via header button and sets aria-sort', async () => {
    const w = mountTable()
    const th = w.findAll('th')[1]!
    expect(th.attributes('aria-sort')).toBe('none')
    await th.get('button').trigger('click')
    expect(th.attributes('aria-sort')).toBe('ascending')
    const first = w.get('tbody tr[data-row] td:nth-child(2)').text()
    expect(first).toBe('0')
    await th.get('button').trigger('click')
    expect(th.attributes('aria-sort')).toBe('descending')
    expect(w.get('tbody tr[data-row] td:nth-child(2)').text()).toBe('10')
    w.unmount()
  })

  it('roving focus with arrow keys and Enter emits rowClick', async () => {
    const w = mountTable()
    const trs = () => w.findAll('tbody tr[data-row]')
    expect(trs()[0]!.attributes('tabindex')).toBe('0')
    expect(trs()[1]!.attributes('tabindex')).toBe('-1')
    await trs()[0]!.trigger('keydown', { key: 'ArrowDown' })
    await nextTick()
    expect(trs()[1]!.attributes('tabindex')).toBe('0')
    expect(document.activeElement).toBe(trs()[1]!.element)
    await trs()[1]!.trigger('keydown', { key: 'End' })
    await nextTick()
    expect(trs()[24]!.attributes('tabindex')).toBe('0')
    await trs()[24]!.trigger('keydown', { key: 'Enter' })
    expect((w.emitted('rowClick') as Row[][])[0]![0]!.id).toBe('r24')
    w.unmount()
  })

  it('opens the detail sheet on row click', async () => {
    const Host = defineComponent({
      setup: () => () => h(DataTable as any, { columns, data: rows, label: 'Regeln' }, {
        detail: ({ row }: { row: Row }) => h('p', { 'data-testid': 'detail' }, `Detail ${row.rule}`),
      }),
    })
    const w = mount(Host, { attachTo: document.body })
    await w.findAll('tbody tr[data-row]')[2]!.trigger('click')
    await flushPromises()
    expect(document.querySelector('[data-testid="detail"]')?.textContent).toBe('Detail rule-02')
    w.unmount()
  })

  it('cursor mode: shows every loaded row, "N geladen · Mehr laden", emits loadMore', async () => {
    const w = mountTable({ cursor: true, hasMore: true })
    expect(w.findAll('tbody tr[data-row]')).toHaveLength(30)
    expect(w.text()).toContain('30 geladen')
    expect(w.text()).not.toContain('von 30')
    expect(w.get('table').attributes('aria-rowcount')).toBe('-1')
    await w.get('[data-testid="load-more"]').trigger('click')
    expect(w.emitted('loadMore')).toHaveLength(1)
    await w.setProps({ hasMore: false })
    expect(w.find('[data-testid="load-more"]').exists()).toBe(false)
    expect(w.text()).toContain('30 geladen · alle Einträge')
    expect(w.get('table').attributes('aria-rowcount')).toBe('30')
    await w.setProps({ hasMore: true, loadingMore: true })
    expect(w.get('[data-testid="load-more"]').attributes('disabled')).toBeDefined()
    w.unmount()
  })

  it('shows an empty state', () => {
    const w = mountTable({ data: [], emptyTitle: 'Noch nichts da' })
    expect(w.text()).toContain('Noch nichts da')
    expect(w.text()).toContain('0 Einträge')
    w.unmount()
  })
})

describe('CommandBlock', () => {
  it('shows the whole command, wraps instead of scrolling and copies it with a labelled button', async () => {
    const writeText = vi.fn(async () => {})
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    // jsdom has no clipboard permissions, so vueuse falls back to the legacy execCommand path.
    const execCommand = vi.fn(() => true)
    Object.defineProperty(document, 'execCommand', { value: execCommand, configurable: true })
    const { default: CommandBlock } = await import('../src/components/app/CommandBlock.vue')
    const w = mount(CommandBlock, { props: { command: 'sudo ufw deny 6379/tcp', copyLabel: 'Befehl kopieren: Redis' } })
    expect(w.get('[data-testid="command-text"]').text()).toBe('sudo ufw deny 6379/tcp')
    expect(w.get('pre').classes()).toContain('whitespace-pre-wrap')
    const btn = w.get('[data-testid="command-copy"]')
    expect(btn.attributes('aria-label')).toBe('Befehl kopieren: Redis')
    await btn.trigger('click')
    await flushPromises()
    expect(writeText.mock.calls.length + execCommand.mock.calls.length).toBeGreaterThan(0)
    expect(w.emitted('copied')).toHaveLength(1)
    expect(w.get('[data-testid="command-copy"]').attributes('aria-label')).toBe('Kopiert')
  })
})
