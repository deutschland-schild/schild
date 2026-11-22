import type { Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

async function axe(page: Page) {
  await page.waitForTimeout(300)
  const result = await new AxeBuilder({ page }).withTags(WCAG).analyze()
  return result.violations.map(v => `${v.id}: ${v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ')}`)
}

async function noOverflow(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow).toBeLessThanOrEqual(0)
}

// MVP-27: someone looking at the dashboard sees at once whether this gateway runs alone or in a group.
test('a single gateway says so on every page and on the server page', async ({ page, isMobile }) => {
  await page.goto('./#/')
  const mode = page.getByTestId('group-mode')
  await expect(mode).toHaveAttribute('data-mode', 'single')
  await expect(mode).toContainText(isMobile ? 'Einzeln' : 'Einzelner Server')
  await noOverflow(page)
  await mode.click()
  await expect(page).toHaveURL(/#\/server$/)
  await expect(page.getByTestId('group-card')).toHaveAttribute('data-mode', 'single')
  await expect(page.getByTestId('group-single')).toContainText('Dieses Gateway läuft allein')
  await expect(page.getByTestId('group-members')).toHaveCount(0)
  expect(await axe(page)).toEqual([])
  await noOverflow(page)
})

test('a node of a group shows the group, its members and the hint on differing configuration', async ({ page, isMobile }) => {
  await page.goto('./?scenario=group#/server')
  const mode = page.getByTestId('group-mode')
  await expect(mode).toHaveAttribute('data-mode', 'group')
  await expect(mode).toContainText(isMobile ? 'Cluster · 3' : 'Cluster · 3 Server')
  const card = page.getByTestId('group-card')
  await expect(card.getByTestId('group-state')).toContainText('Abgleich eingeschränkt')
  await expect(card.getByTestId('group-member')).toHaveCount(3)
  await expect(card.getByTestId('group-self')).toHaveCount(1)
  await expect(card.locator('[data-testid="group-member"][data-name="web-3"]')).toContainText('Nicht erreichbar')
  await expect(card.getByTestId('group-config-hint')).toContainText('web-2')
  await expect(card.getByTestId('group-edge')).toHaveCount(2)
  await expect(card.getByTestId('group-removed')).toContainText('web-0')
  expect(await axe(page)).toEqual([])
  await noOverflow(page)

  // The list of blocked addresses names the node that decided.
  await page.goto('./?scenario=group#/blocks')
  await expect(page.getByTestId('block-node').first()).toHaveText('Von web-2 entschieden')
  await expect(page.getByTestId('group-mode')).toHaveAttribute('data-mode', 'group')
})

test('the page of the group shows every gateway with its state and load', async ({ page, isMobile }) => {
  await page.goto('./?scenario=group#/')
  await page.getByTestId('group-mode').click()
  await expect(page).toHaveURL(/#\/server\/group$/)
  await expect(page.getByTestId('group-page-state')).toContainText('Abgleich eingeschränkt')
  await expect(page.getByTestId('group-total-ready')).toContainText('2 von 3')
  await expect(page.getByTestId('group-total-rps')).toContainText('80,5')
  const nodes = page.getByTestId('group-node')
  await expect(nodes).toHaveCount(3)
  const self = page.locator('[data-testid="group-node"][data-name="web-1"]')
  await expect(self.getByTestId('group-node-self')).toHaveCount(1)
  await expect(self.getByTestId('group-node-service')).toContainText('Nimmt Anfragen an')
  await expect(self.getByTestId('group-node-rps')).toHaveText('41,6')
  await expect(self.getByTestId('group-node-cpu')).toContainText('22')
  const away = page.locator('[data-testid="group-node"][data-name="web-3"]')
  await expect(away.getByTestId('group-node-service')).toContainText('Nicht erreichbar')
  await expect(away.getByTestId('group-node-rps')).toHaveCount(0)
  // The map draws the internet and the three gateways side by side, each linked with the internet.
  if (!isMobile) {
    const map = page.getByTestId('group-map')
    await expect(map.getByTestId('group-map-internet')).toContainText('Internet')
    await expect(map.getByTestId('group-map-node')).toHaveCount(3)
    await expect(map.locator('[data-testid="group-map-link"][data-kind="ready"]')).toHaveCount(2)
    await expect(map.locator('[data-testid="group-map-link"][data-kind="not"]')).toHaveCount(1)
    const tops = await map.locator('[data-testid="group-map-node"] rect').evaluateAll(els => els.map(e => Math.round(e.getBoundingClientRect().top)))
    expect(new Set(tops).size).toBe(1)
  }
  await expect(page.getByTestId('group-page-config-hint')).toContainText('web-2')
  expect(await axe(page)).toEqual([])
  await noOverflow(page)
})

test('a single gateway lists no page of the group', async ({ page }) => {
  await page.goto('./#/server')
  await expect(page.getByRole('link', { name: 'Cluster', exact: true })).toHaveCount(0)
  await page.goto('./#/server/group')
  await expect(page.getByTestId('group-single')).toContainText('Dieses Gateway läuft allein')
})

test('a node of the map opens its details in a sheet', async ({ page, isMobile }) => {
  test.skip(isMobile, 'the map is hidden on narrow screens')
  await page.goto('./?scenario=group#/server/group')
  await page.locator('[data-testid="group-map-node"][data-name="web-2"]').click()
  const sheet = page.getByTestId('group-node-sheet')
  await expect(sheet).toContainText('web-2')
  await expect(sheet.getByTestId('group-node-service')).toContainText('Nimmt Anfragen an')
  await expect(sheet.getByTestId('group-node-rps')).toHaveText('38,9')
  expect(await axe(page)).toEqual([])
  await page.keyboard.press('Escape')
  await expect(sheet).toHaveCount(0)
  // By keyboard too.
  await page.locator('[data-testid="group-map-node"][data-name="web-3"]').focus()
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('group-node-sheet').getByTestId('group-node-service')).toContainText('Nicht erreichbar')
})

test('sixteen gateways stay readable: side by side below the internet, a table instead of cards', async ({ page, isMobile }) => {
  await page.goto('./?scenario=group-large#/server/group')
  await expect(page.getByTestId('group-total-ready')).toContainText('13 von 16')
  await expect(page.getByTestId('group-node-row')).toHaveCount(16)
  await expect(page.getByTestId('group-node')).toHaveCount(0)
  if (!isMobile) {
    const map = page.getByTestId('group-map')
    await expect(map.getByTestId('group-map-node')).toHaveCount(16)
    // One line from the internet to every gateway and none between them; all boxes have one size.
    await expect(map.getByTestId('group-map-link')).toHaveCount(16)
    await expect(map.locator('[data-testid="group-map-link"][data-kind="not"]')).toHaveCount(3)
    const widths = await map.locator('[data-testid="group-map-node"] rect').evaluateAll(els => els.map(e => Math.round(e.getBoundingClientRect().width)))
    expect(new Set(widths).size).toBe(1)
    // All sixteen stand in one row.
    const rowTops = await map.locator('[data-testid="group-map-node"] rect').evaluateAll(els => els.map(e => Math.round(e.getBoundingClientRect().top)))
    expect(new Set(rowTops).size).toBe(1)
    // No two gateways overlap.
    const boxes = await map.locator('[data-testid="group-map-node"] rect').evaluateAll(els => els.map((e) => { const r = e.getBoundingClientRect(); return [r.left, r.top, r.right, r.bottom] }))
    const hit = boxes.some((a, i) => boxes.some((b, j) => j > i && a[0]! < b[2]! && b[0]! < a[2]! && a[1]! < b[3]! && b[1]! < a[3]!))
    expect(hit).toBe(false)
  }
  await page.locator('[data-testid="group-node-row"][data-name="web-12"]').click()
  await expect(page.getByTestId('group-node-sheet').getByTestId('group-node-service')).toContainText('Wird angehalten')
  expect(await axe(page)).toEqual([])
  await page.keyboard.press('Escape')
  await noOverflow(page)
})
