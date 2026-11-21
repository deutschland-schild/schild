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
  await expect(mode).toContainText(isMobile ? 'Gruppe · 3' : 'Gruppe · 3 Server')
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
