import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

test('start page loads in mock mode with shell landmarks', async ({ page }) => {
  await page.goto('./')
  await expect(page.getByRole('heading', { level: 1, name: 'Alle Websites' })).toBeVisible()
  await expect(page.locator('main#main')).toBeVisible()
  await expect(page).toHaveTitle('Alle Websites · Schild')
})

test('sidebar navigation (desktop): one website in the switcher, the sub-page stays', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop only')
  await page.goto('./')
  const nav = page.getByRole('navigation', { name: 'Hauptnavigation' })
  // "Alle Websites" lists only the events of every website (D68).
  await expect(nav.getByRole('link', { name: 'Zugriffe' })).toHaveCount(0)
  await expect(nav.getByRole('link', { name: 'Ereignisse' })).toHaveAttribute('href', /#\/events$/)
  await page.getByTestId('website-switcher').click()
  await page.getByTestId('switcher-item').filter({ hasText: 'verein.example' }).click()
  await expect(page).toHaveURL(/#\/w\/verein\.example$/)
  await expect(nav.getByRole('link', { name: 'Zugriffe' })).toHaveAttribute('aria-current', 'page')
  await nav.getByRole('link', { name: 'Ereignisse' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Ereignisse' })).toBeVisible()
  await expect(nav.getByRole('link', { name: 'Ereignisse' })).toHaveAttribute('aria-current', 'page')
  await page.getByTestId('website-switcher').click()
  await page.getByTestId('switcher-item').filter({ hasText: 'shop.example' }).click()
  await expect(page).toHaveURL(/#\/w\/shop\.example\/events$/)
  // Servers stand in the switcher beside the websites; a server swaps the sidebar to its pages.
  await expect(nav.getByRole('link', { name: 'Auslastung' })).toHaveCount(0)
  await page.getByTestId('website-switcher').click()
  await page.getByTestId('server-item').first().click()
  await expect(page).toHaveURL(/#\/server$/)
  await expect(nav.getByRole('link', { name: 'Ereignisse' })).toHaveCount(0)
  await nav.getByRole('link', { name: 'Auslastung' }).click()
  await expect(page).toHaveURL(/#\/server\/load$/)
  await expect(page.getByTestId('server-switcher')).toHaveCount(0)
})

test('mobile navigation opens as a sheet', async ({ page, isMobile }) => {
  test.skip(!isMobile, 'mobile only')
  await page.goto('./')
  await page.getByRole('button', { name: 'Seitenleiste ein- oder ausblenden' }).click()
  const dialog = page.getByRole('dialog', { name: 'Navigation' })
  await expect(dialog).toBeVisible()
  await dialog.getByRole('link', { name: 'Datenschutz' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Datenschutz' })).toBeVisible()
  await expect(dialog).toBeHidden()
  // No horizontal scrolling at 390px.
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow).toBeLessThanOrEqual(0)
})

// Messung 2026-10-29 abend 4.5: the header overflowed by 82-98 px at 360-430 px.
for (const width of [360, 390, 430]) {
  test(`header fits at ${width} px: mode, search and theme toggle on screen`, async ({ page, isMobile }) => {
    test.skip(!isMobile, 'mobile only')
    await page.setViewportSize({ width, height: 800 })
    for (const path of ['./', './#/w/shop.example/events', './#/behaviour']) {
      await page.goto(path)
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
      const header = await page.evaluate(() => {
        const h = document.querySelector('header')!
        return { overflow: h.scrollWidth - h.clientWidth, doc: document.documentElement.scrollWidth - document.documentElement.clientWidth }
      })
      expect(header).toEqual({ overflow: 0, doc: 0 })
      for (const control of [page.getByTestId('mode-indicator'), page.getByRole('button', { name: 'Suchen' }), page.getByRole('button', { name: 'Darstellung wählen' })]) {
        const box = (await control.boundingBox())!
        expect(box.x + box.width).toBeLessThanOrEqual(width)
      }
    }
  })
}

test('desktop breadcrumb is not clipped to a fixed width', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop only')
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('./#/w/shop.example/events')
  await expect(page.getByRole('heading', { level: 1, name: 'Ereignisse' })).toBeVisible()
  const crumb = page.locator('header [data-slot="breadcrumb-page"]')
  await expect(crumb).toHaveText('Ereignisse')
  expect(await crumb.evaluate(e => e.scrollWidth <= e.clientWidth)).toBe(true)
})

test('command palette navigates with the keyboard', async ({ page }) => {
  await page.goto('./')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await page.keyboard.press('ControlOrMeta+k')
  const palette = page.getByRole('dialog', { name: 'Befehle' })
  await expect(palette).toBeVisible()
  await page.keyboard.type('Datensch')
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { level: 1, name: 'Datenschutz' })).toBeVisible()
})

test('dark mode toggles via class and persists locally', async ({ page }) => {
  await page.goto('./')
  await page.getByRole('button', { name: 'Darstellung wählen' }).click()
  await page.getByRole('menuitemradio', { name: 'Dunkel' }).click()
  await expect(page.locator('html')).toHaveClass(/dark/)
  await page.reload()
  await expect(page.locator('html')).toHaveClass(/dark/)
})

test('mock API answers through MSW', async ({ page }) => {
  await page.goto('./')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  const res = await page.evaluate(async () => {
    const r = await fetch('./api/v0/does-not-exist')
    return { status: r.status, type: r.headers.get('content-type') }
  })
  expect(res.status).toBe(404)
  expect(res.type).toContain('application/problem+json')
})

for (const path of ['./', './#/styleguide']) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`no axe WCAG violations: ${path} (${scheme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto(path)
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
      await page.waitForTimeout(300)
      const result = await new AxeBuilder({ page }).withTags(WCAG).analyze()
      const summary = result.violations.map(v => `${v.id}: ${v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ')}`)
      expect(summary).toEqual([])
    })
  }
}
