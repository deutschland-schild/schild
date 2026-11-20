import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

// D56: the Zugriffsschutz page and its dialog, light and dark, without axe findings or a horizontal scroll.
for (const scheme of ['light', 'dark'] as const) {
  test(`Zugriffsschutz: page and dialog pass axe (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
    await page.goto('./?scenario=default#/w/verein.example/access')
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await expect(page.getByTestId('access-setup')).toBeVisible()
    const check = async (where: string) => {
      const result = await new AxeBuilder({ page }).withTags(WCAG).analyze()
      expect(result.violations.map(v => `${where}: ${v.id}: ${v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ')}`)).toEqual([])
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
      expect(overflow, where).toBeLessThanOrEqual(0)
    }
    await check('page')
    await page.getByTestId('access-setup').click()
    await expect(page.getByTestId('access-dialog')).toBeVisible()
    await page.waitForTimeout(300)
    await check('dialog')
    await page.getByTestId('access-password').fill('korrekt-pferd')
    await page.getByTestId('access-submit').click()
    await expect(page.getByTestId('access-ways')).toContainText('Passwort')
    await page.goto('./?scenario=default#/w/verein.example')
    await expect(page.getByTestId('access-banner')).toContainText('Nur mit Passwort erreichbar')
  })
}
