import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

// D57: the KI-Crawler page with one category open, light and dark, without axe findings or a horizontal scroll.
for (const scheme of ['light', 'dark'] as const) {
  test(`KI-Crawler: page passes axe (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
    await page.goto('./?scenario=default#/w/verein.example/ai-crawlers')
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await expect(page.getByTestId('crawlers-preset')).toBeVisible()
    const check = async (where: string) => {
      const result = await new AxeBuilder({ page }).withTags(WCAG).analyze()
      expect(result.violations.map(v => `${where}: ${v.id}: ${v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ')}`)).toEqual([])
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
      expect(overflow, where).toBeLessThanOrEqual(0)
    }
    await check('page')
    await page.getByTestId('crawlers-preset').click()
    await expect(page.getByTestId('crawlers-preset')).toContainText('KI-Training wieder erlauben')
    // The success toast fades in; axe measures it once it stands.
    await expect(page.locator('[data-sonner-toast][data-mounted="true"]')).toBeVisible()
    await page.waitForTimeout(500)
    await page.getByTestId('crawlers-open-ai_training').click()
    await expect(page.locator('[data-crawler="gptbot"]')).toHaveAttribute('data-effective', 'block')
    await check('open category')
  })
}
