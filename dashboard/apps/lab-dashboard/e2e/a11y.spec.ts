import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { go, login } from './helpers'

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
const PAGES = ['#/', '#/signals', '#/proposals/prop-0007', '#/published', '#/published/42', '#/published/withdrawals', '#/relays', '#/clients', '#/log', '#/settings']

for (const scheme of ['light', 'dark'] as const) {
  test(`axe WCAG 2.2 AA, ${scheme}`, async ({ page, isMobile }) => {
    test.skip(isMobile, 'desktop covers the same markup')
    test.setTimeout(120_000)
    await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: scheme })
    await page.addInitScript(s => localStorage.setItem('schild-color-scheme', s), scheme)
    // Login screen first.
    await page.goto('./')
    await expect(page.getByRole('heading', { level: 1, name: 'Anmelden' })).toBeVisible()
    const loginScan = await new AxeBuilder({ page }).withTags(WCAG).analyze()
    expect(loginScan.violations, 'login').toEqual([])
    await login(page)
    for (const hash of PAGES) {
      await go(page, hash)
      await page.waitForTimeout(600)
      const r = await new AxeBuilder({ page }).withTags(WCAG).analyze()
      expect(r.violations.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).slice(0, 3).join(' | ')}`), hash).toEqual([])
    }
  })
}

test('axe on the withdraw-all and approval dialogs', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop only')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await login(page)
  await go(page, '#/published/withdrawals')
  await page.getByTestId('open-withdraw-all').click()
  await page.waitForTimeout(300)
  let r = await new AxeBuilder({ page }).withTags(WCAG).analyze()
  expect(r.violations.map(v => v.id)).toEqual([])
  await page.keyboard.press('Escape')
  await go(page, '#/proposals/prop-0007')
  await page.getByTestId('action-approve').click()
  await page.waitForTimeout(300)
  r = await new AxeBuilder({ page }).withTags(WCAG).analyze()
  expect(r.violations.map(v => v.id)).toEqual([])
})
