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

// One server at a time (2026-11-02): the switcher in the sidebar picks it, the check shows only that one.
test('MVP-11: findings by area of the gateway, EOL host and silent agent through the switcher', async ({ page, isMobile }) => {
  test.skip(isMobile, 'switcher in the desktop sidebar')
  await page.goto('./#/server/check')
  await expect(page.getByRole('heading', { level: 1, name: 'web-1' })).toBeVisible()
  await expect(page.getByTestId('host-item')).toHaveCount(0)
  await expect(page.getByTestId('host-detail')).toContainText('Redis ist aus dem Netz erreichbar')
  await expect(page.getByTestId('check-now')).toBeVisible()
  await page.getByTestId('website-switcher').click()
  await page.getByTestId('server-item').filter({ hasText: 'verein-alt.example' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'verein-alt.example' })).toBeVisible()
  await expect(page.getByTestId('os-support')).toContainText('keine Sicherheitsupdates mehr')
  await expect(page.getByTestId('inventory').locator('[data-eol="past"]').first()).toBeVisible()
  await expect(page.getByTestId('check-now')).toHaveCount(0)
  await page.getByTestId('website-switcher').click()
  await page.getByTestId('server-item').filter({ hasText: 'app-2.example' }).click()
  await expect(page.getByTestId('silent-banner')).toContainText('meldet sich nicht')
  await noOverflow(page)
})

test('MVP-11: "Jetzt prüfen" on the gateway', async ({ page }) => {
  await page.goto('./#/server/check')
  await page.getByTestId('check-now').click()
  await expect(page.getByTestId('check-now')).toContainText('Prüfung läuft')
  await expect(page.getByText('Prüfung fertig')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByTestId('check-now')).toContainText('Jetzt prüfen')
})

test('MVP-11: enrol an app server and copy the command', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.goto('./#/settings')
  await expect(page.getByTestId('servers-card')).toContainText('1 meldet sich nicht')
  await page.keyboard.press('ControlOrMeta+k')
  await page.keyboard.type('Server hinzufügen')
  await page.keyboard.press('Enter')
  const dialog = page.getByTestId('enrol-dialog')
  await expect(dialog.getByRole('heading', { name: 'Server hinzufügen' })).toBeVisible()
  await dialog.getByTestId('enrol-label').fill('Wiki')
  await dialog.getByTestId('enrol-create').click()
  await expect(dialog.getByTestId('enrol-command')).toContainText('sudo schild-agent enrol --gateway https://gw-1.example:8790 --gateway-name gw-1')
  await dialog.getByTestId('command-copy').click()
  await expect(dialog.getByTestId('command-copy')).toHaveAccessibleName('Kopiert')
  expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^sudo schild-agent enrol .* --code [A-Z2-9-]{19}$/)
  expect(await axe(page)).toEqual([])
  // The simulated app VM answers after a few seconds.
  await expect(dialog.getByTestId('enrol-fingerprint')).toBeVisible({ timeout: 15_000 })
  const fp = await page.evaluate(() => (window as unknown as { __schildMock: { hosts: { agents: { id: string, fingerprint: string }[] } } }).__schildMock.hosts.agents.find(a => a.id === 'wiki')!.fingerprint)
  await dialog.getByTestId('enrol-fingerprint-input').fill(fp)
  await expect(dialog.getByTestId('enrol-match')).toContainText('Stimmt überein')
  expect(await axe(page)).toEqual([])
  await dialog.getByTestId('enrol-confirm').click()
  await expect(page.getByText('wiki.example ist bestätigt')).toBeVisible()
  await expect(page.getByTestId('host-detail')).toContainText('wiki.example')
  await expect(page.getByTestId('waiting-banner')).toBeVisible()
  await noOverflow(page)
})

test('MVP-11: revoke an agent after asking', async ({ page }) => {
  await page.goto('./#/server/check?view=agents')
  const row = page.getByTestId('agent-row').filter({ hasText: 'app-1.example' })
  await row.getByTestId('agent-revoke').click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('sofort und dauerhaft')
  await dialog.getByTestId('confirm-submit').click()
  await expect(row).toContainText('Zurückgezogen')
})

test('MVP-11: empty state explains agents', async ({ page }) => {
  await page.goto('./?scenario=empty#/server/check?view=agents')
  await expect(page.getByTestId('agents-empty')).toContainText('bleibt auf deinen Servern')
  expect(await axe(page)).toEqual([])
})

for (const scheme of ['light', 'dark'] as const) {
  for (const view of ['#/server/check', '#/server/check?server=verein-alt', '#/server/check?server=app-2', '#/server/check?view=agents'] as const) {
    test(`MVP-11: no axe WCAG violations: ${view} (${scheme})`, async ({ page }) => {
      if (scheme === 'dark') await page.addInitScript(() => localStorage.setItem('schild-color-scheme', 'dark'))
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto(`./${view}`)
      // An agent's check carries its own name (2026-11-02).
      const title = view.includes('verein-alt') ? 'verein-alt.example' : view.includes('app-2') ? 'app-2.example' : 'web-1'
      await expect(page.getByRole('heading', { level: 1, name: title })).toBeVisible()
      await expect(page.locator('[data-slot="skeleton"]')).toHaveCount(0)
      if (scheme === 'dark') await expect(page.locator('html')).toHaveClass(/dark/)
      expect(await axe(page)).toEqual([])
      await noOverflow(page)
    })
  }
}
