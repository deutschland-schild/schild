import { expect, test } from '@playwright/test'

test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('./#/styleguide')
  await expect(page.getByRole('heading', { level: 1, name: 'Styleguide' })).toBeVisible()
})

test('data table: sort, keyboard rows, detail sheet', async ({ page }) => {
  const table = page.getByRole('table', { name: 'Ereignisse (Beispieldaten)' })
  await table.getByRole('button', { name: 'Score' }).click()
  await expect(table.getByRole('columnheader', { name: 'Score' })).toHaveAttribute('aria-sort', 'ascending')
  const rows = table.locator('tbody tr[data-row]')
  await rows.first().focus()
  await page.keyboard.press('ArrowDown')
  await expect(rows.nth(1)).toBeFocused()
  await page.keyboard.press('Enter')
  const sheet = page.getByRole('dialog')
  await expect(sheet).toBeVisible()
  await expect(sheet.getByText('verlässt den Server nie')).toBeVisible()
  // An Escape may first close a tooltip opened by the auto-focused IP address (it can open
  // a moment after the sheet), the next one closes the sheet: press until it is gone.
  for (let i = 0; i < 3 && await sheet.isVisible(); i++) {
    await page.keyboard.press('Escape')
    await sheet.waitFor({ state: 'hidden', timeout: 1500 }).catch(() => {})
  }
  await expect(sheet).toBeHidden()
  await expect(rows.nth(1)).toBeFocused()
})

test('filter chips filter and can be removed', async ({ page }) => {
  const chip = page.getByTestId('filter-chip')
  await expect(chip).toHaveCount(1)
  await page.getByRole('button', { name: 'Filter Art: Abgewehrt entfernen' }).click()
  await expect(chip).toHaveCount(0)
})

test('confirm dialog needs the typed phrase', async ({ page }) => {
  await page.getByRole('button', { name: 'Daten löschen …' }).click()
  const dialog = page.getByRole('alertdialog', { name: 'Daten zu dieser IP löschen?' })
  const action = dialog.getByRole('button', { name: 'Löschen', exact: true })
  await expect(action).toBeDisabled()
  await dialog.getByRole('textbox').fill('LÖSCHEN')
  await expect(action).toBeEnabled()
  await action.click()
  await expect(page.getByText('Daten gelöscht')).toBeVisible()
})

test('form validation messages are attached to fields', async ({ page }) => {
  await page.getByRole('button', { name: 'Eigene IP hinzufügen' }).click()
  await expect(page.getByText('Bitte gib einen Namen ein.')).toBeVisible()
  const name = page.getByLabel('Name', { exact: true })
  await expect(name).toHaveAttribute('aria-invalid', 'true')
})

test('reduced motion disables animations', async ({ page }) => {
  const duration = await page.evaluate(() => {
    const el = document.querySelector('.motion-safe\\:animate-ping, [class*="animate-"]')
    return el ? getComputedStyle(el).animationDuration : '0s'
  })
  expect(['0s', '1e-05s', '0.00001s']).toContain(duration)
})
