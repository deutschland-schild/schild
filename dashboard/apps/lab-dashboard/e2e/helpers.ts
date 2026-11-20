import type { Page } from '@playwright/test'
import { expect } from '@playwright/test'

/** Log in to the mock lab (any password except "falsch"). */
export async function login(page: Page, path = './') {
  await page.goto(path)
  await page.getByLabel('Passwort', { exact: true }).fill('geheim')
  await page.getByRole('button', { name: 'Anmelden' }).click()
  await expect(page.locator('main#main h1')).toBeVisible()
}

export async function go(page: Page, hash: string) {
  await page.goto(`./${hash}`)
  await expect(page.locator('main#main h1')).toBeVisible()
}
