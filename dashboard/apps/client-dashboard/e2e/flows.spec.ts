import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

// Each test gets its own page, so the mock state starts fresh (scenario sticks per tab via sessionStorage).

test('U1: Allgemein shows what blocks and the test profile at once', async ({ page }) => {
  await page.goto('./?scenario=observe#/settings')
  await expect(page.getByTestId('test-profile-banner')).toBeVisible()
  await expect(page.getByTestId('protection-sources')).toContainText('OWASP CRS')
})

test('U2: unblock an incident and allow the IP for 7 days', async ({ page }) => {
  await page.goto('./#/incidents')
  await page.getByTestId('incident-input').fill('k7qm4xwd')
  await expect(page.getByTestId('incident-input')).toHaveValue('K7QM-4XWD')
  await page.getByTestId('incident-search').click()
  await expect(page.getByTestId('incident-card')).toContainText('2001:db8::17')
  await page.getByTestId('incident-unblock').click()
  const dialog = page.getByRole('dialog', { name: /Vorfall K7QM-4XWD freischalten/ })
  await expect(dialog.getByTestId('unblock-ttl')).toHaveValue('7d')
  await dialog.getByText('Nein oder unklar, nur diesmal freischalten').click()
  await dialog.getByTestId('unblock-submit').click()
  await expect(page.getByTestId('incident-status')).toHaveText('Freigeschaltet')
  await expect(page.getByText('Vorfall K7QM-4XWD freigeschaltet')).toBeVisible()
  await page.goto('./#/own-ips')
  await expect(page.getByRole('table')).toContainText('Vorfall K7QM-4XWD')
})

test('U4: switch to review, the mode explains rule updates', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop flow')
  await page.goto('./#/settings#mode')
  await page.getByTestId('mode-review').click()
  await expect(page.getByTestId('mode-explain')).toContainText('erkennen nur, bis du sie unter Regeln freigibst')
  await page.getByTestId('mode-save').click()
  await page.getByTestId('confirm-submit').click()
  await expect(page.getByTestId('mode-indicator')).toContainText('Freigeben')
})

test('U5: export and delete everything about one IP', async ({ page }) => {
  await page.goto('./#/privacy')
  await page.getByTestId('privacy-ip').fill('203.0.113.42')
  await page.getByTestId('privacy-search').click()
  await expect(page.getByTestId('privacy-result')).toBeVisible()
  const download = page.waitForEvent('download')
  await page.getByTestId('privacy-export').click()
  expect((await download).suggestedFilename()).toMatch(/^schild-export-203-0-113-42-.*\.json$/)
  await page.getByTestId('privacy-delete').click()
  await page.getByTestId('privacy-confirm').fill('203.0.113.42')
  await page.getByTestId('privacy-confirm-delete').click()
  await expect(page.getByTestId('privacy-events')).toContainText('0')
})

test('events: filter chips are deep links, detail opens, live mode streams', async ({ page }) => {
  await page.goto('./?live=400#/events?outcome=blocked')
  await expect(page.getByTestId('filter-chip')).toContainText('Gesperrt')
  const rows = page.getByRole('table', { name: 'Ereignisse' }).locator('tbody tr[data-row]')
  await expect(rows.first()).toContainText('Gesperrt')
  await rows.first().click()
  await expect(page).toHaveURL(/event=/)
  await expect(page.getByTestId('event-sheet')).toContainText('Warum')
  await page.keyboard.press('Escape')
  await expect(page).not.toHaveURL(/event=/)
  await page.getByTestId('live-toggle').click()
  await expect(page.getByTestId('live-state')).toContainText('Live')
  await page.getByTestId('live-pause').click()
  await expect(page.getByTestId('live-state')).toContainText('Pausiert')
})

test('first run: setup wizard to the overview', async ({ page }) => {
  await page.goto('./?scenario=first-run#/')
  await expect(page).toHaveURL(/#\/setup/)
  await page.getByTestId('setup-code').fill('K7QM4XWD')
  await page.getByTestId('setup-password').fill('ein langes passwort 42')
  await page.getByTestId('setup-repeat').fill('ein langes passwort 42')
  await page.getByRole('button', { name: 'Weiter' }).click()
  await expect(page.getByRole('heading', { name: 'Wie soll Schild arbeiten?' })).toBeVisible()
  await page.getByRole('button', { name: 'Weiter' }).click()
  await page.getByTestId('setup-finish').click()
  await expect(page.getByRole('heading', { level: 1, name: 'Alle Websites' })).toBeVisible()
})

test('login: the dashboard never shows before the session is known', async ({ page }) => {
  await page.addInitScript(() => {
    new MutationObserver(() => {
      if (document.body?.textContent?.includes('Abmelden')) (window as { shellSeen?: boolean }).shellSeen = true
    }).observe(document, { childList: true, subtree: true, characterData: true })
  })
  await page.goto('./?scenario=login#/login')
  await expect(page.getByTestId('login-password')).toBeVisible()
  expect(await page.evaluate(() => (window as { shellSeen?: boolean }).shellSeen)).toBeUndefined()
})

test('login: wrong password, then back to the requested page', async ({ page }) => {
  await page.goto('./?scenario=login#/settings/rules')
  await expect(page).toHaveURL(/#\/login/)
  await page.getByTestId('login-password').fill('falsch')
  await page.keyboard.press('Enter')
  await expect(page.getByRole('alert')).toContainText('Das Passwort stimmt nicht')
  await page.getByTestId('login-password').fill('mock-passwort-123')
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { level: 1, name: 'Regeln' })).toBeVisible()
})

test('keyboard: ? opens the help, g i goes to Eigene IPs', async ({ page, isMobile }) => {
  test.skip(isMobile, 'keyboard')
  await page.goto('./#/settings')
  await expect(page.getByTestId('protection-sources')).toBeVisible()
  await page.keyboard.press('Shift+?')
  await expect(page.getByRole('dialog', { name: 'Tastenkürzel' })).toBeVisible()
  await page.keyboard.press('Escape')
  await page.keyboard.press('g')
  await page.keyboard.press('i')
  await expect(page.getByRole('heading', { level: 1, name: 'Eigene IPs' })).toBeVisible()
})

test('no horizontal scrolling on the server overview, Zugriffe of a website and Vorfall', async ({ page }) => {
  for (const path of ['./#/', './#/w/verein.example', './#/incidents/K7QM-4XWD']) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await page.waitForTimeout(400)
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow, path).toBeLessThanOrEqual(0)
  }
})

const PAGES = ['', 'w/verein.example', 'w/verein.example?view=requests', 'w/verein.example/events', 'w/verein.example/exceptions', 'w/verein.example/access', 'w/verein.example/ai-crawlers', 'status', 'server/load', 'server/check', 'events', 'incidents/K7QM-4XWD', 'behaviour', 'behaviour?view=scenarios', 'behaviour?view=limits', 'behaviour?view=waves', 'settings/rules', 'settings/rules/crs', 'settings/rules/crowdsec', 'settings/rules/local', 'own-ips', 'privacy?ip=203.0.113.42', 'settings']
for (const scheme of ['light', 'dark'] as const) {
  test(`no axe WCAG 2.2 AA violations on all sections (${scheme})`, async ({ page }) => {
    test.setTimeout(90_000)
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
    for (const p of [...PAGES, 'login']) {
      await page.goto(p === 'login' ? './?scenario=login#/login' : `./?scenario=default#/${p}`)
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
      await page.waitForTimeout(500)
      const result = await new AxeBuilder({ page }).withTags(WCAG).analyze()
      const summary = result.violations.map(v => `${p}: ${v.id}: ${v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ')}`)
      expect(summary).toEqual([])
    }
  })
}
