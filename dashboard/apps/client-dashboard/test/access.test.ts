import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import type { AccessProtection } from '../src/api/access'
import { accessTitle, ACCESS_COPY, isAccessAddress, isAccessPath, lines, MAINTENANCE_COPY, scopeText, waysText } from '../src/lib/access'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, type, waitFor } from './helpers'

const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  mock.reset()
})
afterAll(() => mock.server.close())

const site: AccessProtection = {
  scope: 'site', password: true, addresses: ['203.0.113.7', '198.51.100.0/24'], own_networks: true,
  message: '', updated_at: '2026-11-02T12:00:00Z', actor: 'dashboard',
}

describe('Zugriffsschutz copy and helpers', () => {
  it('keeps the required wording', () => {
    const all = [...Object.values(ACCESS_COPY), ...Object.values(MAINTENANCE_COPY).map(v => typeof v === 'function' ? `${v(1)} ${v(3)}` : v)].join(' ')
    expect(all).not.toMatch(/anonym/i)
    expect(all).not.toMatch(/\b(geschützt|sicher|gefährlich|dringend)\b/i)
    expect(all).not.toMatch(/\bSie\b|\bIhr(e|en)?\b/)
    expect(all).not.toMatch(/Schwachstelle|Sicherheitslücke/)
  })

  it('validates paths and addresses like the gateway', () => {
    expect(isAccessPath('/wp-admin/*')).toBe(true)
    expect(isAccessPath('/wp-login.php')).toBe(true)
    expect(isAccessPath('/*')).toBe(false)
    expect(isAccessPath('/wp-*/x')).toBe(false)
    expect(isAccessPath('wp-admin')).toBe(false)
    expect(isAccessPath('/a;b', true)).toBe(false)
    expect(isAccessAddress('203.0.113.7')).toBe(true)
    expect(isAccessAddress('198.51.100.0/24')).toBe(true)
    expect(isAccessAddress('10.0.0.0/8')).toBe(false)
    expect(isAccessAddress('2001:db8::/48')).toBe(true)
    expect(isAccessAddress('2001:db8::/16')).toBe(false)
    expect(lines(' /a \n\n/b\n/a')).toEqual(['/a', '/b'])
  })

  it('says what the protection is, by its ways in', () => {
    expect(accessTitle({ ...site, addresses: [], own_networks: false })).toBe('Nur mit Passwort erreichbar')
    expect(accessTitle(site)).toBe('Nur mit Passwort und von freigegebenen IPs erreichbar')
    expect(accessTitle({ ...site, password: false })).toBe('Nur von freigegebenen IPs erreichbar')
    // The maintenance mode is a switch of its own (D98): a protection for own IPs only is named as what it is.
    expect(accessTitle({ ...site, password: false, addresses: [], own_networks: true })).toBe('Nur von freigegebenen IPs erreichbar')
  })

  it('describes a protection in two rows', () => {
    // D58: password and IPs must both hold; the two IP lists are one condition.
    expect(waysText(site)).toBe('Passwort und 2 IPs oder Eigene IPs')
    expect(waysText({ ...site, addresses: [] })).toBe('Passwort und Eigene IPs')
    expect(waysText({ ...site, addresses: [], own_networks: false })).toBe('Passwort')
    expect(waysText({ ...site, password: false, own_networks: false, addresses: ['203.0.113.7'] })).toBe('IP 203.0.113.7')
    expect(scopeText({ ...site, scope: 'paths', paths: ['/wp-admin/*', '/wp-login.php'] })).toBe('/wp-admin/*, /wp-login.php')
    expect(scopeText(site)).toBe('Ganze Website')
  })
})

describe('Zugriffsschutz page', () => {
  it('sets a site lock, shows it on the overview and lifts it', async () => {
    await mountApp('/w/verein.example/access')
    await waitFor(() => !!byTestId('access-setup'))
    expect(byTestId('access-ways')!.textContent).toContain('Aus')
    await click(byTestId('access-setup'))
    await waitFor(() => !!byTestId('access-dialog'))
    // No way in: the form says so and sends nothing.
    await click(byTestId('access-use-password'))
    await click(byTestId('access-submit'))
    expect(bodyText()).toContain(ACCESS_COPY.noWayIn)
    expect(mock.state.access['verein.example']).toBeUndefined()
    await click(byTestId('access-use-password'))
    await type(byTestId('access-password'), 'korrekt-pferd')
    await type(byTestId('access-except'), '/api/stripe/webhook')
    await click(byTestId('access-submit'))
    await waitFor(() => !!mock.state.access['verein.example'])
    const p = mock.state.access['verein.example']!
    expect(p.scope).toBe('site')
    expect(p.password).toBe(true)
    expect(p.except).toEqual(['/api/stripe/webhook'])
    expect(p).not.toHaveProperty('until')
    await waitFor(() => byTestId('access-ways')!.textContent!.includes('Passwort'))

    cleanup()
    await mountApp('/w/verein.example')
    await waitFor(() => !!byTestId('access-banner'))
    expect(byTestId('access-banner')!.textContent).toContain('Nur mit Passwort erreichbar')
    expect(byTestId('access-banner')!.textContent).toContain(ACCESS_COPY.stays)
    expect(byTestId('access-extend')).toBeNull()
    await click(byTestId('access-remove'))
    await waitFor(() => !!byTestId('access-remove-confirm'))
    await click(byTestId('access-remove-confirm'))
    await waitFor(() => !mock.state.access['verein.example'])
    await waitFor(() => !byTestId('access-banner'))
  })

  it('protects paths for one address without a password', async () => {
    await mountApp('/w/verein.example/access')
    await waitFor(() => !!byTestId('access-setup'))
    await click(byTestId('access-setup'))
    await waitFor(() => !!byTestId('access-dialog'))
    await click(byTestId('access-scope-paths'))
    await click(byTestId('access-use-password'))
    await click(byTestId('access-use-addresses'))
    await type(byTestId('access-addresses'), '10.0.0.0/8')
    await click(byTestId('access-submit'))
    expect(bodyText()).toContain('„10.0.0.0/8“ geht nicht')
    await type(byTestId('access-addresses'), '203.0.113.7')
    await click(byTestId('access-submit'))
    await waitFor(() => !!mock.state.access['verein.example'])
    const p = mock.state.access['verein.example']!
    expect(p).toMatchObject({ scope: 'paths', paths: ['/wp-admin/*', '/wp-login.php'], password: false, addresses: ['203.0.113.7'] })
    await waitFor(() => byTestId('access-ways')!.textContent!.includes('IP 203.0.113.7'))
  })

  it('switches the maintenance mode on with a text and off again', async () => {
    await mountApp('/w/verein.example/access')
    await waitFor(() => !!byTestId('maintenance-own-ips'))
    expect(byTestId('maintenance-own-ips')!.textContent).toMatch(/eigene(n)? IP/)
    await type(byTestId('maintenance-message'), 'Update läuft, gegen 22 Uhr sind wir zurück.')
    await click(byTestId('maintenance-switch'))
    await waitFor(() => !!byTestId('maintenance-confirm'))
    expect(bodyText()).toContain(MAINTENANCE_COPY.confirmOn)
    await click(byTestId('maintenance-confirm'))
    await waitFor(() => !!mock.state.maintenance['verein.example'])
    // A switch of its own (D98): no protection is created for it.
    expect(mock.state.maintenance['verein.example']).toMatchObject({ message: 'Update läuft, gegen 22 Uhr sind wir zurück.' })
    expect(mock.state.access['verein.example']).toBeUndefined()
    await waitFor(() => !!byTestId('maintenance-on'))
    expect(byTestId('maintenance-with-protection')).toBeNull()
    await click(byTestId('maintenance-switch'))
    await waitFor(() => bodyText().includes(MAINTENANCE_COPY.confirmOff))
    await click(byTestId('maintenance-confirm'))
    await waitFor(() => !mock.state.maintenance['verein.example'])
    await waitFor(() => !byTestId('maintenance-on'))
  })

  it('switches the maintenance mode on with a protection of single paths set, and leaves that protection alone (D98)', async () => {
    mock.state.access['verein.example'] = { ...site, scope: 'paths', paths: ['/wp-admin/*'] }
    await mountApp('/w/verein.example/access')
    await waitFor(() => !!byTestId('maintenance-with-protection'))
    expect(byTestId('maintenance-switch')!.hasAttribute('disabled')).toBe(false)
    await click(byTestId('maintenance-switch'))
    await waitFor(() => !!byTestId('maintenance-confirm'))
    await click(byTestId('maintenance-confirm'))
    await waitFor(() => !!mock.state.maintenance['verein.example'])
    await waitFor(() => !!byTestId('maintenance-on'))
    expect(mock.state.access['verein.example']).toMatchObject({ scope: 'paths', paths: ['/wp-admin/*'] })
    await click(byTestId('maintenance-switch'))
    await waitFor(() => bodyText().includes(MAINTENANCE_COPY.confirmOff))
    await click(byTestId('maintenance-confirm'))
    await waitFor(() => !mock.state.maintenance['verein.example'])
    expect(mock.state.access['verein.example']).toMatchObject({ scope: 'paths' })
  })

  it('sets password and own IPs together and says both must hold', async () => {
    await mountApp('/w/verein.example/access')
    await waitFor(() => !!byTestId('access-setup'))
    await click(byTestId('access-setup'))
    await waitFor(() => !!byTestId('access-dialog'))
    expect(bodyText()).toContain(ACCESS_COPY.waysExplain)
    expect(bodyText()).not.toContain('Bis wann?')
    await type(byTestId('access-password'), 'korrekt-pferd')
    await click(byTestId('access-own-networks'))
    await click(byTestId('access-use-addresses'))
    await waitFor(() => !!byTestId('access-ips-together'))
    await click(byTestId('access-use-addresses'))
    await click(byTestId('access-submit'))
    await waitFor(() => !!mock.state.access['verein.example'])
    expect(mock.state.access['verein.example']).toMatchObject({ scope: 'site', password: true, own_networks: true })
    await waitFor(() => byTestId('access-ways')!.textContent!.includes('Passwort und Eigene IPs'))
  })
})
