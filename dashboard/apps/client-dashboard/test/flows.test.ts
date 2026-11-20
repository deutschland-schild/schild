import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, settle, toastAction, type, waitFor } from './helpers'

const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
})
afterAll(() => mock.server.close())

function key(k: string) {
  window.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true }))
}

describe('Allgemein with the former Schutzstatus (U1)', () => {
  it('shows the numbers and the sources without a hero or a mode (D89, 2026-11-18)', async () => {
    const { wrapper } = await mountApp('/settings')
    await waitFor(() => (byTestId('protection-sources')?.querySelectorAll('li').length ?? 0) === 3)
    expect(bodyText()).toContain('Anfragen geprüft')
    expect(byTestId('baseline')).toBeNull()
    expect(byTestId('mode-card')).toBeNull()
    expect(bodyText()).not.toContain('Gerade gibt es nichts zu tun')
    expect(bodyText()).not.toMatch(/Verbund|Labs|Signale/)
    expect(bodyText()).not.toMatch(/geschützt|anonym/)
    wrapper.unmount()
  })

  it('names what needs a look when the Grundschutz is degraded', async () => {
    mock.reset({ scenario: 'degraded' })
    const { wrapper } = await mountApp('/settings')
    await waitFor(() => !!byTestId('attention'))
    expect(byTestId('baseline')!.textContent).toContain('Eingeschränkt')
    expect(byTestId('attention')!.querySelectorAll('li').length).toBeGreaterThan(0)
    wrapper.unmount()
  })

  it('shows the test profile on every screen', async () => {
    mock.reset({ scenario: 'observe' })
    const { wrapper, router } = await mountApp('/settings')
    await waitFor(() => !!byTestId('test-profile-banner'))
    expect(bodyText()).toContain('Im Testprofil kam alles durch')
    await router.push('/events')
    await waitFor(() => !!byTestId('test-profile-banner'))
    expect(byTestId('test-profile-banner')!.textContent).toContain('Schild sperrt gerade nichts')
    wrapper.unmount()
  })

  it('shows an error with a next step when the API fails', async () => {
    mock.reset({ scenario: 'error' })
    const { wrapper } = await mountApp('/settings')
    await waitFor(() => bodyText().includes('Die Zahlen lassen sich gerade nicht laden'), 4000)
    expect(bodyText()).toContain('Erneut versuchen')
    wrapper.unmount()
  })

  it('sends old links to /status to Allgemein', async () => {
    const { wrapper, router } = await mountApp('/status')
    await waitFor(() => router.currentRoute.value.path === '/settings')
    wrapper.unmount()
  })
})

describe('Vorfälle (U2)', () => {
  it('saves an incident as a file (D51)', async () => {
    const create = URL.createObjectURL
    const revoke = URL.revokeObjectURL
    let blob: Blob | undefined
    URL.createObjectURL = (b) => { blob = b as Blob; return 'blob:incident' }
    URL.revokeObjectURL = () => {}
    const { wrapper } = await mountApp('/incidents/K7QM-4XWD')
    await waitFor(() => !!byTestId('incident-export'))
    expect(bodyText()).toContain('Fristen und Löschungen erreichen sie nicht mehr')
    await click(byTestId('incident-export'))
    await waitFor(() => !!blob)
    const file = JSON.parse(await blob!.text())
    expect(file.incident.incident).toBe('K7QM-4XWD')
    expect(file.truncated).toBe(false)
    URL.createObjectURL = create
    URL.revokeObjectURL = revoke
    wrapper.unmount()
  })

  it('unblocks K7QM-4XWD and allows the IP for 7 days', async () => {
    const { wrapper } = await mountApp('/incidents/K7QM-4XWD')
    await waitFor(() => !!byTestId('incident-unblock'))
    await click(byTestId('incident-unblock'))
    // Eigene IPs is a separate decision: off by default, 7 days once ticked.
    expect(byTestId<HTMLInputElement>('unblock-allow-ip')!.getAttribute('data-state')).toBe('unchecked')
    await click(byTestId('unblock-allow-ip'))
    await waitFor(() => !!byTestId('unblock-ttl'))
    expect(byTestId<HTMLSelectElement>('unblock-ttl')!.value).toBe('7d')
    await click(byTestId('unblock-fp-no'))
    await click(byTestId('unblock-submit'))
    await waitFor(() => byTestId('incident-status')?.textContent?.includes('Aufgehoben') ?? false)
    const inc = mock.state.incidents.get('K7QM-4XWD')!
    expect(inc.status).toBe('unblocked')
    const entry = mock.state.allowlist.find(a => a.id === inc.allowlist_entry)!
    expect(entry.ip).toBe('2001:db8::17')
    const days = (Date.parse(entry.expires) - Date.now()) / 86_400_000
    expect(days).toBeGreaterThan(6.9)
    expect(days).toBeLessThan(7.1)
    wrapper.unmount()
  })

  it('preselects no false-positive answer and asks before unblocking', async () => {
    const { wrapper } = await mountApp('/incidents/K7QM-4XWD')
    await waitFor(() => !!byTestId('incident-unblock'))
    await click(byTestId('incident-unblock'))
    await waitFor(() => !!byTestId('unblock-fp-yes'))
    expect(byTestId('unblock-fp-yes')!.getAttribute('data-state')).toBe('unchecked')
    expect(byTestId('unblock-fp-no')!.getAttribute('data-state')).toBe('unchecked')
    await click(byTestId('unblock-submit'))
    await waitFor(() => !!byTestId('unblock-fp-missing'))
    expect(byTestId('unblock-fp-missing')!.textContent).toContain('Fehlalarm')
    await settle()
    expect(mock.state.incidents.get('K7QM-4XWD')!.status).not.toBe('unblocked')
    await click(byTestId('unblock-fp-yes'))
    expect(byTestId('unblock-fp-missing')).toBeNull()
    wrapper.unmount()
  })

  it('normalizes the typed number and explains a miss', async () => {
    const { wrapper, router } = await mountApp('/incidents')
    await waitFor(() => !!byTestId('blocks-incident-input'))
    const input = byTestId<HTMLInputElement>('blocks-incident-input')!
    await type(input, 'abcd efgh')
    expect(input.value).toBe('ABCD-EFGH')
    await click(byTestId('blocks-incident-search'))
    await waitFor(() => router.currentRoute.value.path === '/incidents/ABCD-EFGH')
    await waitFor(() => !!byTestId('incident-not-found'))
    expect(bodyText()).toContain('Prüf die Nummer noch einmal')
    wrapper.unmount()
  })
})

describe('Was Schild sperrt (U4, D89)', () => {
  it('has no mode: it shows each rule source and the scenarios with their own switch', async () => {
    const { wrapper } = await mountApp('/settings')
    await waitFor(() => (byTestId('protection-sources')?.querySelectorAll('li').length ?? 0) === 3)
    expect(byTestId('protection-sources')!.textContent).toMatch(/OWASP CRS.*Sperrt/s)
    expect(byTestId('protection-sources')!.textContent).toContain('CrowdSec Hub')
    await waitFor(() => /Gerade (sperrt|sperren)/.test(byTestId('protection-scenarios')!.textContent!))
    expect(byTestId('protection-scenarios')!.querySelector('a')!.getAttribute('href')).toBe('/settings/rules/behaviour')
    expect(document.querySelector('[data-testid^="mode-"]')).toBeNull()
    expect(bodyText()).not.toMatch(/Modus ändern|Automatisch sperren|Labs|Signale|Netzregel|Regeln aus dem Netz/)
    wrapper.unmount()
  })
})

describe('Datenschutz (U5)', () => {
  it('finds, exports and deletes everything about 203.0.113.42', async () => {
    const { wrapper, router } = await mountApp('/privacy')
    await type(byTestId('privacy-ip'), '203.0.113.42')
    await click(byTestId('privacy-search'))
    await waitFor(() => router.currentRoute.value.query.ip === '203.0.113.42')
    await waitFor(() => !!byTestId('privacy-result'))
    const before = mock.state.events.filter(e => e.summary.ip === '203.0.113.42').length
    expect(before).toBeGreaterThan(0)
    expect(byTestId('privacy-events')!.textContent).toContain(String(before))
    expect(bodyText()).toContain('IP-Adressen verlassen den Server nicht')
    await click(byTestId('privacy-export'))
    await waitFor(() => byTestId('privacy-export')!.textContent!.includes('Exportiert'))
    await click(byTestId('privacy-delete'))
    const confirm = byTestId<HTMLButtonElement>('privacy-confirm-delete')!
    expect(confirm.disabled).toBe(true)
    await type(byTestId('privacy-confirm'), '203.0.113.42')
    expect(confirm.disabled).toBe(false)
    await click(confirm)
    await waitFor(() => mock.state.events.every(e => e.summary.ip !== '203.0.113.42'))
    await waitFor(() => byTestId('privacy-events')?.textContent?.trim().startsWith('0') ?? false)
    wrapper.unmount()
  })
})

describe('Eigene IPs', () => {
  it('allows my IP with one click and deletes an entry with undo', async () => {
    const { wrapper } = await mountApp('/own-ips')
    await waitFor(() => !!byTestId('allow-mine'))
    await click(byTestId('allow-mine'))
    await waitFor(() => !!byTestId('my-ip-allowed'))
    expect(mock.state.allowlist.some(a => a.ip === '192.0.2.10')).toBe(true)
    const count = mock.state.allowlist.length
    const rowsBefore = document.querySelectorAll('table tbody tr[data-row]').length
    await click(document.querySelector('[data-testid="allow-delete"]'))
    expect(document.querySelectorAll('table tbody tr[data-row]').length).toBe(rowsBefore - 1)
    // Undo from the toast: nothing is deleted on the server.
    await waitFor(() => !!toastAction('entfernt'))
    await click(toastAction('entfernt'))
    expect(document.querySelectorAll('table tbody tr[data-row]').length).toBe(rowsBefore)
    expect(mock.state.allowlist.length).toBe(count)
    wrapper.unmount()
  })

  it('validates the add dialog before sending', async () => {
    const { wrapper } = await mountApp('/own-ips?new=1')
    await waitFor(() => !!byTestId('allow-value'))
    await type(byTestId('allow-value'), '999.1.1.1')
    await type(byTestId('allow-label'), 'Test')
    await click(byTestId('allow-submit'))
    expect(bodyText()).toContain('Das ist keine gültige IP-Adresse')
    const n = mock.state.allowlist.length
    await type(byTestId('allow-value'), '198.51.100.99')
    await click(byTestId('allow-submit'))
    await waitFor(() => mock.state.allowlist.length === n + 1)
    expect(mock.state.allowlist[0]).toMatchObject({ ip: '198.51.100.99', label: 'Test', level: 'no_block' })
    wrapper.unmount()
  })
})

describe('Ereignisse', () => {
  it('names the website of every row for all websites, not on the page of one', async () => {
    const all = await mountApp('/events')
    await waitFor(() => !!byTestId('event-website'))
    expect(document.querySelector('th')?.parentElement?.textContent).toContain('Website')
    all.wrapper.unmount()
    cleanup()
    document.body.innerHTML = ''
    const one = await mountApp('/w/verein.example/events')
    await waitFor(() => !!byTestId('events-header'))
    await settle()
    expect(byTestId('event-website')).toBeNull()
    one.wrapper.unmount()
  })

  it('filters from the URL and opens a deep-linked detail', async () => {
    const { wrapper } = await mountApp('/events?outcome=blocked')
    await waitFor(() => document.querySelectorAll('table[aria-label="Ereignisse"] tbody tr[data-row]').length > 0)
    const rows = [...document.querySelectorAll('table[aria-label="Ereignisse"] tbody tr[data-row]')]
    expect(rows.every(r => r.textContent!.includes('Gesperrt'))).toBe(true)
    expect(document.querySelector('[data-testid="filter-chip"]')!.textContent).toContain('Gesperrt')
    wrapper.unmount()

    const second = await mountApp('/events?event=f2064730-835b-4d96-b173-d92534ccd620')
    await waitFor(() => !!byTestId('event-sentence'))
    expect(byTestId('event-sentence')!.textContent).toContain('/wp-login.php gesperrt')
    expect(byTestId('request-line')!.textContent).toContain('POST /wp-login.php HTTP/2')
    expect(bodyText()).toContain('2001:db8::17')
    second.wrapper.unmount()
  })

  it('shows the CRS evaluation as the decision, not as a second finding', async () => {
    const ev = mock.state.events.find(e => e.summary.path === '/.env' && e.summary.outcome === 'blocked')!
    const { wrapper } = await mountApp(`/events?event=${ev.summary.id}`)
    await waitFor(() => !!byTestId('event-decision'))
    const findings = [...document.querySelectorAll('[data-testid="event-finding"]')]
    expect(findings).toHaveLength(1)
    expect(findings[0]!.textContent).toContain('930130')
    expect(findings[0]!.textContent).not.toContain('949110')
    expect(byTestId('event-target')!.textContent).toContain('.env-Datei')
    const decision = byTestId('event-decision')!.textContent ?? ''
    expect(decision).toContain('40 von 100, Sperrschwelle erreicht')
    expect(decision).toContain('Darum hat Schild die Anfrage gesperrt')
    expect(byTestId('event-evaluation')!.textContent).toContain('949110')
    expect(bodyText()).not.toMatch(/Warnzeichen|geschützt|anonym/)
    for (const a of document.querySelectorAll<HTMLAnchorElement>('[data-testid="rule-links"] a')) {
      expect(a.target).toBe('_blank')
      expect(a.rel).toBe('noopener noreferrer')
      expect(a.getAttribute('referrerpolicy')).toBe('no-referrer')
      expect(a.href).toMatch(/^https:\/\/(owasp\.org|coreruleset\.org)\//)
    }
    wrapper.unmount()
  })

  it('streams live events over SSE and pauses', async () => {
    const { wrapper } = await mountApp('/events?live=1')
    const before = mock.state.liveSeq
    await waitFor(() => byTestId('live-state')?.textContent?.includes('Live') ?? false, 3000)
    await waitFor(() => mock.state.liveSeq > before + 1, 3000)
    await click(byTestId('live-pause'))
    expect(byTestId('live-state')!.textContent).toContain('Pausiert')
    wrapper.unmount()
  })
})

describe('Regeln', () => {
  it('switches a rule off with confirmation, without a password', async () => {
    const { wrapper } = await mountApp('/settings/rules/crowdsec?rule=71204448')
    await waitFor(() => !!byTestId('rule-disable'))
    expect(byTestId('rule-hub')).not.toBeNull()
    await click(byTestId('rule-disable'))
    await waitFor(() => !!byTestId('rule-disable-confirm'))
    expect(bodyText()).not.toContain('Labs')
    expect(bodyText()).not.toContain('Passwort')
    await click(byTestId('rule-disable-confirm'))
    await waitFor(() => mock.state.ruleRepos.rules.find(r => r.id === '71204448')!.disabled?.by === 'dashboard')
    await waitFor(() => !!byTestId('rule-enable'))
    wrapper.unmount()
  })
})

describe('keyboard', () => {
  it('opens the shortcut help with ? and navigates with g e', async () => {
    const { wrapper, router } = await mountApp('/')
    await settle()
    key('g')
    key('e')
    await waitFor(() => router.currentRoute.value.path === '/events')
    key('?')
    await waitFor(() => bodyText().includes('Tastenkürzel'))
    expect(bodyText()).toContain('Live-Ansicht ein/aus')
    wrapper.unmount()
  })
})
