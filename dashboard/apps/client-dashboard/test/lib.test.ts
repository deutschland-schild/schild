import type { Overview } from '../src/api/types'
import { describe, expect, it } from 'vitest'
import { chipsFor, parseFilters, toApiQuery } from '../src/composables/useEventFilters'
import { explainLocation, explainRule, explainScore, explainTarget, humanizeToken, isEvaluationRule, ruleLinks, targetAnswer } from '../src/lib/explain'
import { normalizeIncident, validIncident } from '../src/lib/incident'
import { containsIpLiteral, isCidr, isHostName, isIP, isIPv4, isIPv6 } from '../src/lib/ip'
import { SseParser } from '../src/lib/sse'
import { attentionItems, baselineView } from '../src/lib/summary'
import overviewNormal from '../../../../contracts/api/fixtures/client/getOverview.json'
import overviewDegraded from '../../../../contracts/api/fixtures/client/getOverview.degraded.json'

const normal = overviewNormal as Overview
const degraded = overviewDegraded as Overview

describe('ip helpers', () => {
  it('validates addresses, ranges and host names', () => {
    expect(isIPv4('203.0.113.42')).toBe(true)
    expect(isIPv4('203.0.113.256')).toBe(false)
    expect(isIPv4('01.2.3.4')).toBe(false)
    expect(isIPv6('2001:db8::17')).toBe(true)
    expect(isIPv6('::ffff:192.0.2.1')).toBe(true)
    expect(isIPv6('2001:db8::1::2')).toBe(false)
    expect(isIPv6('12:30')).toBe(false)
    expect(isIP('localhost')).toBe(false)
    expect(isCidr('198.51.100.0/24')).toBe(true)
    expect(isCidr('198.51.100.0/33')).toBe(false)
    expect(isCidr('2001:db8::/32')).toBe(true)
    expect(isHostName('home.example.net')).toBe(true)
    expect(isHostName('not a host')).toBe(false)
  })

  it('finds IP literals in payloads, but not in hashes, times or fingerprints', () => {
    expect(containsIpLiteral({ time_bucket: '2026-10-26T11:55:00Z', waf_rules: [942100], origin: { asn: 64500 } })).toBe(false)
    expect(containsIpLiteral({ origin: { note: 'from 203.0.113.7' } })).toBe(true)
    expect(containsIpLiteral(['2001:db8:85a3::8a2e:370:7334'])).toBe(true)
    expect(containsIpLiteral({ time_bucket: '2026-10-26T11:55:00Z', request_sig: 'sha256:abcdef0123' })).toBe(false)
  })
})

describe('incident numbers', () => {
  it('normalizes typing and validates the alphabet', () => {
    expect(normalizeIncident('k7qm4xwd')).toBe('K7QM-4XWD')
    expect(normalizeIncident('k7qm 4x')).toBe('K7QM-4X')
    expect(validIncident('K7QM-4XWD')).toBe(true)
    expect(validIncident('K7QM-4XW0')).toBe(false) // no 0
    expect(validIncident('I7QM-4XWD')).toBe(false) // no I
  })
})

describe('plain language', () => {
  it('explains CRS families and local rules', () => {
    expect(explainRule('930120').title).toBe('Versuchter Dateizugriff')
    expect(explainRule(942100).title).toContain('SQL-Injection')
    expect(explainRule('1000010', 'xmlrpc.php not used on this site').explain).toContain('rules.d')
    expect(explainLocation('ARGS:log')).toBe('im Feld „log“')
    expect(explainLocation('REQUEST_HEADERS:User-Agent')).toBe('in der Kopfzeile „User-Agent“')
    expect(humanizeToken('wordpress-login-bruteforce')).toBe('WordPress Login Passwort-Raten')
    expect(humanizeToken('login-burst/wp-admin')).toBe('Login viele Versuche · wp-admin')
  })

  it('explains the score against the blocking threshold, not as a grade', () => {
    expect(explainScore(40)).toBe('Sperrschwelle erreicht')
    expect(explainScore(72)).toBe('über der Sperrschwelle von 40')
    expect(explainScore(20)).toBe('unter der Sperrschwelle von 40')
    expect(explainScore(0)).toBe('keine Punkte')
    expect(explainScore(undefined)).toBe('')
  })

  it('treats the CRS blocking evaluation as the decision, not as a finding', () => {
    for (const id of ['949110', 949111, '959100', '980170']) expect(isEvaluationRule(id)).toBe(true)
    for (const id of ['930130', '942100', '1000010', 'schild-2026-0412']) expect(isEvaluationRule(id)).toBe(false)
    const e = explainRule('949110')
    expect(e.title).toBe('Auswertung: Sperrschwelle')
    // One critical finding alone reaches the default threshold: the text must not claim several rules matched.
    expect(e.explain).not.toMatch(/Mehrere Regeln/)
    expect(e.explain).toContain('sucht nicht selbst nach Angriffen')
  })

  it('links CRS rules to OWASP and the CRS docs, nothing else', () => {
    const hrefs = (id: string) => ruleLinks(id).map(l => l.href)
    expect(hrefs('930130')).toEqual(['https://owasp.org/www-community/attacks/Forced_browsing', 'https://coreruleset.org/docs/3-about-rules/rules/'])
    expect(hrefs('930120')[0]).toBe('https://owasp.org/www-community/attacks/Path_Traversal')
    expect(hrefs('942100')[0]).toBe('https://owasp.org/www-community/attacks/SQL_Injection')
    expect(hrefs('941100')[0]).toBe('https://owasp.org/www-community/attacks/xss/')
    expect(hrefs('949110')).toEqual(['https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/'])
    expect(hrefs('913100')).toEqual(['https://coreruleset.org/docs/3-about-rules/rules/'])
    expect(ruleLinks('930130', { docs: false }).map(l => l.href)).toEqual(['https://owasp.org/www-community/attacks/Forced_browsing'])
    expect(ruleLinks('1000010')).toEqual([])
    expect(ruleLinks('schild-2026-0412')).toEqual([])
    for (let fam = 911; fam <= 980; fam++) {
      for (const l of ruleLinks(`${fam}100`)) expect(l.href).toMatch(/^https:\/\/(owasp\.org|coreruleset\.org)\//)
    }
  })

  it('says what a request asked for when it is a well-known sensitive file', () => {
    expect(explainTarget('/.git/HEAD')).toContain('Ordner .git')
    expect(explainTarget('/.git/config')).toContain('Quellcode')
    expect(explainTarget('/.env')).toContain('Zugangsdaten')
    expect(explainTarget('/.env.production')).toContain('.env-Datei')
    expect(explainTarget('/download.php', 'file=..%2F..%2Fetc%2Fpasswd')).toContain('/etc/passwd')
    expect(explainTarget('/backup/db.sql.gz')).toContain('Sicherungskopie')
    expect(explainTarget('/produkte/')).toBeNull()
    expect(explainTarget('/environment')).toBeNull()
    expect(explainTarget('/suche', 'q=backup.sql')).toBeNull()
    expect(targetAnswer('blocked', 403)).toContain('Ausgeliefert wurde nichts')
    expect(targetAnswer('would_block', 404)).toContain('gibt es dort nicht')
    expect(targetAnswer('would_block', 200)).toContain('Prüf, ob die Datei wirklich öffentlich abrufbar ist')
    expect(targetAnswer('logged', 500)).toContain('zeigt dieser Treffer nicht')
  })

  it('never says geschützt or sicher in the Grundschutz headline', () => {
    for (const o of [normal, degraded, { ...normal, baseline: { state: 'off', reasons: [{ code: 'waf_down', since: normal.generated_at }] } } as Overview]) {
      const v = baselineView(o)
      expect(`${v.title} ${v.subtitle}`).not.toMatch(/geschützt|sicher\b/i)
    }
    expect(baselineView(normal).title).toBe('Grundschutz aktiv')
    expect(baselineView(degraded).pill).toBe('Eingeschränkt')
    expect(baselineView({ ...normal, baseline: { state: 'off', reasons: [] } }).title).toBe('Grundschutz aus')
  })

  it('lists what needs attention', () => {
    const ids = attentionItems(degraded).map(a => a.id)
    expect(ids).toEqual(['reason-geo_db_old', 'reason-disk_full'])
    expect(attentionItems(normal).map(a => a.id)).toEqual([])
  })
})

describe('event filters in the URL', () => {
  it('parses German query names into API filters', () => {
    const f = parseFilters({ time: '1h', outcome: 'blocked', country: 'nl', asn: 'AS64500', ip: '203.0.113.0/24', path: '/wp', foo: 'x' })
    expect(f).toMatchObject({ time: '1h', outcome: 'blocked', country: 'NL', asn: 'AS64500' })
    expect(toApiQuery(f, '2026-10-26T11:00:00Z')).toEqual({ from: '2026-10-26T11:00:00Z', outcome: 'blocked', country: 'NL', asn: 64500, ip: '203.0.113.0/24', path: '/wp' })
    expect(chipsFor(f).map(c => `${c.label}: ${c.value}`)).toEqual(['Ergebnis: Gesperrt', 'IP: 203.0.113.0/24', 'Land: Niederlande (NL)', 'Netz (ASN): AS64500', 'Pfad: /wp'])
  })

  it('falls back to 24 h and drops unknown outcomes', () => {
    const f = parseFilters({ time: 'forever', outcome: 'nuked' })
    expect(f.time).toBe('24h')
    expect(f.outcome).toBeUndefined()
  })
})

describe('SSE parser', () => {
  it('handles chunks, comments, multi-line data, ids and CRLF split across chunks', () => {
    const p = new SseParser()
    expect(p.feed(': keep-alive\n\nid: 1\nevent: ev')).toEqual([])
    expect(p.feed('ent\ndata: {"a":\ndata: 1}\r')).toEqual([])
    const out = p.feed('\n\r\nretry: 3000\ndata: x\n\n')
    expect(out).toEqual([{ id: '1', event: 'event', data: '{"a":\n1}' }, { id: '1', event: 'message', data: 'x' }])
    expect(p.retry).toBe(3000)
  })
})
