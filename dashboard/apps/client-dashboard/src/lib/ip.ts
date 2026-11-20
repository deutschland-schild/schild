/** Input validation for IP addresses, CIDR ranges and host names (client-side hints; the server validates again). */

export function isIPv4(s: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s)
  return !!m && m.slice(1).every(p => Number(p) <= 255 && String(Number(p)) === p)
}

export function isIPv6(s: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(':')) return false
  const doubles = s.split('::').length - 1
  if (doubles > 1) return false
  let groups = s.split(':')
  // Embedded IPv4 tail (::ffff:192.0.2.1)
  const last = groups[groups.length - 1]!
  if (last.includes('.')) {
    if (!isIPv4(last)) return false
    groups = [...groups.slice(0, -1), '0', '0']
  }
  const filled = groups.filter(g => g !== '')
  if (filled.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) return false
  return doubles === 1 ? filled.length < 8 : groups.length === 8
}

export function isIP(s: string): boolean {
  return isIPv4(s) || isIPv6(s)
}

export function isCidr(s: string): boolean {
  const [addr, bits, extra] = s.split('/')
  if (extra !== undefined || !addr || !bits || !/^\d{1,3}$/.test(bits)) return false
  const n = Number(bits)
  return (isIPv4(addr) && n <= 32) || (isIPv6(addr) && n <= 128)
}

export function isHostName(s: string): boolean {
  return s.length <= 253 && /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(s)
}

const IPV4_IN_TEXT = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])/

/** True if a string contains an IPv4 or IPv6 literal anywhere (used to double-check sent payloads). */
export function textHasIp(text: string): boolean {
  if (IPV4_IN_TEXT.test(text)) return true
  return text.split(/[^0-9a-f:.]+/i).some(tok => (tok.match(/:/g)?.length ?? 0) >= 2 && isIPv6(tok))
}

/** True if any string value in the JSON contains something that looks like an IP address. */
export function containsIpLiteral(value: unknown): boolean {
  if (typeof value === 'string') return textHasIp(value)
  if (Array.isArray(value)) return value.some(containsIpLiteral)
  if (value && typeof value === 'object') return Object.values(value).some(containsIpLiteral)
  return false
}
