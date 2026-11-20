import { readFileSync } from 'node:fs'

/** Parse `--name: value;` declarations of the first block matching `selector {`. */
export function cssVars(file: string, selector: string): Record<string, string> {
  const css = readFileSync(file, 'utf8')
  const start = css.indexOf(`${selector} {`)
  if (start < 0) throw new Error(`block ${selector} not found in ${file}`)
  const end = css.indexOf('}', start)
  const block = css.slice(start, end)
  const out: Record<string, string> = {}
  for (const m of block.matchAll(/--([\w-]+):\s*([^;]+);/g)) out[m[1]!] = m[2]!.trim()
  return out
}

function channel(c: number) {
  const s = c / 255
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
}

export function luminance(hex: string): number {
  const h = hex.replace('#', '')
  const n = h.length === 3 ? h.split('').map(x => x + x).join('') : h
  const [r, g, b] = [0, 2, 4].map(i => Number.parseInt(n.slice(i, i + 2), 16))
  return 0.2126 * channel(r!) + 0.7152 * channel(g!) + 0.0722 * channel(b!)
}

export function contrast(a: string, b: string): number {
  const [l1, l2] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (l1! + 0.05) / (l2! + 0.05)
}
