import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { contrast, cssVars } from './css'

const brandFile = resolve(import.meta.dirname, '../../../../../docs/brand/tokens.css')
const localFile = resolve(import.meta.dirname, '../src/styles/brand-tokens.css')
const themeFile = resolve(import.meta.dirname, '../src/styles/index.css')

describe('brand tokens', () => {
  it.skipIf(!existsSync(brandFile))('match docs/brand/tokens.css (no drift)', () => {
    const brand = cssVars(brandFile, '@theme')
    const local = cssVars(localFile, '@theme')
    for (const [k, v] of Object.entries(local)) {
      if (!k.startsWith('color-')) continue
      expect(brand[k]?.toLowerCase(), k).toBe(v.toLowerCase())
    }
  })
})

describe('theme contrast (WCAG 2.2 AA)', () => {
  const text: [string, string][] = [
    ['foreground', 'background'],
    ['card-foreground', 'card'],
    ['popover-foreground', 'popover'],
    ['muted-foreground', 'background'],
    ['muted-foreground', 'muted'],
    ['muted-foreground', 'card'],
    ['primary-foreground', 'primary'],
    ['secondary-foreground', 'secondary'],
    ['accent-foreground', 'accent'],
    ['destructive-foreground', 'destructive'],
    ['success', 'success-subtle'],
    ['warning', 'warning-subtle'],
    ['danger', 'danger-subtle'],
    ['info', 'info-subtle'],
    ['neutral', 'neutral-subtle'],
    ['signal-text', 'signal-subtle'],
    ['signal-text', 'background'],
    ['signal-foreground', 'signal'],
    ['success', 'background'],
    ['warning', 'background'],
    ['danger', 'background'],
    ['info', 'background'],
    ['sidebar-foreground', 'sidebar'],
    ['sidebar-accent-foreground', 'sidebar-accent'],
    // Website-style parts: neutral tags and inactive tab/segment text, the "Aus" segment.
    ['muted-foreground', 'secondary'],
    ['foreground', 'border'],
    ['card-foreground', 'signal-subtle'],
  ]
  const nonText: [string, string][] = [
    ['ring', 'background'],
    ['input', 'background'],
    // Switch boundary when on (green track with a darker border) and when off.
    ['signal-text', 'background'],
    ['signal-text', 'card'],
    ['input', 'card'],
    ['chart-1', 'card'],
    ['chart-2', 'card'],
    ['chart-3', 'card'],
    ['chart-4', 'card'],
    ['chart-5', 'card'],
    // Monitoring tones: lines and the bands that carry a series alone. tone-wash and tone-light are
    // background fills (below 3:1 by design); the main line on top of them is checked below.
    ['tone-mid', 'card'],
    ['tone-main', 'card'],
    ['tone-deep', 'card'],
    ['tone-neutral', 'card'],
    ['tone-main', 'tone-wash'],
    ['tone-deep', 'tone-light'],
  ]
  for (const mode of [':root', '.dark']) {
    const vars = { ...cssVars(themeFile, ':root'), ...cssVars(themeFile, mode) }
    for (const [fg, bg] of text) {
      it(`${mode} ${fg} on ${bg} >= 4.5`, () => {
        expect(contrast(vars[fg]!, vars[bg]!)).toBeGreaterThanOrEqual(4.5)
      })
    }
    it(`${mode} tone fills step away from the card and from each other`, () => {
      // Ordinal ramp: each step is visibly darker (light) or brighter (dark) than the one before.
      const ramp = ['card', 'tone-wash', 'tone-light', 'tone-mid'].map(k => vars[k]!)
      for (let i = 1; i < ramp.length; i++) expect(contrast(ramp[i]!, ramp[i - 1]!)).toBeGreaterThanOrEqual(1.15)
    })
    for (const [fg, bg] of nonText) {
      it(`${mode} ${fg} on ${bg} >= 3 (non-text)`, () => {
        expect(contrast(vars[fg]!, vars[bg]!)).toBeGreaterThanOrEqual(3)
      })
    }
  }
})
