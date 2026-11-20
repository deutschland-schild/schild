// Pure text-replacement logic for the dev-only inline editor (no I/O, so it can be tested in isolation).
//
// The browser sends the rendered text of one DOM text node (oldText) and the edited version (newText). Rendered text
// has collapsed whitespace, so the search pattern allows any whitespace run where the DOM has one. Only the changed
// middle part (after the common prefix and before the common suffix) is replaced, so line breaks and indentation in
// the rest of the source stay as they are. The edit is refused unless the whole old text occurs exactly once in all
// searched files.

export type SourceFile = { path: string, text: string }

export type EditPlan =
  | { ok: true, path: string, line: number, text: string }
  | { ok: false, code: 'not_found' | 'ambiguous' | 'refused', error: string, matches?: { path: string, line: number }[] }

type Context = 'template' | 'script' | 'markdown' | 'frontmatter' | 'other'

const collapse = (s: string) => s.replace(/[ \t\r\n\f]+/g, ' ').trim()

const escapeChar = (c: string) => /[.*+?^${}()|[\]\\/]/.test(c) ? `\\${c}` : c

// One rendered character → its source pattern.
function charPattern(c: string): string {
  if (c === ' ') return '\\s+'
  if (c === ' ') return '(?: |&nbsp;)'
  // In JS string literals an apostrophe or quote may be escaped.
  if (c === '\'' || c === '"') return `\\\\?${c}`
  return escapeChar(c)
}

const toPattern = (s: string) => [...s].map(charPattern).join('')

const lineOf = (text: string, index: number) => text.slice(0, index).split('\n').length

function contextAt(path: string, text: string, index: number): Context {
  if (path.endsWith('.md')) {
    const fm = text.match(/^---\r?\n[\s\S]*?\r?\n---\r?\n/)
    return fm && index < fm[0].length ? 'frontmatter' : 'markdown'
  }
  if (path.endsWith('.ts')) return 'script'
  if (path.endsWith('.vue')) {
    const before = text.slice(0, index)
    const lastOpen = (tag: string) => before.lastIndexOf(`<${tag}`)
    const lastClose = (tag: string) => before.lastIndexOf(`</${tag}>`)
    if (lastOpen('script') > lastClose('script')) return 'script'
    if (lastOpen('style') > lastClose('style')) return 'other'
    // Templates may nest <template> tags; anything after the first top-level <template> that is not script/style counts.
    if (before.includes('<template')) return 'template'
  }
  return 'other'
}

// True if position `col` of `line` lies inside a '…', "…" or `…` literal (simple scanner, enough for data arrays).
function insideStringLiteral(line: string, col: number): boolean {
  let quote: string | null = null
  for (let i = 0; i < col; i++) {
    const c = line[i]!
    if (quote) {
      if (c === '\\') { i++; continue }
      if (c === quote) quote = null
    }
    else if (c === '/' && line[i + 1] === '/') {
      return false
    }
    else if (c === '\'' || c === '"' || c === '`') {
      quote = c
    }
  }
  return quote !== null
}

// Characters that would change the meaning of the source in the given context. Such edits go through the editor.
const FORBIDDEN: Record<Exclude<Context, 'other'>, RegExp> = {
  template: /[<>]|\{\{|\}\}/,
  script: /['"`\\]|\$\{/,
  markdown: /[*_[\]`<>|\\]/,
  frontmatter: /['"`\\:#]/,
}

export function planEdit(files: SourceFile[], oldRaw: string, newRaw: string): EditPlan {
  const oldText = collapse(oldRaw)
  const newText = collapse(newRaw)
  if (!oldText) return { ok: false, code: 'refused', error: 'Leerer Text, nichts zu ändern.' }
  if (oldText === newText) return { ok: false, code: 'refused', error: 'Keine Änderung.' }
  if (oldText.length < 4) return { ok: false, code: 'refused', error: 'Text zu kurz für eine eindeutige Zuordnung. Bitte im Editor ändern.' }

  let p = 0
  while (p < oldText.length && p < newText.length && oldText[p] === newText[p]) p++
  let s = 0
  while (s < oldText.length - p && s < newText.length - p && oldText[oldText.length - 1 - s] === newText[newText.length - 1 - s]) s++
  const before = oldText.slice(0, p)
  const middle = oldText.slice(p, oldText.length - s)
  const after = oldText.slice(oldText.length - s)
  const replacement = newText.slice(p, newText.length - s)

  const re = new RegExp(`(${toPattern(before)})(${toPattern(middle)})(${toPattern(after)})`, 'g')
  const hits: { file: SourceFile, index: number, m: RegExpExecArray }[] = []
  for (const file of files) {
    re.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = re.exec(file.text))) {
      hits.push({ file, index: m.index, m })
      if (m[0].length === 0) re.lastIndex++
    }
  }

  if (hits.length === 0) {
    return { ok: false, code: 'not_found', error: 'Text nicht in den Quelldateien gefunden (z. B. aus Ausdruck zusammengesetzt, berechnet oder mit Markup/Entities). Bitte im Editor ändern.' }
  }
  if (hits.length > 1) {
    return {
      ok: false,
      code: 'ambiguous',
      error: `Text kommt ${hits.length}-mal vor, Zuordnung nicht eindeutig. Bitte im Editor ändern.`,
      matches: hits.slice(0, 10).map(h => ({ path: h.file.path, line: lineOf(h.file.text, h.index) })),
    }
  }

  const { file, index, m } = hits[0]!
  const ctx = contextAt(file.path, file.text, index)
  if (ctx === 'other') return { ok: false, code: 'refused', error: `Fundstelle liegt nicht in Template, Script oder Markdown (${file.path}).` }
  if (FORBIDDEN[ctx].test(replacement)) {
    return { ok: false, code: 'refused', error: `Neuer Text enthält Zeichen, die in ${ctx} Bedeutung haben. Bitte im Editor ändern.` }
  }
  if (ctx === 'script') {
    const lineStart = file.text.lastIndexOf('\n', index) + 1
    const lineEnd = file.text.indexOf('\n', index)
    const line = file.text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd)
    if (index + m[0].length > lineStart + line.length) return { ok: false, code: 'refused', error: 'Fundstelle im Script geht über mehrere Zeilen. Bitte im Editor ändern.' }
    if (!insideStringLiteral(line, index - lineStart)) return { ok: false, code: 'refused', error: 'Fundstelle im Script liegt nicht in einem String. Bitte im Editor ändern.' }
  }

  const start = index + m[1]!.length
  const end = start + m[2]!.length
  return {
    ok: true,
    path: file.path,
    line: lineOf(file.text, start),
    text: file.text.slice(0, start) + replacement + file.text.slice(end),
  }
}

// Narrow the search with the Vue component chain of the clicked element (dev builds know each component's source
// file): try the component that rendered the text, then its parents, and take the first file where the text occurs
// exactly once. Texts that occur in several places of the site but only once in their own component become editable.
// Without a hit in the chain (e.g. Markdown rendered by ContentRenderer) the whole site is searched as before.
export function planEditScoped(all: SourceFile[], chain: string[], oldRaw: string, newRaw: string): EditPlan {
  for (const path of chain) {
    const file = all.find(f => f.path === path)
    if (!file) continue
    const plan = planEdit([file], oldRaw, newRaw)
    if (plan.ok || plan.code !== 'not_found') return plan
  }
  return planEdit(all, oldRaw, newRaw)
}
