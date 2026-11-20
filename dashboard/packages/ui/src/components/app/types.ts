import type { Component } from 'vue'

/** Semantic tone for status pills, stat cards and indicators. */
export type StatusTone = 'signal' | 'success' | 'warning' | 'danger' | 'info' | 'neutral'

export interface NavItem {
  /** Route path, also used as the stable id. */
  to: string
  label: string
  icon?: Component
  /** Small count or text badge (e.g. open incidents). */
  badge?: string | number
  /** Extra search terms for the command palette. */
  keywords?: string[]
  /**
   * Small status dot (e.g. a server's state); dotLabel names it for screen readers and the tooltip.
   * Without an icon the dot leads the label (a list of websites), with an icon it follows it.
   */
  dot?: StatusTone
  dotLabel?: string
  /** Short muted text at the right edge (e.g. "12,4/s" of a website). */
  meta?: string
  /**
   * The chosen entry of a list whose children carry the active page (a selected website with
   * Überblick, Zugriffe, ...): shown in medium weight and marked, never as the active page itself.
   */
  selected?: boolean
  /** Path prefixes that also make this entry active (e.g. a server entry at "/" with /server/...). */
  activeOn?: string[]
  /** Sub-entries, shown indented below the item (e.g. Regeln -> OWASP CRS). */
  children?: NavItem[]
  /** Active only on exactly this path (not on sub-paths), e.g. a website's Überblick. */
  exact?: boolean
  /** Leave the item out of the command palette (e.g. dynamic entries that the palette lists elsewhere). */
  hideInPalette?: boolean
}

export interface NavGroup {
  label?: string
  items: NavItem[]
  /** A filter field above the items (long lists, e.g. more than 8 websites); matches label and keywords. */
  filter?: { placeholder: string, label: string, empty: string }
}

export interface BreadcrumbEntry {
  label: string
  to?: string
}

export interface CommandEntry {
  id: string
  label: string
  group?: string
  icon?: Component
  shortcut?: string
  keywords?: string[]
  /** Either navigate to a path or run an action. */
  to?: string
  run?: () => void
  /** Status dot before the label and a short muted hint after it (e.g. a website: "ok", "12,4/s"). */
  dot?: StatusTone
  hint?: string
}

export interface FilterChip {
  key: string
  label: string
  value: string
}

export interface ChartSeries {
  /** Stable id; colour follows the entity, never its rank. */
  id: string
  label: string
  values: number[]
  /** 1-5, maps to --chart-N. Defaults to the series index + 1. */
  slot?: 1 | 2 | 3 | 4 | 5
}

/** One series of a TimeChart (monitoring); null values are gaps. */
export interface TimeSeries {
  id: string
  label: string
  values: (number | null)[]
  /** CSS colour (e.g. var(--tone-main)); else --chart-<slot>. */
  color?: string
  slot?: 1 | 2 | 3 | 4 | 5
  /** Part of the stacked area (bottom-up in series order); else a line. */
  stack?: boolean
  /** Dashed line (a second line in the same colour family stays distinguishable). */
  dashed?: boolean
  /** Soft wash under a line (about 10 % of its colour), for the one line a chart is about. */
  fill?: boolean
}

/** One slice of a DonutChart. */
export interface DonutSlice {
  /** Stable id; the colour follows it, never the slice's rank. */
  id: string
  label: string
  value: number
  /** CSS colour (e.g. var(--chart-1)). */
  color: string
  /** The folded rest ("Andere"): never named in the centre. */
  other?: boolean
  /** A click on this slice or its legend row emits select. */
  clickable?: boolean
  /** Tooltip of the legend row. */
  hint?: string
}

export type LiveState ='live' | 'connecting' | 'paused' | 'offline'

/** One option of a SegmentedControl. */
export interface SegmentOption<T extends string = string> {
  value: T
  label: string
  /**
   * Fill of the active segment: `ink` for the strongest action (website: "Blocken"),
   * `signal` for the normal choices, `neutral` for "Aus".
   */
  tone?: 'ink' | 'signal' | 'neutral'
  disabled?: boolean
  /** Short reason shown when disabled (also read by screen readers). */
  reason?: string
  /** Optional data-testid for the segment button. */
  testid?: string
  /** Small mark after the label, e.g. "empfohlen" (D92). */
  mark?: string
}

/** One part of a MetaLine; strings are plain slate text. */
export type MetaItem = string | {
  text: string
  /** `signal` renders green with a check mark (verified facts only). */
  tone?: 'signal' | 'warning' | 'danger'
  mono?: boolean
  /** Title attribute for extra detail (never the only place of information). */
  title?: string
}
