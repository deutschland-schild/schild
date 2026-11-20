import { useColorMode } from '@vueuse/core'

export type ThemeMode = 'light' | 'dark' | 'auto'

/** Colour scheme via the `dark` class on <html>. Light by default like the website; dark and 'auto' are opt-in. Stored locally only. CSP-safe. */
export function useTheme() {
  return useColorMode({
    selector: 'html',
    attribute: 'class',
    modes: { light: '', dark: 'dark' },
    // theme-init.js reads the same key before first paint.
    storageKey: 'schild-color-scheme',
    emitAuto: true,
    initialValue: 'light',
    // VueUse would inject a temporary <style> to suppress transitions while switching; the
    // dashboards run under a strict CSP (style-src 'self') that refuses inline styles.
    disableTransition: false,
  })
}
