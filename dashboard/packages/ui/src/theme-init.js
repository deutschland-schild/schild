// Apply the stored colour scheme before first paint (no flash). Local only.
// External file instead of an inline script: the dashboards run under a strict CSP (script-src 'self').
// One file for both dashboards: app-kit/vite-config.ts serves it and writes it next to index.html.
// Key and default as in composables/useTheme.ts.
try {
  var m = localStorage.getItem('schild-color-scheme') || 'light'
  if (m === 'dark' || (m === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches)) document.documentElement.classList.add('dark')
}
catch {
  // Storage blocked: keep the light default.
}
