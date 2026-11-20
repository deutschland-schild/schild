// Scalar configuration for the API reference at /api. Scalar is bundled from npm (no CDN): no telemetry, no Scalar
// fonts, no agent or MCP features, light mode only, themed with the brand tokens (docs/brand/tokens.css).
// No "Test Request": the agent API listens on loopback and refuses requests with an Origin header.
export const API_SPEC_URL = '/api/gateway-agent.openapi.json'

const SCALAR_CUSTOM_CSS = `
.light-mode {
  --scalar-font: "Inter Variable", ui-sans-serif, system-ui, sans-serif;
  --scalar-font-code: "JetBrains Mono Variable", ui-monospace, monospace;
  --scalar-background-1: #ffffff;
  --scalar-background-2: #f6f9fc;
  --scalar-background-3: #edf2f8;
  --scalar-background-card: #ffffff;
  --scalar-background-accent: #ecfdf5;
  --scalar-color-1: #0a1a33;
  --scalar-color-2: #5b6b82;
  --scalar-color-3: #5b6b82;
  --scalar-color-accent: #0b6e30;
  --scalar-border-color: #d8e2ee;
  --scalar-radius: 0.5rem;
  --scalar-radius-lg: 0.75rem;
  --scalar-radius-xl: 1rem;
}
.light-mode .t-doc__sidebar {
  --scalar-sidebar-background-1: #f6f9fc;
  --scalar-sidebar-item-active-background: #edf2f8;
  --scalar-sidebar-color-active: #0a1a33;
}
`

export function scalarConfiguration() {
  return {
    url: API_SPEC_URL,
    theme: 'none' as const,
    customCss: SCALAR_CUSTOM_CSS,
    layout: 'modern' as const,
    withDefaultFonts: false,
    hideDarkModeToggle: true,
    forceDarkModeState: 'light' as const,
    darkMode: false,
    telemetry: false,
    showDeveloperTools: 'never' as const,
    agent: { disabled: true },
    mcp: { disabled: true },
    hideTestRequestButton: true,
    hideClientButton: true,
    proxyUrl: '',
    documentDownloadType: 'json' as const,
    defaultOpenFirstTag: true,
  }
}
