/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "true" in mock mode (pnpm dev:mock): MSW serves contracts/api/fixtures. */
  readonly VITE_MOCK?: string
  /** Optional absolute API base for development against a remote backend. */
  readonly VITE_API_BASE?: string
}
