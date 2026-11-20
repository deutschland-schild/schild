# Schild UI

pnpm workspace with the shared design system and the two dashboard skeletons.

| Path | What |
| --- | --- |
| `packages/ui` (`@schild/ui`) | Design system: Tailwind v4 theme from `docs/brand/tokens.css`, shadcn-vue components (`src/components/ui`), app building blocks (`src/components/app`) |
| `packages/app-kit` (`@schild/app-kit`) | App plumbing: typed API client (openapi-fetch), vue-query setup, router-aware shell, shared Vite config |
| `apps/client-dashboard` | Local dashboard of `schild` (with `/styleguide`) |
| `apps/lab-dashboard` | Lab dashboard |

Source packages are consumed directly (no build step). The apps resolve them through Vite aliases (`packages/app-kit/vite-config.ts`) and tsconfig `paths`.

## Commands

```sh
pnpm install
pnpm gen:api          # regenerate typed clients from contracts/api/*.yaml
pnpm dev:mock         # both apps with MSW fixtures (gateway dashboard :5173, lab dashboard :5174)
pnpm dev:mock:client  # just one app
pnpm typecheck        # vue-tsc in every package
pnpm lint             # eslint
pnpm test             # vitest (components, contrast, token drift, mock mapping, app skeletons)
pnpm test:e2e         # Playwright against both apps in mock mode, desktop + 390px, axe WCAG 2.2 AA
pnpm build            # apps/*/dist
pnpm check            # typecheck + lint + test + build
```

Playwright is pinned to an exact version (now 1.65.1, Chromium 159). After a bump run `pnpm --filter @schild/client-dashboard exec playwright install chromium` once. Keep it current: the bundled Chromium only gets security fixes through Playwright releases.

## Real backends (no Docker)

For UI work against the real APIs instead of the mock:

```sh
scripts/dev-backends.sh up      # builds and starts schild (gateway), three labs, two relays, site-api natively on 127.0.0.1
scripts/seed-dev.sh             # realistic traffic (documentation IPs only), signals, proposal, approvals, co-signed bundle
scripts/seed-dev.sh bulk 10000  # more rule-matching events for performance checks
node scripts/ux-shots.mjs OUT [sections|flows|perf]   # screenshots 1440x900 / 390x844, light/dark, axe, timings
scripts/dev-backends.sh down    # or reset (also deletes the data dir in $TMPDIR/schild-ui-dev)
```

Gateway dashboard `http://127.0.0.1:41788` (admin), lab-a/b/c `:41789`, `:42789`, `:43789` (carol, alice, bob); TEST ONLY password `schild-dev-passwort`. Run `make ui` first so the binaries embed the current build. Findings of the last review: `tests/results/ux-review.md`.

## Build output and go:embed

`pnpm build` writes `apps/<app>/dist/` with `base: './'`: all asset URLs are relative to `index.html`, so the folder can be served by `go:embed` at `/` or under any sub-path (e.g. `/_schild/`). The apps use hash routing (`#/events`), so the Go server needs no SPA fallback. The API base is the directory of the current document plus the `servers[0].url` path of the OpenAPI spec (e.g. `<sub-path>/api/v0`). Override in development with `VITE_API_BASE`.

Mock code (MSW, fixtures) is only loaded when `VITE_MOCK=true` (`--mode mock`) and is not in production bundles; `mockServiceWorker.js` lives in `public-mock/` and is only copied in mock mode.

## API client and mock mode

`scripts/gen-api.mjs` picks the file in `contracts/api/` whose name contains `client` or `lab` and writes to `apps/<app>/src/api/generated/`:

- `schema.ts`: openapi-typescript `paths` for `createApi<paths>()` in `src/api/client.ts`
- `operations.ts`: the server prefix of the API (`apiPrefix`)

Each app has its own MSW mock in `apps/<app>/src/mock/`: handlers per operation with realistic data, loaded only in mock mode.

## Content Security Policy

Both dashboards run under `script-src 'self'; style-src 'self'` (no `unsafe-inline`). Rules: no inline `<script>` in `index.html` (the colour scheme is applied by `packages/ui/src/theme-init.js`, which the shared Vite config adds to both dashboards as a file), no `style="..."` in markup and no injected `<style>` elements (Vue `:style` bindings are fine, they use CSSOM; `useTheme()` turns off VueUse's transition-suppressing style tag). The browser check of the test lab (`make smoke` + Playwright, see `DEVELOPMENT.md`) fails on any CSP violation.

## Design system rules

- Sober, white, calm. Brand green only for "Grundschutz aktiv" and signal states (`StatusPill tone="signal"`). Status colour never alone: always a label.
- UI copy German, du-form. "Grundschutz aktiv", never "geschützt"/"sicher"; "pseudonym", never "anonym".
- Dark mode via `.dark` on `<html>` (`useTheme()`, stored in `localStorage` only).
- Contrast is tested (`packages/ui/test/tokens.test.ts`): text pairs >= 4.5:1, focus ring, input borders and chart colours >= 3:1, in light and dark. The test also fails if brand colours drift from `docs/brand/tokens.css`.
- Chart palette (`--chart-1..5`) was validated for colour-vision deficiency separation in both modes; colour follows the entity (`ChartSeries.slot`), not its rank.
- Fonts (Inter, JetBrains Mono) ship via `@fontsource-variable`, no external CDN.
- `prefers-reduced-motion` disables animations globally; pulses use `motion-safe:`.

## Building blocks (`@schild/ui`)

`AppShell` (collapsible sidebar, top bar, breadcrumb, Cmd/Ctrl+K palette, theme switch, skip link), `PageHeader`, `StatCard` (with sparkline), `Sparkline`, `AreaChart` (crosshair + tooltip via mouse and arrow keys, screen-reader table), `BarList` (text on the card background, magnitude as a thin bar below, so muted hints keep 4.5:1), `StatusPill`, `LiveIndicator`, `EmptyState`, `ErrorState`, `DataTable` (TanStack: sorting, column visibility, roving keyboard focus, sticky header, client or server pagination, **cursor mode** for `next_cursor` APIs: all loaded rows, footer "N geladen · Mehr laden", `@load-more`; more than 150 rows are virtualized with `@tanstack/vue-virtual`; no pager when everything fits on one page; row detail sheet), `FilterBar` (chips), `DateRangePicker`, `RelativeTime`, `IpAddress` (plaintext, local only: flag, country, ASN tooltip, copy), `JsonView`, `ConfirmDialog` (type-to-confirm), `ThemeToggle`, `CommandPalette`, `BrandMark`.

shadcn-vue components (`components.json`, style new-york) live in `packages/ui/src/components/ui`. Add more with `pnpm dlx shadcn-vue@2.8.2 add <name>` inside `packages/ui`, then replace `from "cn"` with `from "@schild/ui/lib/utils"` and translate visible or screen-reader English strings.

## Who owns what

`apps/*/src/views/` and feature components are filled by the app agents. Routes and nav entries are declared in `apps/*/src/router.ts` (`meta.title`, `meta.nav`).
