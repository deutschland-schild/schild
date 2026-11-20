# Lab dashboard (MVP-10)

Vue 3 app for lab operators and reviewers. Built against `contracts/api/lab-dashboard.openapi.yaml`
(generated types in `src/api/generated`), served by `schild-lab` via `go:embed` (hash routing, relative assets).

## Sections

| Route | What |
| --- | --- |
| `#/` Überblick | ingest rate, ack p50/p99/max against the 50 ms target, queue depth by priority, workers, rejections, feed, open points |
| `#/signals` Signale & Muster | patterns by `action_sig`, counted by issuer (clients shown, never used in thresholds), largest issuer share vs. 34 %, filters as URL query (`q`, `status`, `min_issuers`, `country`, `asn`, `sort`) |
| `#/signals/:patternId` | drill-down: by issuer/operator, countries, ASNs, net classes, agents, WAF rules, 24 h timeline, sample signals; "Vorschlag anlegen" |
| `#/proposals[/:id]` | review queue with keyboard (`j`/`k`, `a`, `r`, `e`), requested vs. allowed max action with the missing evidence in plain words, evidence ladder (observe, challenge, block), reproduction per lab, SecLang check, approvals (person + organisation, four-eyes hint, the author of a proposal cannot approve it), reject with mandatory reason, attach evidence |
| `#/published[/:version]` | bundles, k-of-n signatures by distinct operators, relay coverage (bundle version per relay), assemble the next bundle from approved proposals, co-sign bundles of other labs ("Mitzeichnen …") |
| `#/published/withdrawals` Rückzüge | withdraw single rules, or as an option "Alle Netzregeln zurückziehen" (wire: `POST /emergency-stop`; typed `ALLE ZURÜCKZIEHEN` + reason + password), progress (signed, co-signatures missing, effective, relays), co-sign withdrawals of other labs. `#/published/withdrawals` redirects here. |
| `#/relays` | relay health and lag, frozen-relay hint (last event unchanged for 3 min), peers and operator independence |
| `#/clients` | issuers and site keys: quota usage, rejections, revoke with password, quota changes |
| `#/log` | public log with head size/root, kind filter, client-side check of sequence, envelope digests and the RFC 6962 root (head and the root the newest checkpoint signs) |
| `#/settings` | scoring floors (min 3 issuers, max share 34 %), ingest, retention; save with password; account |

Login/setup screens come from `/auth/session`. State changes send `X-CSRF-Token` from the session.

## Safety rules in the UI

- No visitor IP anywhere: the API has none; tests scan the mock data and every rendered section for IPv4 literals.
- Approvals never offer an action above the evidence (`src/lib/evidence.ts` mirrors `contract/msg.EvidenceLevel`; the server stays authoritative). An approval always carries the session user and an organisation.
- Keyboard shortcuts never fire in inputs or behind dialogs and never trigger anything irreversible; they only open dialogs.
- Withdrawing all network rules needs the exact text `ALLE ZURÜCKZIEHEN` and the password. It is not reachable by a single key and has no own nav item or shortcut. The UI sends the wire constant `confirm_text: "NOT-AUS"` until contracts v0.4; operators never see it.

## Live updates

`src/lib/live.ts` opens `GET <api>/events/stream` (SSE, contracts v0.1, served by `schild-lab`). Events are named by
topic (`health` carries a full `LabHealth`, `signals` a ReceivedSignal, `log` a LogEntry, the others a LiveNotice; every
topic except health invalidates its queries). Without the stream, queries poll at
calm intervals (health 5 s, withdrawals/relays 10 s, rest 30 s), only while the tab is visible. The header shows the live
state and lets you pause.

## Mock mode

`pnpm dev:mock` (port 5174) starts a stateful in-memory lab (`src/mock`) seeded from `contracts/api/fixtures/lab`
plus a few deterministic extras. Any password works except `falsch` (simulates wrong password). A simulated peer lab
co-signs bundles and withdrawals after 15 s. `?first-run` on the URL shows the setup screen. Mock code is only loaded
with `--mode mock` and is not part of `pnpm build`.

## Tests

```sh
pnpm typecheck        # vue-tsc
pnpm test             # vitest: evidence ladder, mock rules, live/SSE fallback, shortcuts, log checks, alerts, integration via msw/node
pnpm test:e2e         # Playwright (pinned, bundled Chromium), desktop + 390 px: usability tasks L1-L5, keyboard review, palette, axe WCAG 2.2 AA light/dark
pnpm build            # dist/
```
