# Gateway dashboard (MVP-09, `client-dashboard`)

Local dashboard of `schild`, built against `contracts/api/client-dashboard.openapi.yaml` (API under `/api/v0`, next to the page). UI copy is German (du-form, brand glossary); code and comments are English.

## Sections

| Route | What |
| --- | --- |
| `#/` Überblick | MVP-21 "Gerade jetzt" (status line, six live tiles from the monitoring SSE stream, hints, website switch `website=`), then "Grundschutz aktiv" or what needs attention, mode with explanation, one sentence on the last 24 h, counters with sparklines, top patterns, rules |
| `#/w/<website>` Zugriffe | Start page of a website (D68): status line (Grundschutz, running blocks, link to Ereignisse), tabs Überblick (KPI row, traffic and alarms on one axis, Letzte Alarme, countries, donuts, top lists), Seiten, Herkunft, Länder, Bots & KI-Crawler, Technik, Fehler & Langsam, Anfragen. URL: `view`, `time`, `metric`, `filter` (repeated); the list of Anfragen adds `window`, `until`, `outcome`, `bot`, `verification`, `visitor` |
| `#/w/<website>/events` | Running blocks, incidents of 7 days, Alarme nach Regel, then the event table of this website (same filters as `#/events`, website fixed). `#/events?website=` opens it |
| `#/events` | Events of all websites ("Alle Websites" in the sidebar): event table, filters in the URL (`time`, `outcome`, `ip`, `country`, `asn`, `path`, `rule`, `session`, `type`, `net`, `method`, `client`, `q`), live view over SSE with pause/resume (`live=1`), detail sheet (`event=<id>`) with full IP, geo, request line, rules in plain German, session timeline, actions |
| `#/incidents[/:incident]` | Incident lookup and unblock flow (false positive, allow IP with TTL) |
| `#/settings/rules` | The rule repositories (D73) side by side; `/crs`, `/crowdsec`, `/local`: one page each with the switch Aus / Erkennen / Sperren, sync and reset, the rules (`status=`) and the rule sheet (`rule=<id>`: disable/enable, approve/reject) |
| `#/w/<website>/charts` | MVP-21: every request counted (not the sampled events): requests per second stacked by outcome (durchgelassen, hätte gesperrt, gesperrt, 503), stop reasons, detections and page views, status classes, latency split app vs. Schild, bytes, app errors, unique and new addresses; top lists for pages (with detections), rules, countries, ASNs, net classes, referrers, bot categories, clients, browsers, OS, devices, methods, websites. URL: `time=1h|6h|48h|14d` |
| `#/server`, `#/server/load` | MVP-21 "Auslastung": what is visible in this environment, OS and uptime, CPU (per core live), load, memory and swap, disks, network, TCP and conntrack, open files, Schild itself; "Server-Check" at `#/server/check` (MVP-11; `?server=<agent id>`, `?view=agents`, `?new=1`) |
| `#/own-ips` | "Meine IP freischalten", IPs, ranges, DynDNS names, expiry, delete with undo |
| `#/privacy` | Search, export (JSON download) and delete by IP, retention explained |
| `#/settings` | Mode (password again), retention, password |
| `#/settings/audit` | Protokoll (MVP-36): the audit log of `GET /audit`, newest first, with the filters of `listAudit` in the URL (`website`, `class`, `action`, `way`, `actor`, `subject` + `subject_id`, `session`, `event`, `incident`, `from`, `to` as days) and the open entry (`entry=<id>`): who, when, way, address, object, cause, reason, before and after. Own IPs, rule exceptions, the retention and the Agent-API card link here with "Zuletzt geändert von …"; an event and an incident list what was changed because of them |
| `#/setup`, `#/login` | First-run wizard (password, mode, own IP) and login |

Global: Cmd/Ctrl+K palette (pages and actions such as "Meine IP freischalten", "Vorfall suchen"), `?` shortcut help, `g` + letter navigation, mode indicator on every screen, observe banner, dark mode, reduced motion.

## Layout

- `src/api/` typed client (`client.ts`: CSRF header from the session, 401 handling, problem mapping to German messages), vue-query hooks (`queries.ts`), schema aliases (`types.ts`), generated files (`generated/`, `pnpm gen:api`).
- `src/lib/` pure logic with unit tests: German labels, plain-language rule explanations, summaries, URL filters, IP and incident validation, SSE parser.
- `src/mock/` stateful mock backend (MSW) for every operation, seeded from `contracts/api/fixtures/client` plus deterministic generated data (documentation addresses only). Loaded only with `VITE_MOCK=true`; not in production builds.

## Mock mode

```sh
pnpm dev:mock          # http://localhost:5173
```

Scenarios via query string before the hash, kept per tab: `?scenario=default|observe|review|first-run|login|degraded|empty|error|standalone` (review: mode Freigeben, three CrowdSec rule updates wait for approval; standalone: started a few hours ago, CrowdSec Hub unreachable). Login password in mock mode: `mock-passwort-123`; any password except `falsch` confirms a mode change. `?latency=<ms>` and `?live=<ms>` (interval of new live events) tune the mock. Monitoring (MVP-21) comes from a deterministic model in `src/mock/monitoring.ts` (three websites in `default`, `observe` and `degraded`; hints in `degraded`; one website in `standalone`); `?monitoring=off` answers 409 `monitoring_off`.

## Tests

```sh
pnpm typecheck && pnpm test     # vitest: lib units, mock API conventions, full-app flows (U1-U5) on MSW in Node
pnpm test:e2e                   # Playwright (pinned, bundled Chromium): flows, 390 px, keyboard, axe WCAG 2.2 AA on all sections, light and dark
pnpm build                      # dist/ for go:embed (relative asset paths, hash routing)
```
