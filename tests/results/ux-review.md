# UX and usability review of both dashboards (real backends)

Date: 2026-10-26. Scope: client dashboard (MVP-09, embedded in `schild`) and lab dashboard (MVP-10, embedded in `schild-lab`), reviewed against the **real binaries**, not the MSW mock. Docker was not used.

## Setup

| What | How |
| --- | --- |
| Backends | `ui/scripts/dev-backends.sh up` (new): builds and starts natively on 127.0.0.1 one `schild` client (profile production, test keys, non-release build) in front of the test-lab `site-api`, three labs of three operators (`lab-a/b/c`, TLS with a test CA, co-signing peers) and two relays. Ports 41080/41788 (client), 41789/42789/43789 (labs), 41480/41481 (relays). Data and logs in `$TMPDIR/schild-ui-dev`. |
| Content | `ui/scripts/seed-dev.sh` (new): first password, mode "Freigeben", two allowlist entries, browsing/API traffic from 198.51.100.0/24, 192.0.2.0/24 and 2001:db8::/32, attacks from 203.0.113.0/24 and 2001:db8:bad::/48 (SQLi, XSS, traversal, scanners, command injection, one false positive), `X-Forwarded-For` from the trusted proxy 127.0.0.1, `Host: shop.example`. Signals of three more TEST ONLY sites (other issuers) via `schild-lab dev-send`, so patterns reach >= 3 issuers and one pattern has a dominant issuer. Lab: proposal by carol (reproduction + negative corpus), approved by alice (Betreiber A) and bob (Betreiber B), bundle assembled, co-signed on lab-b and lab-c, published, picked up by the client's review queue; a second proposal stays open. `seed-dev.sh bulk 10000` adds 10,000 rule-matching events. Documentation ranges only. |
| Browser | Cached Playwright 1.56 (`~/.npm/_npx/e78b33305587cb7c/node_modules/playwright`), Chromium 1194. Harness `ui/scripts/ux-shots.mjs` (new): every section at 1440x900 and 390x844, light and dark; axe-core 4.14 with tags wcag2a/aa, 21a/aa, 22aa per section; console, page and 5xx errors; key flows; first-load size and timing; 10k-row table. |
| Screenshots | `results/ux/before/` (build at the start) and `results/ux/after/` (final build), 27 MB in total. File names `<app>-<section>-<viewport>-<scheme>.png` and `flow-<app>-<viewport>-<flow>-<step>.png`; raw results in `report-*.json` next to them. Full-page shots for desktop light, viewport shots for the rest. |

Heuristics used: Nielsen's ten heuristics, WCAG 2.2 AA, the polish of Linear/Vercel/Grafana-type ops tools, clarity for non-experts (client) and on-call security staff (lab), German copy (short, calm, du, no unexplained jargon, never "geschützt"/"sicher"/"anonym").

## Summary

The dashboards were in good shape against the mock; the real backends and realistic data surfaced one serious problem (the event table with 10,000 events was unusable), one honesty problem (copy claimed a browser check that the MVP does not perform), one broken chart, a test-profile dead end with a raw English schema error, several misleading or untranslated strings, layout overlaps and two WCAG findings. All of these are fixed; the remaining items below need a product or backend decision.

| Check | Before | After |
| --- | --- | --- |
| axe WCAG 2.2 AA (66 section shots, desktop light/dark + mobile overview) | 2 violations (`label-content-name-mismatch`, lab bundle JSON view, light and dark) | 0 |
| Console / page / CSP / 5xx errors | 0 | 0 |
| Horizontal overflow at 390 px | lab Überblick (before only measured after the first fixes: also lab Relays) | none |
| Flows | 34 of 41 steps (failures: harness selectors, and approve disabled because the seeded rule id was outside the SecLang subset) | 40 of 41 (the remaining one is by design: the mobile run tries to unblock the incident the desktop run already unblocked) |

## Performance (client, Ereignisse, 10,000+ stored events, 1440x900, localhost)

| Metric | Before | After |
| --- | --- | --- |
| Transferred on first load (all resources) | 868 KB | 390 KB |
| JS / CSS transferred | 600 KB / 107 KB (no compression) | 210 KB / 18 KB (gzip) |
| First heading visible | 225 ms | 193 ms |
| "Mehr laden" with 10k rows loaded (102 clicks) | 116 ms first, 4,460 ms last, 179 s in total | 59 ms first, 81 ms last (max 99), 7.4 s in total |
| DOM nodes with 10,290 / 10,266 rows loaded | 317,084 | 1,280 (21 rows in the DOM) |
| JS heap (Chrome `performance.memory`, coarse) | 1.2 GB | 225 MB |
| Frame times while scrolling | p50 183 ms, p95 217 ms, max 483 ms (~5 fps; measured by scrolling the document, the page was busy even when idle) | p50 17 ms, p95 33 ms, max 67 ms (scrolling the table's own scroll area top to bottom in 300 steps) |

Lab Überblick (after): 304 KB transferred, JS 179 KB, CSS 18 KB, first heading after 148 ms. Lab "before" was not measured. Main chunk of the client: 444 KB raw / 140 KB gzip; total JS of all lazily loaded chunks ~310 KB gzip, below the 500 KB gzip budget of MVP-09. Timings are from one machine (Apple silicon, localhost) and one run each.

## Findings and fixes

Severity: high = blocks a task or states something false; medium = confusing or wrong in a visible place; low = polish.

### Both dashboards (shared packages)

| # | Sev. | Finding | Fix |
| --- | --- | --- | --- |
| S1 | high | `DataTable` in cursor mode rendered every loaded row: 10k events = 317k DOM nodes, 10k `RelativeTime` timers, 4.5 s per "Mehr laden", ~5 fps. | Rows are virtualized above 150 rows (`@tanstack/vue-virtual` 3.13.48, MIT, already in the lockfile as a reka-ui dependency, added offline): spacer rows keep the scroll height, rows keep their absolute `aria-rowindex`, measured heights fall back to the estimate, keyboard navigation scrolls the row into view before focusing it; no virtualization without `ResizeObserver`. Tests: virtual window and indexes, pager. `packages/ui/src/components/app/DataTable.vue`. |
| S2 | medium | Backend: dashboard assets were served uncompressed (868 KB first load). | `client/internal/webui/gzip.go`, `lab/internal/webui/gzip.go`: compressible embedded assets (js, css, svg, json, html, txt; >= 1 KB, only if >= 10 % smaller) are gzip-compressed once and cached, `Vary: Accept-Encoding`, `q=0` honoured, HEAD without body. Tests `gzip_test.go` in both packages. |
| S3 | medium | WCAG 2.5.3: JSON tree toggles had `aria-label="signatures aufklappen"` while the visible text was `"signatures": [ 3 Einträge ]` (axe `label-content-name-mismatch`, lab bundle view). | The button's name is now its visible text plus a screen-reader-only "aufklappen/zuklappen", state via `aria-expanded`. `JsonNode.vue`. |
| S4 | low | Tables with 2 to 25 rows showed a full pager ("1–2 von 2 · Pro Seite 25 · 1 / 1"). | Pager hidden when everything fits on one page ("2 Einträge"). |
| S5 | low | Pages with a `space-y-6` wrapper (lab) had 48 px between the header and the first section. | `PageHeader` drops its bottom padding inside such a wrapper. |

### Client dashboard

| # | Sev. | Finding | Fix |
| --- | --- | --- | --- |
| C1 | high | Honesty: the Überblick card "Unsichtbar geprüft – Rechenaufgabe im Browser statt Sperre", the outcome "Geprüft", the glossary, the event sentence and the Freigaben hint all said Schild runs a browser check. The MVP does not implement challenge; such requests pass and are logged (client README). | Copy now says what happens: card "Zum Prüfen vorgemerkt – Noch ohne Prüfung im Browser, nur notiert", outcome "Vorgemerkt", glossary and Freigaben: "Diese Version kann das noch nicht: Solche Anfragen kommen durch und werden notiert." |
| C2 | medium | Test profile: setup wizard and Einstellungen offered "Freigeben" and "Automatisch sperren"; choosing one failed with `Diese Einstellung ist nicht möglich: schema: config/schild: jsonschema validation failed ... value must be 'observe'` (English, technical). | UI: in the test profile the other modes are shown disabled with one sentence why. Backend (`client/internal/dashboard/api.go`): the test profile is checked before the config validator and answers "Im Testprofil ist nur der Modus Beobachten möglich." with pointer `/mode` (the old string match never matched). Test extended (`TestTestProfileStaysObserve`). Mock aligned (blocking scenarios run the production profile; PATCH refuses non-observe modes in the test profile). |
| C3 | medium | "Testprofil mit simulierten Lab-Betreibern" (Überblick, setup step 3, Einstellungen) appeared for every test profile, also without simulated operators (open issue of the integration report). | Shown only when `independent_operators.simulated` / a lab has `simulated_operator`; otherwise "Testprofil: Schild beobachtet nur." |
| C4 | medium | Ereignisse: the Herkunft column's ASN line ran into the Grund column; the Score column was cut off at 1440 px; the search placeholder was truncated ("… IP oder Progr"). | Herkunft and Grund have fixed widths with ellipsis; Score hidden by default (still in "Spalten" and in the detail sheet); placeholder "Pfad, IP, Vorfall, Programm …". |
| C5 | medium | Ereignisse at 390 px: the IP (the key fact) was off-screen; "vor 14 Sekunden" took a third of the width. | On small screens the time and IP columns are hidden and shown under the request line ("198.51.100.48 · gerade eben"). |
| C6 | medium | Signale: categories `protocol` and `reputation-scanner` appeared untranslated ("reputation Scanner"); `lfi` read "Dateizugriff" while Regeln said "Zugriff auf Systemdateien". | All CRS attack tags (protocol, reputation-scanner, rfi, injection-php/-generic, fixation, java, ssrf, disclosure, generic, multipart-header, network-rule, local-rule, anomaly) have German words consistent with the rule families. |
| C7 | low | Häufigste Muster listed "Zugriff auf Systemdateien" twice with different counts (two CRS rules share the family title). | Duplicate titles get "· Regel 930120". |
| C8 | low | "Schild braucht dafür meist unter 1,776 ms". | "unter 1 ms" / whole milliseconds rounded up. |
| C9 | low | Setup step 3: "mindestens 3unabhängigen Betreibern" (missing space); stepper cut off at 390 px. | Space restored; stepper wraps. |
| C10 | low | Freigaben: keyboard hint (J/K/B/C/O/X) shown on phones; sample events without a request line rendered as empty boxes with "–". | Hint only from `md`; samples filtered to request events. |
| C11 | low | Labs never contacted showed "Unbekannt". | "Noch kein Kontakt". |
| C12 | low | Eigene IPs: "(von diesem Server (localhost))"; Regeln: "1 Regeln"; Überblick footer mixed the share of suspicious requests behind the refresh note. | Fixed wording, singular, footer reordered ("15,4 % der Anfragen in 24 Stunden auffällig · Stand …, aktualisiert sich alle 30 Sekunden · Version …"). |

### Lab dashboard

| # | Sev. | Finding | Fix |
| --- | --- | --- | --- |
| L1 | high | Muster drill-down: "Signale über Zeit" and "Bürgen über Zeit" were empty although the pattern had 17 signals. The API lists only hours with signals; one active hour is a single point the area chart cannot draw. | `src/lib/timeline.ts` fills the last 24 hourly buckets (merges, drops outside the window); unit tests. |
| L2 | medium | Vorschlag: the ladder said "2. Challenge erreicht" while "Belege erlauben: Beobachten"; the yellow box explained only the missing block evidence, the approve dialog said "Die Belege reichen nicht." The lab's own gates (negative corpus run without hits, simulated operators) were never named. | `labCapReasons()` mirrors `Engine.Level` and explains the cap ("Es fehlt ein Lauf gegen den Negativkorpus …"); the ladder shows such a step as "vom Lab begrenzt"; the approve dialog uses the same reason. Unit tests. |
| L3 | medium | Muster: "Reicht für Beobachten? Noch nicht" on a published pattern, without context. | Title "Reichen die Hinweise für Beobachten?" plus, for proposed/published patterns, "Der Vorschlag dazu stützt sich auf eigene Belege der Labs, nicht nur auf Hinweise." |
| L4 | low | Überblick: "Abonnenten 4 Relays" with two relays (the count includes peer labs following the feed). | "4 Verbindungen (Relays und Peers)". |
| L5 | low | Net classes untranslated ("hosting"). | "Rechenzentrum (hosting)" etc. |
| L6 | low | 390 px: horizontal overflow on Überblick (worker table widened the grid column) and Relays (a long `whitespace-nowrap` pill). | `min-w-0` on the grid column; pill shortened to "Testprofil" plus a sentence. |
| L7 | low | "Testprofil: simulierte Betreiber nur zum Beobachten" although no operator was simulated. | "Simulierte Betreiber zählen nur zum Beobachten." (conditional wording; the lab API has no simulated flag). |

### Dev data (not product code)

The first seed sent requests to `Host: 127.0.0.1`, so CRS 920350 ("Host header is a numeric IP address") flagged all 182 requests and dominated every view; the seed now sends `Host: shop.example`. The second proposal's rule id was outside the SecLang subset (7700000–7799999), which disabled "Freigeben"; fixed in the seed.

## Remaining issues (not fixed)

1. **Two different "largest issuer share" numbers for one pattern** (lab): the pattern view shows 47.1 % (share of signals), the proposal's evidence 39 % (scoring window, counting unit issuer × request_sig × bucket), and the pattern list counts it under "Ein Bürge über 34 %" while it is published. Needs a decision in the lab API which share the dashboard shows (backend, `lab/internal/scoring`).
   **Fix owner (2026-10-26):** reproduced with the dev backends: 47.1 % belongs to `sqli/api` (p_ee56…, prop-0001, 0.471 in pattern view, list and evidence), the 39 % to prop-0002's own pattern (XSS, p_b2b5…, 0.385). Per pattern the numbers agreed; the screenshots compared two proposals. Real latent defect fixed: the pattern list used the window stored at the last signal while the view and the evidence compute it live, so they drifted once units aged out; `scoring.Live` now feeds list, filters and detail (`TestPatternReadsUseLiveWindow`). The quick answer now counts only open (new/watching) patterns: "Offen, ein Bürge über 34 %".
2. **Peer labs listed as relays** (lab Relays & Peers, bundle distribution "4 von 4 Relays"): lab-b and lab-c appear in the relay table because they follow the feed. Correct technically ("labs are relays"), confusing for on-call staff; the API has no field to tell them apart.
   **Fix owner (2026-10-26):** peer labs subscribe under their own lab id, so the dashboard joins `/relays` with `/peers` (`src/lib/relays.ts`): column "Art" (Relay / Peer-Lab), coverage "2 von 2 Relays … Dazu folgen 2 Peer-Labs dem Feed", alerts separate. No contract change; a server-side `kind` field stays an open option.
3. **Challenge is not implemented** (MVP limit): the copy is now honest, but whether "Nur prüfen" should be offered at all in the MVP is a product decision.
4. **Unblock dialog preselects "Ja, das war ein echter Besuch"** (false positive). For network rules that sends feedback to the labs; a neutral default would avoid reflex feedback. Not changed (affects the U2 flow and feedback semantics).
   **Fix owner (2026-10-26):** nothing is preselected unless the caller passes an explicit intent; submitting without a choice asks "Wähl bitte zuerst, ob die Sperre ein Fehlalarm war." (unit + e2e tests).
5. **Setup code field** is shown even when the dashboard is opened from localhost, where it is not needed; the session does not tell the UI how it was reached before login.
6. **"Meine IP freischalten" from localhost** offers 127.0.0.1 (the dashboard's peer), which says nothing about the visitor-side address when the dashboard is reached through an SSH tunnel.
7. **English technical strings from the backend** in the client footer (`schild 0.1.0-mvp (non-release: test keys and test profile allowed)`, `schild-geo-fixture (TEST ONLY, documentation ranges)`) and in the public log summaries (contract payloads, English by design).
8. **Regeln: "Wirkung: Sperren" for every CRS rule**, although CRS works with anomaly scoring (single rules add to a score; 949110 blocks).
9. **Eigene IPs at 390 px**: the table scrolls horizontally inside its card (columns Gültig/Angelegt cut).
10. **Production bundle contains the styleguide chunk** (276 KB raw, lazy, never loaded without the dev route); could be excluded from release builds.
11. **Lab Relays: "Letztes Ereignis" shows an opaque event id** (`xk6khgdtfi-69`); a time or kind would help.
12. **Not measured**: usability tasks U1–U5 / L1–L5 with real people, SUS; lab first-load before the fixes; overview < 1 s with 1,000,000 events (MVP-09 measure); dark mode at 390 px was only shot for the setup screens (`SHOTS=all` takes every combination).

## Verification

- `pnpm typecheck`, `pnpm lint` (0 problems), `pnpm test` (ui 96, app-kit 9, lab 66, client 40), `pnpm build`, `pnpm test:e2e` (client 50/50, lab 27/27, mock mode, includes axe), all green.
- `make ui` re-run; the screenshots in `results/ux/after/` come from binaries embedding the final build.
- `make client-test` and `make lab-test` exit 0 (includes the new gzip tests and the extended test-profile test).
- New dependency: `@tanstack/vue-virtual` 3.13.48 (MIT) in `ui/packages/ui`.

Reproduce: `make ui && ui/scripts/dev-backends.sh up && ui/scripts/seed-dev.sh && node ui/scripts/ux-shots.mjs results/ux/after sections && node ui/scripts/ux-shots.mjs results/ux/after flows && ui/scripts/seed-dev.sh bulk 10000 && node ui/scripts/ux-shots.mjs results/ux/after perf && ui/scripts/dev-backends.sh down`.
