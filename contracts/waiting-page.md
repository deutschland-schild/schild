# Waiting page (v0.5, D37, MVP-23 step 1)

Under overload schild answers 503 and never passes a request unchecked (fail closed). Since D37 a person whose browser asked for a page gets a calm waiting page with automatic reload instead of the block page. Machines keep 503 with `Retry-After` and problem details. The waiting page changes only the answer, never the outcome: the request is not forwarded and counts as `fail_closed` as before.

Go reference: `contract/waitingpage` (`Decide`, `Document`, `Language`, `SiteName`, `RetryAfter`, `Texts`, `CSP`). Vectors: `waiting-page` (input [waiting-page.schema.json](waiting-page.schema.json)), Go and Python agree. Switch: `schild.yaml` `waiting_page.enabled` (default `true`).

## 1. When

Only the fail-closed reasons of overload (the keys of `TrafficCounters.fail_closed_by`):

| Reason | Cause | Waiting page |
| --- | --- | --- |
| `waf_busy` | no evaluation slot within `waf.queue_wait_ms`: all slots taken, the client's share of expensive slots taken, or the memory budget of expensive evaluations exhausted (the memory budget has no reason of its own) | yes |
| `waf_timeout` | the evaluation did not finish within its budget (`waf.eval_timeout_ms`, plus the text-body allowance) | yes |
| `body_busy` (D41, D45) | the gateway-wide body or request limits are full, memory is under pressure, or a client on a shared address (`cgnat`, `mobile`, `tor`) is over its share ([body-limits.md](body-limits.md)) | yes |
| `not_ready` | the gate is starting | no, unchanged |
| `panic` | a recovered handler panic | no, unchanged (keeps the incident number for the operator) |

With `waiting_page.enabled: false` every reason keeps the answer from before D37 (block page or problem details by `Accept`, `Retry-After: 5`); the result is `unchanged`.

## 2. Document or not

A request with reason `waf_busy`, `waf_timeout` or `body_busy` gets the waiting page when it is a document navigation, otherwise problem details. Checked in this order; header values are trimmed of spaces and tabs and compared ASCII case-insensitively; a repeated header is its values joined with `, `.

1. Method other than `GET`, `HEAD` or `POST`: problem.
2. `X-Requested-With` present and not empty: problem (jQuery and other XHR libraries).
3. `Sec-Fetch-Mode` present and not `navigate`: problem (`cors`, `no-cors`, `same-origin`, `websocket`: fetch, XHR, assets).
4. `Sec-Fetch-Dest` present: waiting page exactly for `document`. `iframe`, `frame`, `empty`, `image`, `script` and the rest get the problem (the page's `frame-ancestors 'none'` would hide it in a frame anyway).
5. Otherwise (browsers without Fetch Metadata, plain HTTP, non-browsers): waiting page when `Accept` lists `text/html` or `application/xhtml+xml` with a q above 0 and above the best q of every JSON type (`application/json` or a `+json` suffix). A tie goes to JSON. `*/*`, `text/*` and a missing `Accept` count for neither, so curl and most HTTP libraries get the problem.

Fetch Metadata wins over `Accept`: a `fetch()` asking for HTML (htmx, Turbo, Livewire) gets the problem, so no page is swapped into a document.

Bots that send a browser `Accept` (search engines) get the waiting page with the same status 503 and `Retry-After`, which is what crawlers act on.

`Accept` and `Accept-Language` are read as RFC 9110 lists: the first 32 comma-separated elements, the range before the first `;` (trimmed, ASCII lower case), the first `q=` parameter (`0`, `0.`, up to three decimals, `1` to `1.000`; absent = 1). An element with an invalid q or an empty range is skipped.

## 3. Method variants

| Method | Variant | Behaviour |
| --- | --- | --- |
| `GET` | `reload` | meta refresh and CSS countdown of `Retry-After` seconds |
| `HEAD` | `reload` | the same headers, no body |
| `POST` (a form submit) | `form` | no meta refresh and no countdown: a refresh would load the URL with GET and silently drop what the form sent; the copy asks to wait a few seconds, go back and send again |

## 4. Response

Waiting page:

- Status `503`. `Retry-After: N` with N = 5 + a uniform jitter of 0 to 3 whole seconds, drawn per response (`RetryAfter(draw) = 5 + draw mod 4`, bounds [5, 8]), so reloads do not come back in waves.
- `Content-Type: text/html; charset=utf-8`, `Content-Language: de` or `en` (and `<html lang>`), `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Vary: Accept, Accept-Language, Sec-Fetch-Dest, Sec-Fetch-Mode, X-Requested-With`.
- `Content-Security-Policy` exactly as the block page: `default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. No JavaScript, no external resource, the illustration is inline SVG.
- Variant `reload`: `<meta http-equiv="refresh" content="N">` without URL (N equal to `Retry-After`), the countdown `N … 1` as CSS-only digits (one element per second with an animation delay) and a progress bar of N seconds; with `prefers-reduced-motion` the illustration stands still and the bar is hidden.
- `<meta name="robots" content="noindex">`. No incident number and no `X-Schild-Incident` header: this is not a block.
- **Marker** (D37 amendment, initiator 2026-10-29): response header `Schild-Waiting: 1` (`MarkerHeader`, `MarkerValue`; no `X-` prefix, RFC 6648, like `Schild-Peer-Auth`). Also on `HEAD`.
- At most 8 KiB (`MaxPageBytes`). Rendered from a template held in memory per language and variant; only N, the website name and the time are filled in. No WAF evaluation, no database write, no lookup per request, so serving it never adds to the overload.

Problem details (every other request with `waf_busy`, `waf_timeout` or `body_busy` while enabled): status 503, `Content-Type: application/problem+json` whatever `Accept` says, the block page's problem body with code **`waiting`** (`ProblemCode`, type `https://schild.invalid/problems/waiting`; D37 amendment 2026-10-29, before: `timeout`) and `retry_after` equal to the jittered `Retry-After` header, the marker header `Schild-Waiting: 1`, `Cache-Control: no-store`. Title, detail and the incident number stay as the block page's 503 problem. `HEAD` gets the headers only.

The marker tells an overload answer from every other 503: `not_ready`, `panic` and every answer with `waiting_page.enabled: false` keep code `timeout` and carry no `Schild-Waiting` header (result `unchanged`, `marker` false). A 503 from the backend never carries it either: schild sets it only on answers of this decision, and the gateway removes a `Schild-Waiting` header that a backend response carries, so the marker cannot be forged by an app. Vectors: result fields `marker` (true for `waiting_page` and `problem`) and `problem_code` (`waiting` for `problem`, else null).

## 5. Language

`Accept-Language` decides between `de` and `en`: among the elements whose primary subtag is `de` or `en` (`de-CH`, `en-GB` …) the one with the highest q above 0; on equal q the first listed. Default `de` (no header, only other languages, `*`, or q=0).

## 6. Website name

The page names the website (D36): the request's `Host` (HTTP/2 `:authority`) with the port and one trailing dot removed, ASCII lower case, when the host resolved to a website with hosts and is a DNS name or IPv4 literal (labels of 1 to 63 characters `a-z`, `0-9`, `-`, not starting or ending with `-`; at most 253 characters). No name, and the generic wording "Diese Website" / "This website", for no website, `_any` (it takes any host), `default` (proxy mode without `upstream.site_hosts`), IPv6 literals and any other host. Punycode A-labels are shown as they are. The page HTML-escapes the name anyway.

## 7. Copy (illustration A "Parkbank", chosen by the initiator on 2026-10-29)

Source: `tests/results/waiting-page-2026-10-29/variant-a.html`. Go: `waitingpage.Texts`.

| | German (default) | English |
| --- | --- | --- |
| Title | Einen Moment, bitte | One moment, please |
| Headline | Kurz Platz nehmen, bitte. | Please take a seat for a moment. |
| Lead | **{site}** bekommt gerade sehr viele Anfragen auf einmal. Deine Anfrage kommt deshalb in diesem Moment nicht durch. | **{site}** is getting a lot of requests at once right now, so yours can't get through at this moment. |
| Lead without name | Diese Website bekommt gerade sehr viele Anfragen auf einmal. Deine Anfrage kommt deshalb in diesem Moment nicht durch. | This website is getting a lot of requests at once right now, so yours can't get through at this moment. |
| Next (reload) | Du musst nichts tun. Die Seite lädt in ein paar Sekunden von selbst neu. | No need to do anything. This page reloads by itself in a few seconds. |
| Next (form) | Was du abgeschickt hast, ist nicht angekommen. Warte bitte ein paar Sekunden, geh dann einen Schritt zurück und schick es noch einmal ab. | What you sent did not arrive. Please wait a few seconds, then go back one step and send it again. |
| Countdown (reload) | Neuer Versuch in {n} s | Next try in {n} s |
| Footer | Zeit: {time} UTC | Time: {time} UTC |

## 8. Monitoring

- `TrafficCounters.waiting_page_shown` (optional, absent = 0): fail-closed 503s answered with the waiting page (both variants, `HEAD` included), per bucket, gateway-wide and per website. An overlay, not a class: the requests stay in `fail_closed` and `fail_closed_by.waf_busy` / `waf_timeout` / `body_busy`. Invariant `waiting_page_shown <= fail_closed_by.waf_busy + fail_closed_by.waf_timeout + fail_closed_by.body_busy` (`TrafficCounters.Check`).
- Metric id `traffic.waiting_page_shown` (counter, requests, exact, per website); OpenTelemetry `schild.http.server.waiting_page` (`{request}`).
- Prometheus on the metrics port: `schild_http_waiting_page_shown_total` (counter, no labels, cumulative since start). It is not a class of `schild_http_requests_total`.
- D36 website status is unchanged: waiting pages are fail-closed answers and count towards the `fail_closed` reason (>= 5 %).

## 9. Not in this version

Per-website text and image overrides, a queue (MVP-23 step 2, contracts v0.6), JavaScript of any kind, a waiting page for `not_ready`.
