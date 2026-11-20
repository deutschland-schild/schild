# Request body limits (contracts v0.5, D41, D44, D45, D46)

How much of the gateway's memory, disk and connections request bodies may hold while they are read, and what a client sees when a limit is reached. Decided by the initiator on 2026-10-30, recorded in [DECISIONS](DECISIONS.md) D41. These limits are a condition for the first live test.

Go: `contract/bodylimit`. Vectors: `body-limits` (input [body-limits.schema.json](body-limits.schema.json)), appended to `waiting-page`, `storage-bounds` and `config-schild`, cross-checked by `tools/crosscheck.py`.

**They act in every mode, observe included.** They protect the ingress, not a website. D29 ("observe acts on nobody") is about behaviour and stays. They are resource limits, not rate limits: they count what runs now, not what happened in a window.

**No exemption by media type, ever.** The `Content-Type` header is the client's word. In this contract a body class selects a size limit and nothing else: every class is inspected exactly as before. A class may make a request stricter, never freer.

## 1. Admission

Before the gate, the listener counts connections (section 2c). Order in the gate: behaviour and rate limits as today, the **admission of the request** (section 2a), the `bypass_waf` allowlist level as today (those bodies are never read by the gate), then **admission** of the body, then `Precheck`, phase 1, reading the body, phase 2. Admission comes before `NewTransaction`, so a refused client causes no WAF work. Reading stays outside the evaluation slots.

A request **has a body** when its declared length is above 0 or unknown (chunked, HTTP/2 and HTTP/3 without a length). A request without a body is not touched by this section, only by section 2a. A request holds one admission however often it is evaluated (D33 re-check).

| Key in `schild.yaml` | Default | Counts |
| --- | --- | --- |
| `waf.body.max_per_client` | 8 | bodies being read per client key (IPv4 address, IPv6 /64, as D29). Requests, not connections: one HTTP/2 connection carries many |
| `waf.body.max_per_network` | 32 | bodies being read per IPv4 /24 and IPv6 /48 |
| `waf.body.max_in_flight` | absent: 512 per GiB of memory, at least 64, at most 65536, 1024 when the memory is unknown (op `in_flight`) | bodies being read on the gateway |
| `waf.body.max_large_in_flight` | absent: 128 per GiB of memory, at least 16, at most 16384, 256 when the memory is unknown (op `large_in_flight`) | large bodies being read on the gateway: declared over 128 KiB, or of unknown length (D45) |
| `waf.body.max_in_flight_bytes` | 4 GiB | held bytes of the gateway, section 2 |
| `waf.body.max_waiting_bytes_per_client` | 64 MiB | waiting bytes per client key, section 2 (D44) |
| `waf.body.max_waiting_bytes_per_network` | 256 MiB | waiting bytes per IPv4 /24 and IPv6 /48 (D44) |
| `waf.body.max_waiting_bytes` | absent: a quarter of the memory, at least 32 MiB, at most 16 GiB, 256 MiB when the memory is unknown (op `waiting_limit`) | waiting bytes of the gateway (D44) |

Memory is what `gateway/internal/memlimit` derived from: the container limit or the machine, or `GOMEMLIMIT` when the operator set it.

Net classes `cgnat` and `mobile` get four times the client and network limits (`SharedFactor`, as for the evaluation slots), so 32 and 128 by default. `tor` keeps the plain limits. Without a valid client address only the gateway-wide limits apply.

Semantic checks of `schild.yaml` (code `config`): `max_per_client <= max_per_network`, `max_per_network <= max_in_flight` when set, `max_in_flight_bytes >= 2 × request_body_limit_bytes`, `max_waiting_bytes_per_client <= max_waiting_bytes_per_network`, `max_waiting_bytes_per_network <= max_waiting_bytes` when set.

**Decision** (op `admit`), first match wins, so a client over its share gets its own answer whatever else is full:

| Condition | Code | Status | Answer | Traffic class |
| --- | --- | --- | --- | --- |
| client at its limit of bodies being read | `body_client_share`, scope `client` | 429, or 503 for `cgnat`, `mobile`, `tor` | see below | `rejected_limit`, the 503 `fail_closed` + `body_busy` |
| client at its waiting bytes | `body_waiting_share`, scope `client` | same | same | same |
| network at its limit of bodies being read | `body_client_share`, scope `network` | same | same | same |
| network at its waiting bytes | `body_waiting_share`, scope `network` | same | same | same |
| `max_in_flight` reached, for a large body `max_large_in_flight`, held bytes at `max_in_flight_bytes`, waiting bytes at `max_waiting_bytes`, or memory pressure (section 2b) | `body_busy`, scope `gateway` | 503 | waiting page or problem | `fail_closed` + `body_busy` |

The limits apply to every request the gate reads a body for, also to the allowlist level `no_block`, as all hard limits do.

| Answer | For whom | What |
| --- | --- | --- |
| 429 | a client over its share, not on a shared address | `Retry-After` 5 + draw mod 4, bounds [5, 8]; the calm page of rate limits for browsers, problem details with code `body_client_share` or `body_waiting_share` for everything else. It is not a rate limit: D29's "never 429" for shared addresses is kept by the row below |
| 503, reason `body_busy` | shared addresses over their share, everybody when the gateway is full | [waiting-page.md](waiting-page.md): the waiting page for a document navigation (form variant for POST), else problem details with code `waiting` and the marker `Schild-Waiting: 1` |

None of these answers writes an incident. Events follow "requests stopped by a running block": sampled only, value class `sampled` (D38). `schild_hard_limit_rejects_total{code}` counts each.

**When a place is free again.** The count of a body ends when reading ends: at its end, on an error, or when the client left. A finished body does not count here, however long the backend takes: it counts in held and waiting bytes (section 2).

**How the two shares differ.** `body_client_share` says: this client reads too many bodies at once, a matter of seconds. `body_waiting_share` says: what this client sent earlier still waits for the backend, so it ends when the backend answers. The answers look the same to the client, the code tells an operator which one it was, and it points at the backend, not at the client's upload. Neither depends on the size of the body now being sent, and no body that was admitted is ended by them. A 413 is about one body and stays final; these two are about what runs now, and repeating later works.

## 2. Held bytes

`max_in_flight_bytes` bounds memory and temp space together. **Waiting bytes** (below) bound the memory on their own, because 4 GiB of held bytes mean nothing to a gateway with 2 GiB of memory.

Held bytes:

- grow with every byte **read**. Declared lengths are not reserved: a length nobody sends costs nothing, and must not be able to fill the limit.
- count a multipart body twice (`MultipartWeight`, op `size`) while Coraza holds it, because its file parts lie on disk twice while Coraza copies them, and once from the moment the transaction closed.
- stay until the request ended, however long the backend takes, and its temp files are gone (D44). A request refused or failed before that ends them with its transaction. So this count has a longer life than the counts of section 1.

Reaching the limit refuses new bodies (`body_busy`). A body already being read that crosses the limit is ended with the same answer, its bytes released.

### Waiting bytes (D44)

A checked body waits for the backend outside its transaction. The transaction keeps every transformed value of the evaluation and, for text, the body as a string, so it is closed before the request is forwarded, at every size. Up to `WaitingMemoryBodyBytes` (128 KiB, Coraza's own memory limit) the body waits in memory, above that in a temp file of its own under section 7 (prefix `body`, cleaned at start, counted by `schild_body_spool_bytes`).

Waiting bytes of a request (op `waiting`) are `WaitingOverheadBytes` (128 KiB), plus the body when it waits in memory, else what of it the send queue of the backend's socket holds, at most `WaitingSendBytes` (384 KiB, D45). So 128 to 512 KiB. The overhead is measured: 105 KiB per waiting HTTP/1.1 request with four goroutines and the buffers of two connections, the same for a body of 1 KB. It is why many tiny bodies count at all. The send queue is measured too: 335 KiB per socket on Linux with default buffers while the backend reads nothing. A temp file takes the body out of the heap, not out of the container.

They count from the end of the evaluation until the request ended, per client, per network and for the gateway. They are checked at admission only: a body that passed its evaluation has cost its work and is never dropped, so a client can overshoot by what it is reading at that moment, at most `max_per_client` bodies. A request without a body has no waiting bytes, it counts in section 2a. A re-check (D33) counts its own copy.

If the copy into the temp file fails, the answer is `body_busy`, as for a full gateway: it is our disk, not the client's fault.

Waiting bytes count the send queue of the backend, not the receive buffers of clients. Those and dirty pages are charged to the container, and the Go runtime knows nothing of them, so `schild run` takes them off the Go memory limit five times per second, down to half of it (`memlimit.Follower`), in a container without an operator's `GOMEMLIMIT`.

## 2a. Requests waiting for the backend (D45)

A running request costs about 100 KiB with or without a body (section 2). Every request counts from its admission until it ended. The admission comes before any WAF work and before the `bypass_waf` level, so the allowlist does not exempt a request: an entry says who is trusted, not how much memory there is. It acts in every mode. A request holds one place however many schild handlers it passes (D33): a nested evaluation takes none, one that follows in `handle_errors` takes a new one. A WebSocket and an event stream count for as long as they run, because they cost the same.

| Key in `schild.yaml` | Default | Counts |
| --- | --- | --- |
| `waf.requests.max_waiting_per_client` | 1024 | requests per client key. Requests, not connections: one HTTP/2 connection carries many |
| `waf.requests.max_waiting_per_network` | 4096 | requests per IPv4 /24 and IPv6 /48 |
| `waf.requests.max_waiting` | absent: a quarter of the memory at 128 KiB each, at least 256, at most 1048576, 4096 when the memory is unknown (op `request_limit`). 4096 at 2 GiB (D60) | requests on the gateway |

`cgnat` and `mobile` get four times the client and network limits, `tor` keeps the plain ones, without a valid client address only the gateway limit applies, as in section 1.

**Decision** (op `request_admit`), first match wins:

| Condition | Code | Status | Traffic class |
| --- | --- | --- | --- |
| client at its limit | `request_waiting_share`, scope `client` | 429 with `Retry-After` 5 to 8, or 503 for `cgnat`, `mobile`, `tor` | `rejected_limit`, the 503 `fail_closed` + `body_busy` |
| network at its limit | `request_waiting_share`, scope `network` | same | same |
| `max_waiting` reached, or memory pressure level 2 | `request_busy`, scope `gateway` | 503 | `fail_closed` + `body_busy` |

The answers are those of section 1: the calm page or problem details for the 429, the waiting page for a document navigation and problem details with the marker for the 503. No incident, event sampled, `schild_hard_limit_rejects_total{code}`. `fail_closed_by.body_busy` and the waiting page reason `body_busy` cover these too: the class says the gateway took no more on, the limit code says which limit. Neither limit ends a request that was admitted.

**Why these numbers.** A page of 100 assets over HTTP/2 is 100 requests, so ten browsers can load one at the same moment behind one address. 40 requests per second behind one address with a backend of 25 s fit when they have no body. With a body the waiting bytes of section 2 bind first: at 128 KiB each, 64 MiB are about 512 requests, reached after about 13 s at that rate, whatever the request limit says. A backend that holds 1024 requests of one address for longer has run out of workers. At 2 GiB, measured with HTTP/1.1 and the collector's margin: a client at its limit holds about 220 MiB, a full gateway about 1.2 GiB, so a request costs up to 150 to 200 KiB of the container, not the 100 KiB of live memory. When the gateway is full everybody gets the waiting page: a limit that keeps the container alive does not keep a site reachable.

## 2b. Memory pressure (D45)

Admission counts what it knows. The kernel kills on what it sees, and a burst moves that by hundreds of MiB per second. So `schild run` reads `memory.stat` of the container five times per second. **Held memory** (D46, op `held`) is `anon + sock + slab + kernel_stack + pagetables + shmem + file_dirty + file_writeback`, with `slab` as `slab_reclaimable + slab_unreclaimable`: what the kernel cannot give back at once. All of the slab counts, because most of the reclaimable part is the inodes and dentries of open sockets, which stay as long as the socket does. Clean page cache does not count: the kernel drops it on its own, and a healthy gateway often stands at 100 % of `memory.current` with hundreds of MiB of it. Op `pressure`, in percent of the container limit:

| Level | From | Effect |
| --- | --- | --- |
| 0 | | none |
| 1 | 70 % | new bodies get `body_busy`; a refused body is not drained, and on HTTP/1 its connection closes at once, without the half-close of the server, so the client may lose the answer to a reset; the Go heap is given back to the kernel, at most every 2 s |
| 2 | 85 % | new requests get `request_busy` |

It is a brake, not a bound: it stops what comes in, not what is inside. It needs the limit of a cgroup v2, because that is where the kernel kills. An operator's `GOMEMLIMIT` changes nothing about that (D46): the brake runs beside it, and the Go limit follows the kernel down from the operator's value as it does from the derived one, at most to half of it. `GOMEMLIMIT=off` leaves no limit to move, the levels still run. Without a limit of a cgroup, or when `memory.stat` cannot be read, no brake runs: `schild run` warns once and `schild_memory_pressure` shows `-1`, because 0 would look like calm.

**The thresholds stay at 70 and 85 % (D46).** Checked on the samples of the fourth measurement, 250 runs of the D45 image, 24 of them killed, one sample per second. With the slab counted, every killed run crossed 85 % first, 16 s before the kill in the median, at least 1 s; with the count of D45 two did not. At 90 % one killed run would go unwarned. At 80 % surviving runs spend 9.0 % of their samples at the level instead of 5.3 %, and no further kill is warned of. At 70 % the same holds for level 1.

## 2c. Open connections (D46)

A connection without a running request holds memory that sections 1 to 2a do not see: about 50 KiB on HTTP/2 with TLS and 30 KiB on HTTP/1.1 with the collector at its limit. The listener counts connections below TLS, on every server of the config, the redirect server of automatic HTTPS included. It acts in every mode.

| Key in `schild.yaml` | Default | Counts |
| --- | --- | --- |
| `waf.connections.max_per_client` | 2048 | open connections per client key (IPv4 address, IPv6 /64) |
| `waf.connections.max_per_network` | 8192 | open connections per IPv4 /24 and IPv6 /48 |
| `waf.connections.max_open` | absent: a quarter of the memory at 64 KiB each, at least 1024, at most 1048576, 8192 when the memory is unknown (op `conn_limit`). 8192 at 2 GiB (D60) | open connections of the gateway, all ports together |

`cgnat` and `mobile` get four times the client and network limits, `tor` keeps the plain ones, as in section 1. Semantic checks (code `config`): `max_per_client <= max_per_network`, `max_per_network <= max_open` when set. `schild run` warns when a limit lies below the same limit of `waf.requests`, because a client on HTTP/1.1 would then meet the closed connection first, not the answer of section 2a.

**The peer is not always the client.** The listener sees only the address of the connection, before any header. A peer in `ingress.trusted_proxies`, and every peer of a server with `proxy_protocol` in its listener wrappers, counts for the gateway alone (op `conn_admit`, `proxy`). Behind a proxy the client and network limits of this section therefore do not act: there the proxy's own limits and sections 1 and 2a do. With a list that is too broad (G5) nobody is a proxy, as for client attribution. A proxy that is missing from the list meets the client limit; the log says so, at most once per minute.

**Decision** (op `conn_admit`), first match wins:

| Condition | With an idle connection in the scope | Without one |
| --- | --- | --- |
| client at its limit | the oldest idle connection of the client is closed, the new one takes its place | closed at once |
| network at its limit | the same in the network | closed at once |
| `max_open` reached | the same on the gateway | closed at once |

**Idle** means: no request runs on it, it is not hijacked, and it was opened or ended its last request at least `ConnEvictMinAgeS` (5 s) ago. Bytes alone keep no place: a PING, a part of a header, a TLS handshake or an HTTP/2 stream the server refuses or that is reset before it reaches a handler is no request. A request counts once it reaches the first route of its server, on every server, also on sites without schild. A WebSocket, an event stream and any running request are never closed. The wait bounds what a client at its limit can make the gateway do, about 400 TLS handshakes per second at the default. A browser opens a new connection for its next request and repeats a request lost on an idle one; on a full gateway that race can cost one request a reset.

**HTTP/2 streams.** One HTTP/2 connection runs at most `H2MaxStreams` (100) requests at once, announced in its SETTINGS; Go's default is 250. A stream over it gets `REFUSED_STREAM`, and the client repeats it. This holds on every server of the Caddyfile (D60).

A refused connection gets no answer: there is no TLS yet, so no status can reach the client. No incident, no event. `schild_connections_refused_total{scope}` counts it, `schild_connections_evicted_total{scope}` the ones that gave way.

**Why these numbers.** Twice the requests of section 2a, because on HTTP/1.1 every running request holds a connection and browsers keep others open beside it. An office of 200 browsers behind one address on HTTP/1.1, six connections each, with 200 WebSockets, is 1400 connections; without the idle rule even more browsers would lock each other out. In the builder's runs at 2 GiB a client at its limit stayed under 20 % of the memory, a gateway full of idle connections at 47 % on HTTP/1.1 and 70 % on HTTP/2, the edge of level 1 of section 2b: with room in the heap a connection costs more than the figures above, about 50 and 80 KiB.

**Not covered.** A limit on connections does not stop a ramp of bodies: see D46 for the host network. HTTP/3 is off (section 8); its packets do not pass a listener wrapper. Bytes behind a connection (`sock` of a client that reads nothing) are bounded by section 2b only.

## 3. Size by class

Op `size`. The class comes from the `Content-Type` value before the first `;`, read as Coraza and `mime.ParseMediaType` read it: Unicode space trimmed, Unicode lower case. A header sent more than once is `raw` whatever it says (D44): rules read every value, Coraza's parser and most backends only the first, so no value can be trusted to name the parser.

| Class | Media types | Limit |
| --- | --- | --- |
| `text` | `application/x-www-form-urlencoded`, `application/json`, `application/xml`, `text/*`, `+json`, `+xml` | `waf.request_body_limit_bytes` |
| `multipart` | `multipart/form-data`, nothing else | `waf.request_body_limit_bytes` |
| `raw` | everything else, also no `Content-Type` and every other `multipart/*` | `waf.raw_body_limit_bytes` (default 128 KiB), at most `request_body_limit_bytes` |

**Only a form is multipart (D44).** Coraza parses a body as multipart only for this media type, and CRS reads any other body as text. So only this class counts as a cheap file in the cost estimate; every other body counts as text whole, under its class limit. Coraza's own test is a prefix (`multipart/form-data-x`): its parser runs there, here the class stays `raw`, which is stricter, never freer. A form that Go or Coraza cannot read (no or empty `boundary`, a broken or doubled parameter, a comma after the type) is `body_unparseable` before phase 2. `multipart/mixed` and `multipart/related` have real uses (batch APIs), and an application that takes them raises `raw_body_limit_bytes` as for any raw upload.

Over the limit: 413 in every mode, `raw_body_too_large` for a raw body under the whole limit, `body_too_large` as today above it. Checked against the declared length in `Precheck` and against the bytes read while streaming. An incident as for `body_too_large`.

Below the limit a raw body is inspected as it was. Until declared upload routes exist, an application with larger raw uploads raises `raw_body_limit_bytes` after its access logs were checked (D23).

## 4. Client gone

When the client leaves while its body is read (`client_gone`), nothing can be answered. No incident, no event, no `body_read_error`. It counts in `schild_bodies_aborted_total{reason="client_gone"}` and stays in the traffic class `rejected_limit`, where such a request counted before. A radio gap is no attack.

A body that stalls until a read timeout of the server (`read_body`, `read_body_idle`) counts the same in every mode (D45, op `read_end`): from the outside a tunnel looks like a client that went away. Only the status differs in effect, because this client can still read it: 400 without a page. Every other read error stays `body_read_error`.

Nobody blocked such a request. In `schild_requests_total` and the hourly summary it counts as `client_gone`, not `blocked`, and the rolling count of blocked requests leaves it out (D46, op `read_outcome`).

## 5. Measuring the receive rate

The first live test **measures** the minimum rate and enforces nothing (E2). The rule to be judged is 1 KiB/s over a fixed window of 30 s, from the start of the body. Op `rate`:

- Windows are fixed, not an average from the start, so bytes sent early pay for nothing later.
- Only complete windows give a sample. A body under 30 s says nothing about the rule, and the partial window at the end of a finished body gives none.
- An open body is measured while it runs, so a body that never ends shows up. Each complete window gives one sample of `schild_body_rate_bytes_per_second`, at the end of that window. A stall gives a sample of 0.
- The first window below 1 KiB/s counts the body once in `schild_bodies_below_min_rate_total`. That number is what an enforcement would have ended; the histogram shows how far the threshold could move.

## 6. Prometheus

On the metrics port, no labels unless named. No UI, no API, no metric id in this version.

| Name | Type | Meaning |
| --- | --- | --- |
| `schild_bodies_in_flight` | gauge | bodies being read (section 1) |
| `schild_body_bytes_in_flight` | gauge | held bytes (section 2), until the request ended |
| `schild_bodies_waiting` | gauge | checked bodies waiting for the backend (D44) |
| `schild_body_waiting_bytes` | gauge | waiting bytes of the gateway (section 2, D44): the number to watch for a slow backend |
| `schild_requests_waiting` | gauge | requests between admission and end (section 2a, D45), with or without a body |
| `schild_memory_pressure` | gauge | level of section 2b: 0, 1, 2; `-1`: no brake is running (D46) |
| `schild_connections_open` | gauge | open connections of the gateway (section 2c, D46) |
| `schild_connections_refused_total{scope}` | counter | connections closed at accept: `client`, `network`, `gateway` |
| `schild_connections_evicted_total{scope}` | counter | idle connections closed for a new one, same scopes |
| `schild_local_rules_reloads_total{result}` | counter | reloads of `rules.d`: `applied`, `unchanged`, `refused` (D46) |
| `schild_body_spool_bytes` | gauge | size of the temp files of bodies: a directory read at most every 10 s, never on a request path |
| `schild_bodies_aborted_total{reason}` | counter | `too_large`, `share`, `waiting`, `busy`, `client_gone`; `too_slow` stays 0 until the rate is enforced |
| `schild_bodies_below_min_rate_total` | counter | section 5 |
| `schild_body_read_seconds` | histogram | start to end of reading; buckets 0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600 |
| `schild_body_rate_bytes_per_second` | histogram | section 5; buckets 256, 512, 1024, 2048, 4096, 16384, 65536, 262144, 1048576, 10485760 |

Go: `bodylimit.Prom*`, `ReadSecondsBuckets`, `RateBuckets`. `schild_bodies_aborted_total{reason="share"}` is not in the first draft; the share of one client is the value most likely to need tuning, so it stays apart from `busy`.

## 7. Temp space

[storage-bounds.md](storage-bounds.md) section 8: bodies spool to `<storage.path>/tmp`, in the disk budget, cleaned at start. D14: bodies are stored only temporarily during the request.

## 8. Settings of the first server

In the global options of the Caddyfile: `servers { protocols h1 h2; timeouts { read_body 6m; read_header 10s; idle 2m } }`. Configuration only, no contract. Caddy 2.11 adds `read_body_idle` with a default of 1 minute: a pause of more than 60 s in a body ends it, whatever `read_body` says (section 4). HTTP/3 stays off until the minimum rate is enforced (E9): browsers fall back to HTTP/2.

## 9. Fixes without a contract

These change no wire format, key or code, and are part of the P0 list:

- The body limit handed to Coraza is the gate limit + 2.
- Text fields of a multipart form count as text in the cost estimate (`waf.max_concurrent_evals` description updated). Only the class `multipart` has such fields (D44).
- A full temp disk while reading a body answers `body_busy`, no incident (D44). A multipart file part Coraza cannot write stays `body_unparseable`: Coraza does not say why.
- A refused request is drained for at most 2 s, under memory pressure not at all (section 2b).
- Temp files of bodies left from an earlier process are removed at start.

## 10. Next, not in this version

P1: a share of held bytes per client (one address can still fill `max_in_flight_bytes` with bodies on disk, and then every upload gets `body_busy`), enforcing the minimum rate and `max_duration_s` (408 `body_too_slow`), HTTP/3 back on, `text_body_limit_bytes`, declared upload routes with head inspection, dashboard tile, agent `body_status`, hints, event fields `body_inspection` and `upload_route`, the overlay `TrafficCounters.bodies_aborted_by`. P2: evicting the slowest body, checking the first bytes of raw uploads, upload rate limits per route.
