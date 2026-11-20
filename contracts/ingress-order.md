# Ingress order rule: no rewrite before schild (v0.5, D31 amendment 2026-10-29, MVP-19)

`schild ingress validate` (and `schild run`, which runs the same check) refuses a Caddyfile in which a request rewrite can run before the schild handler that first inspects the request. Trigger: the measurement of 2026-10-29 evening (`tests/results/messung-2026-10-29-abend.md`, section 2.3) brought unchecked input to the backend with two Caddyfiles, P20 and P21: an explicit `route` hides the query from `schild` with `rewrite * /hidden?` and puts it back after `schild` with `uri replace`. The binding of the "already checked" marker does not help there, and P20 needs no `handle_errors` at all.

Go reference: `contract/ingress` (`Check`, `Message`, codes). Vectors: `ingress-order` (input [ingress-order.schema.json](ingress-order.schema.json)), Go and Python agree. The vector Caddyfiles were adapted with the stock Caddyfile adapter of the embedded Caddy (v2.11.4); `caddyfile` in each vector is the source, `servers` the adapter's `apps.http.servers`.

## 1. What is checked

The rule reads the adapted Caddy JSON, as the validator does, so imports, snippets, named routes and Caddy's directive order count as Caddy sees them. In the JSON the Caddyfile directives `rewrite`, `uri` (every subcommand: `strip_prefix`, `strip_suffix`, `replace`, `path_regexp`, `query`), `method` and `try_files`, and the index rewrite of `php_fastcgi`, are all the handler `rewrite`. Every `rewrite` handler counts, with or without a matcher.

Every site route (each top-level route of a server, `/routes/i`) and every `handle_errors` route (`/errors/routes/i`) is walked on its own, in execution order:

- the routes of a list in order, the handlers of a route in order;
- a `subroute` (from `route`, `handle`, `handle_path`, a site block) is walked at its position;
- `invoke` walks the named route (`/named_routes/<name>`) at the position of the invoke (Caddy compiles it with the rest of the chain as its next handler); an unknown name or an invoke cycle is a `schema` error of the vector;
- route lists anywhere else inside a handler (`handle_response` of `reverse_proxy` and `intercept`, the `errors` of a subroute) are walked after the handler; they never guard what follows them, and error lists start unguarded;
- the site route's own matcher (the host) is dropped: within the site its handlers run unconditionally. A `handle_errors` route starts unguarded although the site's schild may have run: that schild may have inspected a rewritten URI (P21).

**Guarded:** as in the validator, an unconditional `schild` guards everything after it in its route list and in the enclosing lists. A route is unconditional when it has no matcher and is the first route of its group; `schild` with a matcher (`schild /api/*`) guards only the rest of its own route.

**Refused:** a `rewrite` handler that runs while not guarded and **precedes** a later `schild` handler. "Precedes" = the schild comes later in the walk and the two are not in different routes of the same group of one route list (Caddy runs at most the first matching route of a group, so `handle /assets/* { uri strip_prefix /assets; file_server }` never runs before the `schild` of a sibling `handle`).

**Exempt:** the prefix strip that `handle_path` generates. In the JSON: a route whose matcher is exactly one path matcher with one path `P` starting with `/`, whose only handler is a `subroute`, whose first route has no matcher and no group and exactly the handler `{"handler": "rewrite", "strip_path_prefix": S}` with `S` = `P` without a trailing `/*`, else without a trailing `*`. The same rewrite written by the operator (`uri strip_prefix /app` inside a `route`) is refused. A request that `handle_path` stripped before `schild` and that schild in `handle_errors` checks again counts once (D33 amendment, `request-recheck`).

**Allowed after schild:** everything. A rewrite after an unconditional `schild` (`route { schild; rewrite * /x; ... }`, `rewrite` and `try_files` after `import schild` at the top of a site, `uri replace` after `schild` in `handle_errors`) changes only what reaches the backend, not what schild inspected. If a second `schild` runs after such a rewrite, it evaluates the changed request again (the marker is bound to what was inspected), and the request still counts once.

**Not in this rule:** `request_body` and `vars` before schild (no URI or method change; P10 brought nothing unchecked through), and `request_header` unless section 1a applies. A rewrite with no `schild` after it on any path (a static site) is not a finding here; sites that reach a backend without schild stay the validator's existing error.

## 1a. Headers: hidden from schild and written back (D40)

Trigger: the measurement before the live step (2026-10-30, shapes V01 and V14) brought attacks in Referer, Cookie and User-Agent to the backend with `route { request_header -Referer; schild; request_header Referer {...}; reverse_proxy ... }`. A removal alone hides nothing that matters (the backend does not get the header either); the write behind schild is what brings it back.

The walk of section 1 also records every `headers` handler with a `request` part and every `reverse_proxy` with `headers.request` (Caddyfile `header_up`). Names compare case-insensitively.

- **Hides:** the names in `delete`, `set` and `replace` of a `headers` handler. `add` hides nothing (the client's value stays). `header_up` before schild hides nothing either: it changes the proxy's copy of the request, never the request schild reads.
- **Writes back:** the names in `replace`, and in `set` or `add` when a value can carry a client value, of a `headers` handler or a `reverse_proxy`. A literal value cannot bring a client's bytes back, and a `delete` cannot either.
- **Can carry a client value (D43):** a value with a `{` that is left after taking out the placeholders below. So a placeholder that is not listed counts, a default (`{http.request.scheme:x}`) counts, and every `{http.vars.*}` counts, also `{client_ip}`, because `vars` can overwrite any variable before schild.
  - Server-side, no client can put bytes into them: `{http.request.scheme}`, `{http.request.uuid}`, `{http.request.proto}`, `{http.request.remote}`, `{http.request.remote.host}`, `{http.request.remote.port}`, `{http.reverse_proxy.upstream.host}`, `{http.reverse_proxy.upstream.hostport}`, `{http.reverse_proxy.upstream.port}`.
  - The Host: `{http.request.host}`, `{http.request.hostport}`, `{http.request.port}` hold what schild inspected, so they are not a write either, unless an unguarded `headers` handler of the same route hides `Host`. Then they count: a value moved into `Host` before schild was seen under that name only.
- **Patterns:** a `delete` entry `*`, `*x`, `x*`, `*x*` and a `replace` key `*` cover every name they match; a name with a placeholder (`{`) counts as any name.

**Refused** (`header_hidden_from_schild`): a `headers` handler that runs not guarded and hides name N, a `schild` it precedes, and a later handler behind that schild that writes N back, where "precedes" is the rule of section 1 between hider and schild, hider and writer, schild and writer. The writer may also sit in any `handle_errors` route of the server: Caddy runs those on the same request, so a site route's hider is checked against them too.

**Allowed:** a header removed before schild and never written back, or written back with a server-side value (`request_header X-Forwarded-Proto {http.request.scheme}` before schild and `header_up X-Forwarded-Proto {http.request.scheme}` behind it; D43); any change behind an unconditional schild; a site-level `request_header` (Caddy's directive order runs it after `schild`); a value written back before schild runs; hider and schild or writer in exclusive `handle` branches.

**Known limits, deliberately not checked:** a value carried back under another name (`request_header X-B {vars.saved}`) or as a `fastcgi` env entry, because telling that from an everyday header needs value tracking; a request body swapped with `request_body`. Both need a deliberate Caddyfile, not a slip.


## 2. Result and message

At most one finding per code and per site route or `handle_errors` route: the first refused rewrite in walk order and the first `schild` it precedes, then the first refused hider with that schild and writer (the fields of `header_hidden_from_schild` are listed below the table). Servers in byte order of their names, site routes before error routes.

| Field | Value |
| --- | --- |
| `code` | `rewrite_before_schild` (`ingress.CodeRewriteBeforeSchild`) |
| `msg_key` | `ingress.err.rewrite_before_schild` |
| `server`, `route`, `hosts` | the server name, the JSON pointer of the site or error route within the server, its host matchers |
| `directive` | `method` (field `method`), `uri` (`strip_path_prefix`, `strip_path_suffix`, `uri_substring`, `path_regexp`, `query`), else `rewrite` |
| `rewrite`, `schild` | JSON pointers (RFC 6901, relative to the server object) of the two handlers |

`header_hidden_from_schild` (`ingress.CodeHeaderHiddenFromSchild`, `msg_key` `ingress.err.header_hidden_from_schild`) has the same `code`, `msg_key`, `server`, `route`, `hosts`, `schild`, with `directive` always `request_header` and without `rewrite`; instead `hide` and `restore` (JSON pointers of hider and writer) and `header` (lower case, the written name; the hidden pattern when the writer is a wildcard).

It is an error, not a warning: `schild ingress validate` ends with FAIL and `schild run` does not start. Printed form (`ingress.Message`):

```
rewrite_before_schild: site a.example.test runs `rewrite` before schild inspects the request (<rewrite pointer> before <schild pointer>); a part it hides from schild could be put back after it and reach the backend unchecked. Put `schild` (or `import schild`) first: at the top of the site block, or as the first line of the route or handle_errors block
```

```
header_hidden_from_schild: site a.example.test changes request header referer before schild inspects the request and writes it again behind schild (<hide pointer> before <schild pointer>, written at <restore pointer>); a value schild never saw could reach the backend. Put `schild` (or `import schild`) before the first change of the header
```

For a `handle_errors` route it says `handle_errors of <hosts>` instead of `site <hosts>`. `ingress.unprotected_sites` does not lift this rule for a site that runs schild: a listed site without schild has no schild to precede.

## 3. Effect on earlier measurement variants

Checked by the contracts agent with the embedded Caddy's adapter over the 91 gateway test variants (`gateway/internal/caddymod/testdata/variants`) and the 24 P variants of the measurement. Newly refused (all accepted before): M18, M24, M25 and P01-P04, P07, P09, P12-P15, P17-P23 (P22 for its site route, the M24 shape; its `handle_errors` route, schild first, passes), every one of them a rewrite, `uri` or `method` before schild in a route, including the error-path variants whose re-check in `handle_errors` caught the attack at runtime. Every other variant keeps its verdict, among them P08 (handle_path strip), P24, the eight files with the recommended line (A-*) and the O set (Laravel, WordPress, SPA with try_files and the other everyday shapes).

D40 (`header_hidden_from_schild`): all 115 gateway test variants keep their verdict, among them M26 (a header removed before schild, never written back) and P06 (`request_header Host` before schild, `header_up` of another name). Refused now: only shapes that hide and write back, V01 and V14 of the measurement of 2026-10-30 (with its other thirteen shapes in `testdata/variants`, 130 files).

D43 (server-side values): all 130 files keep their verdict. Of the measurement of 2026-10-30 (`testlab/measure/crowdsec-hub/d40/ingress_variants.py`) the 26 hide-and-restore shapes keep theirs, and the four false alarms `a11`, `a12`, `a13`, `a16` pass now: `X-Request-Id {http.request.uuid}`, `X-Forwarded-Proto {http.request.scheme}`, `X-Forwarded-Host {host}` and `Forwarded "for={remote_host}"`. Vectors `ingress-order` valid 045-055 show both directions.
