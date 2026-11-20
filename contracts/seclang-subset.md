# SecLang subset for network rules (contracts v0)

Network (remote) rules can only **protect**: they can never switch protection off, exfiltrate data, target one site, or use IPs or locations (K7, G1, M4). Every `seclang` text in a rule bundle must pass this subset; anything not explicitly allowed is rejected with error code `seclang`. Local rules of the operator are not affected. Go: `contract/seclang` (cases shared with the vectors in `seclang.Cases`), Python: `contracts/tools/crosscheck.py`.

## Text format

- Printable ASCII (0x20-0x7E) and LF only, 1..8192 bytes. No tabs, no CR, no line continuations, no comments.
- Exactly one `SecRule`, optionally followed by chained `SecRule` lines (one per line, at most 4 lines in total). Each line but the last carries `chain`; the last does not.
- Line grammar (one space between parts, nothing after the actions):

  ```
  SecRule <VARIABLES> "<OPERATOR>" "<ACTIONS>"
  ```

- A double-quoted argument ends at the next `"`. There are **no escaped quotes** (write `\x22` inside `@rx`), and an argument may not end with a backslash. Reason: Coraza ends an argument at a quote preceded by an even number of backslashes, other parsers count differently; without `\"` every parser sees the same three parts.
- No other directive: `SecAction`, `SecMarker`, `SecRuleRemove*`, `SecRuleUpdate*`, `SecRuleEngine`, `SecDefaultAction`, `Include` and everything else are rejected.

## Variables

`VAR(|VAR)*`, at most 16. `VAR = [!|&]NAME[:selector]`, selector `[A-Za-z0-9_.-]{1,64}` (literal names only, no `/regex/` selectors).

| Allowed collections (selector optional) | Allowed scalars (no selector) |
| --- | --- |
| `ARGS`, `ARGS_GET`, `ARGS_POST`, `ARGS_NAMES`, `ARGS_GET_NAMES`, `ARGS_POST_NAMES`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_HEADERS` (selector **required**), `REQUEST_HEADERS_NAMES`, `FILES`, `FILES_NAMES` | `REQUEST_URI`, `REQUEST_URI_RAW`, `REQUEST_FILENAME`, `REQUEST_BASENAME`, `REQUEST_LINE`, `REQUEST_METHOD`, `REQUEST_PROTOCOL`, `QUERY_STRING`, `REQUEST_BODY` |

- `REQUEST_HEADERS` needs a header name, and the name must not identify the site or the client: `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Original-Host`, `X-Host`, `Forwarded`, `Forwarded-For`, `X-Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `CF-Connecting-IPv6`, `Fastly-Client-IP`, `X-Envoy-External-Address`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `Via` are rejected (case-insensitive).
- `Referer` and `Origin` carry the site's own host name: a line that inspects them may only use the argument-free detection operators (`@detectSQLi`, `@detectXSS`, `@validateUrlEncoding`, `@validateUtf8Encoding`), which cannot name a host. Otherwise `REQUEST_HEADERS:Referer "@contains shop.example"` would block one site's own navigation.
- `!` (exclusion) only for a named member of a collection; at least one non-excluded variable. `&` (count) only in a line with a numeric operator (a count is a number; `&REQUEST_HEADERS "@rx [2-9]"` would match every request).
- Everything else is rejected, in particular `REMOTE_ADDR`, `REMOTE_HOST`, `REMOTE_PORT`, `SERVER_NAME`, `SERVER_ADDR`, `SERVER_PORT`, `GEO`, `TX`, `IP`, `SESSION`, `USER`, `GLOBAL`, `ENV`, `RESPONSE_*`, `XML`, `MATCHED_*`, `TIME*`.

## Operators

Explicit `@name` only (no implicit `@rx`). Optional `!` negation only in chained lines (a negated head matches almost everything). The operator text is `[!]@name` or `[!]@name<SP><argument>` with exactly one space; the argument must not start or end with a space (Coraza trims it, so `"@rx  .*"` would become the catch-all `.*`). **No `%{` anywhere in an operator** : Coraza expands macros in `@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@within` and the numeric operators, so `"@streq %{REMOTE_ADDR}"` or `"@contains %{REQUEST_HEADERS.host}"` would use the client address or the site's host.

| Operator | Argument | Where |
| --- | --- | --- |
| `@rx` | regex, see below | everywhere |
| `@pm` | 1..100 phrases separated by exactly one space (Coraza splits on single spaces; `a  b` would add the empty phrase, which matches everything) | everywhere |
| `@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@within` | non-empty | everywhere |
| `@detectSQLi`, `@detectXSS`, `@validateUrlEncoding`, `@validateUtf8Encoding` | none | everywhere |
| `@eq`, `@gt`, `@ge`, `@lt`, `@le` | integer `0..999999999` | chained lines only (a number alone is never the whole condition) |

Rejected, among others: `@ipMatch`, `@ipMatchF`, `@ipMatchFromFile`, `@geoLookup`, `@rbl`, `@pmFromFile`, `@pmf`, `@inspectFile`, `@fuzzyHash`, `@unconditionalMatch`, `@noMatch`, `@rsub`, `@gsbLookup`, `@verifyCC`, `@validateByteRange`, `@validateDTD`, `@validateSchema`.

### `@rx` regex subset

Coraza evaluates `@rx` with Go RE2 (linear time, no catastrophic backtracking). The subset keeps patterns portable between RE2 and the Python cross-check and rejects catch-all patterns:

- at most 1024 characters, repeat counts at most 1000 without leading zeros, no `{,n}`; the largest count of every `{...}` in the text, summed, is at most 1000 (RE2 expands counted repetition; the sum bounds the program size and so the matching cost on every client);
- **no nested quantifiers**: a group that is repeated with `*`, `+`, `{n,}` or `{n,m}` (m >= 2) may contain neither a quantifier nor `|`, at any depth (`(a+)+`, `(?:a|ab)*`, `((?:ab?)c){2,}` are rejected; `(?:\.\./)+` is fine). Coraza's RE2 is linear, but the same rules must stay safe in backtracking engines (PCRE in libmodsecurity, the Python cross-check). A `?` directly after a quantifier makes it lazy and is not a second quantifier;
- no quantifier directly after an assertion (`^`, `$`, `\b`, `\B`), no range next to a class escape inside a class (`[\d-z]`, `[a-\w]`);
- no lookaround or atomic groups (`(?=`, `(?!`, `(?<`, `(?>`), no named groups (`(?P`), no comments `(?#`, no POSIX classes `[[:`, no possessive quantifiers (`*+`, `++`, `?+`, `}+`), no `[]` or `[^]`;
- group flags only `(?:`, `(?i:`, `(?s:`, `(?is:` anywhere and `(?i)`, `(?s)`, `(?is)` at the very start;
- escapes: any escaped punctuation, `\d \D \w \W \s \S \n \r \t \f \v`, `\xHH` (exactly two hex digits), and `\b \B` outside character classes. Everything else (`\1`-`\9`, `\k`, `\g`, `\Q`, `\E`, `\p`, `\P`, `\C`, `\z`, `\Z`, `\A`, `\u`, `\x{...}`) is rejected;
- the pattern must compile (RE2). Whether it matches too much is decided by the catch-all check below (the empty string is part of the benign corpus, so `.*`, `^`, `a?` are rejected there).

## Actions

Comma-separated, no spaces outside quotes. `name[:value]`, value either unquoted (no `'`) or single-quoted (`\'` escapes a quote).

| Action | Rule |
| --- | --- |
| `id` | required in the first line, integer in `7700000..7799999` (reserved for network rules), unique within a bundle |
| `phase` | required, `1` or `2` (request phases only) |
| `deny`, `block`, `pass` | exactly one, required in the first line. `max_action: observe` requires `pass`. The client maps the action to its mode (observe never blocks, review asks first). |
| `status` | `403` or `429`, only with `deny` |
| `severity` | required: `CRITICAL`, `ERROR`, `WARNING`, `NOTICE` or `2`..`5` |
| `msg` | required, static text up to 200 characters |
| `logdata` | optional, static text up to 200 characters |
| `tag`, `rev`, `ver`, `maturity`, `accuracy` | static text up to 64 characters; at most 8 tags |
| `t:<name>` | at most 16, from: `none lowercase urlDecode urlDecodeUni htmlEntityDecode jsDecode cssDecode cmdLine compressWhitespace removeWhitespace removeNulls replaceNulls removeComments replaceComments normalizePath normalisePath normalizePathWin normalisePathWin base64Decode base64DecodeExt hexDecode utf8toUnicode length trim trimLeft trimRight escapeSeqDecode sqlHexDecode` |
| `setvar` | at most 2, only raising the score: `tx.inbound_anomaly_score_pl[1-4]=+N` or `tx.schild_remote_hits=+N` with `N` in `1..10` or `%{tx.critical_anomaly_score}`, `%{tx.error_anomaly_score}`, `%{tx.warning_anomaly_score}`, `%{tx.notice_anomaly_score}` |
| `chain`, `multiMatch`, `log`, `auditlog` | no value |

"Static text" means characters `A-Z a-z 0-9 space _ . : ; / ( ) [ ] # + = -` and **no macro expansion `%{`**: no header, cookie, argument or body value can reach logs (exfiltration). No comma, so even a parser that ignores single quotes splits the actions the same way (`msg:'x,ctl:ruleEngine=Off'` is rejected). The actions text contains **no backslash** at all (no action value needs one, and parsers disagree on escapes). `t:length` only in a line with a numeric operator (after `t:length` every value is a short number, so a string operator would match almost everything). Chained lines may only use `t:`, `multiMatch` and `chain`; `id`, `phase`, disruptive actions, `msg`, `logdata`, `tag`, `setvar` and the other metadata belong to the first line.

Rejected, among others: `allow` (switches inspection off), `ctl:*` (rule engine, rule removal, body access), `skip`, `skipAfter`, `exec`, `append`, `prepend`, `proxy`, `redirect`, `drop`, `setenv`, `setuid`, `setsid`, `setrsc`, `initcol`, `expirevar`, `deprecatevar`, `sanitise*`, `xmlns`, `capture`, `nolog`, `noauditlog`, `pause`.

## Catch-all check

A chain matches only if every line matches, so a rule is specific if **at least one line** is specific. A line is specific if its operator is not negated and

- it is one of the argument-free detection operators (`@detectSQLi`, `@detectXSS`, `@validateUrlEncoding`, `@validateUtf8Encoding`), or
- it is a string operator (`@rx`, `@pm`, `@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@within`) that matches **no value of the benign corpus**.

Numeric operators are never specific. A rule without a specific line is rejected (`seclang`): `@rx .`, `@rx ^/`, `@beginsWith /`, `REQUEST_METHOD "@streq GET"`, `REQUEST_HEADERS:User-Agent "@pm mozilla"`, `QUERY_STRING "@within abc"` (the empty value is within every argument) and chains made only of such lines.

Operator semantics for the check are Coraza's: `@rx` searches anywhere (RE2; Coraza adds `(?s)` or `(?sm)`, which makes no difference on the corpus because it has no line breaks), `@pm` is an ASCII case-insensitive substring search for any phrase, `@streq` is equality, `@contains`, `@beginsWith`, `@endsWith` are case-sensitive, `@within` is true when the value occurs in the argument. Transformations are not applied (the corpus values are already in decoded form).

The **benign corpus** is part of the contract; it is the file [seclang-benign-corpus.json](seclang-benign-corpus.json) (71 values; the Python cross-check loads it, the Go copy in `contract/seclang/benign.go` is tested to be identical): the empty string and a space; short values (`0`, `1`, `2`, `10`, `100`, `a`, `x`, `id`, `q`, `page`, `en`, `de`, `true`, `false`, `null`, `test`, `hello world`, `Max Mustermann`, `max@example.org`, a date and a timestamp); paths (`/`, `/index.php`, `/index.html`, `/favicon.ico`, `/robots.txt`, `/search?q=test`) and query strings; methods (`GET`, `POST`, `HEAD`, `OPTIONS`); protocols (`HTTP/1.0` to `HTTP/3`) and two request lines; common header names (`Host`, `User-Agent`, `Accept`, ..., `Referer`, `Origin`); three current browser user agents (Chrome on Windows, Safari on iPhone, Firefox on Linux); common `Accept`, `Accept-Language`, `Accept-Encoding`, `Content-Type`, `Connection`, `Cache-Control` and `Sec-Fetch-Site` values; a session cookie; a small JSON object and an HTML fragment. Changing the corpus is a contract change.

The check is a heuristic against obvious catch-alls, not a proof: a rule can still be too broad for one kind of site (for example everything under `/wp-admin/`). The backstops are k-of-n human approval in the labs and the client's local brake (`max_match_share`).

The Python cross-check does not use Python's `re` to run patterns on the corpus (it backtracks: `.*.*.*.*.*x` takes minutes on a user agent). It has its own set-based matcher over the parse tree, so the corpus check is also a differential test of a second regex engine against RE2.

## Rule metadata checks (bundle level)

In addition to the text, each rule in a bundle ([rule-bundle.schema.json](rule-bundle.schema.json)) passes, in this order:

1. SecLang subset (above), with the rule's `max_action`.
2. **Evidence** (G2), code `evidence`: `max_action` must not exceed the level the evidence allows.

   | Level | Evidence |
   | --- | --- |
   | `block` | class `virtual_patch`, reproduced by >= 2 lab operators, human approval in >= 2 organisations |
   | `challenge` | reproduced by >= 1 operator, or own sensors (honeypot, lab range) of >= 2 operators |
   | `observe` | any of the above, own sensors of 1 operator, or tips from >= 3 issuers with `max_issuer_share <= 0.34` |

   `heuristic` and `behavioral` rules therefore never reach `block` from the network.
3. **Validity**, code `validity`: `max_action_until` (required for `challenge` and `block`) lies after `issued_at` and not after the bundle's `expires`; `challenge` lasts at most 7 days.
4. **Uniqueness**, code `duplicate_rule`: `rule_id` and SecRule `id` are unique in the bundle.

Schema-level: `virtual_patch` rules always have `feedback_policy: narrow_only` (G4), `max_match_share` (local brake) is at most 0.05, rule targets name software and versions, never hosts.

## Client-side limits that remain (not part of validation)

- Local brake: a network rule hitting more than `max_match_share` (client default 1 %) of a site's own legitimate traffic is suspended locally and reported (`schild.rule.suspended.v1`, feedback after operator approval).
- Mode: observe never blocks on network rules; review asks the operator; autoblock applies `max_action` at most.
- Emergency stop ([withdrawal.schema.json](withdrawal.schema.json)) removes network rules only; local rules stay.

`make contracts-fuzz` (seeded, `FUZZ_N` rules) generates random patterns and mutated rules and fails if the Go and the Python validator judge any of them differently; the three portability rules about assertions, class ranges and leading zeros came out of it.

Every valid SecLang vector and every rule the fuzz accepts was also loaded into Coraza v3.8.1 during the v0 review: all compile, and no valid vector fires on a set of ordinary requests (GET, form login, JSON POST, search). Several rejected vectors (`rx-leading-space`, `pm-double-space`, `within-empty-catch-all`, `streq-macro-remote-addr`, ...) were shown to block every request in Coraza, which is why they are rejected. The client (MVP-02) keeps such a Coraza conformance test (`make gateway-coraza`: `TestCorazaConformance` and `gateway/internal/waf/coraza_semantics_test.go`, re-run on v3.8.1 with the client upgrade, D24). Note that `streq-macro-remote-addr` and `contains-macro-host` do not block every request; they show that Coraza expands the macro, so the rule would target one client address or one site.

The subset is deliberately small. Extending it is a contract change (new version) and needs new vectors in both implementations.
