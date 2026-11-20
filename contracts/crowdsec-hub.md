# Rule repository crowdsec: CrowdSec Hub virtual patches (contracts v0.5, D39, MVP-26; v0.6, D73)

The public virtual patches of the CrowdSec Hub run in the gateway as the rule repository `crowdsec`, next to `crs` (OWASP CRS) and `local` (the operator's rules.d), with automatic updates. What every repository shares (state, effect, approval, disabling, API, events) is D73 and `contract/rules`; this document is what only this repository has. No account, no Central API, no Console, no IP lists, no data to CrowdSec, and the CrowdSec engine does not run: the gateway fetches one public file and converts the rules itself.

Go: `contract/crowdsec`, the hub profile of `contract/seclang`. Python: `contracts/tools/crosscheck.py`. Vectors: `crowdsec-hub` (input [crowdsec-hub.schema.json](crowdsec-hub.schema.json), four ops; the effect, the state switch and the scope checks are `rule-effect` vectors since D73), `crowdsec-set` ([crowdsec-set.schema.json](crowdsec-set.schema.json)), appended to `config-schild`, `events` and `seclang`. Hub content is data: nothing in it is executed, and no hub text reaches a rule except an operator argument or a selector, both checked here.

## 1. The state

One state for the whole repository, in `schild.yaml` as `rules.crowdsec.state`, in the dashboard with one click and through the agent API, the same as for `crs` and `local` (D73). No per-rule work is needed to use it.

| State | UI | Rules | Fetch | A match |
| --- | --- | --- | --- | --- |
| `off` | aus | none | none | - |
| `detect` (default) | Erkannt | run | yes | the request passes, outcome `logged` |
| `block` | sperren | run | yes | blocks as section 8 says: rules of the image snapshot at once, rules received from the hub after `settling_s` |

**Change:** `PATCH /rule-repositories/crowdsec` in the dashboard (`updateRuleRepository`, session and CSRF header, no password on any transition) and in the agent API (`updateAgentRuleRepository`, scope `rules:write`), body `state` or `reset_state`. Written to the settings overlay, which wins over `schild.yaml` until `reset_state`; `state_source` (`default`, `config`, `dashboard`, `agent`) and with `agent` `state_set_by` say who set it. Who set it lives in the store row `rules_state_by_v1`, one entry per repository. Every change of the effective state writes `schild.rule.repository_switched.v1` and the annotation `rule_repository_changed`. Op `switch` of `rule-effect` fixes `changed` and `rebuild`.

**`off` and the stored set (D43):** `off` unloads the rules and stops the fetch, and that is all. The stored set stays in its row, with its history, and a switch back loads what the start would load (section 6), so it needs no download. `off` is no way back from a bad set: the same set returns. That way back is the reset in section 6.

**Without a restart:** `off` against `detect` or `block` builds a new instance in the background and swaps it (`Engine.Swap`); requests in flight keep theirs. `detect` against `block` needs no rebuild: the rules are the same `pass` rules, the next request decides differently. Op `switch` fixes `changed` and `rebuild`. Several changes in a row coalesce: one build at a time, the last state wins.

## 2. What loads

The source is the file `https://raw.githubusercontent.com/crowdsecurity/hub/master/.index.json`, section `appsec-rules`, and of it the items that are members of the collection `crowdsecurity/appsec-virtual-patching` in the same index and named `crowdsecurity/vpatch-*`. That is what a default CrowdSec install gets. The hub keeps rules out of the collection on purpose; a name prefix alone would load them. Items outside are counted as `not_selected`, not listed as skipped.

Census of the index of 2026-10-30 (3,965,685 bytes, SHA-256 `86f5b58056ae…`): 236 `appsec-rules`, 220 `vpatch-*`; the collection has 208 members, 206 of them `vpatch-*`.

| Result | Rules |
| --- | --- |
| selected | 206 |
| loaded | 201 (97.6 %): 215 AND-groups, 487 SecRule lines, largest regex program 85 instructions |
| skipped | 5: `forbidden_header` 2, `catch_all` 1, `raw_seclang` 1, `value_chars` 1 |
| of the loaded, with `raw_body_partial` | 10 |
| not selected | 30 |

Go and Python gave the same result field by field on all 201 rules, and all 201 compile in Coraza 3.8.1, alone and together, without a match on four ordinary requests. Those are checks of the conversion, not the MVP-26 measurement.

## 3. Mapping

Checked against CrowdSec's own compiler: `pkg/appsec/appsec_rule/modsecurity.go` and `appsec_rule.go` of `crowdsecurity/crowdsec`, commit `f4b4d9d43fb3`. Every hub construct has a line here; anything else is refused (section 4).

**Parsing.** One YAML document with the rules of `schild.yaml`: no anchors, aliases, explicit tags, merge keys or duplicate keys. A scalar stays the text it was written as: `value: false` is the string `false` and `value: 1` the string `1`, as yaml.v3 decodes them into the compiler's `string` field. A plain `null`, `~` or empty value is absent.

**Zones** (`zones`, in the order given; `variables` as selectors, zone by variable, as in the compiler):

| Zone | Variable | Zone | Variable |
| --- | --- | --- | --- |
| `ARGS` | `ARGS_GET` (not `ARGS`) | `COOKIES_NAMES` | `REQUEST_COOKIES_NAMES` |
| `ARGS_NAMES` | `ARGS_GET_NAMES` | `FILES`, `FILENAMES` | `FILES` |
| `BODY_ARGS` | `ARGS_POST` | `FILES_NAMES` | `FILES_NAMES` |
| `BODY_ARGS_NAMES` | `ARGS_POST_NAMES` | `METHOD` | `REQUEST_METHOD` |
| `HEADERS` | `REQUEST_HEADERS` | `PROTOCOL` | `REQUEST_PROTOCOL` |
| `HEADERS_NAMES` | `REQUEST_HEADERS_NAMES` | `URI` | `REQUEST_FILENAME` |
| `COOKIES` | `REQUEST_COOKIES` | `URI_FULL` | `REQUEST_URI` |
| | | `RAW_BODY` | `REQUEST_BODY\|TX:json_request_body` |

`RAW_BODY` is the one place where the engines differ. The compiler writes `RAW_REQUEST_BODY`, a variable of CrowdSec's Coraza fork (`crowdsecurity/coraza` v3.8.0-crowdsec.20261001, `internal/variables/variables.go`) that upstream v3.8.1 does not have. Upstream fills `REQUEST_BODY` for urlencoded bodies only (`internal/bodyprocessors/urlencoded.go`) and keeps a JSON body in `TX:json_request_body` (`json.go`). So a `RAW_BODY` rule sees urlencoded and JSON bodies; **XML and multipart bodies stay invisible to it** (shown in Coraza 3.8.1). Plain text and other bodies without a processor stay invisible in Coraza alone, but with the CRS, rule 901340 runs them through the urlencoded processor and the rule sees them too (measured 2026-10-30, `text/plain` and `application/octet-stream`; without the CRS not measured). A client chooses its own `Content-Type`, so a backend that also takes the body as XML or multipart can be reached past these rules. Such a rule loads and carries the note `raw_body_partial`, which the rule read field shows. A miss, never a false match.

Zones `METHOD`, `PROTOCOL`, `URI`, `URI_FULL` and `RAW_BODY` are one value and take no variable. `name` on a leaf is ignored, as in the compiler (one hub rule has it): the whole zone is inspected.

**Transforms** (`t:none` first, then in order): `lowercase`, `uppercase`, `trim`, `trim_left` `trimLeft`, `trim_right` `trimRight`, `length`, `urldecode` `urlDecode`, `b64decode` `base64Decode`, `b64decode_lenient` `base64DecodeExt`, `hexdecode` `hexDecode`, `htmlentitydecode` and `html_entity_decode` `htmlEntityDecode`, `js_decode` `jsDecode`, `css_decode` `cssDecode`, `cmdline` `cmdLine`, `normalizepath` and `normalize_path` `normalizePath`, `normalizepathwin` and `normalize_path_win` `normalizePathWin`, `remove_whitespaces` `removeWhitespace`, `compress_whitespaces` `compressWhitespace`, `remove_nulls` `removeNulls`, `replace_nulls` `replaceNulls`, `remove_comments` `removeComments`, `replace_comments` `replaceComments`. `count` is no transformation: it puts `&` before every variable.

**Match types:** `regex` `@rx`, `equals` `@streq`, `startsWith` `@beginsWith`, `endsWith` `@endsWith`, `contains` `@contains`, `libinjectionSQL` `@detectSQLi`, `libinjectionXSS` `@detectXSS`, `gt` `@gt`, `lt` `@lt`, `gte` `@ge`, `lte` `@le`, `eq` `@eq`. `equals` with `count` or `length` is `@eq` (the compiler's `@streq` on the digits means the same). `not: true` is `!`.

**`and`, `or`, several entries in `rules:`.** A node is exactly one of `and`, `or` or a leaf. The tree flattens to disjunctive normal form like `flattenToDNF`; entries of `rules:` are alternatives. Each AND-group becomes one chain with its own id. The compiler joins groups with `skip:N`; the subset has no `skip` and none is needed: a group stands alone, and the gateway counts one hub rule once however many groups matched. In a chain, numeric and negated lines go last (stable), because AND is commutative and the subset wants a string head.

**Output** of a group, one line per leaf:

```
SecRule <vars> "<op>" "id:<id>,phase:2,pass,t:none[,t:...],severity:CRITICAL,msg:'crowdsec hub <name>',tag:crowdsec_hub[,chain]"
SecRule <vars> "<op>" "t:none[,t:...][,chain]"
```

Always `pass`: Coraza runs in DetectionOnly and the source state decides (section 8), so no hub rule text can block. The compiler's `deny` and `severity:'emergency'` are not taken over. `msg` holds the checked name; description and labels go to the read fields only.

## 4. Refusal of one rule

An unconvertible rule is skipped and listed, never loaded partly: one bad leaf refuses the whole hub rule. The first failing check counts.

| Code | Reason |
| --- | --- |
| `digest_mismatch` | content does not fit `versions[version].digest`, or the version is not listed |
| `deprecated` | the current version is marked deprecated |
| `bad_name` | the name has other characters than `[A-Za-z0-9._-]` after `crowdsecurity/vpatch-` |
| `name_mismatch` | the path or the YAML name does not fit the index key |
| `rule_too_long` | above 64 KiB of YAML or 8 KiB of SecLang per group |
| `yaml` | see parsing above, or not UTF-8 |
| `raw_seclang` | `seclang_rules` or `seclang_files_rules` |
| `external_data` | `data` |
| `unknown_key` | any key this contract does not know, in any object |
| `no_rules` | no `rules:` |
| `node_shape` | a node is not exactly one of `and`, `or`, leaf; an empty `and`, `or` or `zones`; nested deeper than 8; a wrong type |
| `too_many_groups` | more than 8 groups in one hub rule (hub maximum 4, compiler 50) |
| `too_many_lines` | more than 8 leaves in a group (hub maximum 8) |
| `too_many_variables` | more than 16 variables on a line |
| `unsupported_zone` | not in section 3, e.g. `FILES_TOTAL_SIZE` (in the compiler, unused in the hub) |
| `unsupported_transform` | not in section 3, e.g. `b64encode` |
| `unsupported_match` | not in section 3, e.g. `fromFile` |
| `missing_value` | no value, or an empty one |
| `value_chars` | a byte outside 0x20..0x7E, `"`, `%{`, a trailing backslash, a leading or trailing space |
| `not_numeric` | a numeric match without an integer `0..999999999` |
| `count_without_variable` | `count` on a zone without variables (the compiler drops it silently, which changes the meaning) |
| `selector` | a variable on a one-value zone, or a selector outside the hub profile |
| `headers_without_name` | `HEADERS` without a variable: all headers include Host |
| `forbidden_header` | a header of the subset's forbidden list; `Referer` or `Origin` with anything but libinjection |
| `regex` | the value fails the `@rx` subset |
| `catch_all` | the catch-all check of the subset fails, or a group has only numeric or negated lines |
| `subset` | backstop: the generated text fails the hub profile for another reason |
| `id_collision` | two rules of a set reach one base id, or a local rule uses an id of this rule: the later name is skipped |
| `regex_cost` | Go only, section 6 |
| `compile_failed` | Go only: Coraza refused this rule alone |

Raw SecLang gets no way around the validation: `seclang_rules` lines carry their own ids, which the id range refuses. The lines in the hub today are outside the subset anyway (`TX`, `setvar`, `ctl:`), so such an item is refused whole, even when its `rules:` part converts (`crowdsecurity/vpatch-CVE-2026-109618`, the php2shell rule).

## 5. Hub profile of the subset and ids

Every generated group passes [seclang-subset.md](seclang-subset.md) with `max_action: observe`, in the **hub profile** (`seclang.Options.Hub`). The same checks, with these differences only; the network subset did not change, and `seclang` vectors show it:

| | Network rules | Hub profile |
| --- | --- | --- |
| `id` | 7700000..7799999 | 60000000..99999999 |
| Lines | 4 | 8 |
| Selector | `[A-Za-z0-9_.-]{1,64}` | `[A-Za-z0-9_.\[\]-]{1,128}`, or `/regex/` (up to 128 bytes, pattern in the `@rx` subset, no `\|`, space, `"` or `/`, not on `REQUEST_HEADERS`) |
| Variable | - | also `TX:json_request_body`, this one TX variable |
| `t:` | - | also `uppercase` |

**Ids.** `base = 60000000 + 8 * (n mod 5000000)`, with `n` the first 8 bytes (big endian) of `SHA-256("schild.crowdsec_hub.rule_id/1\n" + name)`; group `g` has `base + g`. A pure function of the name: the same on every gateway, in every image, after every update, with nothing to store. A change of the rule's text keeps its id; a new group takes the next id. The range sits inside `events.schema.json` `matchedRule.id` (at most 99999999) and apart from internal (2000xx), CRS (900000-999999) and network (7700000-7799999). A 100,000-id range next to the network range would not do: with 8 ids per rule it has 12,500 slots, and a hash collides there at today's rule count unless a table of ids is stored. With 5,000,000 slots there is no collision in the hub today (about a 1 % chance at 300 rules, 10 % at 1000), and a later one is safe: the later name is skipped with `id_collision`, listed, and no id moves.

## 6. Updates

**Fetch.** One `GET` with `If-None-Match`; HTTPS with the system roots; no redirect away from `raw.githubusercontent.com`; no cookies, no authentication; `User-Agent: schild` with no version and no node name. The host learns the address of the server, nothing else. Connect 10 s, whole request 60 s. `interval_s` with +-10 % jitter; the first check after the start is delayed by a random 0 to 60 s, so it never holds up a start; a failure waits for the next interval. Never on a request path. With `pin`, the file of that commit is fetched until its set runs, then never again. The URL is not configurable: nothing needs it, and a mirror would be a second trust root. `SCHILD_CROWDSEC_HUB_URL` exists for the test lab only and is ignored in release builds.

**Bounds of a set.** A breach refuses the whole update; the running set stays, nothing else changes.

| Bound | Value | Code |
| --- | --- | --- |
| Index, decompressed (also over gzip) | 32 MiB (today 4 MiB) | `index_oversize` |
| Not JSON, no `appsec-rules`, no collection, a selected item without `path`, `version`, `content`, `versions`, bad base64 | | `index_malformed` |
| Selected rules | 500 (today 206) | `too_many_rules` |
| SecLang of the set | 1 MiB (today 64 KiB), 2000 SecRule lines (today 487) | `set_too_large` |
| No rule loads | | `set_empty` |
| Less than half the rules of the image snapshot; without a snapshot, of the running set; with a pin no check | | `shrink` |
| Network error, deadline / other HTTP status | | `fetch_failed` / `fetch_status` |
| Compile of the whole set / longer than 30 s | Go only | `compile_failed` / `compile_timeout` |
| Added time per request above 4 times what the snapshot adds | measured, below | `set_too_costly` |

**`shrink` against the snapshot (D43).** The mark is the rule count the image snapshot loads, not the running set. A running set can grow too large, and against it every normal index would count as hollow, so the gateway could never come back; a running set can also shrink, and a mark that follows it lets a hollow index walk the rules down in steps. The rules of a set never fall below half of what the image shipped. A pin skips the check: the operator named that commit.

**Bounds of a rule.** Skipped rules are normal, a broken index is not: rule-level problems skip the rule (section 4), structural problems of the index refuse the update.

**Cost check before a set goes live** (`CheckRegexCost`, Go only because it needs the real compiler, so not in the vectors): the compiled program of every `@rx` and `/regex/` selector has at most 4096 instructions (the hub's largest has 85), else `regex_cost`. The checks both languages share are the subset's: at most 1024 characters, repeat counts summing to at most 1000, no nested quantifiers. Coraza's regex engine is linear in the input, so the bound is on the program.

**Measured cost of the whole set (D43).** The bounds above hold for a set that stops the gate anyway: 995 rules of six large regexes each passed all of them and answered 61 to 63 % of normal requests with 503 (MVP-26 measurement, finding 1). So a set with new or changed rules is timed before it goes live.

- **What runs:** `crowdsec.CostProbes`, six fixed requests (`GET /`, a search with query, an asset, a form, Livewire JSON, a small multipart upload, all with browser headers and cookies), on three instances without the CRS: no hub rules (baseline), the image snapshot (reference), the candidate. A hub rule costs the same with and without the CRS (measured: the snapshot adds 72 µs here, 68 to 87 µs in the gate).
- **What counts:** `CostRounds` (16) rounds, each instance every probe. The fastest time of each probe, then the mean over the probes. Disturbance only makes times longer, so the fastest time is what stays on a busy machine.
- **Verdict** (`CheckSetCost`, op `set_cost`, integers, in the vectors): `added = max(candidate - baseline, 0)`, `allowed = 4 * max(reference - baseline, 2 * baseline)`, refused with `set_too_costly` when `added > allowed` or no round finished. All three numbers come from the same machine at the same moment, so a slow machine does not refuse a normal set. The reference is always the snapshot, never the running set, so a hostile index cannot raise the mark step by step. Without a snapshot the reference is the baseline, and the floor of two baselines keeps the bound above the set of today.
- **Effect on requests:** none by design. It runs in the update's goroutine, one request at a time on instances of its own, holds no evaluation slot, pauses as long as each round took (at most 250 ms), ends after `CostBudgetS` (15 s) and from round 4 as soon as a set is more than twice over the bound. Today's set takes about 0.1 s. A failed measurement refuses: a set nobody measured does not go live.
- **Only on a change:** a check with the same rules measures nothing. The image snapshot is not measured, it is the mark.
- **Measured on darwin-arm64:** snapshot 72 µs added, allowed 290 µs; ten hostile rules on top 1.5 ms, ratio 21; 100 rules 17 ms, ratio 280; 294 rules on `URI`, `ARGS` and `BODY_ARGS` 225 ms, ratio 3,700.

**Order.** Download, `CheckIndex`, regex cost check, build the rules alone, measured cost check, build the instance in the background (one at a time, abandoned after 30 s), `Engine.Swap`, store the set. If the whole set does not compile, the gateway compiles the rules one by one, skips those that fail with `compile_failed` and builds again; if that fails too, `compile_failed` refuses the update. A set that fails anywhere never touches the running instance.

**Set format.** [crowdsec-set.schema.json](crowdsec-set.schema.json): the image snapshot and the stored last good set have one format, the selected hub items as they came, at most 8 MiB. Not the SecLang: every load converts again, so a tampered file cannot bring rule text past the converter and a newer contract applies to an old set. Stored in `schild.db` under `crowdsec_hub_set_v1`, one row, replaced on every swap, with the ETag and `cost_checked` beside it. Not subject to retention.

**Reset (D43, D73).** The operator's way back: `POST /rule-repositories/crowdsec/reset` (`resetRuleRepository` in the dashboard, session and CSRF, no password; `resetAgentRuleRepository` with scope `rules:write`) or `schild rules reset crowdsec` on the host (through the control path, or directly in the store while schild is stopped). It drops the stored row and runs the image snapshot without a restart, also with `auto_update: false` and without network. The switch keeps its state. In state `off` only the row goes. Without a valid snapshot it answers 409 and nothing changes. It writes `schild.rule.repository_updated.v1` with outcome `reset` (not in the direct path, where no gateway runs). Updates go on afterwards and pass every check; who wants to stay on the image sets `auto_update: false` or a pin. `POST /rule-repositories/crowdsec/sync` runs a check at once.

**Which set loads at start** (op `select`, D39 amendment), in this order:

1. `off`: none.
2. A pin: the set of that commit, stored first, then image. If neither matches, `pin_pending` stays true and the next steps pick what runs until the fetch worked.
3. A set that fails `ParseSet`, loads no rule or does not compile is out, so a broken stored set falls back to the image snapshot. A stored row is also out when it has no `cost_checked` (written by an earlier version, D43) or is above the set bounds of this contract: a hostile set stored before these checks heals with the upgrade, and the next accepted update writes a new row.
4. Of two valid sets **the newer runs**, whatever `auto_update` says.
5. With no valid set: none. **A start never fails because of this source.** Without outgoing network the image snapshot runs and `update_state` says `unreachable`, calmly.

"Newer" compares `Set.Time()`, never a file time: `hub_commit_at` when the set has it (`make crowdsec-snapshot` always sets it, from the commit it fetched); else `fetched_at` for a set of the master branch, because that index was the head at that moment, so a master fetch and a commit date order correctly against each other; else no date, because a pinned set whose commit time is unknown may be old however recently it came.

| Case | Result |
| --- | --- |
| One date later | that set |
| Tie | stored (it holds this gateway's history of the rules) |
| A date against no date | the set with the date |
| No date on either | stored |
| Unreadable date, or more than 120 s ahead of the clock | counts as no date: a wrong clock must not keep a stale set alive |

When the image wins, the stored row stays until the next accepted update replaces it; an ETag is sent only for the set it belongs to.

**History.** A rule keeps `first_seen`; `changed_at` moves when its digest changes. Rule changes and refusals write one `schild.rule.repository_updated.v1` with `repository: crowdsec` (`index_sha256`, `hub_commit` when known, added, changed and removed names up to 100 each). A check with nothing new builds nothing and writes no event, whatever commit the rules came from; only the row moves on, so the next check can send its ETag.

## 7. Read fields and licence

| Where | Field |
| --- | --- |
| Events (`rules[]`) | `repository: crowdsec`, `id` = SecRule id of the group, `crowdsec {name, version, label, cves}`; required with that repository and forbidden with any other |
| Incidents, decision sources | `crowdsec:<base id>` beside `crs`, `local`, `limit` |
| Rules (`listRules`, `getRule`, both APIs) | `repository: crowdsec`, `id` = base id as a string (stable), `name` = hub name, `version`, `origin` (`release` when name and version are in the image snapshot, else `update`), `status`, `effect`, `crowdsec`: name, version, licence, label, description, cves, cwes, attack, notes, first_seen, changed_at, settling_until; `getRule` adds the SecLang of every group |
| Repository (`getRuleRepository`) | the shared fields of D73 and `crowdsec`: `update_state`, `auto_update`, `interval_s`, `pin`, `settling_s`, `set_source`, `skipped` (with reasons), `index_sha256`, `hub_commit`, `last_check_at`, `last_change`, `last_refusal`, `snapshot_at`, `snapshot_age_days` |

Label and description are third-party text: cleaned of control characters, capped at 128 and 512 characters, rendered as text, never interpreted.

**Disabling one rule** works as for every repository (D73): `rules.crowdsec.disabled_rules` in `schild.yaml` takes hub names; `PATCH /rules/crowdsec/{base id}` with `disabled` in the dashboard or through the agent API (scope `rules:write`) writes the table of rule decisions in `schild.db`. A rule is disabled when either says so; enabling a rule disabled in `schild.yaml` answers 409 `config_limit`. A disabled crowdsec rule stays in the WAF and stops at once, without a rebuild. Unknown names are no error: a rule may have left the hub.

**Licence.** The hub is MIT. The MIT text and the copyright line ship with the rules (`gateway/NOTICE`), each rule carries source, version and `licence: MIT` in its read field. UI label "Regel aus dem CrowdSec Hub, MIT", no logo, nothing that looks like a partnership. Test data derived from the hub carries [vectors/crowdsec-hub/NOTICE](vectors/crowdsec-hub/NOTICE).

## 8. Effect on a request

`contract/rules` (ops `effect` and `request` of the `rule-effect` vectors) decides, the same for every repository. For this repository:

| Rule | State `block` | Test profile |
| --- | --- | --- |
| in the image snapshot (origin `release`) | `block` | `would_block` |
| received from the hub (origin `update`) | `settling`: detect until `changed_at + settling_s`, then `block` | `would_block` |

There is no protection mode and no approval of single updates (D89; this replaces the modes `review` and `autoblock` of D73). With state `detect` every rule detects (`repository_detect`), with `off` none runs. Then per request: `bypass_waf` passes, an unblock excepts, and an allowlist `no_block` entry turns a block into `would_block`.

**Never adds to the CRS anomaly score.** The rules carry no `setvar`, `waf.Analyze` recomputes the CRS score from CRS rules only, and a hub match gives no points, does not raise `Score` and does not set `LocalBlock`. **With `detect` it never blocks, directly or indirectly:** `counts_as_hit` is true only for a real block, so nothing else feeds `waf_repeat`, request shapes or any other behaviour counter. The source is not part of the lab network: hub ids are outside the network range and nothing of a hub match leaves the gateway.

**Settling.** It counts from `changed_at`. A rule of the first set the gateway ever ran counts from when that set was made, so an image snapshot older than `settling_s` does not settle again when the operator switches to `block`. Settling applies to every update outside the test profile; nothing ends it early, a rule that should not block is disabled. There is no automatic brake on match share in this version; with `detect` as the default there is nothing to brake. The initiator decides it together with the move to `block`.

## 9. Known limits

- The hub signs nothing. HTTPS, the digests in the index (same channel), the bounds, the measured cost check, the converter that passes no raw text, `shrink` and settling are the protection. Whether that is enough is open in the spec.
- `catch_all` is a heuristic, as in the subset: a broad hub rule can pass it, and a sharp one can fail it. A hub rule that matches too much in `block` is what settling and disabling are for.
- `raw_body_partial`: see section 3.
