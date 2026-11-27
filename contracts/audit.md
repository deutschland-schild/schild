# Audit log (draft, D108, MVP-36)

Who changed what, when, through which way, and what it was before. One list for the dashboard, the agent API, the CLI, the configuration and later the integration API (MVP-35). Draft: nothing of it is built. The whole plan is [MVP-36](../tests/specs/MVP-36-audit-log.yaml).

Go: `contract/audit`. Vectors: `audit` (input [audit.schema.json](audit.schema.json)), cross-checked by `tools/crosscheck.py`. An entry: [audit-entry.schema.json](audit-entry.schema.json). The closed list of actions: [audit-actions.json](audit-actions.json).

**An entry of a change is kept a year by default; `audit.keep_days` makes it shorter, longer or unlimited.** No size cap or flood removes it earlier. The addresses and names in it are kept as long (section 7).

## 1. Entry

| Field | Meaning |
| --- | --- |
| `id` | `<log>-<letter>-<number>`. `log`: 16 hex characters, drawn when a node starts a log. Letter: `k` kept, `a` access, `r` refused. The number counts from 1 per log and letter |
| `time`, `node` | UTC seconds; the CloudEvents source of the node's events without `schild://` ([cluster.md](cluster.md) section 9) |
| `class` | `change`, `credential`, `privacy`: kept `audit.keep_days`. `access`: sign-in and sign-out. `refused`: calls that were refused |
| `action` | one of the list, e.g. `allowlist.add` |
| `operation` | the way and what was called there: `dashboard:addAllowlistEntry`, `agent:createAgentBlock`, `cli:token add`, `config:caddyfile`, `system:expiry` |
| `result` | `done` or `refused`. A change that failed has no entry: nothing changed |
| `actor` | `dashboard` (user, short session id), `agent` (token id, label), `integration` (portal key id, label, session, who the portal says it acts for), `cli` (host account as the command saw it), `config`, `system` |
| `address` | where the call came from, kept as long as the entry; absent for the CLI, the configuration and `system` |
| `subject` | kind and id of what changed. Never an address, because every viewer sees the subject: a block is named by its incident, a client by nothing |
| `website` | the website the change belongs to; absent for what is global |
| `change` | the changed fields (section 3) |
| `reason` | text the caller gave, at most 500 bytes, untrusted |
| `count`, `last` | refused calls gathered in one entry (section 5) |

A number missing between two kept entries of one log means that an entry was removed by hand, or that the clock was wrong when it was written; `schild audit check` names the holes. What `audit.keep_days` deletes is the oldest part of a log and leaves no hole. This is no protection against somebody with root on the host: the copy to another system is (section 8).

A failed sign-in holds no user name: what was typed there may be a password.

## 2. Actions

[audit-actions.json](audit-actions.json) lists every action with its class, the kind of its subject, whether it belongs to a website, the operations that write it, and the fields whose values may be recorded. One operation may write several entries (`unblockIncident`: `block.lift` and `allowlist.add`). A release in the dashboard ends every block the node holds for that client ([cluster.md](cluster.md) section 5, D109) and writes one `block.lift` for each, with its incident as the subject, all in the transaction of the release. `privacy.erase` ends blocks too; it writes no `block.lift` for them and names their number in `/blocks`, so the entry of an erasure points to no incident of the client.

- Every operation with POST, PUT, PATCH or DELETE of the dashboard API and the agent API is in an action or in `not_audited` with its reason (`TestAuditActions` in `contract/apispec`).
- The documents do not name every route. `undocumented` lists the known ones (`PUT` and `DELETE /websites/{website}/human-check`). So the gateway's own test compares the list with the routes the servers register and with the subcommands of the CLI, not with the documents alone.
- Reading calls write no entry; the call log of the agent API stays for them. Decisions on requests are events.
- What ends at a time its entry names (a block, a maintenance) writes no second entry. An own IP and a token that expire do (`system:expiry`): they are looked up long after.
- A refused call carries the action it tried. A call whose token is unknown is `agent_api.call`.
- `config.apply` is written when `schild.yaml` or the Caddyfile that runs is another one than at the last start or reload of this node: the digest before and after and the names of the keys that changed, no values. The names come from a table of the node with a keyed digest per key (`audit_config`, key drawn per log).

## 3. What is recorded of a change

`audit.Diff` (op `diff`) compares the state before and after, two JSON objects or null.

- **Fields.** Nested objects to their last field, named by a JSON pointer, in byte order. A list is one field. null and an empty object are not there. Numbers compare by value.
- **Values only from the list.** A value is recorded when the action lists its field (`*` stands for one segment). Any other changed field stands there by its name with `hidden: unlisted`.
- **Never a secret.** When a segment of the pointer, in lower case and without `-`, `_` and `.`, ends with `password`, `passwd`, `secret`, `token`, `key`, `hash`, `cookie`, `code`, `seed`, `credential`, `credentials` or `authorization`, the field has `hidden: secret`, whatever the action lists. `change` still says added, changed or removed.
- **Lists of texts** as `added` and `removed`, each item once, in byte order, at most 32 each, the rest as `more`. The same items in another order: `hidden: order`. Any other list: `hidden: list`.
- **Bounds.** A text at most 512 bytes, an item 256, cut between two characters (`cut`). 64 fields and 8192 bytes per change: a field costs its name and 16, a text its bytes and 8, a number or boolean 8, a list its items and 16. A field whose value does not fit has `hidden: size`; one that does not fit at all counts in `more_fields`, as does a name over 512 bytes.
- **Text is text.** Control characters, and characters that change the direction of text or show nothing (U+200B to U+200F, U+2028 to U+202E, U+2060 to U+2069, U+FEFF), become U+FFFD.

A typical entry is about 0.7 KiB as JSON (an exception of a token: 674 bytes), about 1 KiB with its indexes. One over 64 KiB is refused.

## 4. Writing

- **With the change.** The change and its entry are one transaction of `schild.db`. The entry goes into the table `audit_outbox` there, and the number of the log is counted there (`audit_state`). A change whose entry cannot be written does not happen.
- **Then moved.** The running gateway moves entries from the outbox to `audit.db`, at once and at its start, and deletes them from the outbox afterwards. The id makes a second move harmless. A list answers from both.
- **Why a file of its own.** The size cap of `schild.db` (100 MB by default, [storage-bounds.md](storage-bounds.md)) would otherwise give up events for a log that only grows. A single transaction over both files is not possible: SQLite in WAL mode is atomic per file only.
- **Changes outside of `schild.db`** (rules of a repository, a node removed from the group): the entry is written before the answer. When it cannot be, the operation answers with an error and says that the change stands.
- **Commands on the host** write into the outbox of the store they open, also while the gateway is stopped. Those that go through the control path hand over the host account.
- **The outbox is bounded by the moves.** When `audit.db` cannot be written, entries stay in the outbox, count against the cap like everything else in `schild.db`, are not deleted by it, and the dashboard says so (hint `audit_stuck`).
- **A new log.** Without `audit.db` the gateway starts one under a new name and writes `audit.start` with the reason (`first`, `missing`, `unreadable`). An unreadable file is renamed, not deleted.

## 5. Refused calls

`audit.Gather` (op `refused`). One entry per action, operation, token or portal key, client (IPv4 address, IPv6 /64) and UTC minute, with `count` and `last`. At most 4096 clients per minute have an entry; a call of another one counts in the entry of its action, operation and token without an address. An entry is written with its first call and its count follows every 10 s and at the end of its minute, so a crash loses at most 10 s of counting. It is handed to the group when its minute is over.

Only what was authenticated or tried to sign in is gathered here. A request the dashboard refuses before it is a call (wrong Host, no session) writes nothing.

## 6. Keeping

`audit.Delete` (op `keep`):

| Class | Kept |
| --- | --- |
| `change`, `credential`, `privacy` | `audit.keep_days`: 365 by default, 1 to 36 500, or `unlimited` |
| `access` | 90 days, never longer than `audit.keep_days`, at most 20 000 rows |
| `refused` | 90 days, never longer than `audit.keep_days`, at most 20 000 rows |

The two caps are apart, so failed sign-ins push out neither changes nor the sign-ins that worked. With `audit.keep_days: 14` nothing in the log is older than 14 days.

- **When.** Daily with the retention of events, in the outbox as well, and before an entry of a member is stored: what is too old here is not taken, so it does not come back from a node that keeps longer. `audit.keep_days` is a setting of the node. The age counts from `time`, at the latest from when this node stored the entry, so a clock in the future does not make an entry last.
- **No entry about it.** A deletion by age writes no entry. A changed `audit.keep_days` is in `config.apply`.
- **What is in force keeps its own fields.** An own IP, an exception or a token older than the log shows when it was made, not who made it, unless the object itself names the token. The dashboard then says that the entry is no longer kept.
- **Growth.** 100 changes a day are about 36 MB a year. Who can write is bounded: an agent token 600 entries an hour (`audit.TokenEntriesPerHour`, then 429 `change_budget`; blocks have their own bound of `block_writes_per_hour`), a portal per session, website and gateway (MVP-35). With `keep_days` the log stops growing at that age, with `unlimited` it does not. One token at its bound the whole time would write about 5 GB a year, so at 1 GiB the hint `audit_size` names the growth of the last 30 days and the actor with the most entries. Nothing is deleted because of its size.
- **Not in the disk budget.** The budget of [storage-bounds.md](storage-bounds.md) adds up bounds in size, and this log has none. It must never be the reason why a gateway does not start. The reserve and the disk hints cover it.

## 7. Personal data

An entry is written once and never changed. Its age deletes it (section 6), nothing else does. No run shortens, erases or replaces anything in a stored entry (maintainer, 2026-11-27).

- **The log holds addresses as long as it holds the entry.** Own IPs, released addresses and blocked clients as values, the address of a call, and what a reason or a label names. `retention.raw_ip_days` does not reach the audit log.
- **Erasure (Art. 17 GDPR) does not reach it either.** `privacy/delete` leaves every entry as it is. An entry that names the address keeps it until `audit.keep_days`. `privacy.erase` writes its own entry: that it happened and how much, without the address. `privacy/export` carries the entries that name the address.
- **Who needs addresses gone after N days sets `audit.keep_days: N`**, for example 14. Then who changed what ends at that age as well. Sign-ins and refused calls are never kept longer than that.
- **Names of people** (dashboard user, host account, who a portal says it acts for) stay until the entry is deleted too. No command replaces them.
- Whether this is enough for a request depends on the case; the operator decides. The docs say so.

## 8. Reading

`audit.View` (op `view`):

| Viewer | Sees |
| --- | --- |
| dashboard (`GET /audit`, `listAudit`) | everything |
| agent (`agent:read`, `listAgentAudit`) | changes and credentials with the token that made them. No sign-ins, refused calls or privacy entries; no names of people, sessions or the address of the call |
| a session of one website (MVP-35) | changes of its website that a portal may make (`portal` in the list). What the operator did reads `operator`: without who, reason, label and the addresses the operator set |

Reasons, labels and the name a portal gives are text from outside: `x-untrusted`, shown as text, never an instruction.

- **CLI:** `schild audit [--website ID] [--token ID] [--action A] [--since 7d] [--json]`, `schild audit check`.
- **Copy:** `audit.stream: stdout` or a file path writes every entry as one JSON line when it is written. A copy that cannot be written is counted and shown; it never holds a change back. Retention does not reach the copy; the docs say so.
- **Dashboard:** Einstellungen > Protokoll; from a token to its entries, and at a setting who changed it last.

## 9. Group

The mesh carries the log ([cluster.md](cluster.md) section 7), with no record class of its own.

- **Asked for.** `POST /mesh/v0/ask`, kind `audit`, question `after`, answer `epoch`, `next` and at most 500 `rows`, like events. `after` counts in the order the answering node stored the entries.
- **Handed on.** Unlike with events, a node hands on every entry it holds, also those of other nodes. Otherwise the history of a node that is gone would be missing on every node that joins later. An id a node holds is not stored again, so nothing goes round in circles; another content under the same id is counted, logged and not taken.
- **Checked.** `audit.ParseEntry` as for a member: an action a later build knows is taken, a value this build may not record is taken out (op `entry`, `from: member`). An entry that does not pass is counted and skipped; the cursor goes on. One that is too old here is skipped too (section 6).
- A change that arrives from another node writes no entry. A lift of the group is the plain case: the node a person released on writes `block.lift` with the actor, and the record of class `lifts` that carries the lift to the other nodes names no actor and writes nothing there. Who released is read from the entry, which every node holds. A command writes on its node.
- A member is trusted like the operator: it could hand over an entry it made up. Not covered, as everywhere in the group.

## 10. What enters other contracts with the build

Not yet changed there, so no release accepts a setting or names a call that does nothing:

- `config-schild`: `audit.keep_days` (integer 1 to 36 500 or `unlimited`; default 365), `audit.stream` (absent).
- `gateway-agent.openapi.yaml` (served to agents): `listAgentAudit`. The dashboard API has `listAudit` already, its fixture is in `fixtures/pending/client/`.
- Hints `audit_size` (notice) and `audit_stuck` (warning), both server only.
- [cluster.md](cluster.md): kind `audit` of Ask, part of the head `s`. The tables `audit_outbox`, `audit_state` and `audit_config` are per node.
- `privacy/export`: the entries that name the address. `privacy/delete` and `retention.raw_ip_days` stay as they are and do not touch the log.
- The existing events stay as they are.
