# Group of gateways (unreleased, D103, MVP-27)

How several gateways of one operator share their state from node to node: no store beside them, no majority, so two nodes are a group. Direction given by the initiator on 2026-11-21, recorded in [DECISIONS](DECISIONS.md) D103; the whole plan is [MVP-27](../tests/specs/MVP-27-ha-group.yaml).

Go: `contract/cluster`. Vectors: `cluster-record` (input [cluster-record.schema.json](cluster-record.schema.json)): whether a node takes a record, why not, and whether it replaces the record held (sections 3 to 5), cross-checked by `tools/crosscheck.py`. The mesh calls (sections 7 to 11) have no vectors; the gateway's tests cover them. Everything here may still change before a release.

**No request waits for the group.** The gate decides from its own memory. A node that reaches no member serves with the state it has.

**A member is trusted like the operator.** It can set and lift blocks for the group. What ends that for one node is its removal; the signature of every record says afterwards what it wrote.

## 1. Identity

- Every node has an Ed25519 key of its own, made on the node, in `<storage.path>/cluster/node.key` (mode 0600, 64 hex characters of the seed). It never leaves the node.
- Node id: `n-` and the first 16 bytes, in hex, of SHA-256 over `schild-node:` and the public key.
- Group id: `g-` and the first 16 bytes, in hex, of SHA-256 over `schild-group:` and the public key of the node that founded the group. Every trust in a group starts at its id: the founder's record of itself is the one record that needs no member to sign it, because its key hashes to the group id.
- There is no CA. A group set up by configuration has one shared secret, which admits a node and does nothing else (section 6).

## 2. Record

One change of one thing, as a JSON object:

| Field | Meaning |
| --- | --- |
| `v` | 1. A record of another version stays unread and is passed on unchanged |
| `group` | group id |
| `class` | `members`, `blocks`, `settings`, `access`, `logins`, `erasure`, `certificates` or `jobs` |
| `id` | the thing within its class, at most 512 bytes |
| `origin` | node id of the signer |
| `seq` | counts the records of one origin, from 1 |
| `hlc` | hybrid logical clock of the write: wall clock in milliseconds in the upper 48 bits, a counter in the lower 16 |
| `deleted` | a tombstone: the thing is gone, and the record stays so that an older write cannot bring it back |
| `expires` | RFC 3339, UTC, seconds: when every node drops the record; absent: never |
| `data` | standard base64 of the class's JSON object |
| `sig` | standard base64 of the Ed25519 signature |

The signature covers `schild-cluster-record-v1`, `v`, `group`, `class`, `id`, `origin`, `seq`, `hlc`, `deleted` (`1` or `0`), `expires` and the decoded bytes of `data`, in this order, each as its length in decimal, a space, the bytes and a space. Numbers are decimal text. One record is at most 512 KiB on the wire, its data at most 256 KiB.

## 3. Which record is the state

Per `(class, id)` one record is the state. A record replaces the one held when its `hlc` is greater; at the same `hlc` a tombstone beats a write (a lift by a person beats the block of a detector of the same moment), then the greater `origin`, then the greater `seq`. Every node decides the same from the same two records, in any order of arrival. A node keeps only the record that is the state.

## 4. Whether a record is taken

In this order; the first failing check decides.

| # | Reason | Check | Later? |
| --- | --- | --- | --- |
| 1 | `version` | `v` is not 1 | kept unread |
| 2 | `group` | another group | never |
| 3 | `schema` | fields missing, unknown class, `expires` no time | never |
| 4 | `clock` | the wall part of `hlc` is more than 60 s ahead of the receiver | asked for again |
| 5 | `origin` | the origin is no member and the record is not a node's record of itself that proves its place (the founder's, or one with the admission of the group secret), or the origin is an edge | asked for again |
| 6 | `removed` | the origin was removed and `hlc` is not before its removal | never |
| 7 | `signature` | does not verify with the origin's key | never |
| 8 | `schema` | the data does not fit its class (section 5), unknown fields included | never |

A record that is refused for good is counted and never applied or stored. A record that may pass later holds back the sequence number the node asks its peers from, so it comes again.

Records a removed member signed before its removal stand: what it decided while it was a member reads the same on a node that joins later.

## 5. Classes

### members

`id` is the node id. Data: `name` (1 to 63 bytes, no space or `/`), `role` (`gateway` or `edge`, section 11), `public_key` (standard base64, 32 bytes, hashing to `id`), `address` (IP address and port of its mesh listener), `joined`, optional `version`, and for a node admitted by the group secret `admit_public_key` and `admit` (section 6; both or none). Any gateway may sign a member record. The tombstone of a member keeps its data, with the key.

### blocks

`id` is the client key: the IPv4 address, or the first address of the IPv6 /64.

- A block. Data: `client` (equal to `id`), `bits` (32 or 64), `source` (`behaviour:<scenario>`, `agent:<token id>` or `dashboard`), `level`, `since`, `until`, `duration_s` (at most 7 days), `incident`, optional `event_id`, `net_class`, `node` (name of the node that decided). `expires` equals `until`: a block that ends at its time needs no record.
- A lift is a tombstone. Data: `incident` (the block it ends), `node`. Its `expires` lies 7 days and an hour after the lift, the longest any block from before could run.

A node that receives a block decides again with what it holds itself: an address on its own allowlist is not blocked, the test profile blocks nothing, and a block of the same client that already runs there stands. Only the deciding node writes the event and the incident; the others show its incident number.

### settings, access, logins

What the dashboard and the agent API set, who passes and who may sign in. Each thing is a set of entries, and every entry is a record of its own. So two nodes that change different entries of one thing both keep their change, also when they could not reach each other meanwhile, and a node that enters a group adds what it holds instead of losing it.

| Class | Thing | One entry is |
| --- | --- | --- |
| `settings` | `settings_overlay_v1` | one setting the dashboard or the agent API changed of `schild.yaml`: the key is its path, e.g. `["rules","crs","state"]` |
| `settings` | `behaviour_rate_limits_v1`, `rule_exceptions_v2` | one rate limit, one rule exception, by its id |
| `settings` | `rules_state_by_v1` | who set the state of one rule repository |
| `settings` | `crawler_policies_v1`, `access_protections_v1`, `human_check_v1` | the policy of one website, and every other field of the state (the keys behind the cookies of visitors among them) |
| `settings` | `agent_pseudonym_key_v1` | the key of client pseudonyms, one piece, key `""` |
| `settings` | every other key of the gateway's key-value store | by the shape of the value: a JSON object with fields is one entry per top-level field (key `o["field"]`); a JSON list of objects that each carry a string `id`, none twice, is one entry per object (key `l["id"]`); anything else is one piece (key `""`) and the later change wins |
| `access` | `allowlist`, `rule_decisions` | one row, by its key columns |
| `access` | `ip_exceptions` | one released sender, by all the row says (the row number stays on its node) |
| `logins` | `users`, `sessions`, `agent_tokens` | one row, by its key column |

- `id` is the thing, a slash and the first 16 bytes, in hex, of SHA-256 over the entry's key. A record of another thing, or whose id is not the hash of its key, is refused.
- Data: `key`, the entry's key (at most 1024 bytes); `value`, its value as the gateway stores it, in standard base64; `node`, the name of the node the change was made on. A removed entry is a tombstone with `key`, no `value`, and `expires` 30 days after the removal; a node away for longer enters the group anew.
- A node publishes an entry when it changed on that node since the node was last in step with the group. The entries other nodes changed of one thing are put into the value together and the value made effective the way the start loads it: settings are validated with the node's own `schild.yaml`, rules are built again, and what does not fit (config drift) or does not build is not taken; the node keeps its own and says so.
- Two changes of the very same entry on two nodes: the later clock stands, on every node. Nothing else is settled by a clock.
- A node that enters a group publishes the entries it holds and the group does not, and takes the entries the group holds. Only an entry both hold is the group's; what the node held of it is kept (`cluster.db`, table `replaced`) and named in its log and in `schild cluster status`. Before its first sync a node publishes nothing: it does not know yet what the group holds.
- `access_protections_v1` and `human_check_v1` hold the keys behind the cookies of visitors, `users` the password hashes, `sessions` and `agent_tokens` hashes of tokens. They travel between gateways of one operator over the mesh and nowhere else.
- **Everything set at runtime is shared (initiator, 2026-11-22).** Class `settings` takes every key of the gateway's key-value store as a thing, whatever feature wrote it: a key is a lower-case name of letters, digits and `_`, at most 64 characters. A feature that stores a new setting is shared the day it is written, without a change of this contract. The first letter of an entry key names the shape (`o`, `l`), so a node that holds nothing of the value yet puts the entries together the same way; a value that changes its shape replaces the entries of the old one. The classes `access` and `logins` stay closed lists: their things are tables with a schema, and a table is shared by a decision, not by default.
- **Per node, on purpose.** These keys describe one node and never travel; a record that names one is refused (`schema`): `installed_at_v1` (when the node was installed: the start of its own learning phase and the name of its event store), `dashboard_setup_code_v1` (its pending first-run or reset code), `crowdsec_hub_status_v1` (when it last asked the hub), `crowdsec_hub_set_v1` (the hub rules it holds; the index is handed on by its own messages, see "One set of hub rules"), `allow_version` (a counter for its own caches), `jobs_local_v1` (when a once-per-period task last ran on a single gateway; a node of a group keeps that in the records of class `jobs`). Per node are also: `schild.yaml`, `rules.d` and the Caddyfile (a deployment); the server check, with its reports, its agents and the findings accepted for that machine (each server checks itself); the log of agent calls and with it when a token was last used on that node (what an agent changed is an event on every node); the bound of failed logins at the dashboard, which counts per node; the log of applied configuration changes. Go: `cluster.PerNodeSettings`, and in the gateway a list of the tables that stay per node with their reasons; a test fails for a table that is neither shared nor on that list.

### erasure

One erased address (Art. 17 GDPR). `id` is the address. Data: `ip` (equal to `id`), `keep_incidents`, `node`. `expires` lies 31 days after the erasure: longer than any node keeps what is erased, so a node that was away erases when it returns; then the record is gone, and the address with it. A node erases events, incidents, sessions, allowlist entries, exceptions, the running block and the requests of the address, as the dashboard does on its own node. The node that erases publishes after it erased.

### certificates

The storage of the embedded Caddy: certificates with their keys, ACME accounts, the local CA, challenge tokens, the keys of TLS session tickets. `id` is a path below the storage root: relative, no empty, `.` or `..` element.

- Data: `files`, a map from a file name to its content in standard base64, and `node`. Paths below `certificates/`, `acme/` and `pki/` travel per directory: the record names the directory and holds its files (at most 16). So a certificate, its key and its metadata are one record, and no node pairs the certificate of one order with the key of another. Every other path is one file per record, with the file name `""`.
- A node publishes a certificate directory only when its certificate and key fit each other, and writes one it receives only then. A tombstone has no files and removes the file, or the files of the directory.
- The lock files of the file storage (`locks/`) never leave a node.
- A node writes to its own storage first and tells the group after, so a node that reaches no member reads and writes its certificates as a single gateway does. At its first sync a node hands over what its storage holds and the group does not: certificates from before go with it, none is ordered again.
- A challenge token is a file below a directory `challenge_tokens` (certmagic keeps it at `acme/<issuer>/challenge_tokens/<name>.json`). It is a record of its own, never part of a directory record, so the tokens of two orders do not replace each other. It is published at once, and the write returns when every gateway the node reaches said it holds the token, or after 2 s.
- A node does not take the lock of an order before it is in step with its group (section 10), or was once and reaches no member after the wait: a node that just started would order what the group holds, and two nodes started together would both order.
- The keys of TLS session tickets go through the same storage (Caddy's distributed key source), unless the Caddyfile sets session tickets itself.
- With `cluster.enabled` a storage module of its own in the Caddyfile is refused.

**The lock of an order.** `POST /mesh/v0/lock` and `/unlock`, members only, body `name` (and on unlock `seq`, how far the caller is with its own records). The lock is kept by the member with the lowest node id among the gateways a node reaches; a node asks that one, or itself. A lock ends 5 minutes after it was granted when its holder does not give it back. The answer to a grant names what the last holder had written; the new holder waits, at most 10 s, until it holds that, so it finds the certificate instead of ordering it again. Nodes that cannot reach each other each find a keeper on their side and may both order the same certificate: one order too many, two valid certificates.

### jobs

What the tasks that run once per period for the whole group have done. Data of every record: `at` (UTC, seconds) and `node`, the name of the node that wrote it. No tombstone. `id` is one of four, for a task named `<name>` (1 to 40 of `a-z`, `0-9`, `_`, `-`; an id is at most 64 characters):

| `id` | `at` is |
| --- | --- |
| `<name>` | when the latest run started, or last said that it is still at work (while a task works, the node writes this again every third of the grace time) |
| `<name>.period` | the period of the latest run: the instant it was due |
| `<name>.done` | the latest period that was finished |
| `<name>.i.<16 hex>` | the period for which one item of the task is done; the hex digits are the start of the SHA-256 of the item's name. It carries `expires`: two periods and a day after it was written, 40 days at most |

A period is finished when `<name>.done` is not before `<name>.period`. A record `<name>` without `<name>.period` (written by a build that knew the start only) counts as a finished period.

A task that must not happen once per node (a rotation of keys, a summary by mail) is asked for on every node under the same name, and runs like this:

- There is no main node and no election. The task is run by the node that keeps the group's locks (section "certificates": the lowest node id among the gateways a node reaches). When that node is gone, the role moves by itself.
- **When it is due.** With an interval: when the interval has passed since `<name>.period`, and at once when there is none; the new period is the moment it starts. With a time of day (optionally on one day of the week, in a named time zone): the latest occurrence at or before now, when it is later than `<name>.period` by at least half the usual distance (12 h for a daily task, 3.5 days for a weekly one), so a time of day that is changed brings no second run of a day that ran. A time that does not exist on a day (the clock is put forward) falls on the next minute that does; a time that exists twice falls on the first. A task with a time of day that is seen for the first time starts with its next occurrence: the current one is written as finished without a run.
- **Who and when.** A node runs a task when it is in step with the group, keeps the locks, and has been in that position for 3 s without a break: a node that just started has not heard from every member, and one failed call does not make it the keeper. It takes the lock `job:<name>` and looks again under it.
- **A run.** It writes `<name>.period` and `<name>`, runs the task, and writes `<name>.done` when the task succeeded. A task with several items (the recipients of a mail) asks before each whether its item record carries this period, and writes the record after the item. At most 256 items a run.
- **A run that broke off.** A period that is started and not finished, whose `<name>` is older than the task's grace time (default 2 minutes, 5 s to 1 h), is taken up again by the node that keeps the locks then: the same period, and only the items that are not written. That holds after a failure on the same node and after a takeover alike, and again after every grace time until the period is finished or the next one is due.
- **A period nobody was up for** runs once when a node is up again and it is still the current one (a task may bound how late, `MaxLate`); earlier ones are left out. Never several in a row.
- **At least once, not exactly once.** An item is done again when the run broke off between the item and its record. Nodes that cannot reach each other each find a keeper on their side, and a period may run on both: a mail can arrive twice. A task that must never happen twice, whatever the network does, does not belong here.
- A single gateway runs the same tasks by the same rules; it keeps the four notes in its own store (`schild.db`, key `jobs_local_v1`, per node, not shared) instead of records.
- First user: `human_check_keys`, an interval of one hour. The keys of the browser check are rotated when they are older than a day, once for the group; a node of a group does not rotate them at its own start. A single gateway rotates them at its start and, new, while it runs.

## 6. Joining

Two ways. A group set up by configuration can also let a node in by hand, with a join code of one of its members; a group founded with `schild cluster init` has no group secret.

### By configuration

For a deployment that writes the same files to every node (Ansible, for example). No command and no code go from node to node.

```yaml
cluster:
  enabled: true
  listen: "10.0.0.2:8790"                    # this node's address in the private network
  secret_file: /etc/schild/cluster.secret    # the same file on every node, mode 0600
  peers: ["10.0.0.1:8790", "10.0.0.2:8790", "10.0.0.3:8790"]   # every node, the own address included
```

- The secret is at least 32 bytes; `schild cluster secret` prints 32 random bytes in hex. It is made once and kept where the deployment keeps its secrets (Ansible Vault, for example).
- From the secret comes one key pair, the group key: the Ed25519 key with the seed SHA-256 over `schild-group-secret:` and the secret. The group id is the id of its public half (section 1). Another secret is another group.
- At its start a node writes its own member record, signed with its node key as every record, carrying `admit_public_key` (the public half of the group key) and `admit`: the group key's signature over `schild-admit:`, the group id, `:` and the node's public key. A record of a node about itself is taken when `admit_public_key` hashes to the group id and `admit` verifies. The admission of one node does not fit another key.
- The secret admits and does nothing else. It signs no record but the admission, it never travels, and a removed node stays removed although it holds the secret (check 6 of section 4 comes before). To shut out whoever holds a leaked secret, deploy a new one: that is a new group, and every node moves there by itself at its next start (below).
- A node that holds no member for an address of `peers` sends its member record to that address (`POST /mesh/v0/hello`, section 7) and takes the member list it gets back, every second until it holds one. The order in which the nodes start does not matter.
- Name and address come from `node_name` and `cluster.advertise` or `cluster.listen`. When they change in `schild.yaml`, the node writes its member record again at its next start.

#### A new secret

A node that starts with a secret of another group than the one its cluster directory holds moves to the secret's group. Nothing is wiped by hand.

- It keeps its node key, so its id stays. It writes its member record for the new group and carries over every record that is the state of a class other than `members`, tombstones too, unless the record's time is over or its version is not read: blocks and lifts, settings, access, logins, erasures, certificates, jobs. The notes it keeps next to the records come along (what of its own values it brought in step, how far it read the events and requests of the others).
- A carried record is a new record of this node in the new group: `group` the new id, `origin` this node, the next `seq`, a new signature, and `hlc`, `deleted`, `expires` and the data of the record it comes from. It is as old in the new group as it was in the old one, so section 3 settles it against whatever the new group holds: a later change made in the new group wins, and a lift or an erasure a node carries in later beats the block or value an earlier node carried. Two nodes that carry the same record carry the same data.
- A record that tells a node the value it already brought in step never takes back a change of that node that has not left yet.
- The directory of the group before is kept next to the new one (`cluster.replaced-<UTC time>`); the newest two stay. The new directory is built aside and takes the place of the old one only when it is complete; a move that fails leaves the node in the group it was in. A secret that is missing, shorter than 32 bytes or readable by others moves nothing.
- A node that was removed from the group before carries nothing. Members are not carried: every node admits itself with the new secret, and an edge or a gateway that joined by a code is let in again by a code.
- An answer 410 (removed, section 7) names the group of the node that answers in the header `X-Schild-Group`. A node believes it only for the group it is in: a node of the group before may still know a moved node as removed.
- Until every node started with the new secret there are two groups. They exchange nothing: a node of one is no member of the other. Counts (section 8) are per group meanwhile, since the hash key comes from the secret.

### By hand

- `schild cluster init` on the first node makes the key and the group, and writes the node's member record.
- `schild cluster invite` on a member prints a join code: 16 random bytes and the first 16 bytes of SHA-256 over `schild-join:` and that node's public key, base32 in lower case, in four groups. The node keeps SHA-256 over `schild-join-secret:` and the secret, with the expiry. One use, one hour.
- `schild cluster join ADDRESS CODE` on the new node connects to that member and goes on only when the key of the member's certificate fits the code. It sends the secret, its name and its address; its own key is the one of the certificate it shows. The member writes the new member record and answers with the group id and every member record. The new node takes the answer only when the answering key is a member of the group it names, the node itself is one, and every record leads back to the group id.
- `schild cluster remove NODE` on any member writes the tombstone of that member.

## 7. Mesh

One listener per node (`cluster.listen`), TLS 1.3, HTTP/2. Both ends watch a connection with HTTP/2 PING frames: after 1 s without a frame a ping goes out, and a connection that does not answer within 2 s more is closed. A node that hangs or lost its network is therefore unreachable for the others after about 3 s, a node that stopped at once (the connection is refused). A member counts as reachable when its last call was answered, at most 10 s ago. Both sides show a self-signed certificate of their node key; names and dates in it mean nothing, the key is compared with the member list. A node calls every other gateway of the member list.

`POST /mesh/v0/sync`, members only. Request: `group`, `vector` (per origin the highest `seq` the caller has seen) and `wait_ms`. The answer comes at once when the answering node holds records beyond the vector, else after `wait_ms`, at most 4 s (a long poll). Answer: `records` (at most 500), `covered` (per origin, how far these records bring the caller), `vector` (how far the answering node is), `more`. The caller applies the records, members first, then raises its vector to `covered`. The same call serves the push, the catch-up after an outage and the first sync of a new node.

`POST /mesh/v0/join`, any certificate: section 6. A wrong code is answered after half a second.

`POST /mesh/v0/hello`, any certificate: a node set up by configuration sends `record`, its own member record. The key of its certificate has to be the key of the record. The answering node checks the record like any other (section 4) and answers with `group` and every member record when the caller is a member afterwards. The caller checks each of them the same way, so it does not matter that it could not know the answering key before.

A caller that was a member and was removed gets 410 on sync and hello, any other caller that is no member 403. A node that reads 410 says in its log that it was removed, serves with the state it has and shares nothing.

## 8. Counting for the group

Behind a balancer the requests of one client land on every node, so a limit or a scenario that counts on one node sees a part of them. No counter is shared and nothing in the request path asks another node.

- Every node counts as a single gateway does. Once a second it tells every gateway it reaches what it counted in that second: `POST /mesh/v0/tell`, members only, body `kind` (`counts`) and `body`, at most 1 MiB. Nothing of it is stored, and a node that is away misses it.
- `counts`: per client key and rate limit the requests that matched (`limits`); per client key what the scenarios counted (`clients`: `login_failed`, `crawl`, the hashes of user names tried, the hashes and weights of probed paths, the WAF rules matched and the requests that matched any); per website the crawl baseline and the user names of failed logins (`sites`).
- A node adds what it is told to its own counters, as if the requests had come to it, and decides nothing: the next request of the client that reaches it meets the sum. A limit of n therefore lets a client pass n plus what the nodes take in the second a count travels; a scenario fires on the first node that sees a request after the sum is over its threshold.
- Each node tells only what it counted itself, so nothing is added twice. A node tells at most 2 000 client keys and 2 000 limit counts a second; what is over counts on its node only. What a node is told is bounded when it is applied: a count cannot take a bucket further below zero than one burst.
- The nodes merge sketches of user names and clients by the hashes themselves, so the nodes of a group hash under one key: 16 bytes for SipHash-2-4, made by the founder and handed to a node with the answer to its join, or derived from the group secret (SHA-256 over `schild-group-hash-key:` and the secret, the first 16 bytes). A single gateway keeps its random per-process seed.
- **Distributed attacks (MVP-18).** A wave is a sum over many senders, so the same message carries what the detectors compare (`dist`): per website and route the failed and passed attempts, the senders new to the route, the attempts with an inconsistent client and the hashes of the senders (`routes`); per request shape the hashes of its senders (`shapes`); per fingerprint, website and route the hashes of senders and user agents (`fps`); per account the failed attempts, the hashes of the senders and whether the telling node counts the account as attacked (`accounts`). A node adds counters, puts the sender hashes into its own sketch (a union) and decides nothing; an attacked account waits for the group. At most 200 targets of each kind, 32 sender hashes per target and 4 000 in all a second; what is over counts on its node only. A route or website the receiving node does not count on itself is left out.
- **A wave is one wave.** In a group the id of a wave is derived, under the group's hash key, from its detector, website, route or shape and the five minutes it started in, and the incident number of a `shape_block` from that id. Nodes that detect the same wave within the second a count travels write an event with the same id, and a store holds an event once. The detecting node tells the wave (`dist.waves`: id, detector, target, action, start, end, what triggered it); a node that had not detected it holds it under that id without an event of its own, enforces its response as far as its own mode, profile and learning period allow, extends it and ends it with the others. The end at its time is written by the nodes that wrote the detection, under one derived id; an end by the operator is written on the node it was made on and told. A wave detected across the end of such five minutes gets two ids: the earlier wave stays, the other leaves memory, both events name their node by their source.
- Per node stay: open connections and waiting requests, the waiting page, memory limits (they protect the machine), whether a sender is new to a route, and how many requests a response to a wave stopped.
- A balancer that picks the node by the client address makes every count exact while the set of nodes is unchanged.

## 8a. The running counts at a start, and a clock that is off

- **Handover.** The counts of section 8 tell a node what the others count from now on. A node that starts asks one member it reaches for what the group holds already: `POST /mesh/v0/ask`, members only, kind `counts_state`, question `cursor` (0 at the start), answer `next` (the cursor of the following page, below zero: the last) and `state`: per client key the tokens used of each rate limit (`limits`: `client`, `limit`, `used`) and what the scenarios count within their windows (`clients`: `login_fast`, `login_slow`, `login_n`, `crawl`, `waf_hits`, the probed paths `probe` with their weight `probe_w`, the rule ids `waf`, the registers of the sketch of user names `users`), per website the crawl window, its learned baseline and the sketches (`sites`), per route its window and learned baseline (`routes`), per account the failed attempts and for how long it counts as attacked (`accounts`), and the waves that run (`waves`, as in the counts). A page holds about 2 000 entries and at most 6 MiB; a pass over all pages has 5 s.
- **Join.** The state is a snapshot, the counts that follow are what was counted after a node's last word; they do not join exactly. The first pass adds: what the member had counted and not told yet, and what a third node told both, is then counted twice, about a second of the group at most. A second pass 3 s later only raises what is below the member's state and adds nothing twice; it brings what was counted while the others did not tell the starting node yet. Sets and sketches join by union and are exact. A counter taken over starts a window of its own, so it lasts at most one window longer than on the member. Baselines are taken only where the node has learned none; they live in memory and do not survive a restart otherwise. Not handed over: the senders seen per fingerprint and per request shape (their windows are short), and which sender is new to a route.
- **Bounds.** Everything in a state is input from outside: a client key has to parse, a limit to exist, a number is cut at the bounds of the counts, tokens used at two bursts, lists at the size of their tables. An address erased in the last ten minutes is left out by the node that takes the state.
- **Readiness** (section 10) waits for the first pass. After 3 failed tries with a member in reach the node serves with counters that began at zero, logs it and shows the baseline reason `cluster_counts_not_taken`. A member of an older build answers 404; when no member in reach knows the question, there is nothing to take and no reason is shown. A node with no member in reach is covered by section 10.
- **A clock that is the odd one.** Each gateway knows the clock difference to every gateway it reaches (section 14). When at least two of them agree with each other within 5 s and this node's clock differs from theirs by 60 s or more, the node answers 503 on `/.schild/readyz`, logs it, notes it for `schild cluster status` and shows the baseline reason `cluster_clock_out_of_service`; it looks every 2 s and returns when the difference is gone. With one other gateway, or when the gateways in reach do not agree among themselves, no node leaves: the rule never takes every node of a group out.

## 9. Events, incidents and requests

Every node keeps the events, the incidents and the single requests of every node in its own store. Every list, search, chart of the requests and the live view of a dashboard show the group without a query going from node to node, and what a node wrote is still there when the node is gone.

- **Whose event it is.** The CloudEvents source of an event names its node. In a group the source is `schild://<node_name>.<the first 12 hex digits of the node id>`, so nodes with the same `node_name` (one `schild.yaml` deployed to all) still tell their events apart. A node hands on only what it wrote itself, and takes no event that carries its own source.
- **Events** are asked for: `POST /mesh/v0/ask`, members only, body `kind` and `body`. Kind `events`, question `after` (a sequence number of the answering node), answer `epoch`, `next` and at most 500 `rows`. A node asks a member when that member has news (see "When a node asks" below) and keeps the cursor per member, so a node that was away catches up from where it stopped. `epoch` names the store the cursor counts in; when it changes, the cursor starts at 0. An event a node holds already is left as it is.
- **Incidents**: kind `incidents`, question `since_ms`, answer the incidents that changed since and whose event the answering node wrote. A node stores a new one and takes over a higher count, a later last request and that it was unblocked. It asks 2 minutes back again, because an incident that gathers the requests of a minute still changes.
- **Single requests** are asked for too: kind `requests`, question `after` (a sequence number of the answering node), answer `epoch`, `first`, `next` and at most 2 000 `rows` with about 1 MiB of text. Every node numbers the requests it serves itself, from 1, and writes the number into the record of its request store. It holds its newest 32 768 requests (within 24 MiB of their text) in memory and answers a cursor that lies further back from the store on disk, as far back as the store keeps its segments (`monitoring.requests.keep_hours`, `monitoring.requests.max_size_mb`). A node asks a member when that member has news (see below), again at once while the member has more (four times in any case, then for up to 0.8 s, 64 times at most; its own writer bounds it besides), and keeps the cursor per member. So a node that was away, however long, takes every request the member still keeps, once, also when the member restarted meanwhile. The numbers survive a restart: the next one is written to the store once a second, and a start goes on 1 048 576 above it, so none is handed out twice. Numbers therefore have holes; a cursor follows `next` whatever it is. `epoch` is the node id and a random name of the request store, which stays over restarts; when it changes (a new store), the cursor starts at 0. `first` is the lowest number that cannot have left with a deleted segment: when it lies beyond the cursor, requests may be gone for good; the asking node counts the numbers and says so in its log. What the store does not hold, it cannot hand over later: a request sampled out under load (unless it is in a pinned segment), one dropped by a full writer queue, and one of an erased address. Those reach the others only while they are in the log in memory. A request of another node carries no number where it is stored, so a node never hands it on as its own.
- **When a node asks.** Not every second: a group that has nothing to say asks nothing. Every node says how far its own data went, the **heads**: `boot` (a name of this run of the process, at most 64 bytes), `s` (a number that grows with every event or incident the node writes itself) and `r` (the number its next served request gets). They say that something is new, not what; the cursors stay what they are.
  - A node tells its heads (`POST /mesh/v0/tell`, kind `heads`, body the three fields) to every member that has not asked for what they cover: it looks twice a second and tells a member again every second until that member asked.
  - A member that just took requests is told nothing for 2.5 s: every answer to `requests` carries `heads` too, and a node that got at least one request asks again after a second by itself. Under steady traffic that is one question per member and second.
  - A node asks a member for `requests` when the member's `r` moved, for `events` and `incidents` when its `s` moved, for everything when its `boot` changed, and for everything again 25 to 35 s after it last asked, whatever was said, so a lost word cannot stall it.
  - A member that never said heads (an earlier build) is asked every second for all three, as before, and a member that said them and then answers `requests` without them (it runs an earlier build again) is asked that way from then on.
- **The compact form of requests** (`b1`). The question may carry `enc: "b1"` and `limit` (at most 4 096). A node that knows `b1` then answers not with JSON but with `"SRQ1"`, text(`epoch`), uvarint(`first`), uvarint(`next`), text(`boot`), uvarint(`s`), uvarint(`r`) and a block of at most `limit` requests with about 2 MiB of text: uvarint(count), then per request one byte of flags (1 page view, 2 crawler policy, 4 pin, 8 an event id follows, 16 a referrer follows, 32 the address has 16 bytes), zigzag(time minus the time of the request before), zigzag(number minus the number before), the address (4 or 16 bytes), ref(site), ref(host), ref(path template), the path (uvarint 0: the template; else uvarint(length + 1) and the bytes), ref(user agent), ref(referrer) and text(event id) when their flags are set, one byte with the number of rules (at most 3) and a ref per rule, uvarint(score), uvarint(status), uvarint(bytes out), uvarint(ASN), the two letters of the country, one byte each for method, outcome, would-block reason, net class, UA class, browser, OS, device, bot category, verification and latency bucket, and uvarint(bot id). text is uvarint(length) and the bytes; ref is uvarint(id), where 0 is followed by a text that takes the next id (from 1) and any other id names a text seen before in this block. A request is about 60 bytes this way and about 600 as JSON.
  - **Versions.** A node of an earlier build sends neither `enc` nor `limit` and gets JSON with at most 2 000 rows; asked with them, it ignores both and answers JSON. An answer in JSON starts with `{`, so the asking node tells the two apart by the first bytes. Old and new nodes therefore exchange every request in the form the older one speaks, in both directions.
  - The reader refuses a block as a whole that is cut short, holds more requests than asked for, a text over 4 096 bytes, a reference to a text it has not seen, or bytes after its end. Every check of a request below applies after it.
- **Long answers travel compressed.** An answer to an Ask of 2 048 bytes or more is sent with `Content-Encoding: gzip` when the asking side sent `Accept-Encoding: gzip` (Go's HTTP client does by itself, also in earlier builds) and the answer is JSON; a `b1` answer is sent as it is. The asking side bounds what it reads after unpacking (8 MiB).
- A node that asks may wait for the writer of its own request store, because it is not in the request path: it hands the requests of an answer over in order and uses the lower half of the writer's queue only, so the requests it serves itself keep the upper half and are never made to wait. What did not fit within 2 s is not dropped: the cursor goes on after the last request handed over, and the rest is asked for again.
- A node that asks does not ask on while the writer of its own request store is more than half behind, and stores a request of another node only when its fields are within their bounds (host 255 bytes, path 2 048, other text 1 024), its time lies within what the node keeps and not more than a minute ahead, and its address was not erased at or after that time (a minute of margin for the clocks). An erasure also takes the requests of the address out of the log a node answers from, so a node that returns later is not handed them.
- Each node applies its own retention, its size caps and every erasure to what it holds, whoever wrote it. A node erases again, for ten minutes, what the group erased: an event of the address may have come from a node that had not erased yet. At its start a node applies every erasure it holds.
- Each node stores what the whole group records. There is no switch for it (initiator, 2026-11-22): every node has to hold the same to judge by it.
- The counters and charts read from the metric rings are shared too: section 9a.

## 9a. Counters and charts

Every gateway keeps the metric buckets (`MetricBucket`, the rings of 10 s, 1 min and 10 min of `metrics.db`) of every other gateway, so each dashboard shows the group added up and any one node, also a node that is gone.

- **Asked for.** `POST /mesh/v0/ask`, members only, kind `metrics`. Question: `res` (`10s`, `1m`, `10m`) and `from`, the start of the first bucket wanted in unix seconds (0: the oldest the ring holds). Answer: `res`, at most 60 `items` (buckets the answering node measured itself, oldest first, about 4 MiB), `more` and `next`: the answer does not reach the present, the next question goes on at `next`. A node hands on only its own buckets, never those it holds of others.
- **How often.** A gateway asks every member it reaches every 10 s, each ring, at most 4 questions per ring and member in a round. Its cursor per member and ring is the start of the newest bucket it stored. A bucket that ended within the last 30 s is asked for again and stored again when it changed: a restart inside a bucket merges two parts on the node that wrote it.
- **What is taken.** A bucket of more than 512 KiB is left out, and so is one whose time is no bucket start of the ring, lies more than 2 minutes ahead of the asking node's clock or before what its ring keeps. The cursor never moves past the asking node's clock.
- **Where it is kept.** One ring store per member under `storage.path/metrics-nodes/<node id>.db`, with the rings of the node's own `monitoring.keep`: the same bounds as its own `metrics.db`, per member. The stores of a member go when the member is removed.
- **How an answer adds up.** A query reads the node's own store and the members' stores and adds what it finds per bucket: counters, latency histograms and top lists add (top lists as space-saving summaries, with their error bound). Estimates of distinct clients do not add, because a visitor may have reached several nodes: the answer carries the largest estimate of the nodes, a lower bound (`ClusterScope.clients_at_least`). Gauges and host values (CPU, memory, disk, network) are never added: an answer over several nodes carries those of the answering gateway.
- **One node.** The dashboard and agent API take `node` on `getMonitoringNow`, `queryMetricSeries`, `getTrafficBreakdown`, `getWebsiteKpis` and `getWebsiteRealtime`: absent or `all` is the group, a node id that node alone from the history the answering gateway holds of it. One node is never answered from the request ring, which holds the requests of every node without their node; a filter that needs the ring then answers `filter_unavailable`.
- **What an answer says of itself.** `cluster` (`ClusterScope`): `node`, the `nodes` it holds, `partial_nodes` (a node whose newest bucket ends more than 45 s before the span does, with `until`), `clients_at_least`. A point whose bucket a member has not handed over yet is marked partial. Absent on a single gateway, whose answers do not change.
- **The last minute.** `getMonitoringNow` and the numbers of the website list answer for the group from the 10 s ring: the last six buckets every node had time to hand over, so they end about 20 s before the present. This gateway alone answers from memory as before. Hints and the host sample are those of the answering gateway.
- Per node stay: `getMonitoringServer` (the host sample of this moment), `streamMonitoring` (the live second), `Overview.counters_24h` and `series_24h` (counted in the memory of the gate since its start), the status of a website (`runs_on` names the server it is the status of).

## 10. Readiness and stopping

- `/.schild/readyz` on the web ports, the health check of the balancer, answers 503 on a node of a group until the node took the records of the group from a member (blocks, settings, access, logins, erasures) and applied them, and while it drains. A sync that put a record off (a clock more than 60 s ahead of the node's, an origin not known yet) does not count: a node whose clock is far behind stays out of traffic until it holds what the others wrote. A node that reaches no member for 10 s serves with the state it has, but only when it was in step with its group once (noted in its store, carried over by a move to a new group). A node that never was (a fresh one whose named peers do not answer, one the group refused because it is full) answers 503 until it reaches a member. It also waits for the running counts of the group (section 8a), and answers 503 while its clock is the odd one of the group (section 8a). A paused or removed node answers for the state it has. Events, incidents and requests of the others follow after it is ready.
- A stop (SIGTERM, `schild cluster drain`) turns the answer to 503, serves on for `cluster.drain.delay_s` (default 15) so the balancer sends new connections elsewhere, answers every request in that time with `Connection: close` (HTTP/2: GOAWAY) so a client that keeps a connection open through a balancer in TCP mode leaves it, then ends idle connections and lets running requests finish within `cluster.drain.grace_s` (default 30).

## 11. Edges

An edge is a member that only enforces: a balancer VM in front of the gateways that drops blocked addresses before they cost a gateway a handshake. Behind a balancer that sends the PROXY protocol the packets a gateway sees come from the balancer, so the firewall on a gateway's own host holds nothing there; the balancer is where a drop belongs.

- **Joining.** `schild cluster invite -role edge` on a gateway; the code says what it admits. On the VM `schild cluster join ADDRESS CODE -edge -name NAME -data DIR`, then `schild firewall run -group -data DIR`. The member record of an edge has the role `edge` and the address `0.0.0.0:0`: nobody calls it, it calls. An edge is admitted by a join code only, never by the group secret: a VM that held the secret could let itself in as a gateway.
- **What it may read.** `POST /mesh/v0/sync` answers an edge with records of class `members` only, so it knows whom to ask. `POST /mesh/v0/ask` answers it the kind `firewall` only: the block list as `schild firewall run` gets it from its own gateway (D87): per block the client key and its end, own and allowlisted addresses left out, at most 10 000. Not the incident, not the source, nothing else. The call waits up to 20 s for a change.
- **What it may not.** Every other call of the mesh answers an edge 403: no events, requests, settings, logins, certificates, counts, locks. No gateway takes a record an edge signed (check 5 of section 4), and an edge gets no hash key and no value of the classes settings, access and logins, which hold the secrets.
- **Whom it asks.** The gateways of the member list, one after the other until one answers; the one that answered last first. Every element of its table carries its end as the kernel timeout, so no block outlives its end when no gateway answers.
- A removed edge is answered 410 and gets nothing more.

## 12. One set of hub rules

Every node may download the index of the CrowdSec Hub. The node that took a new one says which, and the others take it from that node, so the rules are the same on every node without each waiting for its own daily check.

- A node tells every gateway it reaches the index it runs from a download (`POST /mesh/v0/tell`, kind `hub`): `digest` (SHA-256 of the index, hex), `etag`, `pin` (its `rules.crowdsec.pin`) and `fetched_at` (when it was downloaded from the hub). It says so within 2 s of a change and again every 30 s.
- A node wants an announced index when its hub rules are on and updated, its pin is the same, the index is another one than it runs, it was downloaded later than its own (not more than a minute ahead of its clock, not more than 30 days ago), and the node did not refuse this very index before.
- It then asks the announcing node for it (`POST /mesh/v0/ask`, kind `hub_index`, question the announcement, answer the index gzipped; empty when that node moved on) and checks the digest.
- The index goes through the node's whole update, as a download of its own does: the index check, the compile check, the cost check, the build. What does not pass is refused, the running rules stay, and the node asks the hub itself at its next check. Nothing is taken on a member's word.
- It is taken under the time of the first download, so a rule that is new was first seen at the same moment on every node and settles to block on all of them together. The node keeps the ETag, so its own next check finds nothing new.
- A node that restarted holds its set and not the index: it hands none on until it downloaded or took one again.
- A reset to the image snapshot holds for the group: the node that was reset writes when under the key `crowdsec_hub_reset_v1`, which is shared like every other key. A node that takes it drops a stored set downloaded before that time and runs its snapshot, and no node takes or hands on an index downloaded before the reset. The next download, on any node, is shared as ever.
- Own rules (`rules.d`) are files of the deployment and are not shared.

## 13. Bounds and the brake

- A group of this version takes at most 16 gateways and 8 edges; a join or a hello beyond that is answered 409.
- A node hands at most 200 new blocks a second to the group, and none while it knows 20 000 that run. What waits runs on its node all the same and leaves with a later round.
- `schild cluster pause` on a node: it serves with the state it has, answers sync with 503, takes no record and no count and hands none over, also from calls that were under way. What is written on it waits. `schild cluster resume` ends it; the node then takes what it missed. For the day a record that should not be travels through the group: a change reaches every node within a second, a wrong one too.

## 14. What a node says of itself, and what the dashboard shows

- **Versions.** Every 5 s a gateway tells the gateways it reaches (`POST /mesh/v0/tell`, kind `config`, at most 1 KiB): `config`, 64 hex characters, and `version`, the text of its build (at most 128 bytes). `config` is SHA-256 over `schild.yaml` as JSON with sorted keys, without `node_name`, `cluster.name`, `cluster.listen` and `cluster.advertise` (they differ from node to node by design), a zero byte and the text of `rules.d`. Nothing is stored and nothing is decided by it: a node compares what it was told in the last minute with its own and names the members that differ. No configuration travels (D32).
- **Blocks and their incident.** A node that takes the block of another node stores an incident from the record at once (address, source, event id, number), so `unblockIncident` finds it on every node from the moment the node lists the block; the incident itself follows with the events of the node that blocked and fills in the rest.
- **Clock.** The same message may carry `now`, the sender's clock (RFC 3339). The node that takes it keeps the difference to its own clock and shows it for a minute (`GroupMember.clock_skew_ms`); from 10 s on the overview carries the reason `cluster_clock_skew`. The node keeps the difference in its store too, and `schild cluster status` names a member from 5 s on. A node logs (rate limited) when it puts a record off because its time is more than 60 s ahead. Nothing is decided by it.
- **State.** The same message may carry `state`: per class (`blocks`, `settings`, `access`, `logins`) 16 hex characters, the first 8 bytes of HMAC-SHA-256 under the hash key of the group over what is in force on the node. For `settings`, `access` and `logins` that is every entry of every thing as the node holds it, as thing, entry key and the SHA-256 of the value in one canonical JSON form, sorted; per-node keys never appear. For `blocks` it is the block records the node holds that are not lifted and end more than 5 s from now, as client key and incident (a node's own allowlist may keep it from running a block the group holds; that is per node and not hashed). Two nodes in step hold the same entries and the same records, so their hashes are equal; a hash says nothing about the content. A node compares what a reachable gateway told within the last 20 s with its own: a difference younger than 10 s is a change on its way, from 10 s on `GroupMember.shared_state` says `differs`, and from 30 s on the overview carries `cluster_state_differs` and the node repairs: it asks that gateway again for every record from the first on (the store takes what it lacks and leaves the rest), then applies what the group holds of the differing classes once more, never taking back a change made on the node that has not left yet. At most once a minute per gateway. Readiness does not depend on the hashes: a difference never takes a node out of traffic.
- **Vitals.** The same message may carry `vitals`: `service` (`ready`, `draining`, `not_ready`: what the node answers on `/.schild/readyz`), `started_at`, `requests_per_s` over its last 60 s, and `stopped_share`, `latency_p95_ms`, `cpu_usage`, `memory_used_ratio`, `disk_used_ratio`, each a number or null. A node that takes them drops a value outside its range (ratios 0 to 1), stamps them with its own time and shows them for 20 s. A node of an older build sends none and ignores them. They are shown in the dashboard and nothing else: no node routes, blocks or drains by them.
- **Status.** `getGroupStatus` of the client dashboard API (`GET /group`, schema `GroupStatus`) answers from the running node alone, without a call to another node: `mode` (`single`, `group`) and `state` (`no_group`, `syncing`, `active`, `degraded`, `interrupted`, `paused`, `removed`), the members with role, address, state, last contact out and in, how far behind, version, config (`same`, `differs`, `unknown`) and `vitals`, the edges with their last question and the clients their firewall held, what is shared, the counters of the sync and the members whose config version differs. A gateway without `cluster.enabled` answers `{"mode": "single"}`.
- **Blocks.** `RunningBlock.node` is the `node` of the block's record, `node_self` whether this node signed it.
- **Erasure.** The node that erases waits up to 2 s until the gateways it reaches said they hold its erasure record (the `vector` of their next sync call), and answers with `PrivacyDeleteResult.nodes`: `reached` (itself first) and `open`. A gateway holds the record before it has erased; it erases within the same call. An open node erases when it returns (section 5).

## 15. Not built yet

The designs of the two larger parts, with the decisions they need, are at the end of [MVP-27](../tests/specs/MVP-27-ha-group.yaml) (`design_metrics_across_nodes`, built as section 9a; `design_data_copies_and_queries`, set aside).

Of [MVP-27](../tests/specs/MVP-27-ha-group.yaml): where each block holds (edge, node firewall, gate) in the dashboard, a copy on some nodes instead of all and queries from node to node (for groups too large to keep everything everywhere), the live second and the gate's counters of 24 h across nodes (section 9a names what stays per node), the versions of rule sets, bot ranges and the geo database in the config hint, events and dashboard operations of the group (the filter "Server" on the lists of events and requests, hints `cluster_peers_unreachable` and `cluster_config_drift` on the overview).
