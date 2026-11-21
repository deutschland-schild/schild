# Group of gateways (unreleased, D103, MVP-27)

How several gateways of one operator share their state from node to node: no store beside them, no majority, so two nodes are a group. Direction given by the initiator on 2026-11-21, recorded in [DECISIONS](DECISIONS.md) D103; the whole plan is [MVP-27](../tests/specs/MVP-27-ha-group.yaml).

Go: `contract/cluster`. Built so far: the record, the classes `members` and `blocks`, the join code, the sync call. No golden vectors yet and no Python implementation: `make contracts-test` does not cover this contract, its Go tests do. Everything here may still change before a release.

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
| `class` | `members`, `blocks`, `settings`, `access`, `logins`, `erasure` or `certificates` |
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

`id` is the node id. Data: `name` (1 to 63 bytes, no space or `/`), `role` (`gateway`; `edge` is reserved and admitted by no node of this version), `public_key` (standard base64, 32 bytes, hashing to `id`), `address` (IP address and port of its mesh listener), `joined`, optional `version`, and for a node admitted by the group secret `admit_key` and `admit` (section 6; both or none). Any gateway may sign a member record. The tombstone of a member keeps its data, with the key.

### blocks

`id` is the client key: the IPv4 address, or the first address of the IPv6 /64.

- A block. Data: `client` (equal to `id`), `bits` (32 or 64), `source` (`behaviour:<scenario>`, `agent:<token id>` or `dashboard`), `level`, `since`, `until`, `duration_s` (at most 7 days), `incident`, optional `event_id`, `net_class`, `node` (name of the node that decided). `expires` equals `until`: a block that ends at its time needs no record.
- A lift is a tombstone. Data: `incident` (the block it ends), `node`. Its `expires` lies 7 days and an hour after the lift, the longest any block from before could run.

A node that receives a block decides again with what it holds itself: an address on its own allowlist is not blocked, the test profile blocks nothing, and a block of the same client that already runs there stands. Only the deciding node writes the event and the incident; the others show its incident number.

### settings, access, logins

Things that are one value each, replaced as a whole. `id` names the thing; a record of another id is refused, and so is a tombstone.

| Class | `id` | What |
| --- | --- | --- |
| `settings` | `settings_overlay_v1`, `behaviour_rate_limits_v1`, `rules_state_by_v1` | what the dashboard and the agent API changed of `schild.yaml`: switches of the sources, thresholds, CRS levels, rate limits, and who set a repository's state |
| `settings` | `crawler_policies_v1`, `access_protections_v1`, `human_check_v1`, `rule_exceptions_v2` | crawler control, access lock and maintenance, browser check, rule exceptions |
| `settings` | `agent_pseudonym_key_v1` | the key of client pseudonyms, so one address has one pseudonym in the group |
| `access` | `allowlist`, `ip_exceptions`, `rule_decisions` | own addresses, released senders, disabled rules |
| `logins` | `users`, `sessions`, `agent_tokens` | who may sign in to the dashboard and the agent API |

Data: `v`, the value as the gateway stores it, in standard base64, and `node`, the name of the node the change was made on. For a table the value is `{"columns": [...], "rows": [[...]]}`, rows in the order of the key; a node refuses a table with other columns (another version of schild) and keeps its own.

`access_protections_v1` and `human_check_v1` hold the keys behind the cookies of visitors, `users` the password hashes, `sessions` and `agent_tokens` hashes of tokens. They travel between gateways of one operator over the mesh and nowhere else.

- A node publishes a value when it changed on that node since the node was last in step with the group. A value of another node is stored and made effective the way the start loads it: settings are validated with the node's own `schild.yaml`, rules are built again, and a value that does not fit (config drift) or does not build is not taken; the node keeps its own and says so.
- Two changes of the same thing on two nodes within the second a change takes to travel: the later one stands, on every node. The other is not merged in.
- A node that enters a group takes the group's value of every thing the group holds, and publishes only what the group does not hold yet. What it gives up the first time is kept on the node (`cluster.db`, table `replaced`) and named in its log and in `schild cluster status`. Nodes that hold different settings are therefore brought into a group one after the other: started at the same moment, each thing is settled by the later clock.
- Not shared: `schild.yaml`, `rules.d` and the Caddyfile (a deployment), the state of the CrowdSec Hub download, `installed_at_v1`, the first-run setup code.

### erasure

One erased address (Art. 17 GDPR). `id` is the address. Data: `ip` (equal to `id`), `keep_incidents`, `node`. `expires` lies 31 days after the erasure: longer than any node keeps what is erased, so a node that was away erases when it returns; then the record is gone, and the address with it. A node erases events, incidents, sessions, allowlist entries, exceptions, the running block and the requests of the address, as the dashboard does on its own node. The node that erases publishes after it erased.

### certificates

The storage of the embedded Caddy: certificates with their keys, ACME accounts, the local CA, challenge tokens, the keys of TLS session tickets. `id` is a path below the storage root: relative, no empty, `.` or `..` element.

- Data: `files`, a map from a file name to its content in standard base64, and `node`. Paths below `certificates/`, `acme/` and `pki/` travel per directory: the record names the directory and holds its files (at most 16). So a certificate, its key and its metadata are one record, and no node pairs the certificate of one order with the key of another. Every other path is one file per record, with the file name `""`.
- A node publishes a certificate directory only when its certificate and key fit each other, and writes one it receives only then. A tombstone has no files and removes the file, or the files of the directory.
- The lock files of the file storage (`locks/`) never leave a node.
- A node writes to its own storage first and tells the group after, so a node that reaches no member reads and writes its certificates as a single gateway does. At its first sync a node hands over what its storage holds and the group does not: certificates from before go with it, none is ordered again.
- A challenge token is published at once, and the write returns when every gateway the node reaches said it holds the token, or after 2 s.
- The keys of TLS session tickets go through the same storage (Caddy's distributed key source), unless the Caddyfile sets session tickets itself.
- With `cluster.enabled` a storage module of its own in the Caddyfile is refused.

**The lock of an order.** `POST /mesh/v0/lock` and `/unlock`, members only, body `name` (and on unlock `seq`, how far the caller is with its own records). The lock is kept by the member with the lowest node id among the gateways a node reaches; a node asks that one, or itself. A lock ends 5 minutes after it was granted when its holder does not give it back. The answer to a grant names what the last holder had written; the new holder waits, at most 10 s, until it holds that, so it finds the certificate instead of ordering it again. Nodes that cannot reach each other each find a keeper on their side and may both order the same certificate: one order too many, two valid certificates.

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
- At its start a node writes its own member record, signed with its node key as every record, carrying `admit_key` (the public half of the group key) and `admit`: the group key's signature over `schild-admit:`, the group id, `:` and the node's public key. A record of a node about itself is taken when `admit_key` hashes to the group id and `admit` verifies. The admission of one node does not fit another key.
- The secret admits and does nothing else. It signs no record but the admission, it never travels, and a removed node stays removed although it holds the secret (check 6 of section 4 comes before). To shut out whoever holds a leaked secret, deploy a new one: that is a new group, which the nodes enter with a new cluster directory.
- A node that holds no member for an address of `peers` sends its member record to that address (`POST /mesh/v0/hello`, section 7) and takes the member list it gets back, every second until it holds one. The order in which the nodes start does not matter.
- Name and address come from `node_name` and `cluster.advertise` or `cluster.listen`. When they change in `schild.yaml`, the node writes its member record again at its next start.

### By hand

- `schild cluster init` on the first node makes the key and the group, and writes the node's member record.
- `schild cluster invite` on a member prints a join code: 16 random bytes and the first 16 bytes of SHA-256 over `schild-join:` and that node's public key, base32 in lower case, in four groups. The node keeps SHA-256 over `schild-join-secret:` and the secret, with the expiry. One use, one hour.
- `schild cluster join ADDRESS CODE` on the new node connects to that member and goes on only when the key of the member's certificate fits the code. It sends the secret, its name and its address; its own key is the one of the certificate it shows. The member writes the new member record and answers with the group id and every member record. The new node takes the answer only when the answering key is a member of the group it names, the node itself is one, and every record leads back to the group id.
- `schild cluster remove NODE` on any member writes the tombstone of that member.

## 7. Mesh

One listener per node (`cluster.listen`), TLS 1.3, HTTP/2. Both sides show a self-signed certificate of their node key; names and dates in it mean nothing, the key is compared with the member list. A node calls every other gateway of the member list.

`POST /mesh/v0/sync`, members only. Request: `group`, `vector` (per origin the highest `seq` the caller has seen) and `wait_ms`. The answer comes at once when the answering node holds records beyond the vector, else after `wait_ms`, at most 4 s (a long poll). Answer: `records` (at most 500), `covered` (per origin, how far these records bring the caller), `vector` (how far the answering node is), `more`. The caller applies the records, members first, then raises its vector to `covered`. The same call serves the push, the catch-up after an outage and the first sync of a new node.

`POST /mesh/v0/join`, any certificate: section 6. A wrong code is answered after half a second.

`POST /mesh/v0/hello`, any certificate: a node set up by configuration sends `record`, its own member record. The key of its certificate has to be the key of the record. The answering node checks the record like any other (section 4) and answers with `group` and every member record when the caller is a member afterwards. The caller checks each of them the same way, so it does not matter that it could not know the answering key before.

A caller that was a member and was removed gets 410 on sync and hello, any other caller that is no member 403. A node that reads 410 says in its log that it was removed, serves with the state it has and shares nothing.

## 8. Not built yet

Of [MVP-27](../tests/specs/MVP-27-ha-group.yaml): the role edge, counters across nodes, copies of events and requests and queries across the group, the readiness answer and the drain, the caps on what a node may send, the nodes an erasure reached in `PrivacyDeleteResult`, events and dashboard operations of the group.
