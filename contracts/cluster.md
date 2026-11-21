# Group of gateways (unreleased, D103, MVP-27)

How several gateways of one operator share their state from node to node: no store beside them, no majority, so two nodes are a group. Direction given by the initiator on 2026-11-21, recorded in [DECISIONS](DECISIONS.md) D103; the whole plan is [MVP-27](../tests/specs/MVP-27-ha-group.yaml).

Go: `contract/cluster`. Built so far: the record, the classes `members` and `blocks`, the join code, the sync call. No golden vectors yet and no Python implementation: `make contracts-test` does not cover this contract, its Go tests do. Everything here may still change before a release.

**No request waits for the group.** The gate decides from its own memory. A node that reaches no member serves with the state it has.

**A member is trusted like the operator.** It can set and lift blocks for the group. What ends that for one node is its removal; the signature of every record says afterwards what it wrote.

## 1. Identity

- Every node has an Ed25519 key of its own, made on the node, in `<storage.path>/cluster/node.key` (mode 0600, 64 hex characters of the seed). It never leaves the node.
- Node id: `n-` and the first 16 bytes, in hex, of SHA-256 over `schild-node:` and the public key.
- Group id: `g-` and the first 16 bytes, in hex, of SHA-256 over `schild-group:` and the public key of the node that founded the group. Every trust in a group starts at its id: the founder's record of itself is the one record that needs no member to sign it, because its key hashes to the group id.
- There is no CA and no secret that opens everything.

## 2. Record

One change of one thing, as a JSON object:

| Field | Meaning |
| --- | --- |
| `v` | 1. A record of another version stays unread and is passed on unchanged |
| `group` | group id |
| `class` | `members` or `blocks` |
| `id` | the thing within its class, at most 128 bytes |
| `origin` | node id of the signer |
| `seq` | counts the records of one origin, from 1 |
| `hlc` | hybrid logical clock of the write: wall clock in milliseconds in the upper 48 bits, a counter in the lower 16 |
| `deleted` | a tombstone: the thing is gone, and the record stays so that an older write cannot bring it back |
| `expires` | RFC 3339, UTC, seconds: when every node drops the record; absent: never |
| `data` | standard base64 of the class's JSON object |
| `sig` | standard base64 of the Ed25519 signature |

The signature covers `schild-cluster-record-v1`, `v`, `group`, `class`, `id`, `origin`, `seq`, `hlc`, `deleted` (`1` or `0`), `expires` and the decoded bytes of `data`, in this order, each as its length in decimal, a space, the bytes and a space. Numbers are decimal text. One record is at most 32 KiB on the wire, its data at most 16 KiB.

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
| 5 | `origin` | the origin is no member, is not the founder's own record, or is an edge | asked for again |
| 6 | `removed` | the origin was removed and `hlc` is not before its removal | never |
| 7 | `signature` | does not verify with the origin's key | never |
| 8 | `schema` | the data does not fit its class (section 5), unknown fields included | never |

A record that is refused for good is counted and never applied or stored. A record that may pass later holds back the sequence number the node asks its peers from, so it comes again.

Records a removed member signed before its removal stand: what it decided while it was a member reads the same on a node that joins later.

## 5. Classes

### members

`id` is the node id. Data: `name` (1 to 63 bytes, no space or `/`), `role` (`gateway`; `edge` is reserved and admitted by no node of this version), `public_key` (standard base64, 32 bytes, hashing to `id`), `address` (IP address and port of its mesh listener), `joined`, optional `version`. Any gateway may sign a member record. The tombstone of a member keeps its data, with the key.

### blocks

`id` is the client key: the IPv4 address, or the first address of the IPv6 /64.

- A block. Data: `client` (equal to `id`), `bits` (32 or 64), `source` (`behaviour:<scenario>`, `agent:<token id>` or `dashboard`), `level`, `since`, `until`, `duration_s` (at most 7 days), `incident`, optional `event_id`, `net_class`, `node` (name of the node that decided). `expires` equals `until`: a block that ends at its time needs no record.
- A lift is a tombstone. Data: `incident` (the block it ends), `node`. Its `expires` lies 7 days and an hour after the lift, the longest any block from before could run.

A node that receives a block decides again with what it holds itself: an address on its own allowlist is not blocked, the test profile blocks nothing, and a block of the same client that already runs there stands. Only the deciding node writes the event and the incident; the others show its incident number.

## 6. Joining

- `schild cluster init` on the first node makes the key and the group, and writes the node's member record.
- `schild cluster invite` on a member prints a join code: 16 random bytes and the first 16 bytes of SHA-256 over `schild-join:` and that node's public key, base32 in lower case, in four groups. The node keeps SHA-256 over `schild-join-secret:` and the secret, with the expiry. One use, one hour.
- `schild cluster join ADDRESS CODE` on the new node connects to that member and goes on only when the key of the member's certificate fits the code. It sends the secret, its name and its address; its own key is the one of the certificate it shows. The member writes the new member record and answers with the group id and every member record. The new node takes the answer only when the answering key is a member of the group it names, the node itself is one, and every record leads back to the group id.
- `schild cluster remove NODE` on any member writes the tombstone of that member.

## 7. Mesh

One listener per node (`cluster.listen`), TLS 1.3, HTTP/2. Both sides show a self-signed certificate of their node key; names and dates in it mean nothing, the key is compared with the member list. A node calls every other gateway of the member list.

`POST /mesh/v0/sync`, members only. Request: `group`, `vector` (per origin the highest `seq` the caller has seen) and `wait_ms`. The answer comes at once when the answering node holds records beyond the vector, else after `wait_ms`, at most 4 s (a long poll). Answer: `records` (at most 500), `covered` (per origin, how far these records bring the caller), `vector` (how far the answering node is), `more`. The caller applies the records, members first, then raises its vector to `covered`. The same call serves the push, the catch-up after an outage and the first sync of a new node.

`POST /mesh/v0/join`, any certificate: section 6. A wrong code is answered after half a second.

## 8. Not built yet

Of [MVP-27](../tests/specs/MVP-27-ha-group.yaml): the role edge, the classes access, settings, secrets, logins, certificates and erasure, counters across nodes, copies of events and requests and queries across the group, the readiness answer and the drain, the caps on what a node may send, the check of the PROXY protocol allow list, events and dashboard operations of the group.
