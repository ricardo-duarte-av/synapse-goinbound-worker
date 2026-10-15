# synapse-goinbound-worker

A Go front door for Synapse's inbound federation transactions,
`PUT /_matrix/federation/v1/send/{txnId}`.

On this homeserver 96% of inbound transactions carry only EDUs, and most of
those EDUs are presence that Synapse throws away. This worker answers those
transactions itself and proxies everything else to the Python inbound
federation worker, unchanged:

| Transaction | What happens |
|---|---|
| EDU-only, well-formed, origin not in backoff | **Answered here.** Each EDU is forwarded to the instance Synapse would forward it to, over Synapse's own replication endpoint (`fed_send_edu`). The response is `{"pdus":{}}`. |
| Carries any PDU | Proxied to the Python worker, byte for byte. |
| Anything else (malformed, over the limits, auth we cannot verify, an origin in backoff, a redacted ACL, a database hiccup) | Proxied. When in doubt, Synapse answers. |

**It writes nothing to Synapse's data.** Every write is done by Synapse's stream
writers, exactly as when the Python worker forwards an EDU. It serves as a
read-only role, `goinbound_ro`, and all its queries are primary-key lookups.

On every start it connects as that role and checks the role's grants. If the
role is missing or lacks something, it creates or repairs it using
homeserver.yaml's credentials (`internal/dbrole`), then checks again. That
DDL on the role is the only change to the database it ever makes, and the admin
connection is closed before serving starts. Set `database.manage_role: false`
to do it by hand with `deploy/readonly-role.sql` instead.

## What it reproduces

Everything below is read from Synapse's source and cited in the code:

- **EDU routing.** The table comes from `stream_writers` in homeserver.yaml, as
  `register_instances_for_edu` builds it on a generic worker: typing, receipts,
  to-device and presence go to their writers. Device list and signing key
  updates go to the *first* `device_lists` writer. Any other type goes to main.
- **Presence is dropped when `track_presence` is off**, before routing
  (`federation_server.py:1686`).
- **Server ACLs for typing and receipts** (MSC4163). A banned origin's typing
  EDU is dropped. Banned rooms are removed from a receipt EDU, and the EDU is
  dropped if no room is left.
- **One transaction per origin at a time, and a 429 for a second one.** This is
  enforced across the native *and* proxied paths. A retry of the transaction in
  flight waits for it. A retry within 30s gets the cached answer. A transaction
  Synapse already answered gets Synapse's stored answer (`received_transactions`).
- **A failed forward fails the transaction with a 500**, so that the sender
  retries. That matters because to-device messages must be delivered reliably.
- **The backoff reset Synapse does on every signed request**
  (`transport/server/_base.py:143`). We don't do it ourselves. A transaction
  from an origin with a non-zero `destinations.retry_last_ts` is proxied, so
  Synapse resets the backoff and broadcasts `REMOTE_SERVER_UP` itself. That is
  ~0.7% of transactions here.

## Modes

Each kind of payload has its own mode in `goinbound-worker.yaml`, and both are
required, so what is proxied, shadowed or served here is always spelled out:

```yaml
modes:
  edu: shadow   # transactions carrying only EDUs
  pdu: proxy    # transactions carrying any PDU
```

`modes.edu` follows the same path as the gopro worker:

| Mode | Behaviour |
|---|---|
| `proxy` | Forward untouched. With `pdu: proxy` too, nothing is parsed, verified or read. Safe first deploy. |
| `shadow` | Forward, then evaluate afterwards what native mode would have done. Counts only; nothing is forwarded. |
| `canary:N` | Serve natively for N% of **origins**. Each origin stays on one path. |
| `native` | Serve natively whenever possible. Anything uncertain is still forwarded. |

`modes.pdu` is `proxy` or `shadow`. Either way a transaction with any PDU goes
to the Python worker whole, its EDUs included, whatever `modes.edu` says;
`shadow` additionally checks each PDU Synapse accepted, once Synapse has
persisted it (see below). There is no native PDU handling. The old single `mode:` key is refused, with a message giving
the replacement. The modes in force are exported as `goinbound_mode` and shown
at the top of the dashboard.

## Configuration

Only what is ours lives in `goinbound-worker.yaml`; see
`deploy/goinbound-worker.example.yaml`. These are read from homeserver.yaml,
mounted read-only, so they cannot drift:

- `server_name`
- `instance_map` (with `main` read as `master`)
- `stream_writers`
- `worker_replication_secret` or `_path`
- `presence.enabled` / `use_presence`
- `trusted_key_servers`
- `federation_domain_whitelist`
- `database`

## Deploying

1. Run the container: `docker-compose.yaml`. It mounts `/opt/matrix/synapse/synapse`
   at `/etc/synapse:ro`, and `/var/sockets`.
2. Point nginx's `/send` location at `av-goinbound-worker`
   (`deploy/nginx.conf.example`). In `proxy` mode this changes nothing.
   Rollback means pointing it back.
3. Move to `shadow`, then `canary:N`, then `native`, checking the metrics below
   at each step.

## Logging

At `info` it logs startup, the database role check, the first EDU of each type
Synapse has no handler for, shadow disagreements, and failures. Nothing per
transaction: at 5 requests a second, that belongs in metrics.

At `debug` every transaction gets one line, with these fields:

| Field | Meaning |
|---|---|
| `route` | native, proxy or abandoned |
| `reason` | what happened, or why it was proxied |
| `status` | the HTTP status |
| `origin` | the origin, and whether it was verified |
| `txn_id` | the transaction id |
| `edus` | for native: the EDU plan, e.g. `m.presence:drop_presence_untracked=3 m.typing:forward@av-edu-worker=1` |

In shadow mode each evaluation also gets a "Shadow evaluation" line, with the
decision and the plan.

## Metrics and dashboard

Prometheus job: `av-goinbound-worker-1:9200`. The Grafana dashboard is in
`deploy/grafana/` (import `goinbound-worker.json`).

The same listener serves Go's profiles at `/debug/pprof/`, e.g.
`go tool pprof http://<container IP>:9200/debug/pprof/heap`.

## Verifying each step

```promql
# Where transactions go, and why.
sum by (route, reason) (rate(goinbound_requests_total[1h]))

# Shadow: what native would have done, by EDU type and destination ...
sum by (edu_type, action, writer) (increase(goinbound_edus_total{path="shadow"}[1d]))
# ... against what Synapse's writers actually receive.
sum by (job) (increase(synapse_http_server_requests_received_total{
  server_name="aguiarvieira.pt", servlet="ReplicationFederationSendEduRestServlet"}[1d]))
# Note: the Python worker sends receipts and to-device EDUs to MAIN, which
# re-forwards them to av-edu-worker (it never builds those handlers; see
# internal/edu/router.go). So in shadow mode our av-edu-worker forwards equal
# Synapse's av-edu-worker count minus main's re-forwards, and main's share
# shows up under av-edu-worker on our side. Once native, main's count falls
# to ~0 and av-edu-worker's total stays the same.
sum by (job) (increase(synapse_outgoing_replication_requests_total{
  server_name="aguiarvieira.pt", name="fed_send_edu"}[1d]))

# Shadow: transactions we would have answered 200 that Synapse did not.
sum by (synapse_status) (increase(goinbound_shadow_disagreements_total[1d]))

# Native: forwards, their latency and failures.
sum by (writer, edu_type, result) (rate(goinbound_replication_send_edu_duration_seconds_count[1h]))
```

Once native, the Python worker's `FederationSendServlet` rate should fall by
about 96%. Receipts, typing and to-device should keep arriving: check
`receipts_linearized` and `device_inbox` growth, and a real client.

## Tests

```sh
go test -race ./...
```

Live tests skip without their environment variables:

```sh
SYNAPSE_DSN="host=/var/sockets user=synapse dbname=synapse-db" go test ./internal/store/
# Creates, checks and drops a throwaway goinbound_selftest_* role; the TCP DSN
# must require a password, or the SCRAM verifier is not really tested.
DBROLE_ADMIN_DSN="host=/var/sockets user=synapse dbname=synapse-db" \
DBROLE_TCP_DSN="host=172.20.0.38 port=5432 dbname=synapse-db sslmode=disable" \
  go test -run LiveEnsure ./internal/dbrole/
HOMESERVER_YAML=/opt/matrix/synapse/synapse/homeserver.yaml go test ./internal/synapsecfg/
HOMESERVER_YAML=/opt/matrix/synapse/synapse/homeserver.yaml go test -run LivePresenceProbe ./internal/replication/
```

`TestLivePresenceProbe` forwards one presence EDU to the real presence writer,
and checks that a wrong secret is refused. It is a no-op only because presence
is untracked here; the test refuses to run otherwise.

## PDU checker

PDUs are always proxied. With `modes.pdu: shadow`, every PDU in a transaction
Synapse answered 200 is followed into Synapse's database: once persisted, it
gets the same checks as the offline replay -- event ID, content hash and
signatures; state resolution, the auth verdict and the resulting state --
compared with what Synapse stored. Counted in `goinbound_pdu_shadow_total`
(dashboard row "PDU shadow"); disagreements are logged at warn.

| Package | What it is |
|---|---|
| `internal/pdu` | A port of Synapse's `event_auth.py`, with room version flags from `rust/src/room_versions.rs`. |
| `internal/stateres` | A port of Synapse's state resolution v1, v2 and v2.1 (`state/v1.py`, `state/v2.py`). Its tests are Synapse's own `tests/state/test_v2.py` cases; v1 is checked against room v1 history (176/176 forked events, 88 resolutions). |
| `internal/pdustore` | Reads events, auth edges and state groups. |
| `cmd/pdusweep` | Replays stored events through both, and compares the result with what Synapse decided and stored. |

`cmd/pdusweep`, for each sampled event:

1. resolves the state of its prev events;
2. runs Synapse's receive-path auth pipeline;
3. compares the verdict with Synapse's rejection record, and the resulting
   state with the state group Synapse stored.

It is light by default: the read-only role (so its statement timeout
bounds every query), one worker, 5 events a second (`-rate`), 50 events per
room version from the last 200k stream orderings, sampled in one pass.

```sh
go run ./cmd/pdusweep -n 100 -forks      # events where state resolution runs
go run ./cmd/pdusweep -n 100 -rejected   # events Synapse rejected
go run ./cmd/pdusweep -event '$id'       # one event, with a full trace
```

First results, 2026-10-14: 1,180 comparable events across room versions 4–12,
including 533 real state resolutions and 513 rejected events. Every one
matches Synapse, in its verdict and in its resolved state.

What the replay skips, and why:

- events whose prev events have no state group;
- events where a prev's state group is newer than the event's own. Synapse
  then got that state from a remote, not from what is stored now.

Size limits (`_check_size_limits`) are ported too:

- **Fields:** sender, room ID, state key, type and event ID are limited to
  255 codepoints (always strict) and 255 bytes. The byte limit is strict
  only from v11. Below that, Synapse persists the event as
  `oversized_event`; the 8 such rejections stored here are all v4-v6 member
  events with long multibyte state keys.
- **Whole PDU:** the 64 KiB limit applies only to PDUs Synapse drops, so the
  live shadow checks it on those.

State resolution uses Synapse's chain cover index, cross-checked against a
plain DAG walk (`pdusweep -crosscheck`, 308 resolutions agreeing). Signatures,
content hashes and event IDs are checked with `pdusweep -sigs`: 9,000 stored
events across v3-v12 all reproduce, apart from keys reissued under the same
ID since.

Soft-fail is checked too. The shadow snapshots each PDU's room: forward
extremities, the current state for the event's auth types, and whether its
prevs are known. It waits until the PDU's prev events are persisted, up to
`pdu_shadow.prev_wait_seconds`, because Synapse handles a room's PDUs one at
a time and reaches this one only after them. A snapshot taken on arrival
would see the room before PDUs still queued, and report "missing prevs"
Synapse never had. Once the event is
persisted, it reproduces `_check_for_soft_fail` from that snapshot and
compares the verdict with Synapse's stored `soft_failed` flag. If any other
event of the room was persisted between the snapshot and this one, the
current state may have moved, and the case is counted as `race` rather than
compared.

A PDU from an origin the room's server ACL denies is not waited for
either: Synapse ignores all of that room's PDUs in the transaction
(`federation_server.py:514`), so this is agreement ("origin denied by server
ACL"). A PDU for a room no local user is joined to is not waited for: Synapse
drops it ("not in room", `federation_event.py:296`), and so do we. Someone
else's leave for a local user is the exception Synapse may persist as an
outlier; it is skipped. A PDU that is still not persisted when the wait ends
is `still queued by Synapse` if it is in `federation_inbound_events_staging`
(the room's queue is behind, usually fetching missing prevs), and
`not persisted` if Synapse dropped it.

State groups are checked after state and auth, for write mode: they are
rows the inbound worker stores itself before handing the event to the
persister. When the state matched, the shadow works out which group
Synapse should have used for the state before: the prev's group when
there is one, an exact match among the prevs' groups, or a new group on
the one needing the smallest delta (in full when that chain is 100 hops
long, or when no group can be built on). It checks the stored group's
shape: which group, built on which, with which rows, and for a state event
a new group after it with the event as its one row. Synapse breaks ties in
the order it iterates a Python set of group IDs, which `pySetOrder`
reproduces (tested against the Python in the Synapse image); it is a `tie`
only when the random order event IDs were added in could change it. A
group Synapse stored for another event with the same prevs is `resolution
cached by Synapse` (its hour-long `_state_cache`). A full group where a
reuse or delta was possible is the missing-prevs path, state from a
remote's `/state_ids`; the live check counts it as a mismatch only when its
snapshot saw every prev in the timeline. `pdusweep -groups` runs it on
history.

The `send_body` check builds the `fed_send_events` entry write mode would
hand the persister (`_serialize_payload`, `EventContext.serialize`) from our
own verdicts, and compares it with what Synapse persisted:

- the event, after `event_from_pdu_json` (unsigned stripped to its
  whitelist, `age` turned into `age_ts` at the request time) and
  `replaces_state`, against `event_json`;
- `internal_metadata`: `soft_failed` from our soft-fail verdict,
  `recheck_redaction` from event auth;
- the context's groups, from the state group check's plan, with
  `state_group_deltas` as `_build_state_group_deltas` orders them.

It runs only when state_groups, soft_fail and policy matched. A PDU whose
content hash fails is `redacted on receipt` (Synapse sends its pruned copy).

The `policy` check covers room policy servers (MSC4284; 75 rooms here).
On receipt, before staging, Synapse lets a PDU through on the policy
server's `ed25519:policy_server` signature, checked with the key in the
room's `m.room.policy` (or unstable) event; otherwise it asks the policy
server to sign it (`/_matrix/policy/v1/sign`). A signature it gets is added
to the event before it is persisted; a refusal soft-fails it as
`policy_server_spammy`. The shadow decides on arrival which Synapse will
do, from the room's current state (`no policy server`, `policy event`,
`signed`, `Synapse asks`), and reads what it did from the stored copy:
`asked, signed` or `asked, refused`. It does not ask the policy server
itself. `send_body` then expects the signature Synapse was given. `pdusweep -send` runs it on history, rebuilding each PDU as received
from the stored JSON. On 2026-10-15, 625 events across v3-v12, forks
included: every remote one matched; the rest are `local event`.

Push actions are checked last. The shadow reproduces
`BulkPushRuleEvaluator._action_for_event_by_user` against each user's push
rules (`internal/push`, a port of Synapse's Rust evaluator, with the base
rules dumped from the deployed 1.162). Then it compares the rows with
`event_push_actions`. The inputs are:

- the local members, minus the sender and appservice-exclusive users;
- the member count, power levels and related events;
- the thread and thread subscriptions;
- the history-visibility filter;
- Synapse's unread rule (`msc2654`).

Who is in the room is read from current state. So the check is skipped as
`race` when any member event has landed since the snapshot. Other skips:

- `redacted`: a redaction deletes the event's rows;
- `pruned`: summarised rows are deleted after a day;
- `invite`: invite filtering (MSC4155) is not ported.

A reader's receipt at or past the event deletes their non-highlight rows.
That happens in a background loop, so the row may still be there when the
check runs. Such readers are left out of the comparison on both sides.
Each row's `actions` column is also compared byte for byte, as write mode
must write it to `event_push_actions_staging`: `_serialize_action`'s `""` for
the default lists (by Python equality, so key order and `False == 0` don't
matter), otherwise the actions after the Rust evaluator's serde round trip,
encoded compactly with `ensure_ascii`. Every distinct stored column (8
forms, 38k rows, 2026-10-15) re-serializes to itself.
`pdusweep -push` runs the same check over recent stored events. On
2026-10-14, 1,251 events with rows matched exactly, across v1-v12:
2,574 rows, 1,410 of them notifying. A deliberate mutation (unread always
false) produced 402 mismatches.

Missing prev events are not fetched: the shadow compares only what Synapse
computed from state it already held.
