# Write mode: replacing the Python inbound worker

Goal: Go handles every `/send` itself, PDUs included, so the Python inbound
worker can be retired (operator, 2026-10-14). nginx sends only
`/_matrix/federation/(v1|v2)/send/` to us; every other federation endpoint is
gopro's or main's, so this is the whole of the job.

This file is the plan and its status. Each item is done when it does what
Synapse 1.162 does, checked against Synapse, not against the spec.

## What the Python worker does for `/send`

1. Answers a retried transaction from `received_transactions`, else handles
   PDUs and EDUs in parallel, then **writes the answer to
   `received_transactions`** (`federation_server.py`, `_handle_incoming_transaction`).
2. Per PDU, grouped by room, rooms in parallel (10), PDUs of a room in order:
   room known, origin passes the room's server ACL, `event_from_pdu_json`,
   `_check_sigs_and_hash` (redact on a bad content hash; ask the policy
   server), then **stages it** (`federation_inbound_events_staging`) and
   tries the room's lock (`worker_locks`). The `/send` answer is decided
   here, before processing.
3. Whoever holds a room's lock drains its staging queue, oldest first,
   releasing and retaking the lock after each event, pruning the queue to
   its extremities past 100, under the room's purge read lock
   (`worker_read_write_locks`).
4. `on_receive_pdu`: seen-check, sanity (20 prevs, 10 auth events), missing
   prevs by `/get_missing_events` (10 events, depth window), else the state
   at each missing prev by `/state_ids` and `/event` (`event_failed_pull_attempts`
   on failure), auth events fetched and persisted as outliers.
5. Event auth against the auth events and against the state before; state
   resolution; soft-fail against current state; the state group (**written
   by the worker**: `state_groups`, `state_group_edges`,
   `state_groups_state`, `state_groups_pending_deletion` bump).
6. Push actions (**written by the worker**: `event_push_actions_staging`;
   removed again if persisting fails), unless the event predates the room's
   min depth.
7. `fed_send_events` to the room's persister, then the staged row is removed.
8. Side effects: an encrypted event from an unknown device or key resyncs
   the sender's devices (`multi_user_device_resync` on the device-list
   writer); a guest-access change kicks local guests.
9. Every minute, rooms with staged events whose lock is free are picked up
   (`_handle_old_staged_events`), so a dead process's queue is not lost.

## Tables write mode writes

Only these, through a role granted exactly them (`internal/dbrole`):

| Table | How |
|---|---|
| `received_transactions` | upsert (insertion values only) |
| `federation_inbound_events_staging` | upsert, select, delete |
| `worker_locks` | insert ... on conflict, update, delete |
| `worker_read_write_locks` | insert, update, delete (read locks only) |
| `state_groups`, `state_group_edges`, `state_groups_state` | insert |
| `state_group_id_seq` | nextval |
| `state_groups_pending_deletion` | update (the bump) |
| `event_push_actions_staging` | insert, delete |
| `event_failed_pull_attempts` | upsert, delete |
| `device_lists_remote_resync` | upsert (insertion values only) |

Everything else goes through Synapse's replication endpoints:
`fed_send_events` (the persister), `fed_send_edu` (the writers),
`multi_user_device_resync`.

## Status

| # | Piece | Status |
|---|---|---|
| 1 | Decisions match Synapse: signatures, policy, auth, state, state groups, soft-fail, push, `fed_send_events` body | **done** (shadow, 0 mismatches) |
| 2 | v2.1 forwards reachability over several link batches | **done** (`c851f57`) |
| 2b | Decide: write mode's decision for a staged event, through the state cache, checked live against Synapse (`decide` check) | **in shadow**; defers missing prevs, de-outliering, invites' push, v1 state res, partial state, content-hash failures |
| 3 | Write role with exactly the tables above | **done** (`dbrole` writes, `inbound.Grants`); not yet created at startup |
| 4 | Staging, room lock, purge read lock, interoperable with Python | **done** (`internal/inbound`: Synapse's SQL, tested on a throwaway PostgreSQL) |
| 5 | Room queue processor and the one-minute sweep | **done** (`inbound.Processor`); a deferred event stays staged, with its room, for Synapse's sweep |
| 6 | `/send` answer per PDU, and `received_transactions` | **done** (`inbound.FrontDoor`, `txn`); a transaction whose PDUs we cannot answer exactly (unknown keys, bad signatures, redaction on receipt) is Synapse's |
| 7 | The writes: state groups, push staging, `fed_send_events`, unstage | **done**; a failed persist is left staged for Synapse, where Synapse would log it and drop the event |
| 8 | Missing prevs and state: `/get_missing_events`, `/state_ids`, `/event`, outliers, failed pull attempts | **ported, unverified** (`write.missing_events: fetch`; default `defer`). Deferred still: a pulled event that needs a key we lack, has a bad signature or hash, was seen as an outlier, or has failed pulls (Synapse retries those in the background). The shadow cannot check this path: Synapse's own fetches happen out of its sight |
| 9 | Side effects: device resync, guest kicks | **done**: device resync (stale mark, then `multi_user_device_resync`); guest-access changes are deferred to Synapse (`allow_guest_access: false` here) |
| 10 | Rejected events' context | **done** (same groups, `rejected` set; mapped to the group before) |
| 11 | State resolution v1 | **done** (ported earlier, `a4f5864`); rejected events now left out, as v1's state_map_factory does. v1 forks are rare: 8 in the last 2M stream orderings, all matching |
| 12 | Verification in reverse: after Go writes, re-derive and compare | todo |
| 13 | A/B replay on two copies of a snapshot | todo |

## Rollout

`modes.pdu` takes `canary:N` (per origin, as for EDUs: a canary origin's
whole transaction is Go's) and `native`, with `write.instance_name`. The
shadow keeps checking every PDU, ours included. Rooms are safe to share with the
Python worker throughout: both stage into the same table and take the same
lock, so a room is only ever processed by one process at a time, and
whichever holds the lock processes everything staged in it.

Gates, in order: local tests against a Synapse schema; the A/B replay; a
canary of a few origins with the reverse verification; native.
