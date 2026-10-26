# Write mode: replacing the Python inbound worker

Goal: Go handles every `/send` itself, PDUs included, so the Python inbound
worker can be retired (operator, 2026-10-14). nginx sends only
`/_matrix/federation/(v1|v2)/send/` to us; every other federation endpoint is
gopro's or main's, so this is the whole of the job.

This file is the plan and its status. Each item is done when it does what
the deployed Synapse (1.163) does, checked against Synapse, not against the spec.

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
| 2b | Decide: write mode's decision for a staged event, through the state cache, checked live against Synapse (`decide` check) | **in shadow**; defers missing prevs (fetched with `write.missing_events: fetch`), missing auth events (likewise), de-outliering, partial state, content-hash failures |
| 3 | Write role with exactly the tables above | **done** (`dbrole` writes, `inbound.Grants`); created or repaired at startup |
| 4 | Staging, room lock, purge read lock, interoperable with Python | **done** (`internal/inbound`: Synapse's SQL, tested on a throwaway PostgreSQL) |
| 5 | Room queue processor and the one-minute sweep | **done** (`inbound.Processor`); a deferred event stays staged, with its room, for Synapse's sweep |
| 6 | `/send` answer per PDU, and `received_transactions` | **done** (`inbound.FrontDoor`, `txn`); a transaction whose PDUs we cannot answer exactly (unknown keys, bad signatures, redaction on receipt) is Synapse's |
| 7 | The writes: state groups, push staging, `fed_send_events`, unstage | **done**; a failed persist is left staged for Synapse, where Synapse would log it and drop the event |
| 8 | Missing prevs and state: `/get_missing_events`, `/state_ids`, `/event`, outliers, failed pull attempts | **done, checked against daedric.net** (`write.missing_events: fetch`; default `defer`): 3- and 12-event gaps made on purpose (`write.test_drop_pdus`, 2026-10-15) were filled as Synapse would. Pulled events with a bad content hash are kept pruned, and with a bad signature looked for elsewhere (held, or from the sender's server), both recorded as failed pulls; events with failed pulls are retried in the background, as Synapse does. The shadow cannot check this path: Synapse's own fetches happen out of its sight |
| 9 | Side effects: device resync, guest kicks | **done**: device resync (stale mark, then `multi_user_device_resync`); guest-access changes: with no local guest joined or invited (Synapse's own test, on content `kind: guest`), nothing to kick, as in Synapse; otherwise deferred (79 guest accounts from before 2023-11, none in a room, 2026-10-16) |
| 10 | Rejected events' context | **done** (same groups, `rejected` set; mapped to the group before) |
| 11 | State resolution v1 | **done** (ported earlier, `a4f5864`); rejected events now left out, as v1's state_map_factory does. v1 forks are rare: 8 in the last 2M stream orderings, all matching |
| 14 | Signing keys Synapse does not hold yet | **done** (`internal/keyring`: Synapse's order, notaries merged, then the origin); kept in memory, not stored, since storing means invalidating Synapse's caches over replication |
| 15 | Push on invites of local users: MSC4380 and MSC4155 invite config | **done** (`inviteAllowed`); checked live by the push check |
| 12 | Verification in reverse: after Go writes, re-derive and compare | todo |
| 13 | A/B replay on two copies of a snapshot | **dropped**: a second Synapse needs our server name and signing key, and anything it sent out would look like a second homeserver to the network (operator, 2026-10-26) |

## Testing the fetch path

The fetch path can't be compared with Synapse live: by the time we see an
event, Synapse has fetched its prevs already, or it hasn't. So it is tested
against a server we control. `write.test_drop_pdus` answers the next few PDUs
from a write origin, in one room, without staging them. The next event then
arrives with missing prev events, and write mode fetches them as Synapse would:
`/get_missing_events` for up to 10, `/state_ids` beyond that. Every dropped
event must end up persisted exactly once, with nothing left staged.

## Known gaps

- Transactions write mode leaves to Synapse on purpose: `PlanPDUs` returns a
  `pdu_*` reason when a PDU's outcome is not certain to match Synapse's
  (unknown keys, bad signatures, content hash, policy, ACL). For PDU
  transactions from origins write mode does not serve, the plan shadow plans
  them anyway and counts the reason it would have given:
  `goinbound_pdu_plan_shadow_total{reason}` (`ok`: it would have served it).
  That is the list of what still needs Python under `native`.

- Partial state rooms are deferred. The only long-lived one, a v1 room
  that could not be joined (`!cURbafjkfsMDVwdRDQ:matrix.org`), was deleted by the
  operator on 2026-10-16.
- Guest-access changes that would make local guests leave are deferred
  (none are in any room).
- Partial state rooms do occur: a room is partial while someone joins it.
  One event was deferred at 09:45 on 2026-10-20, and the sweep nudge got
  Python to persist it 1.5s later.
- A signing key nobody holds valid at the event's time (a dead server's,
  expired) is decided as Synapse decides it, on `/send` and for pulled
  events alike: "Failed to find any key to satisfy: _FetchKeyRequest(...)",
  the PDU dropped and, when pulled, the failure recorded. Our keyring looks
  as far as Synapse's every time (held keys, notaries, the server), as
  Synapse does, with no delay after a failed lookup. With more than one key
  ID (Synapse lists them in set order), it is still left to Synapse.
- Event auth that raises (a `SynapseError`, `KeyError`, `ValueError`; for
  example `$oBePoe…`, power levels with a string notification level, in
  `!bdbbTYhctZTWzoTzn9:federated.nexus`, 2026-10-22) is handled as Synapse
  handles it: a received event fails ("Failed to handle PDU", outcome
  `failed`) after its state groups are stored; a pulled prev that raises
  fails the received event too; an outlier that raises behind missing prevs
  records "ERROR 403: We can't get valid state history." for the pulled
  event. Raises in state resolution (after bumping the groups, before
  storing any), soft-fail and push (after the groups are stored; push
  rules are evaluated for soft-failed events too, as Synapse evaluates
  them before its visibility filter) are handled the same way.
- Auth events we do not hold are fetched as Synapse fetches them: the
  event's state groups stored, `/event_auth` from the origin (any failure
  logged and swallowed), the chain persisted as outliers, then decided
  again. Still missing: "ERROR 403: Auth events could not be found", the
  received event dropped, or the pulled one recorded as a failed pull.
- Remote fetches retry as Synapse's federation client does: `/state_ids`,
  `/event` for missing state, `/event_auth` and the notary key query,
  which Synapse requests without a timeout, get 60s an attempt and up to 3
  retries on no response, a 5xx or a 429 (`fedclient.Retrying`).
  `/get_missing_events` (60s), `/state` (10 minutes), the fetch from the
  sender (10s), a server's own keys (10s) and policy asks (30s) are tried
  once. Every attempt gets its timeout until the response arrives and the
  same again for the body, as `_send_request` and `_handle_response` time
  them (`fedclient.Attempt`).
- Every request write mode makes is under Synapse's destination retry
  limiter (`internal/backoff`, `retryutils.py`): a destination in backoff is
  not contacted (`NotRetryingDestination`), except for key fetches and
  policy asks (`ignore_backoff`); a failure (no response, 5xx, 401, 429)
  starts or lengthens its backoff (`federation.destination_*`, defaults 10m,
  ×2, 7d), and a success clears it, announcing REMOTE_SERVER_UP when it was
  failing. The timings are stored as Synapse stores them, with their
  `caches` row and RDATA (`write.mark_origins_up` must be on; without it
  backoff is honoured but not stored). The shadow's own policy asks are not
  limited, so they change nothing.
- `get_pdu`'s per-process state is ported: a destination is asked for an
  event at most once a minute (`PDU_RETRY_TIME_MS`), and a fetched event is
  reused for two minutes (`_get_pdu_cache`).
- Origins in backoff: served with `write.mark_origins_up` (the reset, its
  `caches` stream row and RDATA, then `REMOTE_SERVER_UP`). Only `/send`
  reaches this worker (`not_send` is 0); other federation endpoints go to
  other workers, which reset the origin themselves.
- nginx vhost `gosync.aguiarvieira.pt` (`proxy_host/324.conf`) sent `/send`
  straight to the Python worker. It was left over from testing gosync, carried
  no federation traffic, and is being removed (operator, 2026-10-15). After
  that, the only route to the Python worker is through us.

## Rollout

`modes.pdu` takes `canary:N` (per origin, as for EDUs: a canary origin's
whole transaction is Go's) and `native`, with `write.instance_name`. The
shadow keeps checking every PDU, ours included. Rooms are safe to share with the
Python worker throughout: both stage into the same table and take the same
lock, so a room is only ever processed by one process at a time, and
whichever holds the lock processes everything staged in it.

Gates, in order: local tests against a Synapse schema; a canary of a few
origins with the reverse verification; native.

### Retiring the Python worker

While the Python worker runs, `write.fallback: synapse`: a staged event write
mode is not certain to handle as Synapse would stays staged, and Synapse's
one-minute sweep takes it with the room's lock. Without that worker, such an
event would stay at the head of its room's queue, and every later event in
the room would wait behind it. `write.fallback: none` is for then: the event
is tried three times, at least two minutes apart (a persister restart must not
use up its attempts), then dropped and logged at ERROR
(`goinbound_write_events_total{outcome="given_up"}`). That is Synapse's own
rule: `_process_incoming_pdus_in_room_inner` logs any exception and unstages
the event. In the week to 2026-10-16 the only deferrals were for missing prevs,
which write mode fetches itself.

Main is the last resort (operator, 2026-10-16): it serves the `federation`
resource on `/var/sockets/nginx/av-synapse-main.sock` and can do everything the
inbound worker does, though it is single-threaded and busy, so it should get
as little as possible. Retiring the inbound worker can therefore be: point the
upstream at main, keep `write.fallback: synapse`. Main then answers what we
proxy (auth failures, about ten an hour; malformed bodies; `pdu_*` reasons)
and takes what we defer.

One catch, which the sweep nudge covers: a Synapse process starts
`_handle_old_staged_events` only once it has received a transaction
(`on_incoming_transaction`, `federation_server.py:306`). Main, getting almost
none, might never start it, and an event we defer would wait. So on every
deferral (at most once a minute) we send the upstream a copy of the last
transaction we answered and stored. Synapse answers it from
`received_transactions` before touching its PDUs or EDUs, as it answers the
sender's own retry, and the copy authenticates, as X-Matrix signs no
timestamp. The sweep starts, nothing else happens.
`goinbound_sweep_nudges_total{outcome}`: `stored_answer` is the expected one;
`other_answer` means the upstream handled the copy instead of recognising it.
