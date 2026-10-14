# Working on synapse-goinbound-worker

The front door for inbound `/send`. It answers EDU-only transactions by
forwarding EDUs to Synapse's stream writers, and proxies everything else to the
Python inbound worker. Read `README.md` for what it does. This file is for
things that are not derivable from the code.

## The deployment

- `aguiarvieira.pt`. The Python worker `av-inbound-federation-worker-1` stays
  up as the upstream, on `/var/sockets/nginx/av-inbound-federation-worker-1.sock`.
  nginx currently routes `^/_matrix/federation/v1/send/` to it via upstream
  `av-inbound-federation-workers-ih` (in `/opt/npm/data/nginx/custom/http_top.conf`).
- Every stream writer is `av-edu-worker`. Presence is **untracked**, so ~340k of
  the 410k EDUs a day are dropped on arrival.
- The `inbound-federation` Prometheus job also scrapes `matrixbridg.es`. Always
  filter by `server_name="aguiarvieira.pt"`.
- Synapse source: `/home/daedric/synapse`. Sibling workers whose code was
  reused: `/home/daedric/synapse-gopro-worker` (fedauth, proxy, ACL) and
  `/home/daedric/synapse-gofederation-worker` (synapsecfg).

## Decisions that are easy to undo by accident

- **The goal is retiring the Python inbound worker(s)** (operator,
  2026-10-14). "Keep PDUs on Python" is not an end state, so the PDU path,
  remote fetching included, must eventually be Go's.
- **Whatever a persister or writer can persist, it persists.** Writes go over
  replication (`fed_send_events`, `fed_send_edu`). Only what Synapse's own
  inbound worker writes directly (staging, `worker_locks`, state groups,
  `event_push_actions_staging`, `event_failed_pull_attempts`) may be written
  by us, from write mode only, through a role granted exactly those tables.
- **Until write mode: no writes to Synapse's data.** `TestEveryQueryIsASelect` enforces it.
  A write, even to `received_transactions` or `destinations`, skips the caches
  and streams Synapse keeps in step with its tables. The one exception is the
  role itself: `internal/dbrole` creates or repairs `goinbound_ro` at
  startup, when connecting as it fails or a grant is missing.
- **The role connects directly, not through pgcat.** homeserver.yaml's
  database is `matrix-pgcat:6432`. pgcat only accepts users in
  `/opt/matrix/db/pgcat/pgcat.toml`, so `goinbound_ro` uses
  `/var/sockets/.s.PGSQL.5432`, which pg_hba trusts. The admin DDL still goes
  through pgcat, with the simple protocol.
- **Superuser is normal here.** A dedicated PostgreSQL for Synapse makes
  `synapse` its only user, and therefore a superuser (the operator, on
  2026-10-14). Don't refuse to start because of it.
- **The role's password is derived**, as HMAC(admin password, role), and is
  sent only as a SCRAM verifier. Nothing to store, and the same on every start.
  On PostgreSQL 16+ only a superuser may name SUPERUSER attributes in
  ALTER ROLE, so `Ensure` sets only LOGIN.
- **An origin in backoff is proxied, not reset by us.** Synapse resets
  `destinations` and streams a cache invalidation plus `REMOTE_SERVER_UP` on
  every signed request from such an origin (`transport/server/_base.py:143`).
  gofederation depends on that broadcast. Doing it from here would need the
  caches stream, which gofederation's notes explain is worse than not doing it.
- **Shadow mode reads transaction state BEFORE proxying.** It runs
  concurrently, with the header's claimed origin. Read afterwards, every
  transaction looks like a retry, because Synapse has just written
  `received_transactions`.
- **EDUs of one type are forwarded in order.** Different types go in
  parallel. This is slightly stricter than Synapse, on purpose.
- **Auth failures are proxied, never answered.** Python gives the
  authoritative 401, or verifies something we couldn't.
- **Modes are per payload, and both are required** (`modes.edu`,
  `modes.pdu`). The operator asked for explicit over implicit: nothing is
  proxied "because that is the default". `modes.pdu` accepts only `proxy`
  until a PDU path exists. The old `mode:` key fails with the replacement
  spelled out.
- **Canary is per origin**, so one origin's transactions never run in two
  processes at once.

## Verified against the live system (2026-10-14)

- The live homeserver.yaml parses, and every writer is in `instance_map`
  (`TestLiveHomeserverYAML`).
- Synapse's stored answer for an EDU-only transaction is `{"pdus":{}}`,
  byte-identical to ours (`TestLiveTxnState`).
- `fed_send_edu` to `av-edu-worker` with the real secret gets 200, and with a
  wrong secret Synapse's 500 (`TestLivePresenceProbe`). The edu-worker does
  not log at info, so its logs show nothing either way.

## PDU checker notes

- **Port Synapse, not the spec, and not mautrix's eventauth.** mautrix's
  `Authorize` follows the spec, which differs from Synapse in ways that
  change outcomes:
  - it rejects a v12 create event passed among precomputed auth events;
  - it has no special-case `m.room.aliases` rule for v1–v5;
  - it treats `m.federate` as "not false" where Synapse requires exactly
    `True`.

  `internal/pdu` is a line-by-line port of `event_auth.py` instead.
- **Synapse's non-AuthError exceptions are a third outcome** (`RaiseError`).
  A `SynapseError` (stringy power levels in v10+, a bad user ID in `users`),
  a `KeyError` or a `ValueError` from `int()` escapes `except AuthError`. In
  the receive path the event then fails rather than being rejected. In
  state resolution the whole resolution fails. Never count one as a
  rejection.
- **v12 `auth_event_ids()` appends the create event**
  (`rust/src/events/formats/v4.rs`). `ParseEvent` does the same. Without it,
  every v12 event fails "no create event in auth events".
- **A state set's auth chain includes the set's own events**, as Synapse
  implements it. That is not the spec's wording.
- **The state group IDs date the computation.** If a prev's group is newer
  than the event's, Synapse cannot have used it. That was the only cause of
  mismatches in the first sweep.

- **The chain cover links query is Synapse's slowest part, not ours to copy.**
  Synapse fetches links with one recursive query per thousand chains; in a
  67k-member room that is 67 queries and 18s. Breadth-first plain queries
  give the same links in a few round trips (2.6s for the whole resolution).
  For v2.1 with >1000 chains Synapse's own answer depends on Python set
  order; `goinbound_pdu_chain_link_batches` says how often that happens.
- **Signing key lookups at ~0.24/s are normal** (measured 2026-10-14, after
  warm-up from 1.3/s). Servers whose published key response has a short
  validity drop out of the in-memory cache and are re-read from Synapse's
  server_keys_json, one indexed lookup each. Auth failures stayed at ~1/hour.
- **Keys get reissued under the same ID.** A signature failure where the key
  Synapse holds was stored after the event arrived is not evidence of anything.
- **A failing content hash on a stored event is normal** when the event is
  already in its redacted form: Synapse redacts on receipt and stores that.
- **Port push against the deployed Synapse (1.162), not the checkout.** The
  `/home/daedric/synapse` checkout is 1.163. At 1.162 there is no
  `msc4075_enabled` switch (its rules always apply). Every experimental flag
  defaults to False, msc4210 included. Read the code with
  `git show v1.162.0:<path>`.
- **`event_push_actions` loses rows, which is not a disagreement.**
  - A read receipt of any type, at or past the event, deletes the reader's
    non-highlight rows. A background loop does it, so the live check
    can still see the row seconds after the receipt (3 mismatches on
    2026-10-14). Skip such readers on both sides; don't expect the row
    to be gone.
  - A redaction deletes all of the event's rows.
  - Rows a day old are deleted once summarised.

  The push check allows for all three. Before them, 98% of its "mismatches"
  were missing stored rows.
- **State groups are the inbound worker's own writes**, so write mode must
  make the same ones (`state_groups` check). The first sweep showed 4% of
  resolved events tie on "smallest delta" or on two exact matches; Synapse
  breaks them by Python set order, which `pySetOrder` simulates (CPython
  3.13: slot = id & mask, 9 linear probes, perturb, resize at 3/5 full,
  and `set(set)` copies). The insertion order is a frozenset of event IDs,
  random per process, so only colliding slots are real ties (~0.3%).
- **Matrix HQ's missing prevs store full groups**: ~13.6k rows each, 364
  in one day (2026-10-14). Synapse's missing-prevs path passes the
  fetched state as `state_ids_before_event`, which never becomes a delta.
- **homeserver.yaml has duplicate keys** (`msc3814_enabled` twice).
  PyYAML keeps the last one; yaml.v3 refuses the whole file, so
  `experimental_features` is decoded by hand (`lastWins`).

## Traps

- **Bound state caches by entries, never by group count.** A big room's
  state is 150k entries, 31MB as a Go map. The first PDU shadow cached up
  to 2,000 groups and copied the state per event to build "after". RSS reached
  1.7GB, and a 180-event replay of three big rooms peaked at 4.6GB of
  heap. Now: an LRU of 400k entries, groups rebuilt from a cached prev
  group's delta, and the state after compared as an overlay. Peak 141MB.

- **Never name a metric label `instance` (or `job`).** Prometheus owns those.
  Ours was renamed to `exported_instance` at scrape time, and every "by
  writer" panel silently grouped by the scrape target. The label is `writer`.

- `TestLiveEnsure` (dbrole) does DDL on the real database: it creates and
  drops a throwaway role. The auto-mode classifier blocks it, so the operator
  runs it.
- Unix socket paths must be under 108 bytes. The session scratchpad path is
  too long for one.
- **The Python worker sends receipts and to-device EDUs to main**, not to
  their writer: a federation-only worker never constructs ReceiptsHandler or
  DeviceMessageHandler, whose constructors register the routes. Main
  re-forwards them to av-edu-worker. This was the "24k/day to main of unknown
  type". It was found by matching shadow forwards against
  `synapse_outgoing_replication_requests_total{name="fed_send_edu"}`, which
  shows main as a sender too. We go straight to the writer, on purpose.
  Expect, once native: main's received fed_send_edu falls to ~0, main's
  outgoing fed_send_edu falls with it, and av-edu-worker's total is unchanged.
- Main and the workers log at ERROR, so Synapse's own "Got %r edu" lines are
  never written. Use metrics.
