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
  That is Synapse's label. goinbound's own series (job `goinbound-worker`) carry
  `job`, `instance` and `deployment="aguiarvieira.pt"`, and no `server_name`: a
  `server_name` filter on them returns no data (an alert written that way fired
  on no data, 2026-10-16).
- Synapse source: `/home/daedric/synapse`. Sibling workers whose code was
  reused: `/home/daedric/synapse-gopro-worker` (fedauth, proxy, ACL) and
  `/home/daedric/synapse-gofederation-worker` (synapsecfg).

## Decisions that are easy to undo by accident

- **The goal is retiring the Python inbound worker(s)** (operator,
  2026-10-14). "Keep PDUs on Python" is not an end state, so the PDU path,
  remote fetching included, must eventually be Go's.
- **Main is the last resort, always** (operator, 2026-10-16). It can do
  anything a worker does, but it is single-threaded and busy, so it gets as
  little as possible. Retiring the inbound worker can mean pointing the
  upstream at main with `write.fallback: synapse`; the sweep nudge
  (`internal/txn/nudge.go`) makes sure main sweeps what we defer.
- **Whatever a persister or writer can persist, it persists.** Writes go over
  replication (`fed_send_events`, `fed_send_edu`). Only what Synapse's own
  inbound worker writes directly (staging, `worker_locks`, state groups,
  `event_push_actions_staging`, `event_failed_pull_attempts`, the
  `destinations` reset and its `caches` stream row) may be written
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
- **An origin in backoff is reset by us, as the inbound worker does.** Synapse
  resets `destinations`, streams a cache invalidation, and publishes
  `REMOTE_SERVER_UP` on every signed request from such an origin
  (`transport/server/_base.py:143`). gofederation depends on that broadcast.
  `write.mark_origins_up` does all three: the upsert, a `caches` stream row
  under `write.instance_name`, its RDATA, then REMOTE_SERVER_UP, and a
  POSITION in answer to REPLICATE. Being a caches-stream writer is normal:
  every Synapse process is one (`writers=[]`), and Synapse says a quiet one
  holds nothing back (`resource.py`: "nothing cares if a given worker's
  caches stream position lags"). gofederation's warning against it was too
  broad. Two rules: publish RDATA in stream ID order (a process drops a token
  at or below the last it saw from an instance), and announce an RDATA that
  failed with a POSITION, so processes read the row from the database. Our
  lines round-trip byte-identical through Synapse's own parsers (checked
  2026-10-15). Without the setting, those transactions are proxied.
- **Shadow mode reads transaction state BEFORE proxying.** It runs
  concurrently, with the header's claimed origin. Read afterwards, every
  transaction looks like a retry, because Synapse has just written
  `received_transactions`.
- **EDUs of one type are forwarded in order.** Different types go in
  parallel. This is slightly stricter than Synapse, on purpose.
- **Auth failures are answered only in Synapse's words** (operator,
  2026-10-26; they were all proxied before). `internal/synapseauth` ports
  `authenticate_request` onto write mode's keyring: the body parsed first,
  the headers, the destination, the whitelist, then
  `verify_json_for_server`. A request our fast verifier refuses is answered
  only when the port refuses it too, with an error whose text we
  reproduce; when the port accepts it, or the words depend on what we do
  not reproduce (a body Python canonicalizes differently, an unusual
  repr), it is proxied. Checked against the 1.163 image's own
  `_parse_auth_header` and signedjson.
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
  rejection. Where it escapes decides what was written (write mode,
  `Decision.Raise`): a received or pulled event's state groups are stored
  first (`compute_event_context` runs before auth), then nothing else; a
  pulled prev's raise also fails the event that pulled it, recording no
  failed pull; an outlier's raise, behind missing prevs, is caught as
  "We can't get valid state history." and recorded for the pulled event.
  State resolution raises after bumping the groups and before storing
  any; soft-fail and push after the groups are stored. Push rules run
  for soft-failed events too (the visibility filter comes after them).
  Our "missing auth events" is not one of them (`ErrMissingAuth`): Synapse
  fetches those (`/event_auth`). Nor is our parser refusing a stored
  event, nor a resolution we have not ported: those are plain errors. A
  `RaiseError` must only ever mean "Synapse raises here"; using it for
  "not reproduced" (as soft-fail once did, before `f3ff20c`) would now
  drop events.
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
  But for v2.1 with >1000 chains, forwards reachability must be walked
  batch by batch, as Synapse walks it: a chain an earlier batch reached is
  not walked again, so paths across batches are missed. Which chains share
  a batch is CPython set order (`internal/pyset`). Every multi-batch
  resolution in a big v12 room needs this (46 of 46 sampled, 2026-10-15);
  `testdata/forward_cases.json` is Synapse's own answer on random graphs,
  where 10 of 12 differ from walking every link at once.
- **Signing key lookups at ~0.24/s are normal** (measured 2026-10-14, after
  warm-up from 1.3/s). Servers whose published key response has a short
  validity drop out of the in-memory cache and are re-read from Synapse's
  server_keys_json, one indexed lookup each. Auth failures stayed at ~1/hour.
- **Keys get reissued under the same ID.** A signature failure where the key
  Synapse holds was stored after the event arrived is not evidence of anything.
- **A failing content hash on a stored event is normal** when the event is
  already in its redacted form: Synapse redacts on receipt and stores that.
- **Port against the deployed Synapse, not the checkout.** Since 2026-10-16
  that is 1.163.0 (it was 1.162.0); the `/home/daedric/synapse` checkout
  runs ahead of it. Read the code with `git show v1.163.0:<path>`. On an
  upgrade, diff the two tags for what we port (`event_auth.py`, `state/`,
  `federation_event.py`, `federation_server.py`, `rust/src/push/`, the
  replication endpoints, the schema of the tables we write) and re-dump the
  base push rules from the running Synapse into `internal/push/base_rules.json`
  (`PushRules([]).rules()`). 1.163 added the MSC4075 RTC invite rules behind
  `msc4075_enabled`, which this homeserver turns on. Every experimental flag
  defaults to False, msc4210 included.
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
- **The resolution cache is per process, and so are its group IDs.** Two
  sibling events on the same prevs reuse one group only if one process
  handles both. Our writer drains any origin's staged events with its own
  cache, so Python (or we) may store an identical new group where the
  shadow's cache reused one (2026-10-19, Matrix HQ). Skipped as
  "resolution not cached by Synapse".
- **The shadow waits for prevs; Synapse doesn't.** When some prevs reach the
  timeline only after a PDU, Synapse may have failed to fetch them and
  dropped it, while our snapshot, taken once they came in by other
  transactions, decides to persist (2026-10-19, `!ping12…`). Skipped as
  "prevs arrived after it".
- **A PDU dropped on `/send` can be persisted later, by a pull.** When a
  sender won't divulge a prev, the event is dropped (by us or Synapse
  alike), and a later event's `/get_missing_events` brings it in. The
  shadow then judges the transaction's copy against the pulled one:
  its state may come from a remote's `/state_ids` (stored in full), its
  copy may be pruned for a bad hash (no policy ask), and two prev groups
  may hold identical state (a set-order tie). All three seen in the ping
  room and Matrix HQ on 2026-10-23/24; each is skipped, not a mismatch.
- **Matrix HQ's missing prevs store full groups**: ~13.6k rows each, 364
  in one day (2026-10-14). Synapse's missing-prevs path passes the
  fetched state as `state_ids_before_event`, which never becomes a delta.
- **Policy servers decide soft-fail on receipt** (MSC4284, 75 rooms here,
  2026-10-15). An event without a valid `ed25519:policy_server` signature
  makes Synapse ask the policy server, inside the `/send` request, with a
  30s timeout. Write mode must ask too: without it, spam Synapse soft-fails
  gets through. The stored copy shows what happened (an added signature,
  or `policy_server_spammy`), so the shadow can check without asking.
  It asks anyway (`policy_ask`), signed as us: the operator allows
  contacting policy servers at any time (2026-10-15). About 8% of PDUs in
  policy rooms make Synapse ask (~45/hour).

- **A partial-state resync rewrites what was decided on partial state**
  (`update_state_for_partial_state_event`, `state.py:793`). Main gives each
  such event a new state group and flips its rejection status, so rejections
  made while partial vanish on resync (5 → 0 on a 2026-10-26 join). The
  shadow skips such decisions ("partial state, resynced since"). Rejections
  are logged ("Rejected: failed auth"), as Synapse warns, since afterwards
  the database no longer shows them. A join also brings a burst of outliers
  (~28k for a 20k-state room), from main's resync and from our missing-prevs
  path racing it, as Python's would.

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

- **Server ACLs are big and churn.** Moderation bots post ~800 ACL events a
  day here, of up to 1,600 globs each. One compiled regexp per glob, kept
  by event ID, grew the heap ~45MB/hour (found with pprof, 2026-10-15).
  Now one evaluator per room, replaced when the room's ACL event changes,
  and globs are matched directly; `globToRegex` stays as the test oracle.

- **mautrix's federation client sends no Content-Type.** beta2.matrix.org
  and dommy-mommy.codestorm.net then answer 400 with M_FORBIDDEN, which
  looks exactly like a spam refusal. `policysign` sets application/json, as
  Synapse does. Any new request through mautrix needs the same.

- **Never name a metric label `instance` (or `job`).** Prometheus owns those.
  Ours was renamed to `exported_instance` at scrape time, and every "by
  writer" panel silently grouped by the scrape target. The label is `writer`.

- **Write-mode tests use a throwaway PostgreSQL, never the live one.**
  It holds the live schema and no rows:

      docker run --rm -v /var/sockets:/var/sockets:ro postgres:18-alpine \
        pg_dump --schema-only --no-owner --no-privileges -h /var/sockets -U synapse synapse-db > schema.sql
      docker run -d --name goinbound-testpg --tmpfs /var/lib/postgresql \
        -e POSTGRES_USER=synapse -e POSTGRES_PASSWORD=test -e POSTGRES_DB=synapse \
        -p 127.0.0.1:55432:5432 postgres:18-alpine
      docker exec -i goinbound-testpg psql -q -U synapse -d synapse < schema.sql
      INBOUND_TEST_ADMIN_DSN="host=127.0.0.1 port=55432 user=synapse password=test dbname=synapse" go test ./internal/inbound/

  The tests create the write role from `inbound.Grants` and run as it, so a
  missing grant fails there. `worker_read_write_locks`' triggers run as the
  caller, which is why `worker_read_write_locks_mode` is granted too.

- **The replication bus test uses a throwaway Redis**, never `/var/sockets/keydb`:
  `docker run -d --rm --name goinbound-testredis -p 127.0.0.1:56379:6379 redis:7-alpine`,
  then `ORIGINUP_TEST_REDIS=127.0.0.1:56379 go test ./internal/originup/`.
  A stray RDATA on the live bus would invalidate caches in every process.

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
