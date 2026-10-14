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

- **No writes to Synapse's data, ever.** `TestEveryQueryIsASelect` enforces it.
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

## Traps

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
