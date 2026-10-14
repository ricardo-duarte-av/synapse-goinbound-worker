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

Set by `mode:` in `goinbound-worker.yaml`. They follow the same path as the
gopro worker:

| Mode | Behaviour |
|---|---|
| `proxy` | Forward every request untouched. Nothing is parsed, verified or read. Safe first deploy. |
| `shadow` | Forward every request, then evaluate afterwards what native mode would have done. Counts only; nothing is forwarded. |
| `canary:N` | Serve EDU-only transactions natively for N% of **origins**. Each origin stays on one path. |
| `native` | Serve every eligible EDU-only transaction natively. |

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

## Verifying each step

```promql
# Where transactions go, and why.
sum by (route, reason) (rate(goinbound_requests_total[1h]))

# Shadow: what native would have done, by EDU type and destination ...
sum by (edu_type, action, writer) (increase(goinbound_edus_total{path="shadow"}[1d]))
# ... against what the Python worker actually forwarded (47k/day to av-edu-worker,
# 24k/day to master in October 2026).
sum by (job) (increase(synapse_http_server_requests_received_total{
  server_name="aguiarvieira.pt", servlet="ReplicationFederationSendEduRestServlet"}[1d]))

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

## Not done yet

The PDU shadow verifier from the plan: state resolution, event auth, soft-fail
and push actions, diffed against what Synapse writes. It has not been started.
PDUs are always proxied.
