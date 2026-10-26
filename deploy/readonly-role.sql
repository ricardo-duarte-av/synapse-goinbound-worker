-- Read-only PostgreSQL role for goinbound-worker.
--
-- The worker creates and repairs this role itself at startup, with
-- homeserver.yaml's credentials (internal/dbrole), unless database.manage_role
-- is false. This file is for doing it by hand instead. The GRANT list must
-- match store.Tables plus pdustore.Tables; TestQueriesReadOnlyListedTables
-- checks it.
--
-- The worker only reads: published server keys, a room's current server ACL,
-- an origin's retry state and Synapse's record of transactions it already
-- answered. Every write it causes is made by Synapse's own stream writers over
-- replication. This role makes "never writes" a guarantee enforced by the
-- database rather than a property of the code.
--
-- Run as a superuser against the Synapse database:
--   psql -h /var/sockets -U synapse -d synapse-db -f readonly-role.sql
--
-- To undo:  DROP OWNED BY goinbound_ro; DROP ROLE goinbound_ro;

BEGIN;

CREATE ROLE goinbound_ro WITH LOGIN;

GRANT CONNECT ON DATABASE "synapse-db" TO goinbound_ro;
GRANT USAGE ON SCHEMA public TO goinbound_ro;

-- Exactly the tables internal/store (EDU path) and internal/pdustore (PDU
-- checker) read.
GRANT SELECT ON
    account_data,
    current_state_events,
    destinations,
    device_lists_remote_cache,
    event_auth,
    event_auth_chain_links,
    event_auth_chains,
    event_edges,
    event_forward_extremities,
    event_json,
    event_push_actions,
    event_relations,
    event_to_state_groups,
    events,
    federation_inbound_events_staging,
    ignored_users,
    local_current_membership,
    partial_state_rooms,
    partial_state_events,
    push_rules,
    push_rules_enable,
    receipts_linearized,
    received_transactions,
    redactions,
    rejections,
    room_ban_redactions,
    room_depth,
    room_memberships,
    rooms,
    server_keys_json,
    server_signature_keys,
    state_group_edges,
    state_groups,
    state_groups_state,
    thread_subscriptions
TO goinbound_ro;

-- Belt and braces: reject writes at the transaction level.
ALTER ROLE goinbound_ro SET default_transaction_read_only = on;

-- Every query is a primary-key lookup; anything slow is wrong.
ALTER ROLE goinbound_ro SET statement_timeout = '10s';

COMMIT;

-- Verify: the first succeeds, the second must fail.
--   psql -h /var/sockets -U goinbound_ro -d synapse-db -c 'select count(*) from destinations;'
--   psql -h /var/sockets -U goinbound_ro -d synapse-db -c 'select count(*) from users;'
