import json, sys
DS = {"type": "prometheus", "uid": "${datasource}"}
G = 'job=~"$job"'
SY = 'server_name="$synapse_server"'
panels = []
pid = [0]
y = [0]

def nid():
    pid[0] += 1
    return pid[0]

def row(title):
    panels.append({"type": "row", "title": title, "id": nid(), "collapsed": False,
                   "gridPos": {"x": 0, "y": y[0], "w": 24, "h": 1}, "panels": []})
    y[0] += 1

cur = {"x": 0, "h": 0}
def place(w, h):
    if cur["x"] + w > 24:
        y[0] += cur["h"]; cur["x"] = 0; cur["h"] = 0
    pos = {"x": cur["x"], "y": y[0], "w": w, "h": h}
    cur["x"] += w; cur["h"] = max(cur["h"], h)
    return pos

def flush():
    y[0] += cur["h"]; cur["x"] = 0; cur["h"] = 0

def targets(exprs):
    out = []
    for i, (expr, legend) in enumerate(exprs):
        out.append({"datasource": DS, "editorMode": "code", "expr": expr,
                    "legendFormat": legend, "range": True, "refId": chr(65 + i)})
    return out

def stat(title, desc, exprs, unit="short", w=4, decimals=None, thresholds=None):
    fc = {"unit": unit, "color": {"mode": "thresholds"},
          "thresholds": {"mode": "absolute", "steps": thresholds or [{"color": "text", "value": None}]}}
    if decimals is not None:
        fc["decimals"] = decimals
    panels.append({"type": "stat", "title": title, "description": desc, "id": nid(), "datasource": DS,
                   "gridPos": place(w, 4), "fieldConfig": {"defaults": fc, "overrides": []},
                   "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto",
                               "orientation": "auto", "textMode": "auto",
                               "reduceOptions": {"calcs": ["lastNonNull"], "fields": "", "values": False}},
                   "targets": targets(exprs)})

def ts(title, desc, exprs, unit="short", w=12, h=8, stack=False, decimals=None):
    custom = {"drawStyle": "line", "lineWidth": 1, "fillOpacity": 10 if not stack else 40,
              "showPoints": "never", "spanNulls": False,
              "stacking": {"mode": "normal" if stack else "none", "group": "A"}}
    d = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if decimals is not None:
        d["decimals"] = decimals
    panels.append({"type": "timeseries", "title": title, "description": desc, "id": nid(), "datasource": DS,
                   "gridPos": place(w, h), "fieldConfig": {"defaults": d, "overrides": []},
                   "options": {"legend": {"displayMode": "table", "placement": "bottom",
                                          "calcs": ["mean", "max", "lastNotNull"]},
                               "tooltip": {"mode": "multi", "sort": "desc"}},
                   "targets": targets(exprs)})

R = "[$bucket]"

# ---------------------------------------------------------------- Overview
row("Overview")
stat("Transactions/s", "Every /send this worker received, whatever it did with it.",
     [(f'sum(rate(goinbound_requests_total{{{G}}}{R}))', "req/s")], unit="reqps", decimals=2)
stat("Answered natively", "Share of transactions answered here instead of by the Python worker. About 96% is the ceiling on this homeserver; 0 in proxy and shadow mode.",
     [(f'sum(rate(goinbound_requests_total{{{G}, route="native"}}{R})) / sum(rate(goinbound_requests_total{{{G}}}{R}))', "native")],
     unit="percentunit", decimals=1)
stat("Would answer natively", "Shadow mode: share of evaluated transactions native mode would have answered.",
     [(f'sum(rate(goinbound_shadow_decisions_total{{{G}, decision="native"}}{R})) / sum(rate(goinbound_shadow_decisions_total{{{G}}}{R}))', "would")],
     unit="percentunit", decimals=1)
stat("Shadow disagreements (window)", "Transactions we would have answered 200 that Synapse answered otherwise. A 429 is usually Synapse refusing a concurrent transaction, which our own claim would refuse too; anything else deserves a look in the logs.",
     [(f'sum(increase(goinbound_shadow_disagreements_total{{{G}}}{R}))', "disagreements")],
     decimals=0, thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}])
stat("Forward failures (window)", "EDUs that could not be handed to their stream writer. Each fails its transaction with a 500, and the sender retries.",
     [(f'sum(increase(goinbound_replication_send_edu_duration_seconds_count{{{G}, result!="ok"}}{R}))', "failures")],
     decimals=0, thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
stat("Upstream unreachable (window)", "Requests the Python inbound worker could not be reached for.",
     [(f'sum(increase(goinbound_upstream_errors_total{{{G}}}{R}))', "errors")],
     decimals=0, thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
flush()

# ---------------------------------------------------------------- Routing
row("Routing")
ts("Transactions by route and reason", "Where each transaction went (native, proxy, abandoned) and why. Proxy reasons: mode_proxy/mode_shadow (the mode), has_pdus, malformed, limits, auth_failed, origin_in_backoff, canary_not_selected, uncertain, db_error, too_large, not_send.",
   [(f'sum by (route, reason) (rate(goinbound_requests_total{{{G}}}{R}))', "{{route}} {{reason}}")], unit="reqps", stack=True)
ts("Latency by route", "Time to answer, by route. Proxied latency is mostly the Python worker's.",
   [(f'histogram_quantile(0.5, sum by (le, route) (rate(goinbound_request_duration_seconds_bucket{{{G}}}{R})))', "p50 {{route}}"),
    (f'histogram_quantile(0.99, sum by (le, route) (rate(goinbound_request_duration_seconds_bucket{{{G}}}{R})))', "p99 {{route}}")],
   unit="s")
flush()

# ---------------------------------------------------------------- EDUs
row("EDUs")
ts("EDUs by type and action", "Every EDU decided, natively or in shadow: forwarded, dropped as untracked presence, or dropped by a room's server ACL. edu_type=\"other\" is a type Synapse has no handler for; the log names the first of each.",
   [(f'sum by (path, edu_type, action) (rate(goinbound_edus_total{{{G}}}{R}))', "{{path}} {{edu_type}} {{action}}")], unit="ops", stack=True)
ts("EDUs forwarded, by destination instance", "Forwards by stream writer. In shadow, set this beside the Synapse panel below: the counts should match what the Python worker sends.",
   [(f'sum by (path, instance) (rate(goinbound_edus_total{{{G}, action="forward"}}{R}))', "{{path}} → {{instance}}")], unit="ops")
ts("Forward latency", "One EDU handed to its writer over replication, retries included.",
   [(f'histogram_quantile(0.5, sum by (le, instance) (rate(goinbound_replication_send_edu_duration_seconds_bucket{{{G}}}{R})))', "p50 {{instance}}"),
    (f'histogram_quantile(0.99, sum by (le, instance) (rate(goinbound_replication_send_edu_duration_seconds_bucket{{{G}}}{R})))', "p99 {{instance}}")],
   unit="s", w=8)
ts("Forwards by outcome", "ok, error (a non-retryable answer) or timeout (gave up after retrying).",
   [(f'sum by (instance, edu_type, result) (rate(goinbound_replication_send_edu_duration_seconds_count{{{G}}}{R}))', "{{instance}} {{edu_type}} {{result}}")],
   unit="ops", w=8)
ts("Replication retries and ACL removals", "Retries of a forward (timeout or connection refused), and rooms removed from receipt EDUs by server ACL.",
   [(f'sum by (instance, reason) (rate(goinbound_replication_retries_total{{{G}}}{R}))', "retry {{instance}} {{reason}}"),
    (f'sum by (path) (rate(goinbound_receipt_rooms_removed_by_acl_total{{{G}}}{R}))', "receipt rooms removed ({{path}})")],
   unit="ops", w=8)
flush()

# ---------------------------------------------------------------- Shadow
row("Shadow evaluation")
ts("Shadow decisions", "For each transaction Synapse handled, what native mode would have done, and why not when it would have proxied.",
   [(f'sum by (decision, reason) (rate(goinbound_shadow_decisions_total{{{G}}}{R}))', "{{decision}} {{reason}}")], unit="ops", stack=True)
ts("Disagreements and dropped evaluations", "Disagreements by Synapse's status; evaluations dropped because the shadow queue was full.",
   [(f'sum by (synapse_status) (increase(goinbound_shadow_disagreements_total{{{G}}}{R}))', "Synapse answered {{synapse_status}}"),
    (f'sum(increase(goinbound_shadow_dropped_total{{{G}}}{R}))', "dropped")], decimals=0)
flush()

# ---------------------------------------------------------------- Synapse
row("Synapse, for comparison")
ts("Synapse: EDUs received over replication, by writer", "ReplicationFederationSendEduRestServlet on each Synapse instance: every EDU forwarded to it, from the Python worker or from us. Moving to native must not change this.",
   [(f'sum by (job) (rate(synapse_http_server_requests_received_total{{{SY}, servlet="ReplicationFederationSendEduRestServlet"}}{R}))', "{{job}}")], unit="ops", w=8)
ts("Synapse: /send reaching the Python worker", "FederationSendServlet on the Python inbound worker. Falls by ~96% once EDU-only transactions are native.",
   [(f'sum(rate(synapse_http_server_requests_received_total{{job="$synapse_inbound_job", {SY}, servlet="FederationSendServlet"}}{R}))', "Python /send"),
    (f'sum(rate(goinbound_requests_total{{{G}, route="native"}}{R}))', "answered by goinbound")], unit="reqps", w=8)
ts("Synapse: inbound EDUs and PDUs at the Python worker", "What the Python worker still parses.",
   [(f'sum(rate(synapse_federation_server_received_edus_total{{job="$synapse_inbound_job", {SY}}}{R}))', "EDUs"),
    (f'sum(rate(synapse_federation_server_received_pdus_total{{job="$synapse_inbound_job", {SY}}}{R}))', "PDUs")], unit="ops", w=8)
flush()

# ---------------------------------------------------------------- Database
row("Database")
ts("Queries by name and result", "Every query is a primary-key lookup: txn_state once per native transaction, current_server_acl for typing and receipts (cached 5s per room), server_keys on a key-cache miss.",
   [(f'sum by (query, result) (rate(goinbound_db_query_duration_seconds_count{{{G}}}{R}))', "{{query}} {{result}}")], unit="ops", w=8)
ts("Query latency (p99)", "",
   [(f'histogram_quantile(0.99, sum by (le, query) (rate(goinbound_db_query_duration_seconds_bucket{{{G}}}{R})))', "{{query}}")], unit="s", w=8)
ts("ACL lookups by source", "cached, db, error, redacted (a redacted ACL sends the transaction to Synapse).",
   [(f'sum by (source) (rate(goinbound_acl_lookups_total{{{G}}}{R}))', "{{source}}")], unit="ops", w=8)
flush()

# ---------------------------------------------------------------- Process
row("Process: goinbound vs the Python inbound worker")
ts("CPU", "Cores used.",
   [(f'sum(rate(process_cpu_seconds_total{{{G}}}{R}))', "goinbound"),
    (f'sum(rate(process_cpu_seconds_total{{job="$synapse_inbound_job", instance="$synapse_server"}}{R}))', "Python inbound worker")], unit="short", w=8, decimals=3)
ts("Resident memory", "",
   [(f'sum(process_resident_memory_bytes{{{G}}})', "goinbound"),
    (f'sum(process_resident_memory_bytes{{job="$synapse_inbound_job", instance="$synapse_server"}})', "Python inbound worker")], unit="bytes", w=8)
ts("Goroutines and restarts", "Goroutines should track request concurrency, not grow. A restart is a step in process_start_time_seconds.",
   [(f'sum(go_goroutines{{{G}}})', "goroutines"),
    (f'sum(changes(process_start_time_seconds{{{G}}}[$__range]))', "restarts in range")], w=8)
flush()

bucket_opts = ["30s", "1m", "2m", "5m", "10m", "15m", "30m", "1h"]
dash = {
    "title": "Synapse GoInbound Worker",
    "uid": "synapse-goinbound-worker",
    "description": "Front door for inbound /send: EDU-only transactions answered natively, everything else proxied to the Python inbound worker.",
    "tags": ["synapse", "matrix", "federation", "goinbound"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 1,
    "editable": True,
    "graphTooltip": 1,
    "refresh": "30s",
    "time": {"from": "now-6h", "to": "now"},
    "templating": {"list": [
        {"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus", "hide": 0, "refresh": 1},
        {"name": "bucket", "label": "Bucket", "type": "interval", "auto": True, "auto_count": 100, "auto_min": "30s",
         "description": "Range window for rate() and histogram_quantile(). Prometheus scrapes every 15s, so 30s is the floor.",
         "query": ",".join(bucket_opts),
         "options": [{"text": b, "value": b, "selected": b == "5m"} for b in bucket_opts],
         "current": {"text": "5m", "value": "5m"}, "hide": 0, "refresh": 2},
        {"name": "job", "label": "Job", "type": "query", "datasource": DS,
         "query": "label_values(goinbound_requests_total, job)", "refresh": 2, "includeAll": True, "multi": True,
         "current": {"text": "All", "value": "$__all"}, "hide": 0, "sort": 1},
        {"name": "synapse_server", "label": "Synapse server_name", "type": "textbox", "query": "aguiarvieira.pt",
         "current": {"text": "aguiarvieira.pt", "value": "aguiarvieira.pt"}, "hide": 0,
         "description": "server_name label on Synapse's own metrics; the inbound-federation job also scrapes other homeservers."},
        {"name": "synapse_inbound_job", "label": "Python inbound job", "type": "textbox", "query": "inbound-federation",
         "current": {"text": "inbound-federation", "value": "inbound-federation"}, "hide": 0},
    ]},
    "annotations": {"list": []},
    "panels": panels,
}
json.dump(dash, open(sys.argv[1], "w"), indent=2)
print(len(panels), "panels")
