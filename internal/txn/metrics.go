package txn

import (
	"encoding/json"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Routes a request can take.
const (
	routeNative = "native"
	routeProxy  = "proxy"
	// routeAbandoned is a request whose sender went away before it was
	// answered. Routine for federation traffic, and not a failure of ours.
	routeAbandoned = "abandoned"
)

func marshalError(errcode, msg string) ([]byte, error) {
	return json.Marshal(struct {
		ErrCode string `json:"errcode"`
		Error   string `json:"error"`
	}{errcode, msg})
}

var (
	requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_requests_total",
		Help: "Requests by route (native, proxy, abandoned) and outcome or proxy reason.",
	}, []string{"route", "reason"})
	duration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "goinbound_request_duration_seconds",
		Help:    "Time to answer a request, by route.",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120},
	}, []string{"route"})
	upstreamErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goinbound_upstream_errors_total",
		Help: "Requests the Python inbound worker could not be reached for.",
	})

	shadowDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_shadow_decisions_total",
		Help: "Shadow mode: what native mode would have done with each transaction Synapse handled.",
	}, []string{"decision", "reason"})
	shadowDisagreements = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_shadow_disagreements_total",
		Help: "Shadow mode: transactions we would have answered 200 natively that Synapse answered otherwise, by Synapse's status.",
	}, []string{"synapse_status"})
	shadowDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goinbound_shadow_dropped_total",
		Help: "Shadow mode: evaluations dropped because the queue was full.",
	})
)
