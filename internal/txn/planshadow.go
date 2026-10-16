package txn

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The plan shadow: for a PDU transaction from an origin write mode does not
// serve, plan its PDUs as write mode would (PlanPDUs, which writes nothing)
// and count why write mode would still have left it to Synapse. It answers
// "what keeps native mode from serving every transaction?" before native
// mode is switched on. It plans as the request arrives, alongside Synapse,
// so keys Synapse is about to fetch are not yet held, as in write mode.

var planShadow = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "goinbound_pdu_plan_shadow_total",
	Help: "PDU transactions write mode does not serve, by why write mode would have left them to Synapse (ok: it would have served them), or dropped.",
}, []string{"reason"})

const (
	// planShadowConcurrency bounds plans in flight; past it, plans are
	// dropped and counted, never queued behind the request.
	planShadowConcurrency = 4
	planShadowTimeout     = 30 * time.Second
	planShadowOK          = "ok"
	planShadowDropped     = "dropped"
)

// planDry plans a transaction's PDUs in the background, saying whether it
// started.
func (h *Handler) planDry(origin string, body []byte, at time.Time) bool {
	if h.pduServer == nil {
		return false
	}
	select {
	case h.planSem <- struct{}{}:
	default:
		planShadow.WithLabelValues(planShadowDropped).Inc()
		return false
	}
	go func() {
		defer func() { <-h.planSem }()
		_, pdus, reason := classify(body)
		if reason != "" || len(pdus) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), planShadowTimeout)
		defer cancel()
		_, why := h.pduServer.PlanPDUs(ctx, origin, pdus, at)
		if why == "" {
			why = planShadowOK
		} else {
			h.log.Info().Str("origin", origin).Str("reason", why).
				Msg("Plan shadow: write mode would have left this transaction to Synapse")
		}
		planShadow.WithLabelValues(why).Inc()
	}()
	return true
}
