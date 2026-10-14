package txn

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"maunium.net/go/mautrix/federation"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/config"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

// shadowRunner works out, after Synapse has answered a transaction, what
// native mode would have done with it. It only counts: nothing is forwarded.
//
// The counts are the evidence for leaving shadow mode. Per destination
// instance and EDU type they can be set beside Synapse's own counters of
// ReplicationFederationSendEduRestServlet on each writer; and a transaction we
// would have answered 200 that Synapse did not is a disagreement worth
// reading.
type shadowRunner struct {
	h       *Handler
	queue   chan shadowJob
	timeout time.Duration
	wg      sync.WaitGroup
}

type shadowJob struct {
	method, requestURI, host string
	header                   http.Header
	body                     []byte
	txnID                    string
	synapseStatus            int
	state                    *prefetch
}

// prefetch reads the transaction's state concurrently with proxying.
//
// It has to start BEFORE Synapse sees the request. Synapse records its answer
// in received_transactions and may reset the origin's backoff, so state read
// afterwards would describe a transaction already handled -- every one of them
// would look like a retry. The origin used is the one the X-Matrix header
// claims, verified later; a request that fails verification is not evaluated
// further, so an unverified claim never decides anything.
type prefetch struct {
	origin string
	done   chan struct{}
	st     store.TxnState
	err    error
}

func newShadowRunner(h *Handler, cfg config.Shadow) *shadowRunner {
	concurrency := cfg.Concurrency
	if concurrency == 0 {
		concurrency = 4
	}
	size := cfg.Queue
	if size == 0 {
		size = 1000
	}
	s := &shadowRunner{h: h, queue: make(chan shadowJob, size), timeout: 30 * time.Second}
	for i := 0; i < concurrency; i++ {
		s.wg.Add(1)
		go s.work()
	}
	return s
}

func (s *shadowRunner) close() {
	close(s.queue)
	s.wg.Wait()
}

// start begins the state read for a request about to be proxied. It returns
// nil when the queue is full: the evaluation would be dropped anyway, and
// skipping the read keeps an overloaded shadow off the database.
func (s *shadowRunner) start(r *http.Request, txnID string) *prefetch {
	if len(s.queue) >= cap(s.queue) {
		return nil
	}
	origin := federation.ParseXMatrixAuth(r.Header.Get("Authorization")).Origin
	if origin == "" {
		return nil
	}
	p := &prefetch{origin: origin, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		p.st, p.err = s.h.store.GetTxnState(ctx, origin, txnID)
	}()
	return p
}

// submit queues an evaluation. It never blocks the request.
func (s *shadowRunner) submit(r *http.Request, body []byte, txnID string, synapseStatus int, p *prefetch) {
	if p == nil {
		shadowDropped.Inc()
		return
	}
	job := shadowJob{
		method:        r.Method,
		requestURI:    r.RequestURI,
		host:          r.Host,
		header:        r.Header.Clone(),
		body:          body,
		txnID:         txnID,
		synapseStatus: synapseStatus,
		state:         p,
	}
	select {
	case s.queue <- job:
	default:
		shadowDropped.Inc()
	}
}

func (s *shadowRunner) work() {
	defer s.wg.Done()
	for job := range s.queue {
		s.evaluate(job)
	}
}

func (s *shadowRunner) evaluate(job shadowJob) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, job.method, "http://"+job.host+job.requestURI, bytes.NewReader(job.body))
	if err != nil {
		shadowDecisions.WithLabelValues("proxy", reasonNotSend).Inc()
		return
	}
	req.Header = job.header
	req.Host = job.host
	req.RequestURI = job.requestURI
	req.ContentLength = int64(len(job.body))

	vr := s.h.verifier.Verify(req)
	if !vr.OK() {
		shadowDecisions.WithLabelValues("proxy", reasonAuth).Inc()
		return
	}
	if vr.Origin != job.state.origin {
		// Verification succeeded for an origin other than the header's
		// claim, which mautrix cannot do; never evaluate on a mismatch.
		shadowDecisions.WithLabelValues("proxy", reasonAuth).Inc()
		return
	}
	if s.h.whitelist != nil && !s.h.whitelist[vr.Origin] {
		shadowDecisions.WithLabelValues("proxy", reasonWhitelist).Inc()
		return
	}

	<-job.state.done
	state := func(context.Context, string, string) (store.TxnState, error) {
		return job.state.st, job.state.err
	}
	d := s.h.decide(ctx, vr.Origin, job.txnID, job.body, false, state)

	switch {
	case d.proxyReason != "":
		shadowDecisions.WithLabelValues("proxy", d.proxyReason).Inc()
	case d.stored != nil:
		// A genuine retry of a transaction Synapse already answered.
		shadowDecisions.WithLabelValues("native", "stored_response").Inc()
	default:
		shadowDecisions.WithLabelValues("native", "ok").Inc()
		edu.Record("shadow", d.steps)
		if job.synapseStatus != http.StatusOK {
			shadowDisagreements.WithLabelValues(strconv.Itoa(job.synapseStatus)).Inc()
			s.h.log.Info().Str("origin", vr.Origin).Str("txn_id", job.txnID).
				Int("synapse_status", job.synapseStatus).
				Msg("Shadow: we would have answered 200, Synapse did not")
		}
	}
}
