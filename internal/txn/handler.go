// Package txn is the front door for PUT /_matrix/federation/v1/send/{txnId}.
//
// Every /send request comes here. A transaction carrying only EDUs -- 96% of
// them on this homeserver, most of those presence that Synapse throws away --
// may be answered here, by forwarding each EDU to the stream writer Synapse
// would forward it to. Everything else goes to the Python inbound worker,
// untouched: transactions with PDUs, anything malformed, anything whose
// handling depends on a detail this worker does not reproduce. The rule
// throughout is that when in doubt, Synapse answers.
//
// Nothing here writes to the database. Synapse's stream writers do every write,
// through the same replication endpoint the Python worker uses.
package txn

import (
	"encoding/json"

	"bytes"
	"context"
	"errors"
	"hash/fnv"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/federation"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/config"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/fedauth"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/proxy"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

// Verifier authenticates an X-Matrix request.
type Verifier interface {
	Verify(r *http.Request) fedauth.Result
}

// Upstream forwards a request to the Python inbound worker.
type Upstream interface {
	Forward(w http.ResponseWriter, r *http.Request, captureLimit int64) proxy.Result
}

// TxnStore reads what decides whether a transaction may be answered here.
type TxnStore interface {
	GetTxnState(ctx context.Context, origin, txnID string) (store.TxnState, error)
}

// PDUSink is the PDU shadow. Prepare is called before the transaction is
// proxied and must not block; the result is committed if Synapse answers 200.
type PDUSink interface {
	Prepare(origin string, txnBody []byte) PDUPending
}

// PDUPending is a transaction's PDUs, prepared.
type PDUPending interface {
	Commit()
	Discard()
}

// PDUServer is write mode's /send side: PlanPDUs checks a transaction's
// PDUs without writing anything, and says when Synapse must answer instead.
type PDUServer interface {
	PlanPDUs(ctx context.Context, origin string, pdus []json.RawMessage, requestTime time.Time) (PDURun, string)
}

// PDURun stages a planned transaction's PDUs, returning each one's entry
// in the answer.
type PDURun interface {
	Run(ctx context.Context) map[string]json.RawMessage
}

// TxnResponses stores the answer given to a transaction
// (set_received_txn_response).
type TxnResponses interface {
	SetTxnResponse(ctx context.Context, origin, txnID string, code int, canonicalJSON []byte) error
}

// OriginUp marks origins in backoff as up (originup.Resetter).
type OriginUp interface {
	// Ready says whether resets currently work.
	Ready() bool
	// Reset marks origin as up, in the background.
	Reset(origin string)
}

// EDUs plans and executes a transaction's EDUs.
type EDUs interface {
	Plan(ctx context.Context, origin string, edus []edu.EDU) ([]edu.Step, error)
	Execute(ctx context.Context, origin string, steps []edu.Step) error
}

// Options builds a Handler.
type Options struct {
	// EDUMode is how EDU-only transactions are served. Transactions with
	// PDUs are always proxied.
	EDUMode config.Mode
	// PDUs, when set, gets every PDU-bearing transaction Synapse answered
	// 200 (modes.pdu: shadow).
	PDUs     PDUSink
	Verifier Verifier
	Upstream Upstream
	Store    TxnStore
	EDUs     EDUs
	// PDUMode and PDUServer are write mode: transactions with PDUs from
	// the origins PDUMode selects are served here. Nil PDUServer proxies
	// them all.
	PDUMode   config.Mode
	PDUServer PDUServer
	// WriteOrigins are served by write mode whatever PDUMode's percentage,
	// EDU-only transactions included.
	WriteOrigins []string
	// Responses, when set, stores every answer given here.
	Responses TxnResponses
	// OriginUp, when set, marks an origin in backoff as up, so its
	// transactions are served here. Nil proxies them.
	OriginUp OriginUp
	// DomainWhitelist is federation_domain_whitelist; nil means none.
	DomainWhitelist map[string]bool
	MaxBody         int64
	ForwardTimeout  time.Duration
	Shadow          config.Shadow
	Log             zerolog.Logger
}

// Handler serves /send.
type Handler struct {
	mode           config.Mode
	verifier       Verifier
	upstream       Upstream
	store          TxnStore
	edus           EDUs
	whitelist      map[string]bool
	maxBody        int64
	forwardTimeout time.Duration
	coord          *coordinator
	shadow         *shadowRunner
	pdus           PDUSink
	pduMode        config.Mode
	pduServer      PDUServer
	writeOrigins   map[string]bool
	responses      TxnResponses
	originUp       OriginUp
	log            zerolog.Logger
	// planSem bounds the plan shadow (planDry).
	planSem chan struct{}
}

// responseCacheTTL is Synapse's _transaction_resp_cache timeout.
const responseCacheTTL = 30 * time.Second

// NewHandler builds a Handler. Store, Verifier and EDUs may be nil in proxy
// mode, which uses none of them.
func NewHandler(o Options) *Handler {
	h := &Handler{
		mode:           o.EDUMode,
		verifier:       o.Verifier,
		upstream:       o.Upstream,
		store:          o.Store,
		edus:           o.EDUs,
		whitelist:      o.DomainWhitelist,
		maxBody:        o.MaxBody,
		forwardTimeout: o.ForwardTimeout,
		coord:          newCoordinator(responseCacheTTL),
		pdus:           o.PDUs,
		pduMode:        o.PDUMode,
		pduServer:      o.PDUServer,
		writeOrigins:   setOf(o.WriteOrigins),
		responses:      o.Responses,
		originUp:       o.OriginUp,
		log:            o.Log,
		planSem:        make(chan struct{}, planShadowConcurrency),
	}
	if h.mode.Kind == config.ModeShadow || h.mode.Kind == config.ModeCanary {
		// In canary mode, the origins not selected are still evaluated.
		h.shadow = newShadowRunner(h, o.Shadow)
	}
	return h
}

// Close stops background work.
func (h *Handler) Close() {
	if h.shadow != nil {
		h.shadow.close()
	}
}

// Reasons a request is proxied that are not about its body. Fixed set, for
// metric labels.
const (
	reasonNotSend    = "not_send"
	reasonModeProxy  = "mode_proxy"
	reasonModeShadow = "mode_shadow"
	reasonTooLarge   = "too_large"
	reasonAuth       = "auth_failed"
	reasonWhitelist  = "not_whitelisted"
	reasonCanary     = "canary_not_selected"
	reasonDBError    = "db_error"
	reasonBackoff    = "origin_in_backoff"
	reasonUncertain  = "uncertain"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &txnRec{start: time.Now(), auth: r.Header.Get("Authorization")}
	defer rec.log(h.log)

	txnID, version, ok := matchSend(r)
	rec.txnID = txnID
	if !ok || version != "v1" || r.Method != http.MethodPut || txnID == "" {
		// Not something we handle: other methods, v2, an undecodable or
		// empty transaction id (Synapse raises on that). Synapse answers.
		h.proxyRaw(w, r, reasonNotSend, rec)
		return
	}
	if h.mode.Kind == config.ModeProxy && h.pdus == nil {
		h.proxyRaw(w, r, reasonModeProxy, rec)
		return
	}

	body, complete, err := readBody(r, h.maxBody)
	if err != nil {
		// The sender went away mid-body. There is nobody to answer.
		rec.route, rec.reason = routeAbandoned, "body_read"
		requests.WithLabelValues(routeAbandoned, "body_read").Inc()
		return
	}
	rec.bodyBytes = len(body)
	if !complete {
		// Too big to buffer: stream it on, read part and all.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		h.proxyRaw(w, r, reasonTooLarge, rec)
		return
	}

	if h.mode.Kind == config.ModeProxy {
		// Buffered only so the PDU shadow can read it.
		h.proxyBody(w, r, body, reasonModeProxy, rec)
		return
	}

	if h.mode.Kind == config.ModeShadow {
		pre := h.shadow.start(r, txnID)
		res := h.proxyBody(w, r, body, reasonModeShadow, rec)
		h.shadow.submit(r, body, txnID, res.Status, pre)
		return
	}

	h.serve(w, r, body, txnID, rec)
}

// serve handles a buffered v1 /send in canary or native mode.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, body []byte, txnID string, rec *txnRec) {
	vr := h.verifier.Verify(withBody(r, body))
	if !vr.OK() {
		// Synapse gives the authoritative 401, or accepts a request we could
		// not verify -- a key server we cannot reach, say. Either way it is
		// Synapse's answer to give.
		h.proxyBody(w, r, body, reasonAuth, rec)
		return
	}
	origin := vr.Origin
	rec.origin = origin

	if h.whitelist != nil && !h.whitelist[origin] {
		h.proxyBody(w, r, body, reasonWhitelist, rec)
		return
	}

	f, ok := h.claim(w, r, origin, txnID, rec)
	if !ok {
		return
	}

	if ans, ok := h.coord.lookup(origin, txnID); ok {
		h.coord.end(origin, f, nil)
		h.write(w, ans, routeNative, "cached", rec)
		return
	}

	d := h.decide(r.Context(), origin, txnID, body, true, h.store.GetTxnState)
	if d.proxyReason == reasonHasPDUs {
		h.planDry(origin, body, time.Now())
	}
	if d.proxyReason == reasonCanary && h.shadow != nil {
		// Not ours to answer, but still evaluated against Synapse's answer,
		// with the transaction's state read before Synapse sees it.
		pre := h.shadow.start(r, txnID)
		res := h.proxyBody(w, r, body, d.proxyReason, rec)
		h.shadow.submit(r, body, txnID, res.Status, pre)
		h.coord.end(origin, f, nil)
		return
	}
	if d.proxyReason != "" {
		h.proxyBody(w, r, body, d.proxyReason, rec)
		h.coord.end(origin, f, nil)
		return
	}
	if d.originDown {
		// As Synapse: on any signed request, before the transaction, and
		// without waiting for it.
		h.originUp.Reset(origin)
	}
	if d.stored != nil {
		ans := answer{status: d.stored.Code, body: d.stored.JSON}
		h.coord.end(origin, f, &ans)
		h.write(w, ans, routeNative, "stored_response", rec)
		return
	}

	edu.Record("native", d.steps)
	rec.steps = d.steps

	// Detached from the sender's connection: Synapse finishes a transaction
	// whose sender hung up, and an EDU forwarded halfway is worse than one
	// forwarded fully or not at all.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), h.forwardTimeout)
	var pduResults map[string]json.RawMessage
	var pending PDUPending
	if d.pdus != nil && h.pdus != nil {
		// The shadow checks what we persist, as it checks Synapse.
		pending = h.pdus.Prepare(origin, body)
	}
	pduDone := make(chan struct{})
	go func() {
		defer close(pduDone)
		if d.pdus != nil {
			pduResults = d.pdus.Run(context.WithoutCancel(r.Context()))
		}
	}()
	err := h.edus.Execute(ctx, origin, d.steps)
	<-pduDone
	cancel()
	if pending != nil {
		pending.Commit()
	}

	if err != nil {
		var fe *edu.ForwardError
		msg := "Error handling EDUs"
		if errors.As(err, &fe) {
			msg = fe.Error()
		}
		// Not remembered: the sender retries, and the retry must be tried
		// again rather than told it failed.
		h.coord.end(origin, f, nil)
		h.write(w, jsonError(http.StatusInternalServerError, "M_UNKNOWN", msg), routeNative, "forward_failed", rec)
		return
	}

	ans := answer{status: http.StatusOK, body: []byte(`{"pdus":{}}`)}
	if len(pduResults) > 0 {
		b, err := canonicaljson.Marshal(map[string]any{"pdus": pduResults})
		if err != nil {
			h.log.Error().Err(err).Msg("Could not encode a transaction answer")
		} else {
			ans.body = b
		}
	}
	if h.responses != nil {
		// set_response: a retry is answered the same, by any process.
		sctx, scancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		if err := h.responses.SetTxnResponse(sctx, origin, txnID, ans.status, ans.body); err != nil {
			h.log.Warn().Err(err).Str("origin", origin).Msg("Could not store a transaction answer")
		}
		scancel()
	}
	h.coord.end(origin, f, &ans)
	h.write(w, ans, routeNative, "ok", rec)
}

// claim takes the origin's one-transaction-at-a-time slot, waiting out a
// concurrent attempt at the same transaction. It answers the request itself
// when it returns false.
func (h *Handler) claim(w http.ResponseWriter, r *http.Request, origin, txnID string, rec *txnRec) (*flight, bool) {
	for {
		own, wait, busy := h.coord.begin(origin, txnID)
		switch {
		case busy:
			h.write(w, jsonError(http.StatusTooManyRequests, "M_UNKNOWN", "Too many concurrent transactions"),
				routeNative, "concurrent_txn", rec)
			return nil, false
		case wait != nil:
			select {
			case <-wait.done:
				continue
			case <-r.Context().Done():
				rec.route, rec.reason = routeAbandoned, "waiting_for_retry"
				requests.WithLabelValues(routeAbandoned, "waiting_for_retry").Inc()
				return nil, false
			}
		default:
			return own, true
		}
	}
}

// decision is what to do with a transaction.
type decision struct {
	// proxyReason is set when Synapse must answer.
	proxyReason string
	// stored is set when Synapse already answered this transaction.
	stored *store.StoredResponse
	// steps is the EDU plan otherwise.
	steps []edu.Step
	// pdus is write mode's plan for the PDUs, if any.
	pdus PDURun
	// originDown is set when the origin is in backoff, so serving the
	// transaction means marking it as up.
	originDown bool
}

// stateFunc reads a transaction's state; see TxnStore.
type stateFunc func(ctx context.Context, origin, txnID string) (store.TxnState, error)

// decide works out whether a verified transaction can be answered here, and
// how. It has no effects. applyCanary is false in shadow mode, which asks what
// native mode would do; shadow mode also supplies state read before Synapse
// saw the request.
func (h *Handler) decide(ctx context.Context, origin, txnID string, body []byte, applyCanary bool, state stateFunc) decision {
	edus, pdus, reason := classify(body)
	if reason != "" {
		return decision{proxyReason: reason}
	}
	if len(pdus) > 0 && (!applyCanary || h.pduServer == nil || !h.pduSelected(origin)) {
		return decision{proxyReason: reasonHasPDUs}
	}
	if applyCanary && h.mode.Kind == config.ModeCanary && !canarySelected(origin, h.mode.CanaryPercent) && !h.writeOrigins[origin] {
		return decision{proxyReason: reasonCanary}
	}

	st, err := state(ctx, origin, txnID)
	if err != nil {
		h.log.Warn().Err(err).Str("origin", origin).Msg("Could not read transaction state; leaving it to Synapse")
		return decision{proxyReason: reasonDBError}
	}
	down := st.RetryLastTS != 0
	if down && (h.originUp == nil || !h.originUp.Ready()) {
		// Synapse resets the backoff of an origin that sends us a signed
		// request, and tells every worker it is back up
		// (transport/server/_base.py:143). Without origin_up, or while it
		// is failing, only Synapse's worker can, so it gets the request.
		return decision{proxyReason: reasonBackoff}
	}
	if st.Previous != nil {
		return decision{stored: st.Previous, originDown: down}
	}

	steps, err := h.edus.Plan(ctx, origin, edus)
	if err != nil {
		if !errors.Is(err, edu.ErrUncertain) {
			h.log.Warn().Err(err).Str("origin", origin).Msg("Could not plan EDUs; leaving the transaction to Synapse")
			return decision{proxyReason: reasonDBError}
		}
		return decision{proxyReason: reasonUncertain}
	}
	d := decision{steps: steps, originDown: down}
	if len(pdus) > 0 {
		run, why := h.pduServer.PlanPDUs(ctx, origin, pdus, time.Now())
		if why != "" {
			return decision{proxyReason: why}
		}
		d.pdus = run
	}
	return d
}

// pduSelected says write mode serves the origin's PDUs.
func (h *Handler) pduSelected(origin string) bool {
	switch h.pduMode.Kind {
	case config.ModeNative:
		return true
	case config.ModeCanary:
		return h.writeOrigins[origin] || canarySelected(origin, h.pduMode.CanaryPercent)
	}
	return false
}

func setOf(l []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range l {
		m[s] = true
	}
	return m
}

// canarySelected picks a stable subset of origins. Selecting by origin rather
// than by request keeps every transaction of one origin on the same path, so
// its transactions are never handled by two processes at once.
func canarySelected(origin string, percent int) bool {
	h := fnv.New32a()
	_, _ = h.Write([]byte(origin))
	return int(h.Sum32()%100) < percent
}

func (h *Handler) proxyRaw(w http.ResponseWriter, r *http.Request, reason string, rec *txnRec) proxy.Result {
	res := h.upstream.Forward(w, r, 0)
	h.recordProxy(res, reason, rec)
	return res
}

func (h *Handler) proxyBody(w http.ResponseWriter, r *http.Request, body []byte, reason string, rec *txnRec) proxy.Result {
	var pending PDUPending
	if h.pdus != nil && hasPDUs(body) {
		// Before Synapse sees it: the shadow snapshots each PDU's room as
		// Synapse is about to find it.
		// The claimed origin: the shadow only checks transactions Synapse
		// accepted, so authenticated ones.
		origin := federation.ParseXMatrixAuth(r.Header.Get("Authorization")).Origin
		pending = h.pdus.Prepare(origin, body)
	}
	res := h.upstream.Forward(w, withBody(r, body), 0)
	h.recordProxy(res, reason, rec)
	if pending != nil {
		if res.Status == http.StatusOK {
			// Synapse took the transaction; its PDUs are on their way
			// through its staging area, and the shadow follows them.
			pending.Commit()
		} else {
			pending.Discard()
		}
	}
	return res
}

func (h *Handler) recordProxy(res proxy.Result, reason string, rec *txnRec) {
	route := routeProxy
	if res.Canceled {
		route = routeAbandoned
	}
	rec.route, rec.reason, rec.status = route, reason, res.Status
	requests.WithLabelValues(route, reason).Inc()
	duration.WithLabelValues(routeProxy).Observe(time.Since(rec.start).Seconds())
	if res.Err != nil {
		upstreamErrors.Inc()
	}
}

func (h *Handler) write(w http.ResponseWriter, ans answer, route, outcome string, rec *txnRec) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ans.status)
	_, _ = w.Write(ans.body)
	rec.route, rec.reason, rec.status = route, outcome, ans.status
	requests.WithLabelValues(route, outcome).Inc()
	duration.WithLabelValues(route).Observe(time.Since(rec.start).Seconds())
}

func jsonError(status int, errcode, msg string) answer {
	b, _ := marshalError(errcode, msg)
	return answer{status: status, body: b}
}

// readBody reads at most limit bytes. complete is false when the body is
// larger, in which case what was read is returned for the caller to replay.
func readBody(r *http.Request, limit int64) (body []byte, complete bool, err error) {
	if r.Body == nil {
		return nil, true, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > limit {
		return b, false, nil
	}
	return b, true, nil
}

// withBody returns r carrying a fresh reader over body. Both verification and
// proxying consume the body, so each gets its own.
func withBody(r *http.Request, body []byte) *http.Request {
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	r2.TransferEncoding = nil
	return r2
}
