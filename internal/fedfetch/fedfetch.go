// Package fedfetch pulls events from remote servers for write mode, as
// Synapse's FederationClient does (federation/federation_client.py):
// /get_missing_events, /state_ids, /event and /state, each pulled PDU
// checked like _check_sigs_and_hash_for_pulled_events_and_fetch checks it.
//
// Where Synapse's handling depends on what we do not reproduce -- a key it
// would fetch, a bad signature it would try to fetch a good copy of, a
// content hash it would redact on -- the pull fails with ErrUncertain, and
// the event it was for is left to Synapse's worker.
package fedfetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"maunium.net/go/mautrix/federation"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/keyring"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
)

// ErrUncertain is a pull whose outcome Synapse would decide in a way we do
// not reproduce.
var ErrUncertain = errors.New("fedfetch: not reproducible")

// Pulled is a checked PDU from a remote server: Raw is the copy Synapse
// would hold (event_from_pdu_json, with any policy server signature added),
// Metadata its internal metadata.
type Pulled struct {
	ID       string
	Raw      []byte
	Event    *pdu.Event
	Metadata map[string]any
}

// Client pulls events.
type Client struct {
	fed    *federation.Client
	st     *pdustore.Store
	v      *pduverify.Verifier
	policy pduverify.PolicyAsker
	server string
	keys   *keyring.Keyring
	// OnFailure records a failed pull attempt (record_failure_callback):
	// a pulled event whose signature or content hash failed.
	OnFailure func(ctx context.Context, roomID, eventID, cause string)
}

// How check treats a bad signature: in a batch, look for a good copy
// (_check_sigs_and_hash_and_fetch_one); for one event, fail (get_pdu).
type checkMode int

const (
	batch checkMode = iota
	single
)

// New builds a client over a signed federation client. keys, when not nil,
// finds signing keys Synapse does not hold yet.
func New(fed *federation.Client, st *pdustore.Store, v *pduverify.Verifier, policy pduverify.PolicyAsker, server string, keys *keyring.Keyring) *Client {
	return &Client{fed: fed, st: st, v: v, policy: policy, server: server, keys: keys}
}

// do is MatrixFederationHttpClient's request with Synapse's timeout:
// timeout for one attempt, or, when Synapse's caller gives none (zero), the
// default with its retries.
func (c *Client) do(ctx context.Context, timeout time.Duration, server, method string, path []any, query url.Values, body, out any) error {
	send := func(ctx context.Context) (*http.Response, error) {
		return c.send(ctx, server, method, path, query, body, out)
	}
	if timeout == 0 {
		return retrying(ctx, send)
	}
	_, err := attempt(ctx, timeout, send)
	return err
}

func (c *Client) send(ctx context.Context, server, method string, path []any, query url.Values, body, out any) (*http.Response, error) {
	_, resp, err := c.fed.MakeFullRequest(ctx, federation.RequestParams{
		ServerName:   server,
		Method:       method,
		Path:         federation.URLPath(path),
		Query:        query,
		Authenticate: true,
		RequestJSON:  body,
		ResponseJSON: out,
	})
	return resp, err
}

// Synapse's federation client for a request made without a timeout
// (matrixfederationclient.py _send_request): each attempt gets
// federation.client_timeout (60s), and a send failure, a timeout, a 5xx or a
// 429 is retried up to max_short_retries (3) times, 0.5s·2ⁿ apart, capped at
// max_short_retry_delay (2s), times uniform(0.8, 1.4). homeserver.yaml sets
// none of the three. A request made with a timeout is tried once.
var (
	attemptTimeout = 60 * time.Second
	shortRetries   = 3
	shortDelay     = 500 * time.Millisecond
	maxShortDelay  = 2 * time.Second
)

// retrying runs send as _send_request's retry loop does.
func retrying(ctx context.Context, send func(context.Context) (*http.Response, error)) error {
	for left := shortRetries; ; left-- {
		resp, err := attempt(ctx, attemptTimeout, send)
		if err == nil || left == 0 || ctx.Err() != nil || !retryable(resp) {
			return err
		}
		d := min(shortDelay<<(shortRetries-left), maxShortDelay)
		d = time.Duration(float64(d) * (0.8 + 0.6*rand.Float64()))
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return err
		}
	}
}

// attempt is one try with Synapse's two timeouts: timeout until the response
// arrives (_send_request's timeout_deferred), then timeout again to read its
// body (_handle_response). One deadline over both cut off big bodies:
// Matrix HQ's /state_ids from matrix.org takes over a minute to arrive
// (2026-10-21).
func attempt(ctx context.Context, timeout time.Duration, send func(context.Context) (*http.Response, error)) (*http.Response, error) {
	actx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	t := time.AfterFunc(timeout, func() { cancel(errTimedOut) })
	defer t.Stop()
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { t.Reset(timeout) }}
	return send(httptrace.WithClientTrace(actx, trace))
}

var errTimedOut = errors.New("fedfetch: timed out")

// retryable is RequestSendFailed(can_retry=True): no response at all (a
// connection error, a DNS failure, the attempt timing out), or a 5xx or 429.
// Other statuses, and a body that fails to read after the headers, are not.
func retryable(resp *http.Response) bool {
	return resp == nil || resp.StatusCode >= 500 && resp.StatusCode < 600 || resp.StatusCode == http.StatusTooManyRequests
}

// MissingEvents is get_missing_events: up to limit events between earliest
// and latest, from origin, checked. Synapse asks with a 60s timeout.
func (c *Client) MissingEvents(ctx context.Context, origin, roomID string, rv *pdu.RoomVersion, earliest, latest []string, limit, minDepth int) ([]*Pulled, error) {
	var resp struct {
		Events []json.RawMessage `json:"events"`
	}
	body := map[string]any{"limit": limit, "min_depth": minDepth, "earliest_events": earliest, "latest_events": latest}
	if err := c.do(ctx, 60*time.Second, origin, http.MethodPost, []any{"v1", "get_missing_events", roomID}, nil, body, &resp); err != nil {
		return nil, err
	}
	out := make([]*Pulled, 0, len(resp.Events))
	for _, raw := range resp.Events {
		p, err := c.check(ctx, raw, rv, roomID, origin, batch)
		if err != nil {
			return nil, err
		}
		if p != nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// StateIDs is get_room_state_ids: the state at eventID and its auth chain.
func (c *Client) StateIDs(ctx context.Context, dest, roomID, eventID string) (state, auth []string, err error) {
	var resp struct {
		PDUIDs  json.RawMessage `json:"pdu_ids"`
		AuthIDs json.RawMessage `json:"auth_chain_ids"`
	}
	q := url.Values{"event_id": {eventID}}
	// get_room_state_ids: no timeout.
	if err := c.do(ctx, 0, dest, http.MethodGet, []any{"v1", "state_ids", roomID}, q, nil, &resp); err != nil {
		return nil, nil, err
	}
	// "invalid response from /state_ids" unless both are lists; a list
	// of anything but strings we leave to Synapse.
	if err := json.Unmarshal(resp.PDUIDs, &state); err != nil {
		return nil, nil, fmt.Errorf("%w: /state_ids pdu_ids: %v", ErrUncertain, err)
	}
	if len(resp.AuthIDs) > 0 && string(resp.AuthIDs) != "null" {
		if err := json.Unmarshal(resp.AuthIDs, &auth); err != nil {
			return nil, nil, fmt.Errorf("%w: /state_ids auth_chain_ids: %v", ErrUncertain, err)
		}
	}
	return state, auth, nil
}

// Event is get_pdu from one destination, without a timeout as
// _get_events_and_persist asks: the event, checked, or nil when the server
// does not have it.
func (c *Client) Event(ctx context.Context, dest, eventID, roomID string, rv *pdu.RoomVersion) (*Pulled, error) {
	return c.event(ctx, 0, dest, eventID, roomID, rv)
}

// event is get_pdu with its caller's timeout (zero: none).
func (c *Client) event(ctx context.Context, timeout time.Duration, dest, eventID, roomID string, rv *pdu.RoomVersion) (*Pulled, error) {
	var resp struct {
		PDUs []json.RawMessage `json:"pdus"`
	}
	if err := c.do(ctx, timeout, dest, http.MethodGet, []any{"v1", "event", eventID}, nil, nil, &resp); err != nil {
		return nil, err
	}
	if len(resp.PDUs) == 0 {
		return nil, nil
	}
	p, err := c.check(ctx, resp.PDUs[0], rv, roomID, dest, single)
	if err != nil || p == nil {
		return nil, err
	}
	if p.ID != eventID {
		return nil, fmt.Errorf("%w: asked for %s, got %s", ErrUncertain, eventID, p.ID)
	}
	return p, nil
}

// State is get_room_state: the complete state at eventID and its auth chain,
// checked.
func (c *Client) State(ctx context.Context, dest, roomID, eventID string, rv *pdu.RoomVersion) (auth, state []*Pulled, err error) {
	var resp struct {
		AuthChain []json.RawMessage `json:"auth_chain"`
		PDUs      []json.RawMessage `json:"pdus"`
	}
	q := url.Values{"event_id": {eventID}}
	// get_room_state: no timeout.
	if err := c.do(ctx, 0, dest, http.MethodGet, []any{"v1", "state", roomID}, q, nil, &resp); err != nil {
		return nil, nil, err
	}
	for _, list := range []struct {
		raws []json.RawMessage
		out  *[]*Pulled
	}{{resp.AuthChain, &auth}, {resp.PDUs, &state}} {
		for _, raw := range list.raws {
			p, err := c.check(ctx, raw, rv, roomID, dest, batch)
			if err != nil {
				return nil, nil, err
			}
			if p != nil {
				*list.out = append(*list.out, p)
			}
		}
	}
	return auth, state, nil
}

// check is event_from_pdu_json, then _check_sigs_and_hash_and_fetch_one for
// the outcomes we reproduce: valid signatures and hash, and the policy
// server's verdict. A PDU event_from_pdu_json rejects is dropped (nil).
func (c *Client) check(ctx context.Context, raw []byte, rv *pdu.RoomVersion, roomID, origin string, mode checkMode) (*Pulled, error) {
	if err := pdu.CheckPDUJSON(raw, rv); errors.Is(err, pdu.ErrIgnoredPDU) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	id := ""
	if rv.EventFormat == pdu.FormatV1V2 {
		var v struct {
			EventID string `json:"event_id"`
		}
		_ = json.Unmarshal(raw, &v)
		id = v.EventID
	} else {
		var err error
		if id, err = pdu.CalculateEventID(raw, rv); err != nil {
			return nil, fmt.Errorf("%w: event id: %v", ErrUncertain, err)
		}
	}
	ev, err := pdu.ParseEvent(raw, id, rv, false)
	if err != nil || id == "" {
		return nil, fmt.Errorf("%w: unparseable pulled event", ErrUncertain)
	}
	hashOK, err := pdu.CheckContentHash(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: pulled event %s: content hash: %v", ErrUncertain, id, err)
	}
	lookup := func(server string, keyIDs []string, _ int64) (map[string]pdu.VerifyKey, error) {
		return c.st.VerifyKeys(ctx, server, keyIDs)
	}
	if c.keys != nil {
		lookup = c.keys.Fetch(ctx)
	}
	if err := pdu.CheckSignaturesWith(ev, raw, lookup); err != nil {
		return c.badSignature(ctx, err, ev, id, rv, roomID, origin, mode)
	}
	p := &Pulled{ID: id, Event: ev, Metadata: map[string]any{}}
	if !hashOK {
		// "Event content has been tampered, redacting": recorded, the
		// pruned copy kept, no policy server asked.
		c.failed(ctx, ev.RoomID, id, "Event content has been tampered with")
		pulled, err := pduverify.PulledEvent(raw, "", nil)
		if err == nil {
			p.Raw, err = pdu.Redact(pulled, rv)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUncertain, err)
		}
		p.Metadata["redacted"] = true
		return p, nil
	}
	v, err := c.v.Policy(ctx, raw, ev, c.server)
	if err != nil {
		return nil, err
	}
	if v.Skip != "" {
		return nil, fmt.Errorf("%w: policy: %s", ErrUncertain, v.Skip)
	}
	var sigs map[string]string
	if v.Verdict == pduverify.PolicyAsk {
		if c.policy == nil {
			return nil, fmt.Errorf("%w: policy server not asked", ErrUncertain)
		}
		a := c.v.AskPolicy(ctx, c.policy, raw, time.Now(), rv, v)
		if a.Sigs == nil {
			p.Metadata["soft_failed"] = true
			p.Metadata["policy_server_spammy"] = true
		} else {
			sigs = a.Sigs
		}
	}
	// No request time: any age is dropped.
	if p.Raw, err = pduverify.PulledEvent(raw, v.Server, sigs); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	return p, nil
}

func (c *Client) failed(ctx context.Context, roomID, eventID, cause string) {
	if c.OnFailure != nil {
		c.OnFailure(ctx, roomID, eventID, cause)
	}
}

// badSignature is _check_sigs_and_hash raising InvalidEventSignatureError:
// recorded as a failed pull, then for one event (get_pdu) an error, and in a
// batch a look for a good copy, ours or the sender's server's.
func (c *Client) badSignature(ctx context.Context, err error, ev *pdu.Event, id string, rv *pdu.RoomVersion, roomID, origin string, mode checkMode) (*Pulled, error) {
	var se *pdu.SignatureError
	if !errors.As(err, &se) {
		// A key Synapse would fetch and we could not find.
		return nil, fmt.Errorf("%w: pulled event %s: %v", ErrUncertain, id, err)
	}
	text, ok := se.SynapseText()
	if !ok {
		return nil, fmt.Errorf("%w: pulled event %s: %v", ErrUncertain, id, err)
	}
	c.failed(ctx, ev.RoomID, id, text)
	if mode == single {
		return nil, fmt.Errorf("event id %s: %s", id, text)
	}
	held, _, err := c.st.GetStoredEvents(ctx, []string{id})
	if err != nil {
		return nil, err
	}
	if se := held[id]; se != nil {
		if se.Outlier {
			// Synapse would go on with its stored outlier copy, which
			// _process_pulled_event then refuses; not reproduced.
			return nil, fmt.Errorf("%w: pulled event %s held as an outlier with a bad signature", ErrUncertain, id)
		}
		// Held in the timeline: _process_pulled_events skips it.
		return nil, nil
	}
	sender := ev.Sender
	if i := strings.IndexByte(sender, ':'); i >= 0 {
		sender = sender[i+1:]
	}
	if sender == origin {
		// "Failed to find copy of ... with valid signature": dropped.
		return nil, nil
	}
	// get_pdu(timeout=10000): one attempt. The timeout is the request's;
	// checking what comes back is not bounded by it.
	p, err := c.event(ctx, 10*time.Second, sender, id, roomID, rv)
	if errors.Is(err, ErrUncertain) {
		return nil, err
	}
	if err != nil {
		return nil, nil
	}
	return p, nil
}
