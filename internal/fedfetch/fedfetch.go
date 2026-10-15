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
	"net/http"
	"net/url"
	"time"

	"maunium.net/go/mautrix/federation"

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
}

// New builds a client over a signed federation client.
func New(fed *federation.Client, st *pdustore.Store, v *pduverify.Verifier, policy pduverify.PolicyAsker, server string) *Client {
	return &Client{fed: fed, st: st, v: v, policy: policy, server: server}
}

func (c *Client) do(ctx context.Context, server, method string, path []any, query url.Values, body, out any) error {
	_, _, err := c.fed.MakeFullRequest(ctx, federation.RequestParams{
		ServerName:   server,
		Method:       method,
		Path:         federation.URLPath(path),
		Query:        query,
		Authenticate: true,
		RequestJSON:  body,
		ResponseJSON: out,
	})
	return err
}

// MissingEvents is get_missing_events: up to limit events between earliest
// and latest, from origin, checked. Synapse asks with a 60s timeout.
func (c *Client) MissingEvents(ctx context.Context, origin, roomID string, rv *pdu.RoomVersion, earliest, latest []string, limit, minDepth int) ([]*Pulled, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var resp struct {
		Events []json.RawMessage `json:"events"`
	}
	body := map[string]any{"limit": limit, "min_depth": minDepth, "earliest_events": earliest, "latest_events": latest}
	if err := c.do(ctx, origin, http.MethodPost, []any{"v1", "get_missing_events", roomID}, nil, body, &resp); err != nil {
		return nil, err
	}
	out := make([]*Pulled, 0, len(resp.Events))
	for _, raw := range resp.Events {
		p, err := c.check(ctx, raw, rv, roomID)
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
	if err := c.do(ctx, dest, http.MethodGet, []any{"v1", "state_ids", roomID}, q, nil, &resp); err != nil {
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

// Event is get_pdu from one destination: the event, checked, or nil when the
// server does not have it.
func (c *Client) Event(ctx context.Context, dest, eventID, roomID string, rv *pdu.RoomVersion) (*Pulled, error) {
	var resp struct {
		PDUs []json.RawMessage `json:"pdus"`
	}
	if err := c.do(ctx, dest, http.MethodGet, []any{"v1", "event", eventID}, nil, nil, &resp); err != nil {
		return nil, err
	}
	if len(resp.PDUs) == 0 {
		return nil, nil
	}
	p, err := c.check(ctx, resp.PDUs[0], rv, roomID)
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
	if err := c.do(ctx, dest, http.MethodGet, []any{"v1", "state", roomID}, q, nil, &resp); err != nil {
		return nil, nil, err
	}
	for _, list := range []struct {
		raws []json.RawMessage
		out  *[]*Pulled
	}{{resp.AuthChain, &auth}, {resp.PDUs, &state}} {
		for _, raw := range list.raws {
			p, err := c.check(ctx, raw, rv, roomID)
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
func (c *Client) check(ctx context.Context, raw []byte, rv *pdu.RoomVersion, roomID string) (*Pulled, error) {
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
	if ok, err := pdu.CheckContentHash(raw); err != nil || !ok {
		// Synapse redacts it.
		return nil, fmt.Errorf("%w: pulled event %s fails its content hash", ErrUncertain, id)
	}
	lookup := func(server string, keyIDs []string) (map[string]pdu.VerifyKey, error) {
		return c.st.VerifyKeys(ctx, server, keyIDs)
	}
	if err := pdu.CheckSignatures(ev, raw, lookup); err != nil {
		// A key Synapse would fetch, or a signature it would look for a
		// good copy of.
		return nil, fmt.Errorf("%w: pulled event %s: %v", ErrUncertain, id, err)
	}
	p := &Pulled{ID: id, Event: ev, Metadata: map[string]any{}}
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
