// Package policysign asks a room's policy server to sign an event (MSC4284),
// as Synapse does on receipt of a PDU it has no valid policy signature for.
//
// It ports FederationClient.ask_policy_server_to_sign_event
// (federation/transport/client.py:145) and the checks around it in
// RoomPolicyHandler.ask_policy_server_to_sign_event (handlers/room_policy.py:201).
// Verifying the returned signature is the caller's: it holds the room's key.
package policysign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
)

// Timeout is Synapse's: one attempt, no retries (a request with a timeout is
// never retried, matrixfederationclient.py:850).
const Timeout = 30 * time.Second

// Client asks policy servers, signing each request as our server, with the
// X-Matrix header Synapse's federation client sends.
type Client struct {
	fed *federation.Client
}

// New builds a client signing as serverName with a Synapse-format key line
// ("ed25519 <version> <seed>"). allow, when not nil, is
// federation_domain_whitelist: Synapse refuses any other destination.
func New(serverName, keyLine string, allow func(string) bool) (*Client, error) {
	key, err := federation.ParseSynapseKey(keyLine)
	if err != nil {
		return nil, fmt.Errorf("policysign: signing key: %w", err)
	}
	settings := exhttp.SensibleClientSettings
	settings.GlobalTimeout = Timeout
	c := federation.NewClient(serverName, key, federation.NewInMemoryCache(), settings)
	c.AllowServer = allow
	c.UserAgent = "goinbound-worker"
	return &Client{fed: c}, nil
}

// Refused is an answer that Synapse takes as the policy server refusing the
// event: an error status, or an empty signature.
type Refused struct {
	Status int
	Body   string
}

func (e *Refused) Error() string {
	if e.Status == 0 {
		return "policy server returned no signature"
	}
	return fmt.Sprintf("policy server answered %d: %s", e.Status, e.Body)
}

// Sign POSTs the event (as get_pdu_json gives it) to server's sign
// endpoint, falling back to the unstable one when the stable one is
// unknown, and returns the signatures the answer holds for server, by key
// ID. Synapse adds every one of them to the event. Any error is, for
// Synapse, a refusal.
func (c *Client) Sign(ctx context.Context, server string, event json.RawMessage) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	body, err := c.post(ctx, server, mautrix.BaseURLPath{"_matrix", "policy", "v1", "sign"}, event)
	var ref *Refused
	if errors.As(err, &ref) && unknownEndpoint(ref.Status, []byte(ref.Body)) {
		body, err = c.post(ctx, server, mautrix.BaseURLPath{"_matrix", "policy", "unstable", "org.matrix.msc4284", "sign"}, event)
	}
	if err != nil {
		return nil, err
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("policy server answer: %w", err)
	}
	if len(resp) == 0 {
		return nil, &Refused{}
	}
	// signature.get(server, {}).items(): anything not an object of strings
	// raises, which is a refusal too.
	sigs := map[string]string{}
	if raw, ok := resp[server]; ok {
		if err := json.Unmarshal(raw, &sigs); err != nil {
			return nil, fmt.Errorf("policy server answer for %s: %w", server, err)
		}
	}
	return sigs, nil
}

func (c *Client) post(ctx context.Context, server string, path mautrix.BaseURLPath, event json.RawMessage) ([]byte, error) {
	body, resp, err := c.fed.MakeFullRequest(ctx, federation.RequestParams{
		ServerName:   server,
		Method:       http.MethodPost,
		Path:         path,
		Authenticate: true,
		RequestJSON:  event,
	})
	if resp != nil && resp.StatusCode >= 300 {
		return nil, &Refused{Status: resp.StatusCode, Body: clip(body)}
	}
	return body, err
}

// unknownEndpoint is is_unknown_endpoint (http/client.py:1336).
func unknownEndpoint(status int, body []byte) bool {
	var e struct {
		Errcode string `json:"errcode"`
	}
	_ = json.Unmarshal(body, &e)
	switch status {
	case 404, 405:
		return len(body) == 0 || !bytes.HasPrefix(body, []byte("{")) || e.Errcode == "M_UNRECOGNIZED"
	case 400:
		return e.Errcode == "M_UNRECOGNIZED"
	}
	return false
}

func clip(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}
