package txn

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edu"
)

// sendPath matches FederationSendServlet's PATH, "/send/(?P<transaction_id>[^/]*)/?",
// under the federation prefix (transport/server/federation.py:80).
//
// Synapse registers it under v1 only. v2 is matched as well so that nginx can
// send both here; a v2 request is proxied unparsed, so Synapse gives whatever
// answer it gives today.
var sendPath = regexp.MustCompile(`^/_matrix/federation/(v1|v2)/send/([^/]*)/?$`)

// matchSend returns the transaction id of a v1 /send request.
//
// The match is against the path exactly as the client sent it, before any
// decoding, which is how Synapse's router matches too: it applies the regex to
// the raw path and then unquotes each group.
func matchSend(r *http.Request) (txnID string, version string, ok bool) {
	raw := r.RequestURI
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	m := sendPath.FindStringSubmatch(raw)
	if m == nil {
		return "", "", false
	}
	id, err := url.PathUnescape(m[2])
	if err != nil {
		return "", m[1], false
	}
	return id, m[1], true
}

// Synapse's transaction limits (federation_server.py:337).
const (
	maxPDUs = 50
	maxEDUs = 100
)

// Reasons a transaction is not EDU-only in a form we can handle. Each is a
// metric label, so the set is fixed.
const (
	reasonMalformed = "malformed"
	reasonHasPDUs   = "has_pdus"
	reasonLimits    = "limits"
)

// classify returns the EDUs of an EDU-only transaction, or why the
// transaction must go to Synapse instead.
//
// Anything Synapse would reject, or whose handling depends on details this
// worker does not reproduce, is "malformed" here: Synapse gives the right
// answer to it, so it gets the request. That includes a body that is not a
// JSON object, "pdus" or "edus" that are not lists, and an EDU without a
// string edu_type or with content that is not an object.
func classify(body []byte) ([]edu.EDU, string) {
	var txn struct {
		PDUs json.RawMessage `json:"pdus"`
		EDUs json.RawMessage `json:"edus"`
	}
	if !isObject(body) {
		return nil, reasonMalformed
	}
	if err := json.Unmarshal(body, &txn); err != nil {
		return nil, reasonMalformed
	}

	// Absent or null is an empty list (units.py:101 _none_to_list).
	var pdus, edus []json.RawMessage
	if !isNull(txn.PDUs) {
		if err := json.Unmarshal(txn.PDUs, &pdus); err != nil {
			return nil, reasonMalformed
		}
	}
	if !isNull(txn.EDUs) {
		if err := json.Unmarshal(txn.EDUs, &edus); err != nil {
			return nil, reasonMalformed
		}
	}

	if len(pdus) > maxPDUs || len(edus) > maxEDUs {
		return nil, reasonLimits
	}
	if len(pdus) > 0 {
		return nil, reasonHasPDUs
	}

	out := make([]edu.EDU, 0, len(edus))
	for _, raw := range edus {
		var e struct {
			Type    *string         `json:"edu_type"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(raw, &e); err != nil || e.Type == nil || !isObject(e.Content) {
			return nil, reasonMalformed
		}
		out = append(out, edu.EDU{Type: *e.Type, Content: e.Content})
	}
	return out, ""
}

func isNull(b json.RawMessage) bool {
	b = bytes.TrimSpace(b)
	return len(b) == 0 || bytes.Equal(b, []byte("null"))
}

func isObject(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '{'
}
