package txn

import (
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/federation"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edu"
)

// txnRec collects what happened to one request, for the debug log line
// written when it is answered. Metrics carry the same information in
// aggregate; this is for following individual transactions.
type txnRec struct {
	start     time.Time
	txnID     string
	auth      string // the Authorization header, for the claimed origin
	origin    string // set once verified
	bodyBytes int
	route     string
	reason    string
	status    int
	steps     []edu.Step
}

// log writes the request's line at debug level. It costs nothing more than a
// level check when debug is off.
func (r *txnRec) log(l zerolog.Logger) {
	e := l.Debug()
	if !e.Enabled() {
		return
	}
	origin, verified := r.origin, true
	if origin == "" {
		origin, verified = federation.ParseXMatrixAuth(r.auth).Origin, false
	}
	e = e.Str("route", r.route).Str("reason", r.reason).Int("status", r.status).
		Str("origin", origin).Bool("verified", verified).Str("txn_id", r.txnID).
		Int("body_bytes", r.bodyBytes).
		Float64("ms", float64(time.Since(r.start).Microseconds())/1000)
	if len(r.steps) > 0 {
		e = e.Str("edus", summarize(r.steps))
	}
	e.Msg("Transaction")
}

// summarize renders a plan compactly, in order of first appearance:
//
//	m.presence:drop_presence_untracked=3 m.typing:forward@av-edu-worker=1
func summarize(steps []edu.Step) string {
	var keys []string
	counts := make(map[string]int)
	for _, s := range steps {
		k := s.Type + ":" + string(s.Action)
		if s.Instance != "" {
			k += "@" + s.Instance
		}
		if counts[k] == 0 {
			keys = append(keys, k)
		}
		counts[k]++
	}
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(counts[k]))
	}
	return b.String()
}
