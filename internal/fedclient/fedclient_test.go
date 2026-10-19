package fedclient

import (
	"testing"
	"time"
)

// A response's headers may take the request's whole timeout, as in Synapse:
// mautrix's default of 10s cut off policy servers that sign in 10-30s.
func TestHeadersGetTheRequestTimeout(t *testing.T) {
	for _, d := range []time.Duration{30 * time.Second, 2 * time.Minute} {
		s := clientSettings(d)
		if s.GlobalTimeout != d || s.ResponseHeaderTimeout != d {
			t.Errorf("timeout %s: global %s, response headers %s", d, s.GlobalTimeout, s.ResponseHeaderTimeout)
		}
	}
}
