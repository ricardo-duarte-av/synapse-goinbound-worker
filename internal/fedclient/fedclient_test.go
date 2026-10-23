package fedclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A response's headers may take the request's whole timeout, as in Synapse:
// mautrix's default of 10s cut off policy servers that sign in 10-30s. The
// request as a whole may take twice that: the response's, then the body's.
func TestHeadersGetTheRequestTimeout(t *testing.T) {
	for _, d := range []time.Duration{30 * time.Second, 2 * time.Minute} {
		s := clientSettings(d)
		if s.GlobalTimeout != 2*d || s.ResponseHeaderTimeout != d {
			t.Errorf("timeout %s: global %s, response headers %s", d, s.GlobalTimeout, s.ResponseHeaderTimeout)
		}
	}
}

// An attempt gives the response its timeout, then its body the timeout again,
// as _send_request and _handle_response do: a body that takes longer than
// one timeout in all still arrives, while a response that never starts does
// not.
func TestAttemptTimesResponseAndBodySeparately(t *testing.T) {
	const timeout = 300 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow-headers" {
			time.Sleep(2 * timeout)
		} else {
			time.Sleep(timeout * 2 / 3)
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(timeout * 2 / 3)
		_, _ = io.WriteString(w, "{}")
	}))
	defer srv.Close()
	get := func(path string) func(context.Context) (*http.Response, error) {
		return func(ctx context.Context) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			resp, err := srv.Client().Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			_, err = io.ReadAll(resp.Body)
			return resp, err
		}
	}
	if _, err := Attempt(context.Background(), timeout, get("/slow-body")); err != nil {
		t.Errorf("headers then body, each within the timeout: %v", err)
	}
	if resp, err := Attempt(context.Background(), timeout, get("/slow-headers")); err == nil || resp != nil {
		t.Errorf("headers later than the timeout: resp %v, err %v", resp, err)
	}
}
