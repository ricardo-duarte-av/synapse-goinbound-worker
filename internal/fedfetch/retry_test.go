package fedfetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A request Synapse makes without a timeout: a send failure, a 5xx or a 429
// is tried again, up to three more times; anything else is not.
func TestRetryingAsSynapsesShortRetries(t *testing.T) {
	defer func(d, m time.Duration) { shortDelay, maxShortDelay = d, m }(shortDelay, maxShortDelay)
	shortDelay, maxShortDelay = time.Millisecond, 4*time.Millisecond

	fail := errors.New("failed")
	status := func(code int) *http.Response { return &http.Response{StatusCode: code} }
	cases := []struct {
		name     string
		resp     *http.Response
		attempts int
	}{
		{"no response (timeout, connection, DNS)", nil, 4},
		{"502", status(http.StatusBadGateway), 4},
		{"429", status(http.StatusTooManyRequests), 4},
		{"404", status(http.StatusNotFound), 1},
		{"403", status(http.StatusForbidden), 1},
	}
	for _, c := range cases {
		n := 0
		err := retrying(context.Background(), func(context.Context) (*http.Response, error) {
			n++
			return c.resp, fail
		})
		if n != c.attempts || !errors.Is(err, fail) {
			t.Errorf("%s: %d attempts (want %d), err %v", c.name, n, c.attempts, err)
		}
	}

	// Success on a later attempt ends it.
	n := 0
	err := retrying(context.Background(), func(context.Context) (*http.Response, error) {
		if n++; n < 3 {
			return nil, fail
		}
		return status(http.StatusOK), nil
	})
	if n != 3 || err != nil {
		t.Errorf("recovering: %d attempts, err %v", n, err)
	}

	// An attempt that never answers is cut off after attemptTimeout, and
	// tried again.
	defer func(d time.Duration) { attemptTimeout = d }(attemptTimeout)
	attemptTimeout = 20 * time.Millisecond
	n = 0
	start := time.Now()
	err = retrying(context.Background(), func(actx context.Context) (*http.Response, error) {
		n++
		<-actx.Done()
		return nil, actx.Err()
	})
	if n != 4 || err == nil || time.Since(start) < 4*attemptTimeout {
		t.Errorf("hanging: %d attempts in %v, err %v", n, time.Since(start), err)
	}

	// The caller giving up stops the retries.
	ctx, cancel := context.WithCancel(context.Background())
	n = 0
	_ = retrying(ctx, func(context.Context) (*http.Response, error) {
		n++
		cancel()
		return nil, fail
	})
	if n != 1 {
		t.Errorf("cancelled: %d attempts", n)
	}
}

// An attempt gives the response its timeout, then its body the timeout again,
// as _send_request and _handle_response do: a body that takes longer than
// one timeout in all still arrives, while a response that never starts does
// not.
func TestAttemptTimesHeadersAndBodySeparately(t *testing.T) {
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
	if _, err := attempt(context.Background(), timeout, get("/slow-body")); err != nil {
		t.Errorf("headers then body, each within the timeout: %v", err)
	}
	if resp, err := attempt(context.Background(), timeout, get("/slow-headers")); err == nil || resp != nil {
		t.Errorf("headers later than the timeout: resp %v, err %v", resp, err)
	}
}
