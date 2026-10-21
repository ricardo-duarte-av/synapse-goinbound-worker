package fedfetch

import (
	"context"
	"errors"
	"net/http"
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

	// Each attempt gets its own timeout, inside the caller's context.
	n = 0
	_ = retrying(context.Background(), func(actx context.Context) (*http.Response, error) {
		n++
		if dl, ok := actx.Deadline(); !ok || time.Until(dl) > attemptTimeout {
			t.Errorf("attempt %d deadline %v", n, dl)
		}
		return status(http.StatusOK), nil
	})

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
