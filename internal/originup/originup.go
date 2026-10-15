// Package originup does what Synapse does when a server we had backed off
// sends us a signed request: it marks the server as up
// (Authenticator.reset_retry_timings, transport/server/_base.py:143).
//
// Synapse's worker does three things, in order:
//
//  1. set_destination_retry_timings(origin, None, 0, 0): an upsert into
//     destinations plus an invalidation of get_destination_retry_timings,
//     streamed to every process on the caches stream;
//  2. notify_remote_server_up in its own process;
//  3. REMOTE_SERVER_UP on the replication bus, so every other process
//     (the federation sender above all) wakes the destination.
//
// The first is done by Synapse itself: the admin API's reset_connection
// (rest/admin/federation.py) calls the very same reset_retry_timings on main.
// Writing destinations from here would leave every process's cached timings
// stale, and streaming the invalidation would make us a writer of the caches
// stream, whose persisted position then waits on us (see gofederation's
// state.SetRetryTimings). On main, reset_retry_timings does steps 1 and 2 but
// not 3 (main has no replication client there), so the command is published
// here, exactly as a worker publishes it.
package originup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
)

var resets = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "goinbound_origin_up_total",
	Help: "Origins in backoff marked as up, by outcome: reset (Synapse reset it and REMOTE_SERVER_UP was published), already_up (someone else reset it first), error, publish_error.",
}, []string{"outcome"})

// Publisher publishes one replication command line on a channel.
type Publisher interface {
	Publish(ctx context.Context, channel, line string) error
}

// Options builds a Resetter.
type Options struct {
	// AdminAPI is main's client listener: a unix socket path, or a base URL.
	AdminAPI string
	// AccessToken is an admin user's access token.
	AccessToken string
	// Channel is the replication channel, Synapse's server_name.
	Channel   string
	Publisher Publisher
	Log       zerolog.Logger
}

// Resetter marks origins as up.
type Resetter struct {
	base    string
	http    *http.Client
	token   string
	channel string
	pub     Publisher
	log     zerolog.Logger
	now     func() time.Time

	mu       sync.Mutex
	inflight map[string]bool
	failedAt time.Time
}

// failureHold is how long after a failed reset Ready says no, so that while
// Synapse's worker exists, the transactions go to it and it resets the
// origin instead.
const failureHold = 5 * time.Minute

// requestTimeout bounds one admin call and one publish.
const requestTimeout = 30 * time.Second

// New builds a Resetter.
func New(o Options) *Resetter {
	base := strings.TrimRight(o.AdminAPI, "/")
	client := &http.Client{Timeout: requestTimeout}
	if strings.HasPrefix(o.AdminAPI, "/") {
		sock := o.AdminAPI
		var d net.Dialer
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return d.DialContext(ctx, "unix", sock)
			},
		}
		base = "http://main"
	}
	return &Resetter{base: base, http: client, token: o.AccessToken, channel: o.Channel,
		pub: o.Publisher, log: o.Log, now: time.Now, inflight: map[string]bool{}}
}

// Ready says whether origins in backoff can be served here: false for a
// while after a reset failed.
func (r *Resetter) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failedAt.IsZero() || r.now().Sub(r.failedAt) >= failureHold
}

// Reset marks origin as up, in the background, as Synapse does: the request
// that showed the origin is alive does not wait for it. A reset already
// running for origin is not repeated.
func (r *Resetter) Reset(origin string) {
	r.mu.Lock()
	if r.inflight[origin] {
		r.mu.Unlock()
		return
	}
	r.inflight[origin] = true
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.inflight, origin)
			r.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*requestTimeout)
		defer cancel()
		outcome, err := r.reset(ctx, origin)
		resets.WithLabelValues(outcome).Inc()
		if err != nil {
			r.mu.Lock()
			r.failedAt = r.now()
			r.mu.Unlock()
			r.log.Warn().Err(err).Str("origin", origin).Str("outcome", outcome).Msg("Could not mark an origin as up")
			return
		}
		r.log.Info().Str("origin", origin).Str("outcome", outcome).Msg("Marked origin as up")
	}()
}

func (r *Resetter) reset(ctx context.Context, origin string) (string, error) {
	status, errcode, err := r.adminReset(ctx, origin)
	if err != nil {
		return "error", err
	}
	switch {
	case status == http.StatusOK:
	case status == http.StatusBadRequest && errcode == "M_UNKNOWN":
		// "The retry timing does not need to be reset for this
		// destination": reset since we read it, by whoever reset it, and
		// that process told everyone.
		return "already_up", nil
	default:
		return "error", fmt.Errorf("originup: reset_connection answered %d %s", status, errcode)
	}
	if err := r.pub.Publish(ctx, r.channel, "REMOTE_SERVER_UP "+origin); err != nil {
		return "publish_error", fmt.Errorf("originup: publishing REMOTE_SERVER_UP: %w", err)
	}
	return "reset", nil
}

func (r *Resetter) adminReset(ctx context.Context, origin string) (int, string, error) {
	u := r.base + "/_synapse/admin/v1/federation/destinations/" + url.PathEscape(origin) + "/reset_connection"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader([]byte("{}")))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	return resp.StatusCode, errcodeOf(resp.Body), nil
}

// Check confirms at startup that the token is an admin's, so a wrong one is
// found before the first origin in backoff instead of at it.
func (r *Resetter) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var who struct {
		UserID string `json:"user_id"`
	}
	if err := r.getJSON(ctx, "/_matrix/client/v3/account/whoami", &who); err != nil {
		return err
	}
	var admin struct {
		Admin bool `json:"admin"`
	}
	if err := r.getJSON(ctx, "/_synapse/admin/v1/users/"+url.PathEscape(who.UserID)+"/admin", &admin); err != nil {
		return err
	}
	if !admin.Admin {
		return fmt.Errorf("originup: %s is not a server admin", who.UserID)
	}
	return nil
}

func (r *Resetter) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("originup: GET %s answered %d %s", path, resp.StatusCode, errcodeOf(resp.Body))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(out)
}

func errcodeOf(body io.Reader) string {
	var e struct {
		Errcode string `json:"errcode"`
	}
	if err := json.NewDecoder(io.LimitReader(body, 1<<16)).Decode(&e); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	return e.Errcode
}
