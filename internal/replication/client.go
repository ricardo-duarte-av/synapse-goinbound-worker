// Package replication speaks Synapse's HTTP replication protocol, as a client.
//
// Only one endpoint is used: fed_send_edu, which is exactly what a Python
// generic worker calls to hand an inbound EDU to the instance that writes its
// stream (FederationHandlerRegistry._send_edu, federation_server.py:1700). The
// writer then runs Synapse's own handler for it -- persisting, notifying,
// validating the sender -- so forwarding is the whole of native EDU handling
// and no EDU logic is reimplemented here.
//
// The wire format is replication/http/_base.py's: POST
// /_synapse/replication/<NAME>/<path args...>/<txn_id>, a JSON body, and the
// shared secret as a Bearer token. The txn_id is what makes a retry safe: the
// writer keeps a 30-minute ResponseCache keyed on it, so the same txn_id is
// processed once however many times it arrives.
package replication

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edutype"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// Client sends replication requests to named Synapse instances.
type Client struct {
	targets map[string]*target
	secret  string
	// sleep is replaced in tests.
	sleep func(context.Context, time.Duration) error
}

type target struct {
	name string
	base string
	http *http.Client
}

// RequestTimeout bounds one replication request. Synapse's replication client
// uses 60s too; an EDU handler that takes longer is stuck, not busy.
const RequestTimeout = 60 * time.Second

// NewClient builds a client for every instance in the instance map.
func NewClient(cfg *synapsecfg.Config) *Client {
	c := &Client{targets: make(map[string]*target), secret: cfg.ReplicationSecret, sleep: sleepCtx}
	for name, inst := range cfg.InstanceMap {
		c.targets[name] = newTarget(inst)
	}
	return c
}

func newTarget(inst synapsecfg.Instance) *target {
	t := &target{name: inst.Name}
	transport := &http.Transport{
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	if inst.Socket != "" {
		sock := inst.Socket
		var d net.Dialer
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", sock)
		}
		// Synapse ignores the host of a replication request.
		t.base = "http://" + inst.Name
	} else {
		t.base = strings.TrimSuffix(inst.URL, "/")
	}
	t.http = &http.Client{Transport: transport, Timeout: RequestTimeout}
	return t
}

// Has reports whether an instance can be reached.
func (c *Client) Has(instance string) bool {
	_, ok := c.targets[canonical(instance)]
	return ok
}

func canonical(name string) string {
	if name == "main" {
		return synapsecfg.MainProcessInstanceName
	}
	return name
}

// HTTPError is a non-2xx answer from the instance.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("replication: HTTP %d: %s", e.Status, e.Body)
}

// Connection errors are retried this many times, with delays doubling from
// one second: replication/http/_base.py's RETRY_ON_CONNECT_ERROR_ATTEMPTS.
const connectRetries = 5

// SendEDU forwards one EDU to instance, as ReplicationFederationSendEduRestServlet
// expects it: {"origin": ..., "content": ...}.
//
// Retries follow _base.py: a timeout is retried after a second, as often as the
// context allows, and a connection failure up to connectRetries times with
// exponential backoff. Both are safe because every attempt carries the same
// txn_id. Any other failure is returned at once.
//
// The stream positions Synapse's own client includes in the body
// (_INT_STREAM_POS) are omitted. They tell the writer to wait until it has
// seen the sender's writes, and this process writes nothing; the server treats
// the key as optional (_base.py:431).
func (c *Client) SendEDU(ctx context.Context, instance, eduType, origin string, content json.RawMessage) error {
	t, ok := c.targets[canonical(instance)]
	if !ok {
		return fmt.Errorf("replication: instance %q is not in instance_map", instance)
	}

	body, err := json.Marshal(struct {
		Origin  string          `json:"origin"`
		Content json.RawMessage `json:"content"`
	}{origin, content})
	if err != nil {
		return fmt.Errorf("replication: encode edu: %w", err)
	}

	url := t.base + "/_synapse/replication/fed_send_edu/" + quote(eduType) + "/" + txnID()

	start := time.Now()
	connectFailures := 0
	for {
		err = c.post(ctx, t, url, body)
		switch {
		case err == nil:
			observe(t.name, eduType, "ok", start)
			return nil
		case ctx.Err() != nil:
			observe(t.name, eduType, "timeout", start)
			return fmt.Errorf("replication: send %s edu to %s: %w", eduType, t.name, ctx.Err())
		case isTimeout(err):
			retries.WithLabelValues(t.name, "timeout").Inc()
			if serr := c.sleep(ctx, time.Second); serr != nil {
				continue // reported by the ctx.Err() case
			}
		case isConnectError(err) && connectFailures < connectRetries:
			retries.WithLabelValues(t.name, "connect").Inc()
			delay := time.Second << connectFailures
			connectFailures++
			if serr := c.sleep(ctx, delay); serr != nil {
				continue
			}
		default:
			observe(t.name, eduType, "error", start)
			return fmt.Errorf("replication: send %s edu to %s: %w", eduType, t.name, err)
		}
	}
}

func (c *Client) post(ctx context.Context, t *target, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// The answer is {} plus stream positions; only the status matters.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return &HTTPError{Status: resp.StatusCode, Body: string(b)}
	}
	return nil
}

// isTimeout matches Synapse's RequestTimedOutError: no answer in time, or a
// 504 from the instance.
func isTimeout(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status == http.StatusGatewayTimeout
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isConnectError matches Synapse's ConnectError: nothing listening, or a socket
// that is not there -- the shape of an instance mid-restart.
func isConnectError(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "dial"
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// quote is Python's urllib.parse.quote(s, safe=""), which _base.py applies to
// every path argument: everything but unreserved characters is escaped.
func quote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z') || ('0' <= ch && ch <= '9') ||
			ch == '_' || ch == '.' || ch == '-' || ch == '~' {
			b.WriteByte(ch)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", ch)
	}
	return b.String()
}

const txnIDLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// txnID is Synapse's random_string(10).
func txnID() string {
	var raw [10]byte
	_, _ = rand.Read(raw[:])
	out := make([]byte, len(raw))
	for i, r := range raw {
		out[i] = txnIDLetters[int(r)%len(txnIDLetters)]
	}
	return string(out)
}

func observe(instance, eduType, result string, start time.Time) {
	sendDuration.WithLabelValues(instance, edutype.Label(eduType), result).Observe(time.Since(start).Seconds())
}

var (
	sendDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "goinbound_replication_send_edu_duration_seconds",
		Help:    "Time to forward one EDU to its stream writer, including retries, by outcome.",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
	}, []string{"writer", "edu_type", "result"})
	retries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_replication_retries_total",
		Help: "Replication requests retried, by instance and reason.",
	}, []string{"writer", "reason"})
)
