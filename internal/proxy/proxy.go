// Package proxy forwards federation requests to Synapse workers verbatim.
//
// Verbatim is the operative word. A Matrix server-server request carries an
// X-Matrix Authorization header whose signature covers the request URI, so the
// path and query must reach Synapse byte-for-byte as the remote server sent
// them. Room and event IDs are percent-encoded in these paths ("!room%3Aserver",
// "%24event"), and any normalisation or re-encoding along the way invalidates
// the signature and turns every request into a 401.
package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/config"
)

// Result describes the outcome of forwarding one request.
type Result struct {
	// Backend is the name of the upstream that served the request.
	Backend string
	// Status is the HTTP status returned upstream, or 0 if the request failed
	// before a response was received.
	Status int
	// Duration is the time spent waiting on the upstream.
	Duration time.Duration
	// Bytes is the number of response body bytes written to the client.
	Bytes int64
	// Body holds the response body when capture was requested and the body fit
	// within the capture limit. Truncated reports whether it did not.
	Body      []byte
	Truncated bool
	// Canceled reports that the client went away before a response was
	// written. This is routine for federation traffic — remote servers time
	// out and hang up — and is not an error on our side.
	Canceled bool
	// Err is non-nil if the upstream could not be reached.
	Err error
}

// Proxy forwards requests to a pool of Synapse federation workers.
type Proxy struct {
	backends []*backend
	next     atomic.Uint64
	log      zerolog.Logger
}

type backend struct {
	name  string
	host  string
	proxy *httputil.ReverseProxy
}

// New builds a Proxy from the upstream configuration.
func New(cfg config.Upstream, log zerolog.Logger) (*Proxy, error) {
	timeout := cfg.Timeout()
	idle := cfg.MaxIdleConns
	if idle == 0 {
		idle = 32
	}

	p := &Proxy{log: log}

	for _, sock := range cfg.Sockets {
		p.backends = append(p.backends, newBackend(sock, unixHost, unixDialer(sock), timeout, idle, log))
	}
	for _, addr := range cfg.Addrs {
		p.backends = append(p.backends, newBackend(addr, addr, tcpDialer(addr), timeout, idle, log))
	}
	if len(p.backends) == 0 {
		return nil, fmt.Errorf("proxy: no upstreams configured")
	}
	return p, nil
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func unixDialer(path string) dialFunc {
	var d net.Dialer
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return d.DialContext(ctx, "unix", path)
	}
}

func tcpDialer(addr string) dialFunc {
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
}

// unixHost is the synthetic Host used for unix socket upstreams. net/http
// requires a non-empty host in the URL; Synapse ignores the value.
const unixHost = "unix"

func newBackend(name, host string, dial dialFunc, timeout time.Duration, idle int, log zerolog.Logger) *backend {
	b := &backend{name: name, host: host}

	transport := &http.Transport{
		DialContext:           dial,
		MaxIdleConns:          idle,
		MaxIdleConnsPerHost:   idle,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		// Upstreams are plain HTTP over a local socket or link.
		DisableCompression: true,
	}

	b.proxy = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			rewrite(r, host)
		},
		ErrorLog: nil,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Recorded by the caller via Result.Err; suppress the default
			// 502-with-no-context behaviour of ReverseProxy.
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Warn().Err(err).Str("backend", name).Str("uri", r.URL.RequestURI()).
				Msg("Upstream request failed")
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return b
}

// rewrite points the outbound request at the given host while preserving the
// inbound URI exactly.
//
// httputil.ProxyRequest.Out starts as a clone of the inbound request, so
// URL.Path and URL.RawPath already carry the original encoding. We must not
// call SetURL, which joins paths and re-encodes them. Setting only the scheme
// and host leaves URL.EscapedPath() — and therefore the wire URI — untouched.
func rewrite(r *httputil.ProxyRequest, host string) {
	r.Out.URL.Scheme = "http"
	r.Out.URL.Host = host
	r.Out.Host = r.In.Host

	// Defence in depth: the clone should already match, but an explicit copy
	// documents the invariant and survives future refactors.
	r.Out.URL.Path = r.In.URL.Path
	r.Out.URL.RawPath = r.In.URL.RawPath
	r.Out.URL.RawQuery = r.In.URL.RawQuery

	// Synapse authenticates on the Authorization header, which ReverseProxy
	// forwards as an ordinary header. X-Forwarded-For is added by the default
	// Rewrite behaviour only when SetXForwarded is called, which we skip: the
	// signature does not cover headers, but adding fields Synapse may reflect
	// serves no purpose here.
}

// Forward proxies r upstream and writes the response to w.
//
// If captureLimit is greater than zero, up to that many bytes of the response
// body are retained in Result.Body.
func (p *Proxy) Forward(w http.ResponseWriter, r *http.Request, captureLimit int64) Result {
	return p.forward(w, r, captureLimit)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, captureLimit int64) Result {
	b := p.pick()
	rec := &recorder{ResponseWriter: w, limit: captureLimit}

	start := time.Now()
	b.proxy.ServeHTTP(rec, r)
	elapsed := time.Since(start)

	res := Result{
		Backend:   b.name,
		Status:    rec.status,
		Duration:  elapsed,
		Bytes:     rec.written,
		Truncated: rec.truncated,
	}
	if captureLimit > 0 {
		res.Body = rec.buf.Bytes()
	}
	switch {
	case rec.status == 0 && r.Context().Err() != nil:
		// The ErrorHandler deliberately writes nothing when the client has
		// disconnected, so there is no status to report.
		res.Canceled = true
	case rec.status == http.StatusBadGateway && rec.written == 0:
		res.Err = errors.New("upstream unreachable")
	}
	return res
}

func (p *Proxy) pick() *backend {
	if len(p.backends) == 1 {
		return p.backends[0]
	}
	i := p.next.Add(1) - 1
	return p.backends[i%uint64(len(p.backends))]
}

// Backends returns the configured upstream names, for logging and readiness.
func (p *Proxy) Backends() []string {
	names := make([]string, len(p.backends))
	for i, b := range p.backends {
		names[i] = b.name
	}
	return names
}

// recorder wraps a ResponseWriter to observe the status and optionally keep the
// start of the body.
type recorder struct {
	http.ResponseWriter
	status    int
	written   int64
	limit     int64
	buf       bytes.Buffer
	truncated bool
}

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
		r.ResponseWriter.WriteHeader(status)
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.written += int64(n)
	if r.limit > 0 {
		remaining := r.limit - int64(r.buf.Len())
		if remaining <= 0 {
			r.truncated = true
		} else if int64(n) > remaining {
			r.buf.Write(p[:remaining])
			r.truncated = true
		} else {
			r.buf.Write(p[:n])
		}
	}
	return n, err
}

// Flush forwards flushes so streaming responses are not buffered.
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
