// Package config loads the goinbound-worker configuration.
//
// Only what is ours lives here: where to listen, which Python worker to proxy
// to, and how far along the proxy -> shadow -> canary -> native path the EDU
// handling is. Everything Synapse already knows -- stream writers, the
// instance map, the replication secret, the database -- is read from
// homeserver.yaml by package synapsecfg and is deliberately not repeated.
package config

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode selects how EDU-only transactions are served.
type Mode struct {
	// Kind is one of "proxy", "shadow", "canary", "native".
	Kind string
	// CanaryPercent is the percentage of ORIGINS served natively when Kind is
	// "canary". Ignored otherwise.
	CanaryPercent int
}

const (
	// ModeProxy forwards every request to Synapse untouched. Nothing is
	// parsed, verified or read from the database.
	ModeProxy = "proxy"
	// ModeShadow forwards every request to Synapse, and afterwards works out
	// what native handling would have done, for metrics only.
	ModeShadow = "shadow"
	// ModeCanary serves EDU-only transactions natively for a stable subset
	// of origins and proxies the rest.
	ModeCanary = "canary"
	// ModeNative serves every eligible EDU-only transaction natively.
	ModeNative = "native"
)

// UnmarshalYAML accepts a bare mode name ("proxy") or a canary specification
// ("canary:5").
func (m *Mode) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	return m.parse(raw)
}

func (m *Mode) parse(raw string) error {
	kind, pct, hasPct := strings.Cut(raw, ":")
	kind = strings.TrimSpace(kind)

	switch kind {
	case ModeProxy, ModeShadow, ModeNative:
		if hasPct {
			return fmt.Errorf("mode %q does not take a percentage", kind)
		}
		m.Kind, m.CanaryPercent = kind, 0
		return nil
	case ModeCanary:
		if !hasPct {
			return fmt.Errorf("mode %q requires a percentage, e.g. %q", kind, "canary:5")
		}
		n, err := strconv.Atoi(strings.TrimSpace(pct))
		if err != nil {
			return fmt.Errorf("invalid canary percentage %q: %w", pct, err)
		}
		if n < 0 || n > 100 {
			return fmt.Errorf("canary percentage must be 0-100, got %d", n)
		}
		m.Kind, m.CanaryPercent = kind, n
		return nil
	default:
		return fmt.Errorf("unknown mode %q", raw)
	}
}

func (m Mode) String() string {
	if m.Kind == ModeCanary {
		return fmt.Sprintf("canary:%d", m.CanaryPercent)
	}
	return m.Kind
}

// ServesNatively reports whether any transaction can be answered by us.
func (m Mode) ServesNatively() bool { return m.Kind == ModeCanary || m.Kind == ModeNative }

// Modes is the serving mode of each kind of payload.
type Modes struct {
	// EDU is how EDU-only transactions are served: proxy, shadow, canary:N
	// or native.
	EDU Mode `yaml:"edu"`
	// PDU is how transactions carrying any PDU are served: proxy sends them
	// to the Python worker whole, EDUs included; shadow also checks each
	// PDU afterwards against what Synapse decided; canary:N and native are
	// write mode (docs/write-mode.md), for N% of origins or all of them,
	// with the shadow still checking every PDU. Write mode needs write.
	PDU Mode `yaml:"pdu"`
}

// Config is the top-level worker configuration.
type Config struct {
	// HomeserverYAML is Synapse's homeserver.yaml, mounted read-only.
	HomeserverYAML string `yaml:"homeserver_yaml"`

	Listen   Listen   `yaml:"listen"`
	Upstream Upstream `yaml:"upstream"`
	Metrics  Metrics  `yaml:"metrics"`
	Log      Log      `yaml:"log"`
	Database Database `yaml:"database"`
	Auth     Auth     `yaml:"auth"`
	EDU      EDU      `yaml:"edu"`
	Shadow   Shadow   `yaml:"shadow"`
	// PDUShadow tunes modes.pdu: shadow.
	PDUShadow PDUShadow `yaml:"pdu_shadow"`
	// Write configures write mode (modes.pdu canary:N or native).
	Write Write `yaml:"write"`

	// Modes says, per kind of payload, whether it is proxied, shadowed or
	// served here. Both are required: what goes where is spelled out, never
	// implied.
	Modes Modes `yaml:"modes"`

	// LegacyMode is the old single `mode:` key, kept only to refuse it with
	// a message that says what to write instead.
	LegacyMode *string `yaml:"mode"`

	// MaxBodyMB bounds a transaction body we buffer. Synapse caps a
	// transaction at 50 PDUs and 100 EDUs, and a PDU at 64KiB, so a
	// legitimate body is at most a few MB. A body over this limit is still
	// proxied, streamed, without being parsed. Zero uses 16.
	MaxBodyMB int `yaml:"max_body_mb"`
}

// Listen is where this worker accepts federation traffic from nginx.
type Listen struct {
	// Socket is a unix socket path. Exactly one of Socket and Addr is set.
	Socket string `yaml:"socket"`
	// Addr is a TCP host:port.
	Addr string `yaml:"addr"`
	// SocketMode is the socket's permission bits, in octal. Default "0660".
	SocketMode string `yaml:"socket_mode"`
}

// ParsedSocketMode returns SocketMode as file permission bits.
func (l Listen) ParsedSocketMode() (os.FileMode, error) {
	n, err := strconv.ParseUint(l.SocketMode, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("listen: socket_mode %q is not an octal mode: %w", l.SocketMode, err)
	}
	return os.FileMode(n), nil
}

// Upstream is the Python inbound federation worker. It remains the only
// processor of PDUs, and the fallback for anything we do not handle.
type Upstream struct {
	Sockets []string `yaml:"sockets"`
	Addrs   []string `yaml:"addrs"`
	// TimeoutSeconds bounds waiting for response headers. A transaction with
	// PDUs that need missing events fetched can legitimately take a minute.
	// Zero uses 180.
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// MaxIdleConns per upstream. Zero uses 32.
	MaxIdleConns int `yaml:"max_idle_conns"`
}

// Timeout returns TimeoutSeconds with its default applied.
func (u Upstream) Timeout() time.Duration {
	if u.TimeoutSeconds == 0 {
		return 180 * time.Second
	}
	return time.Duration(u.TimeoutSeconds) * time.Second
}

// Metrics is the Prometheus listener.
type Metrics struct {
	Addr string `yaml:"addr"`
}

// Log configures zerolog.
type Log struct {
	Level  string `yaml:"level"`
	Pretty bool   `yaml:"pretty"`
}

// Database describes access to Synapse's PostgreSQL database.
//
// Everything this worker does is a read: published server keys, the room's
// current server ACL, the origin's retry state and Synapse's record of
// transactions it already answered. It serves as a dedicated read-only role,
// checked on every start and -- unless ManageRole is false -- created or
// repaired with homeserver.yaml's credentials when it is missing or lacks
// something.
type Database struct {
	// Role is the read-only role served with. Default "goinbound_ro".
	Role string `yaml:"role"`
	// ManageRole lets the worker create or repair Role at startup, connecting
	// with homeserver.yaml's credentials. Default true. With false, a role
	// that is missing or lacks a grant stops the worker; create it with
	// deploy/readonly-role.sql.
	ManageRole *bool `yaml:"manage_role"`
	// DSN is how to reach PostgreSQL as Role; any user it names is replaced
	// by Role. Empty uses homeserver.yaml's connection.
	//
	// It must reach PostgreSQL itself, or a pooler that knows Role. This
	// deployment's homeserver.yaml goes through pgcat, which only accepts the
	// users in its own config, so set this to the unix socket:
	//   host=/var/sockets dbname=synapse-db
	DSN string `yaml:"dsn"`
	// MaxConns bounds the pool. Zero uses 4.
	MaxConns int `yaml:"max_conns"`
	// ConnectTimeoutSeconds bounds the initial connection. Zero uses 10.
	ConnectTimeoutSeconds int `yaml:"connect_timeout_seconds"`
	// QueryTimeoutSeconds bounds a single query on the request path. Zero
	// uses 5. A query that times out sends the transaction to Synapse.
	QueryTimeoutSeconds int `yaml:"query_timeout_seconds"`
}

// RoleName returns Role with its default applied.
func (d Database) RoleName() string {
	if d.Role == "" {
		return "goinbound_ro"
	}
	return d.Role
}

// ManagesRole returns ManageRole with its default applied.
func (d Database) ManagesRole() bool { return d.ManageRole == nil || *d.ManageRole }

// QueryTimeout returns QueryTimeoutSeconds with its default applied.
func (d Database) QueryTimeout() time.Duration {
	if d.QueryTimeoutSeconds == 0 {
		return 5 * time.Second
	}
	return time.Duration(d.QueryTimeoutSeconds) * time.Second
}

// Auth tunes X-Matrix request verification.
//
// No signing key is needed: verifying an incoming request uses the remote
// server's published keys. This worker never handles the homeserver's private
// key.
type Auth struct {
	// KeyRefetchMinutes is the minimum delay before re-querying a server
	// whose key fetch failed. Zero uses 60.
	KeyRefetchMinutes int `yaml:"key_refetch_minutes"`
	// TimeoutSeconds bounds a key fetch. Zero uses 30.
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// TrustedKeyServers overrides Synapse's trusted_key_servers. Leave it
	// unset: if the two disagree, a server Synapse can verify through a
	// notary is one we cannot.
	TrustedKeyServers []string `yaml:"trusted_key_servers"`
}

// EDU tunes forwarding EDUs to their stream writers.
type EDU struct {
	// ForwardTimeoutSeconds bounds forwarding all the EDUs of one
	// transaction, including retries. It is detached from the remote's
	// connection: Synapse keeps processing a transaction whose sender hung
	// up, and so do we. Zero uses 60.
	ForwardTimeoutSeconds int `yaml:"forward_timeout_seconds"`
}

// ForwardTimeout returns ForwardTimeoutSeconds with its default applied.
func (e EDU) ForwardTimeout() time.Duration {
	if e.ForwardTimeoutSeconds == 0 {
		return 60 * time.Second
	}
	return time.Duration(e.ForwardTimeoutSeconds) * time.Second
}

// Shadow tunes the after-the-fact evaluation done in shadow mode.
type Shadow struct {
	// Concurrency bounds simultaneous evaluations. Zero uses 4.
	Concurrency int `yaml:"concurrency"`
	// Queue bounds evaluations waiting for a slot. An evaluation that does
	// not fit is dropped and counted, never allowed to slow the proxy. Zero
	// uses 1000.
	Queue int `yaml:"queue"`
}

// PDUShadow tunes the PDU shadow.
type PDUShadow struct {
	// Concurrency bounds PDUs checked at once. Zero uses 2.
	Concurrency int `yaml:"concurrency"`
	// Queue bounds PDUs waiting to be checked. Zero uses 1000.
	Queue int `yaml:"queue"`
	// MaxWaitSeconds bounds waiting for Synapse to persist a PDU. Zero
	// uses 300.
	MaxWaitSeconds int `yaml:"max_wait_seconds"`
	// MaxConns bounds the PDU checker's own database pool. Zero uses 4.
	MaxConns int `yaml:"max_conns"`
	// PrevWaitSeconds bounds waiting for a PDU's prev events to be
	// persisted before snapshotting its room for soft-fail and push.
	// Zero uses 60.
	PrevWaitSeconds int `yaml:"prev_wait_seconds"`
	// StateCacheEntries bounds the state group cache, in state entries
	// (about 210 bytes each). Zero uses 400000 (~85MB).
	StateCacheEntries int `yaml:"state_cache_entries"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parse(data)
}

func parse(data []byte) (*Config, error) {
	cfg := &Config{
		HomeserverYAML: "/etc/synapse/homeserver.yaml",
		Listen:         Listen{SocketMode: "0660"},
		Metrics:        Metrics{Addr: ":9200"},
		Log:            Log{Level: "info"},
	}

	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.HomeserverYAML == "" {
		return fmt.Errorf("homeserver_yaml is required")
	}
	if (c.Listen.Socket == "") == (c.Listen.Addr == "") {
		return fmt.Errorf("listen: exactly one of socket or addr must be set")
	}
	if c.Listen.SocketMode == "" {
		c.Listen.SocketMode = "0660"
	}
	if _, err := c.Listen.ParsedSocketMode(); err != nil {
		return err
	}
	if len(c.Upstream.Sockets) == 0 && len(c.Upstream.Addrs) == 0 {
		return fmt.Errorf("upstream: at least one of sockets or addrs must be set")
	}
	for _, n := range []struct {
		name string
		v    int
	}{
		{"upstream.timeout_seconds", c.Upstream.TimeoutSeconds},
		{"upstream.max_idle_conns", c.Upstream.MaxIdleConns},
		{"database.max_conns", c.Database.MaxConns},
		{"database.connect_timeout_seconds", c.Database.ConnectTimeoutSeconds},
		{"database.query_timeout_seconds", c.Database.QueryTimeoutSeconds},
		{"auth.key_refetch_minutes", c.Auth.KeyRefetchMinutes},
		{"auth.timeout_seconds", c.Auth.TimeoutSeconds},
		{"edu.forward_timeout_seconds", c.EDU.ForwardTimeoutSeconds},
		{"shadow.concurrency", c.Shadow.Concurrency},
		{"shadow.queue", c.Shadow.Queue},
		{"pdu_shadow.concurrency", c.PDUShadow.Concurrency},
		{"pdu_shadow.queue", c.PDUShadow.Queue},
		{"pdu_shadow.max_wait_seconds", c.PDUShadow.MaxWaitSeconds},
		{"pdu_shadow.max_conns", c.PDUShadow.MaxConns},
		{"max_body_mb", c.MaxBodyMB},
	} {
		if n.v < 0 {
			return fmt.Errorf("%s must not be negative", n.name)
		}
	}
	if c.LegacyMode != nil {
		return fmt.Errorf("the `mode:` key is gone; say what each payload does instead:\n"+
			"  modes:\n    edu: %s   # proxy | shadow | canary:N | native\n    pdu: proxy", *c.LegacyMode)
	}
	if c.Modes.EDU.Kind == "" {
		return fmt.Errorf("modes.edu is required: one of proxy, shadow, canary:N, native")
	}
	if c.Modes.PDU.Kind == "" {
		return fmt.Errorf("modes.pdu is required: one of proxy, shadow, canary:N, native")
	}
	switch {
	case c.Modes.PDU.Kind == ModeNative && c.Modes.EDU.Kind != ModeNative:
		return fmt.Errorf("modes.pdu is native, so modes.edu must be native too: " +
			"a write-mode origin's every transaction is ours")
	case len(c.Write.Origins) > 0 && !c.Modes.PDU.ServesNatively():
		return fmt.Errorf("write.origins is set, but modes.pdu is %s; write origins need modes.pdu canary:N (0 for only them) or native", c.Modes.PDU)
	case c.Modes.PDU.Kind == ModeCanary && !(c.Modes.EDU.Kind == ModeNative ||
		c.Modes.EDU.Kind == ModeCanary && c.Modes.EDU.CanaryPercent >= c.Modes.PDU.CanaryPercent):
		return fmt.Errorf("modes.pdu is %s, so modes.edu must be canary:%d or more, or native: "+
			"a write-mode origin's every transaction is ours", c.Modes.PDU, c.Modes.PDU.CanaryPercent)
	}
	if m := c.Write.MissingEvents; m != "" && m != "defer" && m != "fetch" {
		return fmt.Errorf("write.missing_events is %q; it must be defer or fetch", m)
	}
	if d := c.Write.TestDropPDUs; d != nil {
		switch {
		case !slices.Contains(c.Write.Origins, d.Origin):
			return fmt.Errorf("write.test_drop_pdus: origin %q is not in write.origins; only a server we control may be given a gap", d.Origin)
		case d.Room == "" || d.Count <= 0:
			return fmt.Errorf("write.test_drop_pdus needs a room and a count above 0")
		case !c.Write.FetchesMissingEvents():
			return fmt.Errorf("write.test_drop_pdus tests fetching; it needs write.missing_events: fetch")
		}
	}
	if c.Write.MarkOriginsUp && !c.Modes.PDU.ServesNatively() {
		return fmt.Errorf("write.mark_origins_up writes destinations and the caches stream, as write mode's role; " +
			"it needs modes.pdu canary:N or native")
	}
	if c.Modes.PDU.ServesNatively() && c.Write.InstanceName == "" {
		return fmt.Errorf("modes.pdu is %s, which writes; write.instance_name is required "+
			"(a name no Synapse process uses, e.g. goinbound-worker)", c.Modes.PDU)
	}
	return nil
}

// Write configures write mode.
type Write struct {
	// InstanceName is ours in Synapse's lock tables. No Synapse process may
	// have it: a lock is taken over by its holder's own name.
	InstanceName string `yaml:"instance_name"`
	// Role is the write role, granted exactly the tables write mode writes.
	// Default "goinbound_rw".
	Role string `yaml:"role"`
	// Origins are served by write mode whatever the canary percentage: a
	// canary that starts with servers we control. Their EDU-only
	// transactions are ours too, so an origin is only ever in one process.
	Origins []string `yaml:"origins"`
	// MissingEvents is what write mode does with an event whose prev events
	// are missing: "defer" (the default) leaves it staged for Synapse's
	// worker; "fetch" fetches them from the origin as Synapse does, which
	// contacts remote servers.
	MissingEvents string `yaml:"missing_events"`
	// MarkOriginsUp serves transactions from origins in backoff, marking
	// each as up as Synapse's worker does (transport/server/_base.py:143):
	// the destinations reset, its invalidation on the caches stream under
	// instance_name, and REMOTE_SERVER_UP. False proxies them.
	MarkOriginsUp bool `yaml:"mark_origins_up"`
	// TestDropPDUs makes a gap on purpose, to test missing_events: fetch
	// against a server we control. Synapse has nothing like it.
	TestDropPDUs *TestDrop `yaml:"test_drop_pdus"`
}

// TestDrop answers the next Count PDUs from Origin in Room without staging
// them, once per start.
type TestDrop struct {
	Origin string `yaml:"origin"`
	Room   string `yaml:"room"`
	Count  int    `yaml:"count"`
}

// FetchesMissingEvents says write.missing_events is fetch.
func (w Write) FetchesMissingEvents() bool { return w.MissingEvents == "fetch" }

// RoleName returns Role with its default applied.
func (w Write) RoleName() string {
	if w.Role == "" {
		return "goinbound_rw"
	}
	return w.Role
}

// MaxBodyBytes returns MaxBodyMB in bytes, with its default applied.
func (c *Config) MaxBodyBytes() int64 {
	mb := c.MaxBodyMB
	if mb == 0 {
		mb = 16
	}
	return int64(mb) << 20
}
