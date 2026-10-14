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

	// Mode is how EDU-only transactions are served. Transactions carrying a
	// PDU are always proxied: this worker has no PDU pipeline.
	Mode Mode `yaml:"mode"`

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
		Mode:           Mode{Kind: ModeProxy},
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
		{"max_body_mb", c.MaxBodyMB},
	} {
		if n.v < 0 {
			return fmt.Errorf("%s must not be negative", n.name)
		}
	}
	if c.Mode.Kind == "" {
		c.Mode.Kind = ModeProxy
	}
	return nil
}

// MaxBodyBytes returns MaxBodyMB in bytes, with its default applied.
func (c *Config) MaxBodyBytes() int64 {
	mb := c.MaxBodyMB
	if mb == 0 {
		mb = 16
	}
	return int64(mb) << 20
}
