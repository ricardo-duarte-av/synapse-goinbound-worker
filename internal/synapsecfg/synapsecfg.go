// Package synapsecfg reads the facts this worker needs out of Synapse's own
// homeserver.yaml, at every start.
//
// Which instance an EDU must be forwarded to is not a setting of ours: it is
// Synapse's stream_writers, resolved exactly as Synapse resolves it. A copy in
// goinbound-worker.yaml that drifted by one entry would not fail -- it would
// deliver typing notifications to a process that no longer writes the typing
// stream, which then drops them without complaint. So Synapse's config is the
// single source of truth, re-read on every start, and never written.
//
// The resolution rules are Synapse's, from synapse/config/workers.py,
// synapse/config/server.py, synapse/config/key.py and
// synapse/config/federation.py. The file is expected to be mounted read-only.
package synapsecfg

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// MainProcessInstanceName is what Synapse calls the main process internally.
// The yaml spells it "main" in instance_map and Synapse rewrites it to
// "master" (config/workers.py:73,339). Writer lists default to it.
const MainProcessInstanceName = "master"

// mainProcessInstanceMapName is the yaml spelling of the main process.
const mainProcessInstanceMapName = "main"

// Instance is where one Synapse instance can be reached for HTTP replication.
type Instance struct {
	Name string
	// Socket is set for a unix-socket instance, URL for a TCP one. Exactly one
	// is ever non-empty.
	Socket string
	URL    string
}

// Writers is Synapse's stream_writers, with Synapse's defaults applied.
//
// Every list defaults to ["master"] (config/workers.py:152-190) and keeps file
// order: Synapse picks the FIRST device_lists writer for device list and
// signing key EDUs, so order is load-bearing.
type Writers struct {
	Events      []string
	Typing      []string
	ToDevice    []string
	Receipts    []string
	Presence    []string
	DeviceLists []string
}

// Config is the subset of homeserver.yaml this worker needs.
type Config struct {
	// Path is the file this was read from, for error messages and for
	// resolving relative paths within it.
	Path string

	ServerName string

	// InstanceMap is every named instance's replication address, keyed by
	// Synapse's internal name (so "main" is found under "master").
	InstanceMap map[string]Instance

	Writers Writers

	// ReplicationSecret is worker_replication_secret, or the contents of
	// worker_replication_secret_path. Sent as a Bearer token on every
	// replication request when set (replication/http/_base.py:223).
	ReplicationSecret string

	// TrackPresence is config.server.track_presence. When false Synapse drops
	// inbound presence EDUs on the spot (federation_server.py:1686).
	TrackPresence bool

	// DomainWhitelist is federation_domain_whitelist. Nil means no whitelist;
	// an empty non-nil map means federate with nobody.
	DomainWhitelist map[string]bool

	// TrustedKeyServers is trusted_key_servers' server names, in file order.
	// Synapse defaults to matrix.org when the key is absent (config/key.py).
	TrustedKeyServers []string

	// Database is Synapse's PostgreSQL connection.
	Database Database

	// Backoff is federation's destination retry settings
	// (config/federation.py).
	Backoff Backoff

	// Redis is the replication bus, on which commands such as
	// REMOTE_SERVER_UP are published to the channel named server_name
	// (replication/tcp/redis.py).
	Redis Redis

	// Experimental is experimental_features, as given.
	Experimental map[string]any

	// AppServiceFiles are app_service_config_files, resolved to readable
	// paths (beside homeserver.yaml when Synapse's own path is absent).
	AppServiceFiles []string

	signingKey, signingKeyPath string
}

// Flag reads a boolean experimental feature, with Synapse's default.
func (c *Config) Flag(name string, def bool) bool {
	if v, ok := c.Experimental[name].(bool); ok {
		return v
	}
	return def
}

// raw mirrors only the keys we read. Everything else in the file is ignored, so
// a Synapse upgrade that adds options cannot stop this parsing.
type raw struct {
	ServerName string `yaml:"server_name"`

	SigningKey     string `yaml:"signing_key"`
	SigningKeyPath string `yaml:"signing_key_path"`

	InstanceMap map[string]struct {
		Path string `yaml:"path"`
		Host string `yaml:"host"`
		Port any    `yaml:"port"`
		TLS  bool   `yaml:"tls"`
	} `yaml:"instance_map"`

	// Each value is a string or a list, per _instance_to_list_converter.
	StreamWriters struct {
		Events      any `yaml:"events"`
		Typing      any `yaml:"typing"`
		ToDevice    any `yaml:"to_device"`
		Receipts    any `yaml:"receipts"`
		Presence    any `yaml:"presence"`
		DeviceLists any `yaml:"device_lists"`
	} `yaml:"stream_writers"`

	WorkerReplicationSecret     *string `yaml:"worker_replication_secret"`
	WorkerReplicationSecretPath string  `yaml:"worker_replication_secret_path"`

	// Presence.Enabled is a bool OR the string "untracked", and falls back to
	// the legacy use_presence key (config/server.py:507).
	Presence struct {
		Enabled any `yaml:"enabled"`
	} `yaml:"presence"`
	UsePresence any `yaml:"use_presence"`

	FederationDomainWhitelist []string `yaml:"federation_domain_whitelist"`

	Federation struct {
		MinRetryInterval any `yaml:"destination_min_retry_interval"`
		RetryMultiplier  any `yaml:"destination_retry_multiplier"`
		MaxRetryInterval any `yaml:"destination_max_retry_interval"`
	} `yaml:"federation"`

	ExperimentalFeatures  yaml.Node `yaml:"experimental_features"`
	AppServiceConfigFiles []string  `yaml:"app_service_config_files"`

	// Absent and empty mean different things: absent is matrix.org.
	TrustedKeyServers *[]struct {
		ServerName string `yaml:"server_name"`
	} `yaml:"trusted_key_servers"`

	Redis struct {
		Enabled  *bool  `yaml:"enabled"`
		Path     string `yaml:"path"`
		Host     string `yaml:"host"`
		Port     any    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		DBID     any    `yaml:"dbid"`
	} `yaml:"redis"`

	Database struct {
		Name string `yaml:"name"`
		Args struct {
			User     string `yaml:"user"`
			Password string `yaml:"password"`
			// psycopg2 accepts either spelling.
			Database string `yaml:"database"`
			DBName   string `yaml:"dbname"`
			Host     string `yaml:"host"`
			Port     any    `yaml:"port"`
			SSLMode  string `yaml:"sslmode"`
		} `yaml:"args"`
	} `yaml:"database"`
}

// Load reads and resolves homeserver.yaml.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("synapsecfg: %w", err)
	}
	return parse(b, path)
}

func parse(b []byte, path string) (*Config, error) {
	var r raw
	if err := yaml.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("synapsecfg: parsing %s: %w", path, err)
	}
	if r.ServerName == "" {
		return nil, fmt.Errorf("synapsecfg: %s has no server_name", path)
	}

	cfg := &Config{Path: path, ServerName: r.ServerName, signingKey: r.SigningKey, signingKeyPath: r.SigningKeyPath}

	var err error
	if cfg.InstanceMap, err = instanceMap(r); err != nil {
		return nil, err
	}
	if cfg.Writers, err = writers(r); err != nil {
		return nil, err
	}
	if cfg.ReplicationSecret, err = replicationSecret(r, path); err != nil {
		return nil, err
	}
	if cfg.Database, err = database(r); err != nil {
		return nil, err
	}

	if cfg.Redis, err = redisConfig(r); err != nil {
		return nil, err
	}

	cfg.TrackPresence = trackPresence(r)
	cfg.Experimental = lastWins(&r.ExperimentalFeatures)

	for _, f := range r.AppServiceConfigFiles {
		dir := filepath.Dir(path)
		p := f
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if _, err := os.Stat(p); err != nil && filepath.IsAbs(f) {
			p = filepath.Join(dir, filepath.Base(f))
		}
		cfg.AppServiceFiles = append(cfg.AppServiceFiles, p)
	}

	if r.FederationDomainWhitelist != nil {
		cfg.DomainWhitelist = make(map[string]bool, len(r.FederationDomainWhitelist))
		for _, d := range r.FederationDomainWhitelist {
			cfg.DomainWhitelist[d] = true
		}
	}

	if cfg.Backoff, err = backoffConfig(r); err != nil {
		return nil, err
	}

	if r.TrustedKeyServers == nil {
		cfg.TrustedKeyServers = []string{"matrix.org"}
	} else {
		for _, ks := range *r.TrustedKeyServers {
			if ks.ServerName != "" {
				cfg.TrustedKeyServers = append(cfg.TrustedKeyServers, ks.ServerName)
			}
		}
	}

	return cfg, nil
}

// Redis is how to reach the replication bus.
type Redis struct {
	Enabled bool
	// Socket is redis.path, Addr is host:port. At most one is set.
	Socket   string
	Addr     string
	Username string
	Password string
	DBID     int
}

func redisConfig(r raw) (Redis, error) {
	out := Redis{
		Enabled:  r.Redis.Enabled != nil && *r.Redis.Enabled,
		Socket:   r.Redis.Path,
		Username: r.Redis.Username,
		Password: r.Redis.Password,
	}
	var err error
	if out.DBID, err = parseInt(r.Redis.DBID, "redis.dbid"); err != nil {
		return Redis{}, err
	}
	if out.Socket == "" {
		host := r.Redis.Host
		if host == "" {
			host = "localhost"
		}
		port, err := parseInt(r.Redis.Port, "redis.port")
		if err != nil {
			return Redis{}, err
		}
		if port == 0 {
			port = 6379
		}
		out.Addr = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return out, nil
}

// Instance resolves a writer name to its replication address.
//
// "main" is accepted as a synonym for "master", since that is how the yaml
// spells it in instance_map and an operator may reasonably spell it the same
// way in stream_writers.
func (c *Config) Instance(name string) (Instance, bool) {
	if name == mainProcessInstanceMapName {
		name = MainProcessInstanceName
	}
	inst, ok := c.InstanceMap[name]
	return inst, ok
}

func instanceMap(r raw) (map[string]Instance, error) {
	out := make(map[string]Instance, len(r.InstanceMap))
	for name, loc := range r.InstanceMap {
		if name == mainProcessInstanceMapName {
			name = MainProcessInstanceName
		}
		port, err := parseInt(loc.Port, fmt.Sprintf("instance_map.%s.port", name))
		if err != nil {
			return nil, err
		}
		inst := Instance{Name: name}
		switch {
		case loc.Path != "":
			inst.Socket = loc.Path
		case loc.Host != "" && port != 0:
			scheme := "http"
			if loc.TLS {
				scheme = "https"
			}
			inst.URL = fmt.Sprintf("%s://%s:%d", scheme, loc.Host, port)
		default:
			return nil, fmt.Errorf(
				"synapsecfg: instance_map entry for %q has neither a path nor a host and port", name)
		}
		out[name] = inst
	}
	return out, nil
}

func writers(r raw) (Writers, error) {
	var w Writers
	fields := []struct {
		name string
		v    any
		dst  *[]string
	}{
		{"events", r.StreamWriters.Events, &w.Events},
		{"typing", r.StreamWriters.Typing, &w.Typing},
		{"to_device", r.StreamWriters.ToDevice, &w.ToDevice},
		{"receipts", r.StreamWriters.Receipts, &w.Receipts},
		{"presence", r.StreamWriters.Presence, &w.Presence},
		{"device_lists", r.StreamWriters.DeviceLists, &w.DeviceLists},
	}
	for _, f := range fields {
		names, err := instanceList(f.v)
		if err != nil {
			return Writers{}, fmt.Errorf("synapsecfg: stream_writers.%s: %w", f.name, err)
		}
		if f.v == nil {
			// Absent: Synapse's attrs default.
			names = []string{MainProcessInstanceName}
		} else if len(names) == 0 {
			// Explicitly empty. Synapse accepts this and then fails every
			// EDU of the type (random.choice of [] in on_edu). Refusing to
			// start is louder than reproducing that, and guessing "master"
			// would deliver EDUs Synapse never would.
			return Writers{}, fmt.Errorf("synapsecfg: stream_writers.%s is an empty list", f.name)
		}
		*f.dst = names
	}
	return w, nil
}

// SigningKeyLine is the key Synapse signs federation requests with: the first
// of signing_key, or of the file at signing_key_path (by default
// "<server_name>.signing.key" beside homeserver.yaml), as a
// "<algorithm> <version> <seed>" line. It is read only when asked for:
// nothing but asking a policy server needs it.
func (c *Config) SigningKeyLine() (string, error) {
	body := c.signingKey
	if body == "" {
		p := c.signingKeyPath
		if p == "" {
			p = c.ServerName + ".signing.key"
		}
		b, err := readBeside(p, c.Path)
		if err != nil {
			return "", fmt.Errorf("synapsecfg: signing key: %w", err)
		}
		body = string(b)
	}
	for _, line := range strings.Split(body, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return line, nil
		}
	}
	return "", fmt.Errorf("synapsecfg: the signing key holds no key")
}

// replicationSecret reproduces config/workers.py:248.
//
// worker_replication_secret_path is a path inside SYNAPSE's container. As with
// the signing key in gofederation, an absolute path that is missing here gets a
// second chance beside homeserver.yaml, which is where a read-only mount of
// Synapse's config directory puts it.
func replicationSecret(r raw, cfgPath string) (string, error) {
	if r.WorkerReplicationSecretPath != "" {
		if r.WorkerReplicationSecret != nil && *r.WorkerReplicationSecret != "" {
			return "", fmt.Errorf("synapsecfg: both worker_replication_secret and " +
				"worker_replication_secret_path are set; Synapse refuses this too")
		}
		b, err := readBeside(r.WorkerReplicationSecretPath, cfgPath)
		if err != nil {
			return "", fmt.Errorf("synapsecfg: worker_replication_secret_path: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if r.WorkerReplicationSecret != nil {
		return *r.WorkerReplicationSecret, nil
	}
	return "", nil
}

// readBeside reads p, falling back to its basename in homeserver.yaml's
// directory when p is absolute and absent.
func readBeside(p, cfgPath string) ([]byte, error) {
	dir := filepath.Dir(cfgPath)
	resolved := p
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(dir, resolved)
	}
	b, err := os.ReadFile(resolved)
	if err == nil {
		return b, nil
	}
	if !os.IsNotExist(err) || !filepath.IsAbs(p) {
		return nil, err
	}
	beside := filepath.Join(dir, filepath.Base(p))
	if beside == resolved {
		return nil, err
	}
	b, err2 := os.ReadFile(beside)
	if err2 != nil {
		return nil, fmt.Errorf("%w (and not at %s, beside %s)", err, beside, cfgPath)
	}
	return b, nil
}

// instanceList accepts Synapse's string-or-list, per _instance_to_list_converter.
func instanceList(v any) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{t}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("expected instance names, got %T", e)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected a string or a list, got %T", v)
	}
}

// parseInt accepts a number or a string holding one. YAML makes `port: 5432`
// an int and `port: "5432"` a string, and Synapse takes either.
func parseInt(v any, what string) (int, error) {
	switch t := v.(type) {
	case nil:
		return 0, nil
	case int:
		return t, nil
	case float64:
		return int(t), nil
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("synapsecfg: %s: %q is not a number", what, t)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("synapsecfg: %s: expected a number, got %T", what, v)
	}
}

// trackPresence reproduces config/server.py:507.
//
//	presence_enabled = presence.enabled, else use_presence, else true
//	track_presence = bool(presence_enabled) and presence_enabled != "untracked"
//
// Python's bool("untracked") is TRUE, so reading the key as a plain bool would
// get that case exactly backwards.
func trackPresence(r raw) bool {
	v := r.Presence.Enabled
	if v == nil {
		v = r.UsePresence
	}
	if v == nil {
		return true
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		if t == "untracked" {
			return false
		}
		return t != ""
	case int:
		return t != 0
	case float64:
		return t != 0
	default:
		return true
	}
}

// Database is Synapse's PostgreSQL connection, from the `database:` block.
// Only the psycopg2 backend is understood.
type Database struct {
	// Present is false when homeserver.yaml has no usable `database:` block.
	Present bool

	User     string
	Password string
	DBName   string
	// Host is a hostname or, when it starts with a slash, the directory
	// holding the unix socket.
	Host    string
	Port    int
	SSLMode string
}

// DSN renders the connection in libpq keyword form, which is what pgx takes.
func (d Database) DSN() string {
	if !d.Present {
		return ""
	}
	var b strings.Builder
	add := func(k, v string) {
		if v == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(quoteDSNValue(v))
	}
	add("host", d.Host)
	if d.Port != 0 {
		add("port", strconv.Itoa(d.Port))
	}
	add("user", d.User)
	add("password", d.Password)
	add("dbname", d.DBName)
	add("sslmode", d.SSLMode)
	return b.String()
}

// Redacted is DSN with the password replaced, for logs and error messages.
func (d Database) Redacted() string {
	r := d
	if r.Password != "" {
		r.Password = "xxxxx"
	}
	return r.DSN()
}

// quoteDSNValue escapes a value for libpq keyword/value form.
func quoteDSNValue(v string) string {
	if !strings.ContainsAny(v, " \t\n\r'\\") {
		return v
	}
	var b strings.Builder
	b.WriteByte('\'')
	for _, c := range v {
		if c == '\'' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	b.WriteByte('\'')
	return b.String()
}

func database(r raw) (Database, error) {
	name := r.Database.Name
	if name == "" && r.Database.Args.Host == "" && r.Database.Args.Database == "" &&
		r.Database.Args.DBName == "" {
		return Database{}, nil
	}
	if name != "" && name != "psycopg2" {
		return Database{}, fmt.Errorf(
			"synapsecfg: database.name is %q; only psycopg2 is supported", name)
	}
	port, err := parseInt(r.Database.Args.Port, "database.args.port")
	if err != nil {
		return Database{}, err
	}
	db := Database{
		Present:  true,
		User:     r.Database.Args.User,
		Password: r.Database.Args.Password,
		DBName:   r.Database.Args.Database,
		Host:     r.Database.Args.Host,
		Port:     port,
		SSLMode:  r.Database.Args.SSLMode,
	}
	if db.DBName == "" {
		db.DBName = r.Database.Args.DBName
	}
	if db.DBName == "" {
		return Database{}, fmt.Errorf(
			"synapsecfg: database.args names no database (neither `database` nor `dbname`)")
	}
	return db, nil
}

// lastWins decodes a mapping the way PyYAML does: a repeated key keeps its
// last value. yaml.v3 refuses duplicates outright, and deployments have them
// (msc3814_enabled twice in experimental_features, say).
func lastWins(n *yaml.Node) map[string]any {
	out := map[string]any{}
	if n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		var v any
		if err := n.Content[i+1].Decode(&v); err == nil {
			out[n.Content[i].Value] = v
		}
	}
	return out
}

// EventsWriter is the event persister for a room: _get_instance
// (config/_base.py:1074), the room ID's sha256 read little-endian, modulo the
// number of writers. "master" when stream_writers.events is empty.
func (w Writers) EventsWriter(roomID string) string {
	switch len(w.Events) {
	case 0:
		return MainProcessInstanceName
	case 1:
		return w.Events[0]
	}
	sum := sha256.Sum256([]byte(roomID))
	slices.Reverse(sum[:])
	n := new(big.Int).SetBytes(sum[:])
	return w.Events[new(big.Int).Mod(n, big.NewInt(int64(len(w.Events)))).Int64()]
}

// Backoff is how long Synapse waits before retrying a failing destination:
// Min first, then times Multiplier (and uniform(0.8, 1.4)), up to Max.
type Backoff struct {
	MinMS      int64
	Multiplier float64
	MaxMS      int64
}

// backoffConfig is FederationConfig's destination_* settings: 10m, 2, 7d,
// the max capped at 2**62.
func backoffConfig(r raw) (Backoff, error) {
	b := Backoff{MinMS: 10 * 60 * 1000, Multiplier: 2, MaxMS: 7 * 24 * 3600 * 1000}
	f := r.Federation
	var err error
	if f.MinRetryInterval != nil {
		if b.MinMS, err = ParseDuration(f.MinRetryInterval); err != nil {
			return b, fmt.Errorf("federation.destination_min_retry_interval: %w", err)
		}
	}
	if f.MaxRetryInterval != nil {
		if b.MaxMS, err = ParseDuration(f.MaxRetryInterval); err != nil {
			return b, fmt.Errorf("federation.destination_max_retry_interval: %w", err)
		}
	}
	b.MaxMS = min(b.MaxMS, 1<<62)
	switch m := f.RetryMultiplier.(type) {
	case nil:
	case int:
		b.Multiplier = float64(m)
	case float64:
		b.Multiplier = m
	default:
		return b, fmt.Errorf("federation.destination_retry_multiplier: %v is not a number", m)
	}
	return b, nil
}

// ParseDuration is Config.parse_duration: an int is milliseconds; a string
// is digits with an optional s, m, h, d, w or y suffix (none: ms).
func ParseDuration(v any) (int64, error) {
	switch d := v.(type) {
	case int:
		return int64(d), nil
	case string:
		sizes := map[byte]int64{'s': 1000, 'm': 60000, 'h': 3600000, 'd': 86400000, 'w': 7 * 86400000, 'y': 365 * 86400000}
		if d == "" {
			return 0, fmt.Errorf("empty duration")
		}
		size := int64(1)
		if n, ok := sizes[d[len(d)-1]]; ok {
			size, d = n, d[:len(d)-1]
		} else if c := d[len(d)-1]; c < '0' || c > '9' {
			return 0, fmt.Errorf("bad duration suffix %s", d)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(d), 10, 64)
		if err != nil {
			return 0, err
		}
		return n * size, nil
	}
	return 0, fmt.Errorf("bad duration type %v", v)
}
