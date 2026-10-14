package synapsecfg

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func mustParse(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := parse([]byte(yaml), "/etc/synapse/homeserver.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Shaped like this deployment's homeserver.yaml.
const deployment = `
server_name: aguiarvieira.pt
worker_replication_secret: "s3cret"
instance_map:
  main:
    path: "/var/sockets/av-synapse-replication.sock"
  av-edu-worker:
    path: "/var/sockets/av-edu-worker.sock"
  av-event-persister-1:
    host: event-persister
    port: "9093"
stream_writers:
  events:
    - av-event-persister-1
  typing:
    - av-edu-worker
  to_device:
    - av-edu-worker
  receipts: av-edu-worker
  presence:
    - av-edu-worker
  device_lists:
    - av-edu-worker
presence:
  enabled: false
trusted_key_servers:
  - server_name: "keys.aguiarvieira.pt"
  - server_name: "matrix.org"
database:
  name: psycopg2
  args:
    user: synapse
    password: "pa ss"
    database: synapse-db
    host: /var/sockets
`

func TestDeploymentShape(t *testing.T) {
	cfg := mustParse(t, deployment)

	if cfg.ServerName != "aguiarvieira.pt" {
		t.Errorf("server_name = %q", cfg.ServerName)
	}
	if cfg.ReplicationSecret != "s3cret" {
		t.Errorf("replication secret = %q", cfg.ReplicationSecret)
	}
	if cfg.TrackPresence {
		t.Error("presence.enabled: false must mean track_presence is false")
	}

	// "main" is Synapse's yaml spelling of the instance it calls "master".
	if _, ok := cfg.InstanceMap["master"]; !ok {
		t.Error(`instance_map "main" was not stored under "master"`)
	}
	if inst, ok := cfg.Instance("main"); !ok || inst.Socket != "/var/sockets/av-synapse-replication.sock" {
		t.Errorf(`Instance("main") = %+v, %v`, inst, ok)
	}
	if inst := cfg.InstanceMap["av-event-persister-1"]; inst.URL != "http://event-persister:9093" {
		t.Errorf("TCP instance URL = %q", inst.URL)
	}

	// A bare string is a one-element list, per _instance_to_list_converter.
	if !slices.Equal(cfg.Writers.Receipts, []string{"av-edu-worker"}) {
		t.Errorf("receipts = %v", cfg.Writers.Receipts)
	}
	if !slices.Equal(cfg.Writers.Events, []string{"av-event-persister-1"}) {
		t.Errorf("events = %v", cfg.Writers.Events)
	}

	if !slices.Equal(cfg.TrustedKeyServers, []string{"keys.aguiarvieira.pt", "matrix.org"}) {
		t.Errorf("trusted key servers = %v", cfg.TrustedKeyServers)
	}

	dsn := cfg.Database.DSN()
	if dsn != `host=/var/sockets user=synapse password='pa ss' dbname=synapse-db` {
		t.Errorf("dsn = %q", dsn)
	}
	if strings.Contains(cfg.Database.Redacted(), "pa ss") {
		t.Error("Redacted leaks the password")
	}
}

// An absent writer list is ["master"], which is where Synapse sends the EDU.
func TestWriterDefaultsToMaster(t *testing.T) {
	cfg := mustParse(t, "server_name: example.com\n")
	for name, w := range map[string][]string{
		"events": cfg.Writers.Events, "typing": cfg.Writers.Typing, "to_device": cfg.Writers.ToDevice,
		"receipts": cfg.Writers.Receipts, "presence": cfg.Writers.Presence, "device_lists": cfg.Writers.DeviceLists,
	} {
		if !slices.Equal(w, []string{"master"}) {
			t.Errorf("%s defaults to %v, want [master]", name, w)
		}
	}
	if !cfg.TrackPresence {
		t.Error("presence defaults to tracked")
	}
	// Absent trusted_key_servers is matrix.org (config/key.py).
	if !slices.Equal(cfg.TrustedKeyServers, []string{"matrix.org"}) {
		t.Errorf("trusted key servers default = %v", cfg.TrustedKeyServers)
	}
}

// Writer order is load-bearing: device list EDUs go to the FIRST writer.
func TestWriterOrderIsKept(t *testing.T) {
	cfg := mustParse(t, "server_name: x\nstream_writers:\n  device_lists: [b, a, c]\n")
	if !slices.Equal(cfg.Writers.DeviceLists, []string{"b", "a", "c"}) {
		t.Errorf("device_lists = %v, file order lost", cfg.Writers.DeviceLists)
	}
}

func TestEmptyWriterListIsRefused(t *testing.T) {
	_, err := parse([]byte("server_name: x\nstream_writers:\n  typing: []\n"), "hs.yaml")
	if err == nil {
		t.Fatal("an empty writer list was accepted; Synapse fails every typing EDU with it")
	}
}

func TestEmptyTrustedKeyServersMeansNone(t *testing.T) {
	cfg := mustParse(t, "server_name: x\ntrusted_key_servers: []\n")
	if len(cfg.TrustedKeyServers) != 0 {
		t.Errorf("explicitly empty trusted_key_servers became %v", cfg.TrustedKeyServers)
	}
}

func TestPresenceUntracked(t *testing.T) {
	// bool("untracked") is true in Python: presence is on for clients but
	// not tracked, so federation of it is off.
	cfg := mustParse(t, "server_name: x\npresence:\n  enabled: untracked\n")
	if cfg.TrackPresence {
		t.Error(`presence.enabled: "untracked" must mean track_presence is false`)
	}
	cfg = mustParse(t, "server_name: x\nuse_presence: false\n")
	if cfg.TrackPresence {
		t.Error("the legacy use_presence: false was ignored")
	}
}

func TestDomainWhitelistNilVersusEmpty(t *testing.T) {
	if cfg := mustParse(t, "server_name: x\n"); cfg.DomainWhitelist != nil {
		t.Error("absent whitelist must be nil (federate with everyone)")
	}
	cfg := mustParse(t, "server_name: x\nfederation_domain_whitelist: []\n")
	if cfg.DomainWhitelist == nil {
		t.Error("an empty whitelist must be non-nil (federate with nobody)")
	}
}

// worker_replication_secret_path names a path inside Synapse's container; the
// file is found beside homeserver.yaml when that path does not exist here.
func TestReplicationSecretPathFoundBesideHomeserverYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "replication.secret"), []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hs := filepath.Join(dir, "homeserver.yaml")
	cfg, err := parse([]byte("server_name: x\nworker_replication_secret_path: /data/replication.secret\n"), hs)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReplicationSecret != "from-file" {
		t.Errorf("secret = %q, want the trimmed file contents", cfg.ReplicationSecret)
	}
}

func TestBothReplicationSecretsIsRefused(t *testing.T) {
	_, err := parse([]byte("server_name: x\nworker_replication_secret: a\nworker_replication_secret_path: /b\n"), "hs.yaml")
	if err == nil {
		t.Error("Synapse refuses both worker_replication_secret and _path; so must we")
	}
}

func TestInstanceWithoutAddressIsRefused(t *testing.T) {
	_, err := parse([]byte("server_name: x\ninstance_map:\n  w:\n    tls: true\n"), "hs.yaml")
	if err == nil {
		t.Error("an instance_map entry with no path and no host was accepted")
	}
}

// TestLiveHomeserverYAML reads the deployment's real file. Every writer it
// names must be reachable, or this worker would refuse to start.
//
//	HOMESERVER_YAML=/opt/matrix/synapse/synapse/homeserver.yaml go test ./internal/synapsecfg/
func TestLiveHomeserverYAML(t *testing.T) {
	path := os.Getenv("HOMESERVER_YAML")
	if path == "" {
		t.Skip("HOMESERVER_YAML not set")
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("server_name=%s track_presence=%v writers=%+v notaries=%v",
		cfg.ServerName, cfg.TrackPresence, cfg.Writers, cfg.TrustedKeyServers)
	for _, l := range [][]string{cfg.Writers.Typing, cfg.Writers.Receipts, cfg.Writers.ToDevice,
		cfg.Writers.Presence, cfg.Writers.DeviceLists} {
		for _, name := range l {
			if _, ok := cfg.Instance(name); !ok {
				t.Errorf("writer %q is not in instance_map", name)
			}
		}
	}
	if _, ok := cfg.Instance(MainProcessInstanceName); !ok {
		t.Error("main is not in instance_map; unknown EDU types could not be forwarded")
	}
}
