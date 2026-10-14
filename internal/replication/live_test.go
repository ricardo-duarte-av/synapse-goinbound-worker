package replication

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// TestLivePresenceProbe forwards one presence EDU to the real presence writer,
// which proves the wire format, the instance address and the replication
// secret against a running Synapse.
//
// It is only safe because it does nothing: with track_presence off, the writer
// drops a presence EDU the moment it reaches on_edu (federation_server.py:1686).
// The test refuses to run otherwise. The origin is in the reserved .invalid
// TLD, so even a misconfigured writer could not attribute it to anyone real.
//
//	HOMESERVER_YAML=/opt/matrix/synapse/synapse/homeserver.yaml go test -run LivePresenceProbe ./internal/replication/
func TestLivePresenceProbe(t *testing.T) {
	path := os.Getenv("HOMESERVER_YAML")
	if path == "" {
		t.Skip("HOMESERVER_YAML not set")
	}
	cfg, err := synapsecfg.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrackPresence {
		t.Skip("presence is tracked here, so a presence EDU would not be a no-op")
	}

	c := NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	writer := cfg.Writers.Presence[0]
	err = c.SendEDU(ctx, writer, "m.presence", "goinbound-probe.invalid", json.RawMessage(`{"push":[]}`))
	if err != nil {
		t.Fatalf("forwarding a no-op presence EDU to %s: %v", writer, err)
	}
	t.Logf("%s accepted the forward", writer)

	// The same request with a wrong secret must be refused. Without this, a
	// 200 could have come from anything listening on that socket.
	if cfg.ReplicationSecret == "" {
		return
	}
	wrong := *cfg
	wrong.ReplicationSecret = "not-the-secret"
	err = NewClient(&wrong).SendEDU(ctx, writer, "m.presence", "goinbound-probe.invalid", json.RawMessage(`{"push":[]}`))
	if err == nil {
		t.Fatalf("%s accepted a forward with the wrong replication secret", writer)
	}
	t.Logf("wrong secret refused: %v", err)
}
