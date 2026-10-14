package appservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

func TestExclusiveUsers(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "reg.yaml")
	_ = os.WriteFile(f, []byte(`
namespaces:
  users:
    - exclusive: true
      regex: '@telegram_.*:example\.org'
    - exclusive: false
      regex: '@.*:example\.org'
`), 0o600)
	re, err := ExclusiveUsers([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"@telegram_123:example.org": true, "@alice:example.org": false} {
		if got := re.MatchString(id); got != want {
			t.Errorf("%s: %v, want %v (non-exclusive namespaces do not count)", id, got, want)
		}
	}
}

// The deployment's registrations must load and compile.
//
//	HOMESERVER_YAML=/opt/matrix/synapse/synapse/homeserver.yaml go test ./internal/appservice/
func TestLiveRegistrations(t *testing.T) {
	path := os.Getenv("HOMESERVER_YAML")
	if path == "" {
		t.Skip("HOMESERVER_YAML not set")
	}
	hs, err := synapsecfg.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	re, err := ExclusiveUsers(hs.AppServiceFiles)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d registrations; exclusive regex: %v", len(hs.AppServiceFiles), re)
}
