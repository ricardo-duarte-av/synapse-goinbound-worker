package config

import (
	"os"
	"strings"
	"testing"
)

const minimal = `
listen:
  socket: /var/sockets/goinbound.sock
upstream:
  sockets: [/var/sockets/inbound.sock]
`

func TestDefaults(t *testing.T) {
	cfg, err := parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	// The first deployment must change nothing: proxy is the default.
	if cfg.Mode.Kind != ModeProxy {
		t.Errorf("default mode = %s, want proxy", cfg.Mode)
	}
	if cfg.HomeserverYAML != "/etc/synapse/homeserver.yaml" {
		t.Errorf("homeserver_yaml default = %q", cfg.HomeserverYAML)
	}
	if cfg.MaxBodyBytes() != 16<<20 {
		t.Errorf("max body = %d", cfg.MaxBodyBytes())
	}
	if mode, _ := cfg.Listen.ParsedSocketMode(); mode != 0o660 {
		t.Errorf("socket mode = %o", mode)
	}
}

func TestModes(t *testing.T) {
	cases := map[string]Mode{
		"proxy":      {Kind: ModeProxy},
		"shadow":     {Kind: ModeShadow},
		"native":     {Kind: ModeNative},
		"canary:5":   {Kind: ModeCanary, CanaryPercent: 5},
		"canary:100": {Kind: ModeCanary, CanaryPercent: 100},
	}
	for in, want := range cases {
		cfg, err := parse([]byte(minimal + "mode: " + in + "\n"))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if cfg.Mode != want {
			t.Errorf("%s parsed as %+v", in, cfg.Mode)
		}
		if cfg.Mode.String() != in {
			t.Errorf("%s prints as %s", in, cfg.Mode)
		}
	}
	for _, bad := range []string{"canary", "canary:101", "native:5", "fast"} {
		if _, err := parse([]byte(minimal + "mode: " + bad + "\n")); err == nil {
			t.Errorf("mode %q was accepted", bad)
		}
	}
}

func TestValidation(t *testing.T) {
	bad := map[string]string{
		"no listener":     "upstream:\n  sockets: [/s]\n",
		"two listeners":   "listen:\n  socket: /a\n  addr: ':1'\nupstream:\n  sockets: [/s]\n",
		"no upstream":     "listen:\n  socket: /a\n",
		"negative":        minimal + "max_body_mb: -1\n",
		"unknown key":     minimal + "moed: native\n",
		"bad socket mode": "listen:\n  socket: /a\n  socket_mode: '999'\nupstream:\n  sockets: [/s]\n",
	}
	for name, y := range bad {
		if _, err := parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The shipped example must always load.
func TestExampleConfigLoads(t *testing.T) {
	b, err := os.ReadFile("../../deploy/goinbound-worker.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode.Kind != ModeProxy {
		t.Errorf("the example starts in %s; it must start in proxy", cfg.Mode)
	}
	if !strings.HasPrefix(cfg.HomeserverYAML, "/etc/synapse/") {
		t.Errorf("example homeserver_yaml %q is not under the read-only mount", cfg.HomeserverYAML)
	}
}
