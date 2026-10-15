package config

import (
	"os"
	"strings"
	"testing"
)

const base = `
listen:
  socket: /var/sockets/goinbound.sock
upstream:
  sockets: [/var/sockets/inbound.sock]
`

const minimal = base + `
modes:
  edu: proxy
  pdu: proxy
`

func TestDefaults(t *testing.T) {
	cfg, err := parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Modes.EDU.Kind != ModeProxy || cfg.Modes.PDU.Kind != ModeProxy {
		t.Errorf("modes = %+v", cfg.Modes)
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
		cfg, err := parse([]byte(base + "modes:\n  edu: " + in + "\n  pdu: proxy\n"))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if cfg.Modes.EDU != want {
			t.Errorf("%s parsed as %+v", in, cfg.Modes.EDU)
		}
		if cfg.Modes.EDU.String() != in {
			t.Errorf("%s prints as %s", in, cfg.Modes.EDU)
		}
	}
	for _, bad := range []string{"canary", "canary:101", "native:5", "fast"} {
		if _, err := parse([]byte(base + "modes:\n  edu: " + bad + "\n  pdu: proxy\n")); err == nil {
			t.Errorf("mode %q was accepted", bad)
		}
	}
}

// What is proxied, shadowed or native is spelled out, never implied.
func TestModesAreExplicit(t *testing.T) {
	cases := map[string]string{
		"no modes at all":   base,
		"edu missing":       base + "modes:\n  pdu: proxy\n",
		"pdu missing":       base + "modes:\n  edu: native\n",
		"pdu canary":        base + "modes:\n  edu: native\n  pdu: canary:5\n",
		"pdu native":        base + "modes:\n  edu: proxy\n  pdu: native\n",
		"the old mode: key": base + "mode: shadow\n",
	}
	for name, y := range cases {
		if _, err := parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := parse([]byte(base + "mode: shadow\n"))
	if err == nil || !strings.Contains(err.Error(), "edu: shadow") {
		t.Errorf("the old key's error does not say what to write instead: %v", err)
	}
}

func TestValidation(t *testing.T) {
	bad := map[string]string{
		"no listener":     "upstream:\n  sockets: [/s]\nmodes: {edu: proxy, pdu: proxy}\n",
		"two listeners":   "listen:\n  socket: /a\n  addr: ':1'\nupstream:\n  sockets: [/s]\nmodes: {edu: proxy, pdu: proxy}\n",
		"no upstream":     "listen:\n  socket: /a\nmodes: {edu: proxy, pdu: proxy}\n",
		"negative":        minimal + "max_body_mb: -1\n",
		"unknown key":     minimal + "modez: native\n",
		"bad socket mode": "listen:\n  socket: /a\n  socket_mode: '999'\nupstream:\n  sockets: [/s]\nmodes: {edu: proxy, pdu: proxy}\n",
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
	if cfg.Modes.EDU.Kind != ModeProxy || cfg.Modes.PDU.Kind != ModeProxy {
		t.Errorf("the example starts in %+v; it must start with everything proxied", cfg.Modes)
	}
	if !strings.HasPrefix(cfg.HomeserverYAML, "/etc/synapse/") {
		t.Errorf("example homeserver_yaml %q is not under the read-only mount", cfg.HomeserverYAML)
	}
}

func TestPDUShadowIsAllowed(t *testing.T) {
	cfg, err := parse([]byte(base + "modes:\n  edu: shadow\n  pdu: shadow\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Modes.PDU.Kind != ModeShadow {
		t.Errorf("pdu mode = %s", cfg.Modes.PDU)
	}
}

func TestWriteMode(t *testing.T) {
	w := "write:\n  instance_name: goinbound-worker\n"
	ok := map[string]string{
		"pdu canary under edu canary": base + w + "modes:\n  edu: canary:10\n  pdu: canary:5\n",
		"pdu canary under edu native": base + w + "modes:\n  edu: native\n  pdu: canary:5\n",
		"both native":                 base + w + "modes:\n  edu: native\n  pdu: native\n",
	}
	for name, y := range ok {
		cfg, err := parse([]byte(y))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if cfg.Write.RoleName() != "goinbound_rw" {
			t.Errorf("%s: role %s", name, cfg.Write.RoleName())
		}
	}
	bad := map[string]string{
		"no instance name":        base + "modes:\n  edu: native\n  pdu: native\n",
		"pdu canary over edu's":   base + w + "modes:\n  edu: canary:5\n  pdu: canary:10\n",
		"pdu canary under shadow": base + w + "modes:\n  edu: shadow\n  pdu: canary:5\n",
		"pdu native, edu canary":  base + w + "modes:\n  edu: canary:100\n  pdu: native\n",
	}
	for name, y := range bad {
		if _, err := parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
