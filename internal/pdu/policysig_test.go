package pdu

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/tidwall/sjson"
)

func TestVerifyWithKey(t *testing.T) {
	rv, _ := LookupRoomVersion("10")
	pub, priv, _ := ed25519.GenerateKey(nil)
	ev := []byte(`{"type":"m.room.message","room_id":"!r:x","sender":"@a:x","content":{"body":"hi"},` +
		`"depth":3,"origin_server_ts":1,"prev_events":[],"auth_events":[],"hashes":{"sha256":"x"},` +
		`"signatures":{"x":{"ed25519:a":"s"}},"unsigned":{"age_ts":5}}`)

	// Signed as a policy server signs: over the redacted event, without
	// signatures and unsigned.
	redacted, err := Redact(ev, rv)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := without(redacted, "signatures", "unsigned")
	canon, _ := Canonical(msg)
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	signed, _ := sjson.SetBytes(ev, `signatures.policy\.example.ed25519:policy_server`, sig)

	if err := VerifyWithKey(signed, rv, "policy.example", "ed25519:policy_server", pub); err != nil {
		t.Errorf("valid signature: %v", err)
	}
	// Content is redacted away, so it may change; the rest may not.
	edited, _ := sjson.SetBytes(signed, "content.body", "changed")
	if err := VerifyWithKey(edited, rv, "policy.example", "ed25519:policy_server", pub); err != nil {
		t.Errorf("content change broke it: %v", err)
	}
	tampered, _ := sjson.SetBytes(signed, "depth", 4)
	if VerifyWithKey(tampered, rv, "policy.example", "ed25519:policy_server", pub) == nil {
		t.Error("a changed depth verified")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if VerifyWithKey(signed, rv, "policy.example", "ed25519:policy_server", other) == nil {
		t.Error("the wrong key verified")
	}
	if VerifyWithKey(ev, rv, "policy.example", "ed25519:policy_server", pub) == nil {
		t.Error("an unsigned event verified")
	}
}

func TestValidServerName(t *testing.T) {
	for name, want := range map[string]bool{
		"example.org": true, "example.org:8448": true, "[::1]": true, "[::1]:80": true, "1.2.3.4": true,
		"": false, "ex_ample.org": false, "example.org:": false, "example.org:x": false, "[::1": false, "[]": false,
	} {
		if got := ValidServerName(name); got != want {
			t.Errorf("%q: %v, want %v", name, got, want)
		}
	}
}
