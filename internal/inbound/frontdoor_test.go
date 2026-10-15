package inbound

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// Built from the pieces Synapse 1.162 joins: FederationError's str,
// _check_sigs_on_pdu's wording, Keyring.process_json's SynapseError, and
// signedjson's message around PyNaCl's.
func TestSignatureErrorEntry(t *testing.T) {
	rv, _ := pdu.LookupRoomVersion("10")
	pub, _, _ := ed25519.GenerateKey(nil)
	raw := []byte(`{"type":"m.room.message","room_id":"!r:x","sender":"@a:remote.example","content":{},"depth":3,"origin_server_ts":1,` +
		`"prev_events":[],"auth_events":[],"hashes":{"sha256":"x"},"signatures":{"remote.example":{"ed25519:k":"` +
		`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}`)
	ev, err := pdu.ParseEvent(raw, "$e", rv, false)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(string, []string, int64) (map[string]pdu.VerifyKey, error) {
		return map[string]pdu.VerifyKey{"ed25519:k": {Key: pub, ValidUntilMS: 1 << 60}}, nil
	}
	var se *pdu.SignatureError
	if err := pdu.CheckSignaturesWith(ev, raw, lookup); !errors.As(err, &se) {
		t.Fatalf("not a signature error: %v", err)
	}
	got, ok := signatureErrorEntry(se)
	want := `{"error":"ERROR 403: unable to verify signature for sender domain remote.example: 401: Invalid signature for server remote.example with key ed25519:k: Unable to verify signature for remote.example: <class 'nacl.exceptions.BadSignatureError'> Signature was forged or corrupt"}`
	if !ok || string(got) != want {
		t.Errorf("ok=%v\ngot  %q\nwant %q", ok, got, want)
	}
	unsigned := []byte(`{"type":"m.room.message","room_id":"!r:x","sender":"@a:remote.example","content":{},"depth":3,"origin_server_ts":1,"prev_events":[],"auth_events":[],"hashes":{"sha256":"x"},"signatures":{}}`)
	ev, _ = pdu.ParseEvent(unsigned, "$e", rv, false)
	if err := pdu.CheckSignaturesWith(ev, unsigned, lookup); !errors.As(err, &se) {
		t.Fatalf("unsigned: %v", err)
	}
	got, _ = signatureErrorEntry(se)
	if want := `{"error":"ERROR 403: unable to verify signature for sender domain remote.example: 400: Not signed by remote.example"}`; string(got) != want {
		t.Errorf("unsigned: %s", got)
	}
}
