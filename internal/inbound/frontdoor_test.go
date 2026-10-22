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

	// No key valid at origin_server_ts, none at all or only expired ones:
	// process_request's "Failed to find any key to satisfy", with the
	// _FetchKeyRequest repr as the 1.163 image prints it. It is still
	// ErrKeyUnknown, for lookups that did not look as far as Synapse.
	wantNoKey := `{"error":"ERROR 403: unable to verify signature for sender domain remote.example: 401: Failed to find any key to satisfy: _FetchKeyRequest(server_name='remote.example', minimum_valid_until_ts=1, key_ids=['ed25519:k'])"}`
	for name, keys := range map[string]map[string]pdu.VerifyKey{
		"none":    {},
		"expired": {"ed25519:k": {Key: pub, ValidUntilMS: 0}},
	} {
		lookup := func(string, []string, int64) (map[string]pdu.VerifyKey, error) { return keys, nil }
		err := pdu.CheckSignaturesWith(ev, raw, lookup)
		if !errors.As(err, &se) || se.Kind != pdu.SigNoKey || !errors.Is(err, pdu.ErrKeyUnknown) {
			t.Fatalf("%s: %v", name, err)
		}
		if got, ok := signatureErrorEntry(se); !ok || string(got) != wantNoKey {
			t.Errorf("%s: ok=%v\ngot  %s\nwant %s", name, ok, got, wantNoKey)
		}
	}
	// Two key IDs: key_ids is list(set(...)), in no order we can know.
	two := []byte(`{"type":"m.room.message","room_id":"!r:x","sender":"@a:remote.example","content":{},"depth":3,"origin_server_ts":1,` +
		`"prev_events":[],"auth_events":[],"hashes":{"sha256":"x"},"signatures":{"remote.example":{"ed25519:k":"AA","ed25519:j":"AA"}}}`)
	ev2, _ := pdu.ParseEvent(two, "$e", rv, false)
	none := func(string, []string, int64) (map[string]pdu.VerifyKey, error) { return nil, nil }
	if err := pdu.CheckSignaturesWith(ev2, two, none); !errors.As(err, &se) || se.Kind != pdu.SigNoKey {
		t.Fatalf("two keys: %v", err)
	}
	if _, ok := signatureErrorEntry(se); ok {
		t.Error("two key IDs: claimed Synapse's words")
	}
}
