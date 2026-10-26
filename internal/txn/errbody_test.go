package txn

import "testing"

// Error bodies are canonical, as Synapse's: no HTML escaping, sorted keys.
func TestErrorBodyIsCanonical(t *testing.T) {
	b, err := marshalError("M_UNAUTHORIZED", "x: <class 'nacl.exceptions.BadSignatureError'> & \x1b")
	want := `{"errcode":"M_UNAUTHORIZED","error":"x: <class 'nacl.exceptions.BadSignatureError'> & \u001b"}`
	if err != nil || string(b) != want {
		t.Errorf("got %s %v\nwant %s", b, err, want)
	}
}
