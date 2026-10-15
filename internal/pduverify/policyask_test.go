package pduverify

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// fakePolicyServer signs as a policy server does: the redacted event,
// without signatures and unsigned.
type fakePolicyServer struct {
	priv   ed25519.PrivateKey
	rv     *pdu.RoomVersion
	got    json.RawMessage
	err    error
	tamper bool
}

func (f *fakePolicyServer) Sign(_ context.Context, server string, event json.RawMessage) (map[string]string, error) {
	f.got = event
	if f.err != nil {
		return nil, f.err
	}
	red, err := pdu.Redact(event, f.rv)
	if err != nil {
		return nil, err
	}
	red, _ = sjson.DeleteBytes(red, "signatures")
	red, _ = sjson.DeleteBytes(red, "unsigned")
	if f.tamper {
		red, _ = sjson.SetBytes(red, "depth", 99)
	}
	canon, err := pdu.Canonical(red)
	if err != nil {
		return nil, err
	}
	return map[string]string{policyKeyID: base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.priv, canon))}, nil
}

func TestAskPolicy(t *testing.T) {
	rv, _ := pdu.LookupRoomVersion("10")
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw := []byte(`{"type":"m.room.message","room_id":"!r:x","sender":"@a:x","content":{"body":"hi"},` +
		`"depth":3,"origin_server_ts":1,"prev_events":[],"auth_events":[],"hashes":{"sha256":"x"},` +
		`"signatures":{"x":{"ed25519:a":"s"}},"unsigned":{"age":100,"transaction_id":"t"}}`)
	// A port and dots in the server name must survive the signature paths.
	v := PolicyVerdict{Verdict: policyAsk, Server: "policy.example:8448", key: base64.RawStdEncoding.EncodeToString(pub)}
	at := time.UnixMilli(10_000)
	var s Verifier

	f := &fakePolicyServer{priv: priv, rv: rv}
	a := s.AskPolicy(context.Background(), f, raw, at, rv, v)
	if a.Sigs == nil {
		t.Fatalf("a valid signature was refused: %s", a.Refused)
	}
	// The event as get_pdu_json gives it: unsigned stripped, age as age_ts.
	if u := gjson.GetBytes(f.got, "unsigned").Raw; u != `{"age_ts":9900}` {
		t.Errorf("sent unsigned %s", u)
	}
	signed, err := addSignatures(raw, v.Server, a.Sigs)
	if err != nil {
		t.Fatal(err)
	}
	if got := gjson.GetBytes(signed, `signatures.policy\.example:8448.ed25519:policy_server`).Str; got != a.Sigs[policyKeyID] {
		t.Errorf("signature landed elsewhere: %s", signed)
	}
	if gjson.GetBytes(signed, "signatures.x.ed25519:a").Str != "s" {
		t.Error("the sender's signature was lost")
	}

	for name, f := range map[string]*fakePolicyServer{
		"error":         {priv: priv, rv: rv, err: errors.New("403 M_FORBIDDEN")},
		"bad signature": {priv: priv, rv: rv, tamper: true},
		"another key": func() *fakePolicyServer {
			_, p, _ := ed25519.GenerateKey(nil)
			return &fakePolicyServer{priv: p, rv: rv}
		}(),
	} {
		if a := s.AskPolicy(context.Background(), f, raw, at, rv, v); a.Sigs != nil || a.Refused == "" {
			t.Errorf("%s: not a refusal: %+v", name, a)
		}
	}
}

// Without a store: the cases decided by the answers alone.
func TestCheckPolicyAsk(t *testing.T) {
	var s Verifier
	ask := PolicyVerdict{Verdict: policyAsk, Server: "p"}
	signed := PolicyAnswer{Sigs: map[string]string{policyKeyID: "x"}}
	refused := PolicyAnswer{Refused: "403"}
	syn := func(reason string) *Result { return &Result{Outcome: OutcomeMatch, Reason: reason} }
	for _, c := range []struct {
		name    string
		v       PolicyVerdict
		synapse *Result
		ours    PolicyAnswer
		outcome string
	}{
		{"both refused", ask, syn("asked, refused"), refused, OutcomeMatch},
		{"Synapse refused, we signed", ask, syn("asked, refused"), signed, OutcomeMismatch},
		{"Synapse signed, we refused", ask, syn("asked, signed"), refused, OutcomeMismatch},
		{"not asked", PolicyVerdict{Verdict: policySigned}, syn("signed"), PolicyAnswer{}, OutcomeSkipped},
		{"policy mismatch", ask, &Result{Outcome: OutcomeMismatch}, refused, OutcomeSkipped},
	} {
		if got := s.CheckPolicyAsk(context.Background(), "$e", nil, c.v, c.synapse, c.ours); got.Outcome != c.outcome {
			t.Errorf("%s: %s (%s), want %s", c.name, got.Outcome, got.Reason, c.outcome)
		}
	}
}
