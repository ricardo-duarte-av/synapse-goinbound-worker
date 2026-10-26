package pduverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// policyKeyID is POLICY_SERVER_KEY_ID (handlers/room_policy.py:35).
const policyKeyID = "ed25519:policy_server"

// Policy verdicts: what Synapse does with a received PDU in
// _check_sigs_and_hash (federation_base.py:170), before staging it.
const (
	policyNone   = "no policy server"
	policyExempt = "policy event"
	policySigned = "signed"
	policyAsk    = "Synapse asks"
)

// The verdicts, for write mode.
const (
	PolicyNone   = policyNone
	PolicyExempt = policyExempt
	PolicySigned = policySigned
	PolicyAsk    = policyAsk
)

// PolicyVerdict is our verdict on a PDU, decided when it arrives: the
// policy server is read from the room's current state, as Synapse reads it.
type PolicyVerdict struct {
	Verdict string
	// Server is the policy server, when the room has a valid one, and key
	// its public key, as the policy event gives it.
	Server string
	key    string
	// Skip is a reason the verdict is not Synapse's for certain.
	Skip string
}

// policyServer is _get_policy_server: the room's policy server and its
// public key, or "" when there is no valid one.
func (s *Verifier) policyServer(ctx context.Context, roomID, ourName string) (name, key, skip string, err error) {
	ev, err := s.st.CurrentStateEvent(ctx, roomID, "m.room.policy", "")
	if err != nil {
		return "", "", "", err
	}
	var content gjson.Result
	var keyV gjson.Result
	if ev == nil {
		// The unstable MSC4284 event, consulted only without a stable one.
		ev, err = s.st.CurrentStateEvent(ctx, roomID, "org.matrix.msc4284.policy", "")
		if err != nil || ev == nil {
			return "", "", "", err
		}
		if ev.Redacted {
			return "", "", "policy event redacted", nil
		}
		content = gjson.GetBytes(ev.JSON, "content")
		keyV = pdu.Get(content, "public_key")
	} else {
		if ev.Redacted {
			return "", "", "policy event redacted", nil
		}
		content = gjson.GetBytes(ev.JSON, "content")
		if pks := pdu.Get(content, "public_keys"); pks.IsObject() {
			keyV = pdu.Get(pks, "ed25519")
		}
	}
	if keyV.Type != gjson.String {
		return "", "", "", nil
	}
	via := pdu.Get(content, "via")
	if via.Type != gjson.String || via.Str == ourName || !pdu.ValidServerName(via.Str) {
		return "", "", "", nil
	}
	joined, ok, err := s.st.HostJoined(ctx, roomID, via.Str)
	switch {
	case err != nil:
		return "", "", "", err
	case !ok:
		// is_host_joined raises.
		return "", "", "policy server host not looked up", nil
	case !joined:
		return "", "", "", nil
	}
	return via.Str, keyV.Str, "", nil
}

// Policy decides, for a PDU as received, whether Synapse lets it through on
// the policy server's signature, or asks the policy server
// (RoomPolicyHandler.is_event_allowed).
func (s *Verifier) Policy(ctx context.Context, raw []byte, ev *pdu.Event, ourName string) (PolicyVerdict, error) {
	if ev.IsState() && *ev.StateKey == "" && (ev.Type == "m.room.policy" || ev.Type == "org.matrix.msc4284.policy") {
		return PolicyVerdict{Verdict: policyExempt}, nil
	}
	if ok, err := pdu.CheckContentHash(raw); err != nil || !ok {
		// _check_sigs_and_hash returns the redacted copy before asking.
		return PolicyVerdict{Skip: "redacted on receipt"}, nil
	}
	name, key, skip, err := s.policyServer(ctx, ev.RoomID, ourName)
	if err != nil || skip != "" {
		return PolicyVerdict{Skip: skip}, err
	}
	if name == "" {
		return PolicyVerdict{Verdict: policyNone}, nil
	}
	v := PolicyVerdict{Verdict: policyAsk, Server: name, key: key}
	// decode_base64 and decode_verify_key_bytes failing are caught along
	// with a bad signature: Synapse then asks.
	if kb, err := pdu.DecodeBase64(key); err == nil && len(kb) == ed25519.PublicKeySize {
		if pdu.VerifyWithKey(raw, ev.Room, name, policyKeyID, kb) == nil {
			v.Verdict = policySigned
		}
	}
	return v, nil
}

// CheckPolicy compares our verdict with what Synapse did, which the stored
// event shows: asking adds the policy server's signature to the event
// before it is persisted; a refusal soft-fails it as policy_server_spammy.
func (s *Verifier) CheckPolicy(ctx context.Context, id string, raw []byte, v PolicyVerdict) *Result {
	res := &Result{EventID: id}
	if v.Skip != "" {
		return res.fail(OutcomeSkipped, v.Skip)
	}
	got, _, err := s.st.GetStoredEvents(ctx, []string{id})
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	se := got[id]
	if se == nil {
		return res.fail(OutcomeSkipped, "not found")
	}
	res.RoomID, res.Type, res.Version = se.RoomID, se.Type, se.Room.ID
	meta, err := s.st.InternalMetadata(ctx, id)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if r, _ := meta["redacted"].(bool); r {
		// The copy Synapse persisted failed its content hash and was
		// pruned, so no policy server was asked: one that arrived another
		// way than the transaction we judged (a pull, say).
		return res.fail(OutcomeSkipped, "redacted on receipt")
	}
	_, refused := meta["policy_server_spammy"]
	added := v.Server != "" && !sameJSON(gjson.GetBytes(raw, "signatures").Get(gjson.Escape(v.Server)).Raw,
		gjson.GetBytes(se.JSON, "signatures").Get(gjson.Escape(v.Server)).Raw)

	mismatch := func(why string) *Result {
		res.Outcome, res.Reason, res.StateDiff = OutcomeMismatch, "policy", []string{why}
		return res
	}
	switch v.Verdict {
	case policyAsk:
		switch {
		case refused:
			res.Outcome, res.Reason = OutcomeMatch, "asked, refused"
		case added:
			res.Outcome, res.Reason = OutcomeMatch, "asked, signed"
		default:
			return mismatch("we expected Synapse to ask " + v.Server + "; its copy has no new signature and is not refused")
		}
	default:
		switch {
		case refused:
			return mismatch("Synapse's policy server refused it; ours: " + v.Verdict)
		case added:
			return mismatch("Synapse asked " + v.Server + " for a signature; ours: " + v.Verdict)
		}
		res.Outcome, res.Reason = OutcomeMatch, v.Verdict
	}
	return res
}

// sameJSON compares two JSON texts by value ("" is absent).
func sameJSON(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	var x, y any
	da, db := json.NewDecoder(bytes.NewReader([]byte(a))), json.NewDecoder(bytes.NewReader([]byte(b)))
	da.UseNumber()
	db.UseNumber()
	if da.Decode(&x) != nil || db.Decode(&y) != nil {
		return a == b
	}
	return jsonEqual(x, y)
}

// PolicyAsker asks a policy server to sign an event, returning the
// signatures its answer holds for that server, by key ID. Any error is a
// refusal.
type PolicyAsker interface {
	Sign(ctx context.Context, server string, event json.RawMessage) (map[string]string, error)
}

// PolicyAnswer is what a policy server told us.
type PolicyAnswer struct {
	// Sigs are the signatures it gave, valid for the room's key. Nil when
	// Synapse would count the answer as a refusal.
	Sigs map[string]string
	// Refused says why it is one.
	Refused string
}

// AskPolicy asks the policy server as Synapse does, when its verdict is
// that Synapse asks: the event as get_pdu_json gives it, and the answer's
// signatures added to the event and verified against the room's key
// (RoomPolicyHandler.ask_policy_server_to_sign_event with verify=True).
func (s *Verifier) AskPolicy(ctx context.Context, asker PolicyAsker, raw []byte, received time.Time, rv *pdu.RoomVersion, v PolicyVerdict) PolicyAnswer {
	ev, err := pduEventDict(raw, received, "")
	if err != nil {
		return PolicyAnswer{Refused: "event_from_pdu_json: " + err.Error()}
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return PolicyAnswer{Refused: err.Error()}
	}
	sigs, err := asker.Sign(ctx, v.Server, body)
	if err != nil {
		return PolicyAnswer{Refused: err.Error()}
	}
	signed, err := addSignatures(raw, v.Server, sigs)
	if err != nil {
		return PolicyAnswer{Refused: err.Error()}
	}
	kb, err := pdu.DecodeBase64(v.key)
	if err != nil || len(kb) != ed25519.PublicKeySize {
		return PolicyAnswer{Refused: "the room's policy key does not decode"}
	}
	if err := pdu.VerifyWithKey(signed, rv, v.Server, policyKeyID, kb); err != nil {
		return PolicyAnswer{Refused: "policy server failed to sign event correctly: " + err.Error()}
	}
	return PolicyAnswer{Sigs: sigs}
}

// addSignatures is event.signatures.add_signature for each of sigs.
func addSignatures(raw []byte, server string, sigs map[string]string) ([]byte, error) {
	out := raw
	for keyID, sig := range sigs {
		var err error
		if out, err = sjson.SetBytes(out, "signatures."+sjsonEscape(server)+"."+sjsonEscape(keyID), sig); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// sjsonEscape escapes a key for an sjson path.
func sjsonEscape(k string) string {
	var b strings.Builder
	for _, r := range k {
		switch r {
		case '.', '*', '?', '|', '#', '@', '\\', ':':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CheckPolicyAsk compares the policy server's answer to us with its answer
// to Synapse, which the stored event shows. ed25519 signatures are
// deterministic, so a server that signed for both gave the same signature.
// synapse is the policy check's result.
func (s *Verifier) CheckPolicyAsk(ctx context.Context, id string, raw []byte, v PolicyVerdict, synapse *Result, ours PolicyAnswer) *Result {
	res := &Result{EventID: id}
	switch {
	case synapse == nil || synapse.Outcome != OutcomeMatch:
		return res.fail(OutcomeSkipped, "policy did not match")
	case v.Verdict != policyAsk:
		return res.fail(OutcomeSkipped, "Synapse did not ask")
	}
	res.RoomID, res.Type, res.Version = synapse.RoomID, synapse.Type, synapse.Version
	mismatch := func(why string) *Result {
		res.Outcome, res.Reason, res.StateDiff = OutcomeMismatch, "policy answer", []string{why}
		return res
	}
	refused := synapse.Reason == "asked, refused"
	switch {
	case refused && ours.Sigs == nil:
		res.Outcome, res.Reason = OutcomeMatch, "both refused"
		return res
	case refused:
		return mismatch("Synapse was refused; we were signed")
	case ours.Sigs == nil:
		return mismatch("Synapse was signed; we were refused: " + ours.Refused)
	}
	got, _, err := s.st.GetStoredEvents(ctx, []string{id})
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	se := got[id]
	if se == nil {
		return res.fail(OutcomeSkipped, "not found")
	}
	want, err := addSignatures(raw, v.Server, ours.Sigs)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	path := "signatures." + gjson.Escape(v.Server)
	if !sameJSON(gjson.GetBytes(want, path).Raw, gjson.GetBytes(se.JSON, path).Raw) {
		return mismatch("our signatures " + gjson.GetBytes(want, path).Raw + ", Synapse's " + gjson.GetBytes(se.JSON, path).Raw)
	}
	res.Outcome, res.Reason = OutcomeMatch, "same signature"
	return res
}
