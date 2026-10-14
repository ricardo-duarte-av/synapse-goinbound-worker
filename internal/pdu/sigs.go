package pdu

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"maunium.net/go/mautrix/crypto/canonicaljson"
)

// Redaction, event IDs, content hashes and signatures, as Synapse computes
// them: rust/src/events/utils.rs (redact, compute_event_reference_hash),
// synapse/crypto/event_signing.py (compute_content_hash) and
// synapse/federation/federation_base.py (_check_sigs_on_pdu).
//
// JSON is handled raw. Values that survive are copied byte for byte and the
// result canonicalized, so nothing is re-encoded except by canonicalization.

// rawObject builds a JSON object from raw member values, in the given order.
// Canonicalization sorts it afterwards.
type rawObject struct {
	keys []string
	vals map[string][]byte
}

func newRawObject() *rawObject { return &rawObject{vals: map[string][]byte{}} }

func (o *rawObject) set(k string, raw []byte) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = raw
}

func (o *rawObject) bytes() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := jsonString(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

func jsonString(s string) ([]byte, error) {
	// gjson's raw key text is already valid JSON; re-quoting keeps this
	// simple and correct for any key.
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return []byte(b.String()), nil
}

// lastMembers returns an object's members with duplicates resolved
// last-wins, in first-appearance order.
func lastMembers(obj gjson.Result) (*rawObject, error) {
	if !obj.IsObject() {
		return nil, fmt.Errorf("%w: not an object", ErrMalformed)
	}
	o := newRawObject()
	obj.ForEach(func(k, v gjson.Result) bool {
		o.set(k.String(), []byte(v.Raw))
		return true
	})
	return o, nil
}

// Redact is Synapse's redact (rust/src/events/utils.rs:106): the event as
// the redaction algorithm of its room version leaves it. The result is not
// canonicalized.
func Redact(raw []byte, rv *RoomVersion) ([]byte, error) {
	ev := gjson.ParseBytes(raw)
	if !ev.IsObject() {
		return nil, fmt.Errorf("%w: event is not an object", ErrMalformed)
	}
	allowed := map[string]bool{
		"event_id": true, "sender": true, "room_id": true, "hashes": true, "signatures": true,
		"content": true, "type": true, "state_key": true, "depth": true, "prev_events": true,
		"origin_server_ts": true, "auth_events": true,
	}
	if !rv.UpdatedRedactionRules {
		allowed["prev_state"], allowed["membership"], allowed["origin"] = true, true, true
	}

	typ, ok := field(ev, "type")
	if !ok || typ.Type != gjson.String {
		return nil, fmt.Errorf("%w: type is not a string", ErrMalformed)
	}
	content, ok := field(ev, "content")
	if !ok {
		return nil, fmt.Errorf("%w: no content", ErrMalformed)
	}

	newContent := newRawObject()
	keep := func(name string) {
		if v, ok := field(content, name); ok {
			newContent.set(name, []byte(v.Raw))
		}
	}

	switch typ.Str {
	case "m.room.member":
		keep("membership")
		if rv.RestrictedJoinRuleFix {
			keep("join_authorised_via_users_server")
		}
		if rv.UpdatedRedactionRules {
			if tpi, ok := field(content, "third_party_invite"); ok && tpi.IsObject() {
				if signed, ok := field(tpi, "signed"); ok {
					newContent.set("third_party_invite", []byte(`{"signed":`+signed.Raw+`}`))
				} else {
					newContent.set("third_party_invite", []byte(`{}`))
				}
			}
		}
	case "m.room.create":
		if rv.UpdatedRedactionRules && content.IsObject() {
			for _, k := range keys(content) {
				keep(k)
			}
		}
		if !rv.ImplicitRoomCreator {
			keep("creator")
		}
		if rv.MSC4291RoomIDsAsHashes {
			delete(allowed, "room_id")
		}
	case "m.room.join_rules":
		keep("join_rule")
		if rv.RestrictedJoinRule {
			keep("allow")
		}
	case "m.room.power_levels":
		for _, k := range []string{"users", "users_default", "events", "events_default", "state_default", "ban", "kick", "redact"} {
			keep(k)
		}
		if rv.UpdatedRedactionRules {
			keep("invite")
		}
	case "m.room.aliases":
		if rv.SpecialCaseAliasesAuth {
			keep("aliases")
		}
	case "m.room.history_visibility":
		keep("history_visibility")
	case "m.room.redaction":
		if rv.UpdatedRedactionRules {
			keep("redacts")
		}
	}
	// MSC3389 relation redactions are only in unstable room versions.

	out := newRawObject()
	members, err := lastMembers(ev)
	if err != nil {
		return nil, err
	}
	for _, k := range members.keys {
		if allowed[k] {
			out.set(k, members.vals[k])
		}
	}
	out.set("content", newContent.bytes())

	// Known-good unsigned keys survive.
	if unsigned, ok := field(ev, "unsigned"); ok {
		nu := newRawObject()
		for _, k := range []string{"age_ts", "replaces_state"} {
			if v, ok := field(unsigned, k); ok {
				nu.set(k, []byte(v.Raw))
			}
		}
		out.set("unsigned", nu.bytes())
	}
	return out.bytes(), nil
}

// without returns the object minus the given top-level keys.
func without(raw []byte, drop ...string) ([]byte, error) {
	members, err := lastMembers(gjson.ParseBytes(raw))
	if err != nil {
		return nil, err
	}
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	out := newRawObject()
	for _, k := range members.keys {
		if !skip[k] {
			out.set(k, members.vals[k])
		}
	}
	return out.bytes(), nil
}

// Canonical is the canonical JSON of raw.
func Canonical(raw []byte) ([]byte, error) {
	out, err := canonicaljson.CanonicalJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical JSON: %v", ErrMalformed, err)
	}
	return out, nil
}

// ReferenceHash is compute_event_reference_hash: sha256 of the canonical
// redacted event without signatures, unsigned and age_ts.
func ReferenceHash(raw []byte, rv *RoomVersion) ([32]byte, error) {
	red, err := Redact(raw, rv)
	if err != nil {
		return [32]byte{}, err
	}
	red, err = without(red, "signatures", "unsigned", "age_ts")
	if err != nil {
		return [32]byte{}, err
	}
	canon, err := Canonical(red)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canon), nil
}

// CalculateEventID is calculate_event_id, for room versions whose event IDs
// are reference hashes (v3 and later).
func CalculateEventID(raw []byte, rv *RoomVersion) (string, error) {
	if rv.EventFormat == FormatV1V2 {
		return "", errors.New("pdu: v1/v2 event IDs are not hashes")
	}
	h, err := ReferenceHash(raw, rv)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	if rv.EventFormat == FormatV3 {
		enc = base64.RawStdEncoding
	}
	return "$" + enc.EncodeToString(h[:]), nil
}

// ContentHash is compute_content_hash: sha256 of the canonical event without
// age_ts, unsigned, signatures, hashes, outlier and destinations.
func ContentHash(raw []byte) ([32]byte, error) {
	stripped, err := without(raw, "age_ts", "unsigned", "signatures", "hashes", "outlier", "destinations")
	if err != nil {
		return [32]byte{}, err
	}
	canon, err := Canonical(stripped)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canon), nil
}

// IsRedactedForm reports whether raw is already in its own redacted form,
// as an event Synapse redacted on receipt (for a bad content hash) is stored.
func IsRedactedForm(raw []byte, rv *RoomVersion) (bool, error) {
	red, err := Redact(raw, rv)
	if err != nil {
		return false, err
	}
	a, err := without(red, "unsigned")
	if err != nil {
		return false, err
	}
	b, err := without(raw, "unsigned")
	if err != nil {
		return false, err
	}
	ca, err := Canonical(a)
	if err != nil {
		return false, err
	}
	cb, err := Canonical(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ca, cb), nil
}

// CheckContentHash is check_event_content_hash. A missing or malformed
// hashes field is a SynapseError there, so it is a RaiseError here.
func CheckContentHash(raw []byte) (bool, error) {
	j := gjson.ParseBytes(raw)
	hashes, ok := field(j, "hashes")
	if !ok || !hashes.IsObject() {
		return false, raise("malformed 'hashes'")
	}
	want, ok := field(hashes, "sha256")
	if !ok {
		return false, raise("sha256 not in hashes")
	}
	if want.Type != gjson.String {
		return false, raise("invalid base64 in hashes")
	}
	got, err := ContentHash(raw)
	if err != nil {
		return false, err
	}
	expected, err := decodeUnpaddedBase64(want.Str)
	if err != nil {
		return false, raise("invalid base64 in hashes")
	}
	return bytes.Equal(expected, got[:]), nil
}

// decodeUnpaddedBase64 is unpaddedbase64.decode_base64: standard or
// URL-safe alphabet, padding optional.
func decodeUnpaddedBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// VerifyKey is a server's public key as Synapse holds it: valid until
// ValidUntilMS (for an old key, the time it expired).
type VerifyKey struct {
	Key          ed25519.PublicKey
	ValidUntilMS int64
	// AddedMS is when Synapse stored the key, when known. A key stored
	// after an event arrived may not be the one Synapse checked it with.
	AddedMS int64
}

// KeyLookup returns the keys known for a server, by key ID. Keys it cannot
// find are simply absent.
type KeyLookup func(server string, keyIDs []string) (map[string]VerifyKey, error)

// ErrKeyUnknown means none of a server's signing keys could be found. Synapse
// would fetch them; not having them is not proof the signature is bad.
var ErrKeyUnknown = errors.New("pdu: no known key for the signing server")

// SignatureError is a failed signature check: InvalidEventSignatureError in
// Synapse, which makes it drop the PDU with a 403 in the transaction response.
type SignatureError struct {
	Msg string
	// Key is the key that failed, when one did.
	Key *VerifyKey
}

func (e *SignatureError) Error() string { return "signature: " + e.Msg }

// CheckSignatures is _check_sigs_on_pdu (federation_base.py:207): the event
// must be signed by the sender's server (unless it is an invite from a third
// party invite), for v1/v2 by the server that minted its event ID, and for a
// restricted join by the authorising server.
func CheckSignatures(ev *Event, raw []byte, lookup KeyLookup) error {
	rv := ev.Room
	// Keys must be valid at the event's origin_server_ts from room v5 on
	// (enforce_key_validity); before that, at any time at all.
	validity := int64(0)
	if rv.EnforceKeyValidity {
		validity = ev.OriginServerTS
	}

	redacted, err := Redact(raw, rv)
	if err != nil {
		return err
	}
	signed, err := without(redacted, "unsigned")
	if err != nil {
		return err
	}

	senderDomain, err := domainOf(ev.Sender)
	if err != nil {
		return err
	}
	var servers []string
	tpi := false
	if ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "invite" && has(ev.Content, "third_party_invite") {
			tpi = true
		}
	}
	if !tpi {
		servers = append(servers, senderDomain)
	}
	if rv.EventFormat == FormatV1V2 {
		d, err := domainOf(ev.ID)
		if err != nil {
			return err
		}
		if d != senderDomain {
			servers = append(servers, d)
		}
	}
	if rv.RestrictedJoinRule && ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "join" && has(ev.Content, "join_authorised_via_users_server") {
			au := get(ev.Content, "join_authorised_via_users_server")
			if au.Type != gjson.String {
				return raise("join_authorised_via_users_server is not a string")
			}
			d, err := domainOf(au.Str)
			if err != nil {
				return err
			}
			servers = append(servers, d)
		}
	}

	for _, server := range servers {
		if err := verifyForServer(server, signed, validity, lookup); err != nil {
			return err
		}
	}
	return nil
}

// verifyForServer is Keyring.process_request for one server: every key we
// hold that is valid at validity must verify, and there must be one.
func verifyForServer(server string, signed []byte, validity int64, lookup KeyLookup) error {
	sigs, ok := field(get(gjson.ParseBytes(signed), "signatures"), server)
	if !ok || !sigs.IsObject() {
		return &SignatureError{Msg: "not signed by " + server}
	}
	keyIDs := keys(sigs)
	if len(keyIDs) == 0 {
		return &SignatureError{Msg: "not signed by " + server}
	}
	found, err := lookup(server, keyIDs)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return fmt.Errorf("%w: %s", ErrKeyUnknown, server)
	}

	message, err := without(signed, "signatures", "unsigned")
	if err != nil {
		return err
	}
	canon, err := Canonical(message)
	if err != nil {
		return err
	}

	verified := false
	for _, kid := range keyIDs {
		k, ok := found[kid]
		if !ok || k.ValidUntilMS < validity {
			continue
		}
		sig, ok := field(sigs, kid)
		if !ok || sig.Type != gjson.String {
			return &SignatureError{Msg: "malformed signature " + kid}
		}
		raw, err := decodeUnpaddedBase64(sig.Str)
		if err != nil || !ed25519.Verify(k.Key, canon, raw) {
			k := k
			return &SignatureError{Msg: fmt.Sprintf("invalid signature for %s with key %s", server, kid), Key: &k}
		}
		verified = true
	}
	if !verified {
		// We hold keys, but none valid at the time required. Synapse
		// would go and fetch fresher ones, so this proves nothing.
		return fmt.Errorf("%w: %s (only keys expired before %d)", ErrKeyUnknown, server, validity)
	}
	return nil
}
