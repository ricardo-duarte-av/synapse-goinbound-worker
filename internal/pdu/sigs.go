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

// Canonical is the canonical JSON of raw, as Python's canonicaljson writes
// it: a control character's \u escape in lowercase hex (\u001b, where
// mautrix writes \u001B).
func Canonical(raw []byte) ([]byte, error) {
	out, err := canonicaljson.CanonicalJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical JSON: %v", ErrMalformed, err)
	}
	lowerEscapes(out)
	return out, nil
}

// lowerEscapes lowercases the hex digits of every \u escape in canonical
// JSON, in place, leaving an escaped backslash and what follows it alone.
func lowerEscapes(b []byte) {
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			continue
		}
		if b[i+1] == 'u' && i+5 < len(b) {
			for j := i + 2; j < i+6; j++ {
				if b[j] >= 'A' && b[j] <= 'F' {
					b[j] += 'a' - 'A'
				}
			}
			i += 5
			continue
		}
		i++ // \\, \", \n and the like
	}
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

// KeyFetch is a KeyLookup that is told how long the keys must be valid, so
// it can look further (Synapse's Keyring) when what it holds expires sooner.
type KeyFetch func(server string, keyIDs []string, minValidMS int64) (map[string]VerifyKey, error)

// ErrKeyUnknown means no key of the server's valid at the time required was
// found. Synapse would fetch them; not having them is not proof the signature
// is bad, unless the lookup looked as far as Synapse's Keyring does. The
// failure is a *SignatureError of Kind SigNoKey, which matches it.
var ErrKeyUnknown = errors.New("pdu: no known key for the signing server")

// SignatureError is a failed signature check: InvalidEventSignatureError in
// Synapse, which makes it drop the PDU with a 403 in the transaction response.
type SignatureError struct {
	Msg string
	// Key is the key that failed, when one did.
	Key *VerifyKey
	// Server is the server whose signature failed, Role why it had to sign
	// (SigSender, SigEventDomain, SigAuthorising), KeyID the key, and Kind
	// how it failed (SigNotSigned, SigForged, SigBadLength, SigMalformed).
	Server, Role, KeyID, Kind string
	// KeyIDs and MinValidMS are, for SigNoKey, the keys looked for and the
	// time they had to be valid at: Synapse's _FetchKeyRequest.
	KeyIDs     []string
	MinValidMS int64
}

// Why a server must sign, as _check_sigs_on_pdu words it.
const (
	SigSender      = "sender domain"
	SigEventDomain = "event domain"
	SigAuthorising = "authorising serve" // sic
)

// How a signature failed.
const (
	SigNotSigned = "not signed"
	SigForged    = "forged"     // BadSignatureError
	SigBadLength = "bad length" // nacl ValueError: not 64 bytes
	SigMalformed = "malformed"  // not a string, or base64 we decode differently
	SigNoKey     = "no key"     // no key valid at the time required was found
)

func (e *SignatureError) Error() string { return "signature: " + e.Msg }

// Unwrap makes SigNoKey match ErrKeyUnknown: a caller whose lookup did not
// look as far as Synapse's Keyring treats it as unknown, not as a failure.
func (e *SignatureError) Unwrap() error {
	if e.Kind == SigNoKey {
		return ErrKeyUnknown
	}
	return nil
}

// CheckSignatures is _check_sigs_on_pdu (federation_base.py:207): the event
// must be signed by the sender's server (unless it is an invite from a third
// party invite), for v1/v2 by the server that minted its event ID, and for a
// restricted join by the authorising server.
func CheckSignatures(ev *Event, raw []byte, lookup KeyLookup) error {
	return CheckSignaturesWith(ev, raw, func(server string, keyIDs []string, _ int64) (map[string]VerifyKey, error) {
		return lookup(server, keyIDs)
	})
}

// CheckSignaturesWith is CheckSignatures with a KeyFetch.
func CheckSignaturesWith(ev *Event, raw []byte, lookup KeyFetch) error {
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
	var servers, roles []string
	tpi := false
	if ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "invite" && has(ev.Content, "third_party_invite") {
			tpi = true
		}
	}
	if !tpi {
		servers, roles = append(servers, senderDomain), append(roles, SigSender)
	}
	if rv.EventFormat == FormatV1V2 {
		d, err := domainOf(ev.ID)
		if err != nil {
			return err
		}
		if d != senderDomain {
			servers, roles = append(servers, d), append(roles, SigEventDomain)
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
			servers, roles = append(servers, d), append(roles, SigAuthorising)
		}
	}

	for i, server := range servers {
		if err := verifyForServer(server, signed, validity, lookup); err != nil {
			var se *SignatureError
			if errors.As(err, &se) {
				se.Role = roles[i]
			}
			return err
		}
	}
	return nil
}

// verifyForServer is Keyring.process_request for one server: every key we
// hold that is valid at validity must verify, and there must be one.
func verifyForServer(server string, signed []byte, validity int64, lookup KeyFetch) error {
	return verifyKeyIDs(server, signed, validity, lookup, false)
}

// VerifyJSONForServer is Keyring.verify_json_for_server: process_request
// over VerifyJSONRequest.from_json_object, whose key IDs are signedjson's
// signature_ids (ed25519 ones only, unlike an event's).
func VerifyJSONForServer(server string, signed []byte, validity int64, lookup KeyFetch) error {
	return verifyKeyIDs(server, signed, validity, lookup, true)
}

func verifyKeyIDs(server string, signed []byte, validity int64, lookup KeyFetch, ed25519Only bool) error {
	sigs, ok := field(get(gjson.ParseBytes(signed), "signatures"), server)
	if !ok || !sigs.IsObject() {
		return &SignatureError{Msg: "not signed by " + server, Server: server, Kind: SigNotSigned}
	}
	keyIDs := keys(sigs)
	if ed25519Only {
		kept := keyIDs[:0]
		for _, kid := range keyIDs {
			if alg, _, _ := strings.Cut(kid, ":"); alg == "ed25519" {
				kept = append(kept, kid)
			}
		}
		keyIDs = kept
	}
	if len(keyIDs) == 0 {
		return &SignatureError{Msg: "not signed by " + server, Server: server, Kind: SigNotSigned}
	}
	found, err := lookup(server, keyIDs, validity)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return noKey(server, keyIDs, validity, "")
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
			return &SignatureError{Msg: "malformed signature " + kid, Server: server, KeyID: kid, Kind: SigMalformed}
		}
		raw, err := decodeUnpaddedBase64(sig.Str)
		if err != nil || !ed25519.Verify(k.Key, canon, raw) {
			k := k
			kind := SigForged
			switch {
			case err != nil:
				kind = SigMalformed
			case len(raw) != ed25519.SignatureSize:
				kind = SigBadLength
			}
			return &SignatureError{Msg: fmt.Sprintf("invalid signature for %s with key %s", server, kid), Key: &k,
				Server: server, KeyID: kid, Kind: kind}
		}
		verified = true
	}
	if !verified {
		// We hold keys, but none valid at the time required: the same
		// "Failed to find any key" in Synapse, once it has looked for
		// fresher ones.
		return noKey(server, keyIDs, validity, fmt.Sprintf(" (only keys expired before %d)", validity))
	}
	return nil
}

// noKey is process_request finding no key to verify with.
func noKey(server string, keyIDs []string, validity int64, detail string) error {
	return &SignatureError{
		Msg:    fmt.Sprintf("%v: %s%s", ErrKeyUnknown, server, detail),
		Server: server, Kind: SigNoKey, KeyIDs: keyIDs, MinValidMS: validity,
	}
}

// VerifyWithKey is signedjson's verify_signed_json over the event's redacted
// form, with one given key rather than the server's published ones: how
// Synapse checks a policy server's signature (handlers/room_policy.py
// _verify_policy_server_signature, VerifyJsonRequest.from_event).
func VerifyWithKey(raw []byte, rv *RoomVersion, server, keyID string, key ed25519.PublicKey) error {
	redacted, err := Redact(raw, rv)
	if err != nil {
		return err
	}
	sigs, ok := field(get(gjson.ParseBytes(redacted), "signatures"), server)
	if !ok || !sigs.IsObject() {
		return &SignatureError{Msg: "not signed by " + server}
	}
	sig, ok := field(sigs, keyID)
	if !ok || sig.Type != gjson.String {
		return &SignatureError{Msg: "missing signature " + keyID + " for " + server}
	}
	b, err := decodeUnpaddedBase64(sig.Str)
	if err != nil {
		return &SignatureError{Msg: "undecodable signature " + keyID}
	}
	message, err := without(redacted, "signatures", "unsigned")
	if err != nil {
		return err
	}
	canon, err := Canonical(message)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, canon, b) {
		return &SignatureError{Msg: "invalid signature " + keyID + " for " + server}
	}
	return nil
}

// DecodeBase64 is unpaddedbase64.decode_base64.
func DecodeBase64(s string) ([]byte, error) { return decodeUnpaddedBase64(s) }

// SynapseText is str(InvalidEventSignatureError) for this failure, as
// _check_sigs_on_pdu words it around the Keyring's SynapseError and
// signedjson's message around PyNaCl's (each checked in the Synapse 1.162
// image). ok is false for a failure whose words we do not reproduce.
func (e *SignatureError) SynapseText() (string, bool) {
	var inner string
	switch e.Kind {
	case SigNotSigned:
		inner = "400: Not signed by " + e.Server
	case SigForged:
		inner = fmt.Sprintf("401: Invalid signature for server %s with key %s: Unable to verify signature for %s: "+
			"<class 'nacl.exceptions.BadSignatureError'> Signature was forged or corrupt", e.Server, e.KeyID, e.Server)
	case SigBadLength:
		inner = fmt.Sprintf("401: Invalid signature for server %s with key %s: Unable to verify signature for %s: "+
			"<class 'nacl.exceptions.ValueError'> The signature must be exactly 64 bytes long", e.Server, e.KeyID, e.Server)
	case SigNoKey:
		text, ok := e.fetchKeyText()
		if !ok {
			return "", false
		}
		inner = "401: " + text
	default:
		return "", false
	}
	if e.Role == "" {
		return "", false
	}
	return fmt.Sprintf("unable to verify signature for %s %s: %s", e.Role, e.Server, inner), true
}

// RequestText is the SynapseError a request's verification raises, its
// msg as authenticate_request lets it out: process_request's words, without
// _check_sigs_on_pdu's wrapping. ok is false where we do not reproduce them.
func (e *SignatureError) RequestText() (string, bool) {
	switch e.Kind {
	case SigNotSigned:
		return "Not signed by " + e.Server, true
	case SigForged:
		return fmt.Sprintf("Invalid signature for server %s with key %s: Unable to verify signature for %s: "+
			"<class 'nacl.exceptions.BadSignatureError'> Signature was forged or corrupt", e.Server, e.KeyID, e.Server), true
	case SigBadLength:
		return fmt.Sprintf("Invalid signature for server %s with key %s: Unable to verify signature for %s: "+
			"<class 'nacl.exceptions.ValueError'> The signature must be exactly 64 bytes long", e.Server, e.KeyID, e.Server), true
	case SigNoKey:
		return e.fetchKeyText()
	}
	return "", false
}

// fetchKeyText is keyring.py process_request's f"Failed to find any key to
// satisfy: {key_request}", the attrs repr of _FetchKeyRequest. Its key_ids
// is list(set(...)): with several, their order follows str hashes, which
// are random per Python process, so Synapse writes them in any order, and
// ours (the signatures') is one it could write. Reprs are plain only for
// plain names.
func (e *SignatureError) fetchKeyText() (string, bool) {
	if len(e.KeyIDs) == 0 || !plainRepr(e.Server) {
		return "", false
	}
	ids := make([]string, len(e.KeyIDs))
	for i, k := range e.KeyIDs {
		if !plainRepr(k) {
			return "", false
		}
		ids[i] = "'" + k + "'"
	}
	return fmt.Sprintf("Failed to find any key to satisfy: _FetchKeyRequest(server_name='%s', "+
		"minimum_valid_until_ts=%d, key_ids=[%s])", e.Server, e.MinValidMS, strings.Join(ids, ", ")), true
}

// plainRepr says Python's repr of s is s in single quotes: printable ASCII
// with no quote or backslash.
func plainRepr(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '\'' || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// ContentHashRaise is str() of the SynapseError check_event_content_hash
// raises for raw, whose CheckContentHash failed: "400: Malformed 'hashes':
// <class 'list'>", "400: Algorithm sha256 not in hashes ['md5']", "400:
// Invalid base64: 5". ok is false where it might not raise, or where we do
// not reproduce its words.
func ContentHashRaise(raw []byte) (text string, ok bool) {
	hashes, present := field(gjson.ParseBytes(raw), "hashes")
	if !present || !hashes.IsObject() {
		t, ok := pyTypeName(hashes, present)
		if !ok {
			return "", false
		}
		return "400: Malformed 'hashes': <class '" + t + "'>", true
	}
	want, present := field(hashes, "sha256")
	if !present {
		names := keys(hashes)
		reprs := make([]string, len(names))
		for i, n := range names {
			if !plainRepr(n) {
				return "", false
			}
			reprs[i] = "'" + n + "'"
		}
		return "400: Algorithm sha256 not in hashes [" + strings.Join(reprs, ", ") + "]", true
	}
	var shown string
	switch want.Type {
	case gjson.String:
		for i := 0; i < len(want.Str); i++ {
			if want.Str[i] > 0x7e {
				// .encode("ascii") raises: worded, but only plain text
				// is printed as we print it.
				return "", false
			}
		}
		if _, err := decodeUnpaddedBase64(want.Str); err == nil {
			return "", false // it decodes: no raise
		}
		// b64decode without validate drops what is not in the alphabet,
		// so it may decode what we refuse.
		return "", false
	case gjson.Null:
		shown = "None"
	case gjson.True:
		shown = "True"
	case gjson.False:
		shown = "False"
	case gjson.Number:
		if !pyIntLiteral(want.Raw) {
			return "", false
		}
		shown = strings.TrimPrefix(want.Raw, "+")
		if shown == "-0" {
			shown = "0"
		}
	default:
		return "", false
	}
	return "400: Invalid base64: " + shown, true
}

// pyTypeName is type(v).__name__ for a JSON value as json.loads gives it;
// absent is None.
func pyTypeName(v gjson.Result, present bool) (string, bool) {
	if !present {
		return "NoneType", true
	}
	switch v.Type {
	case gjson.Null:
		return "NoneType", true
	case gjson.String:
		return "str", true
	case gjson.True, gjson.False:
		return "bool", true
	case gjson.Number:
		if pyIntLiteral(v.Raw) {
			return "int", true
		}
		return "float", true
	}
	if v.IsArray() {
		return "list", true
	}
	return "", false
}

func pyIntLiteral(raw string) bool {
	if raw == "" {
		return false
	}
	for i, c := range raw {
		if c == '-' && i == 0 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
