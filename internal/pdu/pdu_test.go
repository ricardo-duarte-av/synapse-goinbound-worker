package pdu

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestPyInt(t *testing.T) {
	ok := map[string]int64{
		`5`: 5, `-3`: -3, `5.9`: 5, `-5.9`: -5, `1e2`: 100,
		`true`: 1, `false`: 0,
		`"42"`: 42, `" 42 "`: 42, `"+7"`: 7, `"-7"`: -7, `"1_000"`: 1000, `"007"`: 7,
	}
	for raw, want := range ok {
		got, err := pyInt(gjson.Parse(raw))
		if err != nil || got != want {
			t.Errorf("int(%s) = %d, %v; want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{`null`, `"5.0"`, `"abc"`, `""`, `"_1"`, `"1__0"`, `[]`, `{}`} {
		if _, err := pyInt(gjson.Parse(raw)); err == nil {
			t.Errorf("int(%s) succeeded; Python raises", raw)
		}
	}
}

func TestIsPyIntRejectsBoolAndFloat(t *testing.T) {
	// type(v) is int: the enforce_int_power_levels test.
	for raw, want := range map[string]bool{`5`: true, `5.0`: false, `true`: false, `"5"`: false} {
		if got := isPyInt(gjson.Parse(raw)); got != want {
			t.Errorf("isPyInt(%s) = %v", raw, got)
		}
	}
}

func TestFieldLastDuplicateWins(t *testing.T) {
	v, ok := field(gjson.Parse(`{"a":1,"a":2}`), "a")
	if !ok || v.Int() != 2 {
		t.Errorf("duplicate key: got %s; json.loads keeps the last", v.Raw)
	}
	// Keys with path metacharacters are plain keys.
	v, ok = field(gjson.Parse(`{"m.room.power_levels":100,"a*b":1}`), "m.room.power_levels")
	if !ok || v.Int() != 100 {
		t.Errorf("dotted key lookup failed")
	}
}

func TestUserIDIsValid(t *testing.T) {
	for id, want := range map[string]bool{
		"@a:example.com":      true,
		"@a:example.com:8448": true,
		"@a:[::1]":            true,
		"@a:[::1]:8448":       true,
		"@a:exa_mple.com":     false,
		"a:example.com":       false,
		"@nocolon":            false,
		"@a:":                 false,
		"@a:[nothex]":         false,
	} {
		if got := userIDIsValid(id); got != want {
			t.Errorf("userIDIsValid(%q) = %v", id, got)
		}
	}
}

// --- events for the auth rule tests ---

func mkEvent(t *testing.T, rv string, fields map[string]any) *Event {
	t.Helper()
	v, _ := LookupRoomVersion(rv)
	b, _ := json.Marshal(fields)
	id, _ := fields["event_id"].(string)
	if id == "" {
		id = "$x"
	}
	ev, err := ParseEvent(b, id, v, false)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func create(t *testing.T, rv string, content map[string]any) *Event {
	return mkEvent(t, rv, map[string]any{
		"event_id": "$create:a.example", "type": "m.room.create", "state_key": "",
		"sender": "@alice:a.example", "room_id": "!r:a.example", "content": content,
	})
}

func member(t *testing.T, rv, id, user, membership string) *Event {
	return mkEvent(t, rv, map[string]any{
		"event_id": id, "type": "m.room.member", "state_key": user,
		"sender": user, "room_id": "!r:a.example", "content": map[string]any{"membership": membership},
	})
}

// m.federate must be exactly True; Synapse checks `is True`.
func TestCanFederateIsExactlyTrue(t *testing.T) {
	for content, want := range map[string]bool{`{}`: true, `{"m.federate":true}`: true,
		`{"m.federate":false}`: false, `{"m.federate":"true"}`: false, `{"m.federate":1}`: false} {
		ev := &Event{Content: gjson.Parse(content)}
		if got := canFederate(AuthState{createKey: ev}); got != want {
			t.Errorf("m.federate %s: canFederate = %v", content, got)
		}
	}
}

// Room versions 1-5 have a special rule for m.room.aliases; 6+ do not.
func TestAliasesSpecialCase(t *testing.T) {
	for _, tc := range []struct {
		rv   string
		key  string
		want bool // allowed
	}{
		{"5", "b.example", true},  // state_key is the sender's domain
		{"5", "c.example", false}, // it is not
		{"6", "b.example", false}, // ordinary rules: needs PL 50
	} {
		c := create(t, tc.rv, map[string]any{"creator": "@alice:a.example"})
		m := member(t, tc.rv, "$mb:b.example", "@bob:b.example", "join")
		ev := mkEvent(t, tc.rv, map[string]any{
			"event_id": "$al:b.example", "type": "m.room.aliases", "state_key": tc.key,
			"sender": "@bob:b.example", "room_id": "!r:a.example", "content": map[string]any{},
		})
		err := CheckStateDependentAuthRules(ev, []*Event{c, m})
		if (err == nil) != tc.want {
			t.Errorf("v%s aliases %s: err = %v, want allowed=%v", tc.rv, tc.key, err, tc.want)
		}
	}
}

// Room v12 events carry the create event implicitly.
func TestV12ImplicitCreateAuthEvent(t *testing.T) {
	ev := mkEvent(t, "12", map[string]any{
		"type": "m.room.message", "sender": "@a:b.example", "room_id": "!abc",
		"content": map[string]any{}, "auth_events": []string{"$pl"},
	})
	if len(ev.AuthEvents) != 2 || ev.AuthEvents[1] != "$abc" {
		t.Errorf("auth events = %v, want the create event $abc appended", ev.AuthEvents)
	}

	v12, _ := LookupRoomVersion("12")
	b, _ := json.Marshal(map[string]any{
		"type": "m.room.message", "sender": "@a:b.example", "room_id": "!abc",
		"content": map[string]any{}, "auth_events": []string{"$abc"},
	})
	if _, err := ParseEvent(b, "$x", v12, false); !errors.Is(err, ErrMalformed) {
		t.Errorf("an explicitly listed create event was accepted; Synapse refuses it")
	}
}

func TestPowerLevelsWithoutStateKeyHasNoCurrent(t *testing.T) {
	// A non-state m.room.power_levels has state_key None, so there is no
	// "current" power levels to compare against and the level checks are
	// skipped.
	c := create(t, "10", map[string]any{"creator": "@alice:a.example"})
	m := member(t, "10", "$ma:a.example", "@alice:a.example", "join")
	pl := mkEvent(t, "10", map[string]any{
		"event_id": "$pl:a.example", "type": "m.room.power_levels", "state_key": "",
		"sender": "@alice:a.example", "room_id": "!r:a.example",
		"content": map[string]any{"users": map[string]any{"@alice:a.example": 100}},
	})
	ev := mkEvent(t, "10", map[string]any{
		"event_id": "$x:a.example", "type": "m.room.power_levels",
		"sender": "@alice:a.example", "room_id": "!r:a.example",
		"content": map[string]any{"users": map[string]any{"@alice:a.example": 1000}},
	})
	if err := CheckStateDependentAuthRules(ev, []*Event{c, m, pl}); err != nil {
		t.Errorf("non-state power levels: %v", err)
	}
}

func TestStringPowerLevelsByVersion(t *testing.T) {
	// "50" is a fine level before v10 and a SynapseError from v10 on --
	// which is a raise, not a rejection.
	for _, tc := range []struct {
		rv    string
		raise bool
	}{{"9", false}, {"10", true}} {
		c := create(t, tc.rv, map[string]any{"creator": "@alice:a.example"})
		m := member(t, tc.rv, "$ma:a.example", "@alice:a.example", "join")
		ev := mkEvent(t, tc.rv, map[string]any{
			"event_id": "$pl:a.example", "type": "m.room.power_levels", "state_key": "",
			"sender": "@alice:a.example", "room_id": "!r:a.example",
			"content": map[string]any{"users": map[string]any{"@alice:a.example": 100}, "ban": "50"},
		})
		err := CheckStateDependentAuthRules(ev, []*Event{c, m})
		var re *RaiseError
		if errors.As(err, &re) != tc.raise {
			t.Errorf("v%s string ban level: err = %v, want raise=%v", tc.rv, err, tc.raise)
		}
	}
}

func TestThirdPartyInvite(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.RawStdEncoding.EncodeToString(pub)

	sign := func(signed map[string]any) map[string]any {
		b, _ := json.Marshal(signed)
		msg, err := signedMessage(b)
		if err != nil {
			t.Fatal(err)
		}
		signed["signatures"] = map[string]any{"id.example": map[string]any{
			"ed25519:0": base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
		}}
		return signed
	}

	c := create(t, "10", map[string]any{"creator": "@alice:a.example"})
	alice := member(t, "10", "$ma:a.example", "@alice:a.example", "join")
	tpiEvent := mkEvent(t, "10", map[string]any{
		"event_id": "$tpi:a.example", "type": "m.room.third_party_invite", "state_key": "tok",
		"sender": "@alice:a.example", "room_id": "!r:a.example",
		"content": map[string]any{"public_key": pubB64, "display_name": "b..."},
	})
	invite := func(signed map[string]any, sender string) *Event {
		return mkEvent(t, "10", map[string]any{
			"event_id": "$inv:a.example", "type": "m.room.member", "state_key": "@bob:b.example",
			"sender": sender, "room_id": "!r:a.example",
			"content": map[string]any{"membership": "invite", "third_party_invite": map[string]any{
				"display_name": "b...", "signed": signed}},
		})
	}
	auth := []*Event{c, alice, tpiEvent}

	good := sign(map[string]any{"mxid": "@bob:b.example", "token": "tok"})
	if err := CheckStateDependentAuthRules(invite(good, "@alice:a.example"), auth); err != nil {
		t.Errorf("a correctly signed third party invite was refused: %v", err)
	}

	tampered := sign(map[string]any{"mxid": "@bob:b.example", "token": "tok"})
	tampered["mxid"] = "@mallory:b.example"
	if err := CheckStateDependentAuthRules(invite(tampered, "@alice:a.example"), auth); !IsAuthError(err) {
		t.Errorf("a tampered signed block: err = %v, want an auth failure", err)
	}

	// Signed by a key the invite does not publish.
	_, other, _ := ed25519.GenerateKey(nil)
	priv = other
	forged := sign(map[string]any{"mxid": "@bob:b.example", "token": "tok"})
	if err := CheckStateDependentAuthRules(invite(forged, "@alice:a.example"), auth); !IsAuthError(err) {
		t.Errorf("a forged signature: err = %v, want an auth failure", err)
	}

	// The invite must come from whoever issued the third party invite.
	if err := CheckStateDependentAuthRules(invite(good, "@carol:a.example"), auth); !IsAuthError(err) {
		t.Errorf("a different sender: err = %v, want an auth failure", err)
	}

	// A public key that is not base64 raises out of the check in Synapse.
	badKey := mkEvent(t, "10", map[string]any{
		"event_id": "$tpi:a.example", "type": "m.room.third_party_invite", "state_key": "tok",
		"sender": "@alice:a.example", "room_id": "!r:a.example",
		"content": map[string]any{"public_key": "%%%"},
	})
	var re *RaiseError
	if err := CheckStateDependentAuthRules(invite(good, "@alice:a.example"), []*Event{c, alice, badKey}); !errors.As(err, &re) {
		t.Errorf("an undecodable public key: err = %v, want a raise", err)
	}
}

// Shaped like the oversized_event rejections stored here: a member event
// whose state key is under 255 codepoints but over 255 bytes.
func TestFieldSizeLimits(t *testing.T) {
	wide := strings.Repeat("é", 200) // 200 codepoints, 400 bytes
	for _, tc := range []struct {
		rv, stateKey  string
		wantErr       bool
		unpersistable bool
	}{
		{"6", wide, true, false},                    // lenient: persisted as rejected
		{"11", wide, true, true},                    // strict byte limits: dropped
		{"6", strings.Repeat("a", 256), true, true}, // codepoints: always strict
		{"6", strings.Repeat("a", 255), false, false},
	} {
		ev := mkEvent(t, tc.rv, map[string]any{
			"type": "m.room.member", "state_key": tc.stateKey, "sender": "@a:a.example",
			"room_id": "!r:a.example", "content": map[string]any{"membership": "join"},
		})
		se := CheckFieldSizes(ev)
		if (se != nil) != tc.wantErr || (se != nil && se.Unpersistable != tc.unpersistable) {
			t.Errorf("v%s, %d-byte state key: %+v", tc.rv, len(tc.stateKey), se)
		}
	}
	if CheckPDUSize([]byte(`{"content":{"body":"`+strings.Repeat("x", MaxPDUSize)+`"}}`)) == nil {
		t.Error("a PDU over 64KiB passed")
	}
}
