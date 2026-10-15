package pdu

import (
	"errors"
	"testing"
)

func TestCheckPDUJSON(t *testing.T) {
	v10, _ := LookupRoomVersion("10")
	v5, _ := LookupRoomVersion("5")
	v12, _ := LookupRoomVersion("12")
	for _, c := range []struct {
		name, js string
		rv       *RoomVersion
		ignored  bool
		ok       bool
	}{
		{"fine", `{"type":"m","depth":3}`, v10, false, true},
		{"no depth", `{"type":"m"}`, v10, true, false},
		{"no type", `{"depth":1}`, v10, true, false},
		{"float depth", `{"type":"m","depth":3.0}`, v10, true, false},
		{"bool depth", `{"type":"m","depth":true}`, v10, true, false},
		{"string depth", `{"type":"m","depth":"3"}`, v10, true, false},
		{"negative depth", `{"type":"m","depth":-1}`, v10, true, false},
		{"minus zero", `{"type":"m","depth":-0}`, v10, false, true},
		{"huge depth", `{"type":"m","depth":9007199254740992}`, v10, true, false},
		{"max depth", `{"type":"m","depth":9007199254740991}`, v10, false, true},
		{"float in content", `{"type":"m","depth":1,"content":{"a":[1.5]}}`, v10, true, false},
		{"float in v5", `{"type":"m","depth":1,"content":{"a":1.5}}`, v5, false, true},
		{"big int", `{"type":"m","depth":1,"content":{"a":-9007199254740992}}`, v10, true, false},
		{"float in stripped unsigned", `{"type":"m","depth":1,"unsigned":{"x":1.5}}`, v10, false, true},
		{"float in kept unsigned", `{"type":"m","depth":1,"unsigned":{"age":1.5}}`, v10, true, false},
		{"unsigned list", `{"type":"m","depth":1,"unsigned":[]}`, v10, false, false},
		{"v12 create in auth", `{"type":"m","depth":1,"room_id":"!abc","auth_events":["$abc"]}`, v12, true, false},
		{"v12 other auth", `{"type":"m","depth":1,"room_id":"!abc","auth_events":["$x"]}`, v12, false, true},
	} {
		err := CheckPDUJSON([]byte(c.js), c.rv)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.ignored && !errors.Is(err, ErrIgnoredPDU):
			t.Errorf("%s: %v, want ignored", c.name, err)
		case !c.ok && !c.ignored && (err == nil || errors.Is(err, ErrIgnoredPDU)):
			t.Errorf("%s: %v, want an uncertain error", c.name, err)
		}
	}
}
