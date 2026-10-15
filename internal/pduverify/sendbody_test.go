package pduverify

import (
	"encoding/json"
	"testing"
	"time"
)

// event_from_pdu_json's unsigned handling, then calculate_context_info's
// replaces_state.
func TestPDUEventDict(t *testing.T) {
	at := time.UnixMilli(1_000_000)
	cases := []struct {
		name, raw, replaces, want string
	}{
		{"age becomes age_ts", `{"type":"m.room.message","unsigned":{"age":250}}`, "",
			`{"type":"m.room.message","unsigned":{"age_ts":999750}}`},
		{"other unsigned keys go", `{"type":"m.room.message","unsigned":{"age":1,"transaction_id":"x","invite_room_state":[]}}`, "",
			`{"type":"m.room.message","unsigned":{"age_ts":999999}}`},
		{"members keep stripped state", `{"type":"m.room.member","unsigned":{"invite_room_state":[1],"knock_room_state":[2],"prev_content":{}}}`, "",
			`{"type":"m.room.member","unsigned":{"invite_room_state":[1],"knock_room_state":[2]}}`},
		{"a sent age_ts is dropped", `{"type":"m.room.message","unsigned":{"age_ts":5}}`, "",
			`{"type":"m.room.message","unsigned":{}}`},
		{"a float age is not an int", `{"type":"m.room.message","unsigned":{"age":1.5}}`, "",
			`{"type":"m.room.message","unsigned":{}}`},
		{"a bool age is", `{"type":"m.room.message","unsigned":{"age":true}}`, "",
			`{"type":"m.room.message","unsigned":{"age_ts":999999}}`},
		{"no unsigned becomes {}", `{"type":"m.room.topic"}`, "",
			`{"type":"m.room.topic","unsigned":{}}`},
		{"replaces_state", `{"type":"m.room.topic","state_key":""}`, "$old",
			`{"type":"m.room.topic","state_key":"","unsigned":{"replaces_state":"$old"}}`},
	}
	for _, c := range cases {
		got, err := pduEventDict([]byte(c.raw), at, c.replaces)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var want map[string]any
		_ = json.Unmarshal([]byte(c.want), &want)
		if a, b := jsonNormal(got), jsonNormal(want); !jsonEqual(a, b) {
			gb, _ := json.Marshal(got)
			t.Errorf("%s: got %s, want %s", c.name, gb, c.want)
		}
	}
	// Pulled events have no request time: age is dropped.
	if got, _ := pduEventDict([]byte(`{"type":"m.room.message","unsigned":{"age":5}}`), time.Time{}, ""); len(got["unsigned"].(map[string]any)) != 0 {
		t.Errorf("pulled: unsigned %v", got["unsigned"])
	}
	if _, err := pduEventDict([]byte(`{"type":"x","unsigned":[]}`), at, ""); err == nil {
		t.Error("a non-object unsigned was accepted; Synapse raises on it")
	}
}

// The body as the persister parses it: context deltas as Python tuples.
func TestSendEntryEncoding(t *testing.T) {
	e := sendEntry{
		Event: map[string]any{"type": "m.room.topic"}, RoomVersion: "10", EventFormatVersion: 3,
		InternalMetadata: map[string]any{},
		Context: sendContext{
			StateGroup: 7, StateGroupBeforeEvent: 6,
			StateGroupDeltas:     []groupDelta{{From: 6, To: 7, Delta: []stateRow{{"m.room.topic", "", "$e"}}}, {From: 5, To: 6, Delta: []stateRow{}}},
			StateDeltaDueToEvent: []stateRow{{"m.room.topic", "", "$e"}},
		},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"event":{"type":"m.room.topic"},"room_version":"10","event_format_version":3,"internal_metadata":{},"outlier":false,"rejected_reason":null,` +
		`"context":{"state_group":7,"state_group_before_event":6,"rejected":null,"state_group_deltas":[[6,7,[["m.room.topic","","$e"]]],[5,6,[]]],` +
		`"state_delta_due_to_event":[["m.room.topic","","$e"]],"app_service_id":null,"partial_state":false}}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}
