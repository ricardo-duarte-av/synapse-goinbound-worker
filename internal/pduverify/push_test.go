package pduverify

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

func pushEvent(t *testing.T, fields map[string]any) *pdu.Event {
	t.Helper()
	rv, _ := pdu.LookupRoomVersion("10")
	fields["room_id"], fields["sender"] = "!r:a.example", "@b:b.example"
	b, _ := json.Marshal(fields)
	ev, err := pdu.ParseEvent(b, "$e", rv, false)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestShouldCountAsUnread(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]any
		want   bool
	}{
		{"message with body", map[string]any{"type": "m.room.message", "content": map[string]any{"body": "hi", "msgtype": "m.text"}}, true},
		{"empty body", map[string]any{"type": "m.room.message", "content": map[string]any{"body": ""}}, false},
		{"non-string body", map[string]any{"type": "m.room.message", "content": map[string]any{"body": 5}}, false},
		{"notice", map[string]any{"type": "m.room.message", "content": map[string]any{"body": "hi", "msgtype": "m.notice"}}, false},
		{"edit", map[string]any{"type": "m.room.message", "content": map[string]any{"body": "hi",
			"m.relates_to": map[string]any{"rel_type": "m.replace", "event_id": "$o"}}}, false},
		// An edit relation without an event_id is no relation at all.
		{"broken edit", map[string]any{"type": "m.room.message", "content": map[string]any{"body": "hi",
			"m.relates_to": map[string]any{"rel_type": "m.replace"}}}, true},
		{"encrypted", map[string]any{"type": "m.room.encrypted", "content": map[string]any{}}, true},
		{"topic", map[string]any{"type": "m.room.topic", "state_key": "", "content": map[string]any{}}, true},
		{"join rules", map[string]any{"type": "m.room.join_rules", "state_key": "", "content": map[string]any{}}, false},
		{"reaction", map[string]any{"type": "m.reaction", "content": map[string]any{}}, false},
	} {
		if got := shouldCountAsUnread(pushEvent(t, tc.fields)); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Synapse stores the default action lists as "", decoded by the highlight
// flag; they must compare equal to the same actions computed here.
func TestDefaultActionsCompareAsDecoded(t *testing.T) {
	var notif, highlight any
	_ = json.Unmarshal([]byte(`["notify",{"set_tweak":"highlight","value":false}]`), &notif)
	_ = json.Unmarshal([]byte(`["notify",{"set_tweak":"sound","value":"default"},{"set_tweak":"highlight"}]`), &highlight)
	if !reflect.DeepEqual(jsonNormal(defaultNotifAction), notif) || !reflect.DeepEqual(jsonNormal(defaultHighlightAction), highlight) {
		t.Error("the default actions do not compare equal to their JSON")
	}
	ours := map[string]pushRow{"@u:a": {actions: notif, notif: true}}
	if d := diffPush(ours, map[string]pushRow{"@u:a": {actions: jsonNormal(defaultNotifAction), notif: true}}); len(d) != 0 {
		t.Errorf("diff = %v", d)
	}
	if d := diffPush(ours, map[string]pushRow{}); len(d) != 1 {
		t.Errorf("a missing stored row was not reported: %v", d)
	}
}
