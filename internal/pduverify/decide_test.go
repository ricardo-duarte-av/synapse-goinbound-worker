package pduverify

import (
	"testing"
	"time"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

func TestDeviceResyncNeeded(t *testing.T) {
	cached := map[string][]byte{
		"DEV1":  []byte(`{"keys":{"keys":{"curve25519:DEV1":"K1","ed25519:DEV1":"E1"}}}`),
		"DEV2":  []byte(`{"keys":{"keys":{"curve25519:DEV2":"K2"}}}`),
		"EMPTY": []byte(`{}`),
	}
	megolm := `"algorithm":"m.megolm.v1.aes-sha2"`
	for _, c := range []struct {
		content string
		want    bool
	}{
		{`{"device_id":"DEV1","sender_key":"K1",` + megolm + `}`, false},
		{`{"device_id":"DEV1","sender_key":"E1",` + megolm + `}`, true},       // megolm wants the curve25519 key
		{`{"device_id":"DEV1","sender_key":"E1","algorithm":"other"}`, false}, // any of the device's keys
		{`{"device_id":"NEW","sender_key":"K1",` + megolm + `}`, true},
		{`{"device_id":"DEV1"}`, false},
		{`{"device_id":"NEW"}`, true},
		{`{"sender_key":"K2"}`, false}, // any key of any device
		{`{"sender_key":"K9"}`, true},
		{`{}`, false},
		{`{"device_id":"EMPTY","sender_key":"K1"}`, true}, // an empty device is no device: no keys
		{`{"device_id":null,"sender_key":"K2"}`, false},
	} {
		if got := deviceResyncNeeded(gjson.Parse(c.content), cached); got != c.want {
			t.Errorf("%s: %v, want %v", c.content, got, c.want)
		}
	}
}

func TestStateCache(t *testing.T) {
	c := NewStateCache()
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	e := NewEntry(0, 5, pdu.StateMap{{Type: "x"}: "$x"}, nil)
	c.put([]int64{9, 7}, e)
	// The key is the set of groups, in any order.
	if got := c.get([]int64{7, 9}); got != e {
		t.Fatal("entry not found by the same groups")
	}
	// Storing the group is seen by every later hit.
	e.SetGroup(42)
	if c.get([]int64{9, 7}).Group() != 42 {
		t.Error("group not shared")
	}
	c.DropUngrouped([]int64{7, 9})
	if c.get([]int64{7, 9}) == nil {
		t.Error("a grouped entry was dropped")
	}
	c.put([]int64{1, 2}, NewEntry(0, 0, nil, pdu.StateMap{}))
	c.DropUngrouped([]int64{2, 1})
	if c.get([]int64{1, 2}) != nil {
		t.Error("an ungrouped entry was kept")
	}
	now = now.Add(61 * time.Minute)
	if c.get([]int64{7, 9}) != nil {
		t.Error("an entry outlived its hour")
	}
}

// EventContext.for_outlier, serialized as fed_send_events sends it.
func TestOutlierEntry(t *testing.T) {
	rv, _ := pdu.LookupRoomVersion("10")
	raw := []byte(`{"type":"m.room.member","state_key":"@a:x","sender":"@a:x","room_id":"!r:x","content":{"membership":"join"},"depth":1,"origin_server_ts":1,"prev_events":[],"auth_events":[],"hashes":{"sha256":"x"},"signatures":{},"unsigned":{}}`)
	ev, err := pdu.ParseEvent(raw, "$e", rv, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OutlierEntry(raw, ev, map[string]any{"soft_failed": true}, RejectedAuthError)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"outlier": "true", "rejected_reason": `"auth_error"`, "room_version": `"10"`,
		"internal_metadata": `{"outlier":true,"soft_failed":true}`,
		"context":           `{"state_group":null,"state_group_before_event":null,"rejected":"auth_error","state_group_deltas":[],"state_delta_due_to_event":null,"app_service_id":null,"partial_state":false}`,
	} {
		if got := gjson.GetBytes(b, path).Raw; got != want {
			t.Errorf("%s: %s, want %s", path, got, want)
		}
	}
}
