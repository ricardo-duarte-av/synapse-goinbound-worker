package pduverify

import (
	"testing"

	"github.com/tidwall/gjson"
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
