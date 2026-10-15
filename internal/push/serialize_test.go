package push

import (
	"encoding/json"
	"testing"
)

func TestSerializeActions(t *testing.T) {
	raw := func(s string) []json.RawMessage {
		var out []json.RawMessage
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := []struct {
		name, actions string
		highlight     bool
		want          string
	}{
		{"default notify", `["notify",{"set_tweak":"highlight","value":false}]`, false, ""},
		{"default notify, keys reordered", `["notify",{"value":false,"set_tweak":"highlight"}]`, false, ""},
		{"False == 0", `["notify",{"set_tweak":"highlight","value":0}]`, false, ""},
		{"default highlight", `["notify",{"set_tweak":"sound","value":"default"},{"set_tweak":"highlight"}]`, true, ""},
		{"default highlight is not the notify default", `["notify",{"set_tweak":"sound","value":"default"},{"set_tweak":"highlight"}]`, false,
			`["notify",{"set_tweak":"sound","value":"default"},{"set_tweak":"highlight"}]`},
		{"plain notify", `["notify"]`, false, `["notify"]`},
		{"null value dropped", `["notify",{"set_tweak":"sound","value":null}]`, false, `["notify",{"set_tweak":"sound"}]`},
		{"tweak keys: set_tweak, value, rest sorted", `["notify",{"z":1,"value":"x","a":2,"set_tweak":"s"}]`, false,
			`["notify",{"set_tweak":"s","value":"x","a":2,"z":1}]`},
		{"unknown action, keys sorted", `["notify",{"b":1,"a":{"d":1,"c":2}}]`, false, `["notify",{"a":{"c":2,"d":1},"b":1}]`},
		{"ensure_ascii, no HTML escaping", `["notify",{"set_tweak":"sound","value":"\u00e9<>&\ud83d\ude00"}]`, false,
			`["notify",{"set_tweak":"sound","value":"` + `\` + `u00e9<>&` + `\` + `ud83d` + `\` + `ude00"}]`},
	}
	for _, c := range cases {
		if got := SerializeActions(raw(c.actions), c.highlight); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
