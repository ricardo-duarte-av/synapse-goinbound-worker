package push

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

// Default action lists, stored as "" (event_push_actions.py
// DEFAULT_NOTIF_ACTION, DEFAULT_HIGHLIGHT_ACTION).
var (
	defaultNotif     = []any{"notify", map[string]any{"set_tweak": "highlight", "value": false}}
	defaultHighlight = []any{"notify", map[string]any{"set_tweak": "sound", "value": "default"}, map[string]any{"set_tweak": "highlight"}}
)

// SerializeActions is the actions column Synapse writes for a row
// (_serialize_action): "" for the default list of the row's kind, otherwise
// the actions as Synapse holds them -- parsed into the Rust evaluator's
// Action and serialized back (rust/src/push/mod.rs) -- encoded by its
// json_encoder.
func SerializeActions(actions []json.RawMessage, highlight bool) string {
	norm := make([]any, 0, len(actions))
	for _, a := range actions {
		norm = append(norm, rustAction(a))
	}
	def := defaultNotif
	if highlight {
		def = defaultHighlight
	}
	if pyEqual(norm, def) {
		return ""
	}
	return pyJSON(norm)
}

// orderedObject is a JSON object with its keys in a given order.
type orderedObject struct {
	keys []string
	vals map[string]any
}

// rustAction is an action after serde's round trip: a string as is; an
// object with a string set_tweak as SetTweak (set_tweak, then value unless
// absent or null, then the other keys sorted, as serde_json's map without
// preserve_order keeps them); anything else as a serde_json Value, whose
// object keys are sorted.
func rustAction(raw json.RawMessage) any {
	v := decode(raw)
	obj, ok := v.(map[string]any)
	if !ok {
		return v
	}
	st, ok := obj["set_tweak"].(string)
	if !ok {
		return v
	}
	o := orderedObject{keys: []string{"set_tweak"}, vals: map[string]any{"set_tweak": st}}
	if val, ok := obj["value"]; ok && val != nil {
		o.keys = append(o.keys, "value")
		o.vals["value"] = val
	}
	var rest []string
	for k := range obj {
		if k != "set_tweak" && k != "value" {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		o.keys = append(o.keys, k)
		o.vals[k] = obj[k]
	}
	return o
}

func decode(raw []byte) any {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	_ = d.Decode(&v)
	return v
}

// pyEqual is Python's == on decoded JSON, as _serialize_action compares
// against the defaults: dicts by key set, and a bool equal to the number
// it counts as.
func pyEqual(a, b any) bool {
	if o, ok := a.(orderedObject); ok {
		a = o.vals
	}
	if o, ok := b.(orderedObject); ok {
		b = o.vals
	}
	if x, ok := pyNumber(a); ok {
		y, ok := pyNumber(b)
		return ok && x == y
	}
	switch a := a.(type) {
	case string:
		b, ok := b.(string)
		return ok && a == b
	case nil:
		return b == nil
	case []any:
		b, ok := b.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !pyEqual(a[i], b[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		b, ok := b.(map[string]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for k, v := range a {
			w, ok := b[k]
			if !ok || !pyEqual(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

func pyNumber(v any) (float64, bool) {
	switch v := v.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

// pyJSON is Synapse's json_encoder: compact separators, ensure_ascii, and
// no HTML escaping. Numbers are written as received.
func pyJSON(v any) string {
	var sb strings.Builder
	writePy(&sb, v)
	return sb.String()
}

func writePy(sb *strings.Builder, v any) {
	switch v := v.(type) {
	case orderedObject:
		sb.WriteByte('{')
		for i, k := range v.keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writePyString(sb, k)
			sb.WriteByte(':')
			writePy(sb, v.vals[k])
		}
		sb.WriteByte('}')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		writePy(sb, orderedObject{keys: keys, vals: v})
	case []any:
		sb.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				sb.WriteByte(',')
			}
			writePy(sb, e)
		}
		sb.WriteByte(']')
	case string:
		writePyString(sb, v)
	case json.Number:
		sb.WriteString(v.String())
	case bool:
		fmt.Fprint(sb, v)
	case nil:
		sb.WriteString("null")
	}
}

// writePyString is json.encoder's py_encode_basestring_ascii.
func writePyString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		default:
			// Anything outside ' '..'~' is escaped.
			switch {
			case r < 0x20 || (r >= 0x7f && r < 0x10000):
				fmt.Fprintf(sb, `\u%04x`, r)
			case r >= 0x10000:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(sb, `\u%04x\u%04x`, hi, lo)
			default:
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}
