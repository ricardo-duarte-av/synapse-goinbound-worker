package pdu

import "testing"

// Python's canonicaljson escapes control characters in lowercase hex; an
// escaped backslash followed by "u001F" is text, left as it is.
func TestCanonicalEscapesAsPython(t *testing.T) {
	in := `{"a":"\u001B[31m\u0001\n\u001f\\u001F"}`
	want := `{"a":"\u001b[31m\u0001\n\u001f\\u001F"}`
	got, err := Canonical([]byte(in))
	if err != nil || string(got) != want {
		t.Errorf("got %s %v, want %s", got, err, want)
	}
}

// Each event's words are what the Synapse 1.163 image's
// check_event_content_hash raises for it (run there, 2026-10-26); "" is
// left to Synapse: a string it may decode leniently.
func TestContentHashRaiseAsSynapse(t *testing.T) {
	for raw, want := range map[string]string{
		`{}`:                               "400: Malformed 'hashes': <class 'NoneType'>",
		`{"hashes":null}`:                  "400: Malformed 'hashes': <class 'NoneType'>",
		`{"hashes":"x"}`:                   "400: Malformed 'hashes': <class 'str'>",
		`{"hashes":5}`:                     "400: Malformed 'hashes': <class 'int'>",
		`{"hashes":1.5}`:                   "400: Malformed 'hashes': <class 'float'>",
		`{"hashes":true}`:                  "400: Malformed 'hashes': <class 'bool'>",
		`{"hashes":[1]}`:                   "400: Malformed 'hashes': <class 'list'>",
		`{"hashes":{}}`:                    "400: Algorithm sha256 not in hashes []",
		`{"hashes":{"md5":"a","x y":"b"}}`: "400: Algorithm sha256 not in hashes ['md5', 'x y']",
		`{"hashes":{"sha256":5}}`:          "400: Invalid base64: 5",
		`{"hashes":{"sha256":null}}`:       "400: Invalid base64: None",
		`{"hashes":{"sha256":false}}`:      "400: Invalid base64: False",
		`{"hashes":{"sha256":-0}}`:         "400: Invalid base64: 0",
		`{"hashes":{"sha256":"!!!"}}`:      "",
		`{"hashes":{"sha256":"a"}}`:        "",
	} {
		got, ok := ContentHashRaise([]byte(raw))
		if want == "" && ok || want != "" && (!ok || got != want) {
			t.Errorf("%s: %q %v, want %q", raw, got, ok, want)
		}
	}
}
