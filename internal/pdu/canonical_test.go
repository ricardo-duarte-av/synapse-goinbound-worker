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
