package inbound

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestTestDropTakesOnlyItsCount(t *testing.T) {
	d := NewTestDrop("daedric.net", "!r:x", 2, zerolog.Nop())
	if d.take("matrix.org", "!r:x", "$a") || d.take("daedric.net", "!other:x", "$b") {
		t.Error("dropped outside its origin and room")
	}
	if !d.take("daedric.net", "!r:x", "$c") || !d.take("daedric.net", "!r:x", "$d") {
		t.Error("did not drop its count")
	}
	if d.take("daedric.net", "!r:x", "$e") {
		t.Error("dropped past its count")
	}
	var none *TestDrop
	if none.take("daedric.net", "!r:x", "$f") {
		t.Error("nil dropped")
	}
}
