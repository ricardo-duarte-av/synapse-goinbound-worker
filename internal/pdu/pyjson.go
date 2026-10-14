package pdu

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

// Synapse reads event content as Python objects decoded by the json module, so
// the questions it asks are Python's: is the key present (even if null), is a
// value None, what does int() make of it. These helpers answer them the same
// way, over raw JSON.

// field returns obj[key] as Python's dict would: for a duplicated key the LAST
// occurrence wins, as json.loads does. A path lookup is deliberately avoided --
// keys are arbitrary strings, and gjson path syntax gives '.', '*' and '?'
// meaning.
func field(obj gjson.Result, key string) (gjson.Result, bool) {
	if !obj.IsObject() {
		return gjson.Result{}, false
	}
	var out gjson.Result
	found := false
	obj.ForEach(func(k, v gjson.Result) bool {
		if k.String() == key {
			out, found = v, true
		}
		return true
	})
	return out, found
}

// get is Python's obj.get(key): None (a zero Result) when absent or null.
func get(obj gjson.Result, key string) gjson.Result {
	v, ok := field(obj, key)
	if !ok || v.Type == gjson.Null {
		return gjson.Result{}
	}
	return v
}

// has is Python's `key in obj`, true even when the value is null.
func has(obj gjson.Result, key string) bool {
	_, ok := field(obj, key)
	return ok
}

func isNone(v gjson.Result) bool { return !v.Exists() || v.Type == gjson.Null }

// keys returns an object's keys in document order, deduplicated as a Python
// dict would be.
func keys(obj gjson.Result) []string {
	var out []string
	seen := map[string]bool{}
	obj.ForEach(func(k, _ gjson.Result) bool {
		s := k.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		return true
	})
	return out
}

// isFloat reports whether json.loads would produce a float for this number.
func isFloat(v gjson.Result) bool {
	return v.Type == gjson.Number && strings.ContainsAny(v.Raw, ".eE")
}

// isPyInt is Python's `type(v) is int`: an integral JSON number. A bool is not
// an int by this test, which is the point of using `type(v) is int` over
// isinstance.
func isPyInt(v gjson.Result) bool { return v.Type == gjson.Number && !isFloat(v) }

// errPyInt is the ValueError or TypeError int() raises. It is not an AuthError,
// so in Synapse it escapes the auth check altogether.
var errPyInt = errors.New("int() failed")

// pyInt is Python's int() applied to a decoded JSON value:
//
//	int(5) = 5, int(5.9) = 5, int(True) = 1, int(" 42 ") = 42, int("1_000") = 1000
//	int("5.0"), int(None), int([]), int({}) raise
func pyInt(v gjson.Result) (int64, error) {
	switch v.Type {
	case gjson.True:
		return 1, nil
	case gjson.False:
		return 0, nil
	case gjson.Number:
		if isFloat(v) {
			f := v.Float()
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return 0, fmt.Errorf("%w: %s", errPyInt, v.Raw)
			}
			return int64(math.Trunc(f)), nil
		}
		n, err := strconv.ParseInt(v.Raw, 10, 64)
		if err != nil {
			// Beyond int64. Canonical JSON caps integers at 2^53, so only
			// a pre-v6 room can hold one, and nothing compares that large.
			return 0, fmt.Errorf("%w: %s", errPyInt, v.Raw)
		}
		return n, nil
	case gjson.String:
		return pyIntString(v.Str)
	default:
		return 0, fmt.Errorf("%w: %s", errPyInt, v.Raw)
	}
}

// pyIntString is int(str): surrounding whitespace, an optional sign, decimal
// digits with single underscores between them.
func pyIntString(s string) (int64, error) {
	t := strings.TrimSpace(s)
	neg := false
	if t != "" && (t[0] == '+' || t[0] == '-') {
		neg = t[0] == '-'
		t = t[1:]
	}
	if t == "" || t[0] == '_' || t[len(t)-1] == '_' || strings.Contains(t, "__") {
		return 0, fmt.Errorf("%w: %q", errPyInt, s)
	}
	digits := strings.ReplaceAll(t, "_", "")
	for _, c := range digits {
		// Python accepts any Unicode decimal digit; JSON content in rooms
		// that hold such power levels is beyond what this needs to match.
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%w: %q", errPyInt, s)
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", errPyInt, s)
	}
	if neg {
		n = -n
	}
	return n, nil
}

// pyEqualString is Python's `a == b` where b is a string: true only when a is
// a JSON string with that value.
func pyEqualString(v gjson.Result, s string) bool {
	return v.Type == gjson.String && v.Str == s
}

// PyInt is Python's int() over a decoded JSON value; see pyInt.
func PyInt(v gjson.Result) (int64, error) { return pyInt(v) }

// IsPyInt is type(v) is int.
func IsPyInt(v gjson.Result) bool { return isPyInt(v) }
