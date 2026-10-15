package acl

import (
	"math/rand/v2"
	"strings"
	"testing"
)

func acl(t *testing.T, content string) *ServerACL {
	t.Helper()
	a, err := ParseServerACL([]byte(`{"type":"m.room.server_acl","content":` + content + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestServerACL(t *testing.T) {
	cases := []struct {
		name    string
		content string
		server  string
		want    bool
	}{
		// The canonical spec example.
		{"allow wildcard", `{"allow":["*"]}`, "evil.com", true},
		{"deny beats allow", `{"allow":["*"],"deny":["evil.com"]}`, "evil.com", false},
		{"deny does not affect others", `{"allow":["*"],"deny":["evil.com"]}`, "good.com", true},
		{"suffix glob", `{"allow":["*.example.com"]}`, "matrix.example.com", true},
		{"suffix glob does not match bare domain", `{"allow":["*.example.com"]}`, "example.com", false},
		{"deny glob", `{"allow":["*"],"deny":["*.evil.com"]}`, "a.evil.com", false},

		// An empty allow list bans everyone. This is a known spec footgun and
		// must be honoured, not softened.
		{"empty allow bans all", `{"allow":[]}`, "good.com", false},
		{"missing allow bans all", `{"deny":["evil.com"]}`, "good.com", false},

		// Matching is over the whole name, so a substring must not match.
		{"substring does not match", `{"allow":["example.com"]}`, "notexample.com.evil", false},
		{"exact match", `{"allow":["example.com"]}`, "example.com", true},

		// Case-insensitive.
		{"case insensitive allow", `{"allow":["Example.COM"]}`, "example.com", true},
		{"case insensitive deny", `{"allow":["*"],"deny":["EVIL.com"]}`, "evil.COM", false},

		// '?' matches exactly one character.
		{"question mark", `{"allow":["e?il.com"]}`, "evil.com", true},
		{"question mark is not multi", `{"allow":["e?il.com"]}`, "eviil.com", false},

		// Dots in a glob are literal, not regex wildcards.
		{"dot is literal", `{"allow":["example.com"]}`, "exampleXcom", false},

		// IP literals.
		{"ipv4 blocked", `{"allow":["*"],"allow_ip_literals":false}`, "1.2.3.4", false},
		{"ipv6 blocked", `{"allow":["*"],"allow_ip_literals":false}`, "[::1]", false},
		{"ipv4 allowed by default", `{"allow":["*"]}`, "1.2.3.4", true},
		{"hostname unaffected by ip rule", `{"allow":["*"],"allow_ip_literals":false}`, "example.com", true},

		// Malformed content must not break the room.
		{"non-list allow ignored", `{"allow":"*"}`, "example.com", false},
		{"non-string entries skipped", `{"allow":[1,"example.com",null]}`, "example.com", true},
		{"non-bool ip literals ignored", `{"allow":["*"],"allow_ip_literals":"yes"}`, "1.2.3.4", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := acl(t, tc.content).Allowed(tc.server); got != tc.want {
				t.Errorf("Allowed(%q) with %s = %v, want %v", tc.server, tc.content, got, tc.want)
			}
		})
	}
}

func TestNilACLAllowsEverything(t *testing.T) {
	// A room with no m.room.server_acl event places no restriction.
	var a *ServerACL
	if !a.Allowed("anything.example") {
		t.Error("a room with no ACL event should allow every server")
	}
}

func TestGlobToRegexCollapsesWildcardRuns(t *testing.T) {
	// "?**?**?" has three '?' and at least one '*', so it must behave as
	// "three or more characters" rather than compiling to a backtracking mess.
	re, err := globToRegex("?**?**?")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"ab", false},
		{"abc", true},
		{"abcd", true},
		{"abcdefghij", true},
	} {
		if got := re.MatchString(tc.in); got != tc.want {
			t.Errorf("%q match %q = %v, want %v", re, tc.in, got, tc.want)
		}
	}
}

func TestParseServerACLRejectsInvalidJSON(t *testing.T) {
	if _, err := ParseServerACL([]byte("{not json")); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

// The ACL cache is keyed by the ACL event's ID, not the room's, so a room that
// changes its ACL cannot be served the old one — the key changes with it.
// This is the property that makes caching a *mutable* piece of room state safe
// without any invalidation signal.

// glob.match must agree with the regular expression it replaces, which is
// what Synapse's glob_to_regex builds.
func TestGlobMatchesItsRegex(t *testing.T) {
	alphabet := []rune("ab.*?:-KkKéÉ\n")
	rng := rand.New(rand.NewPCG(1, 2))
	word := func(n int, wild bool) string {
		var sb strings.Builder
		for range rng.IntN(n) {
			r := alphabet[rng.IntN(len(alphabet))]
			if !wild && (r == '*' || r == '?') {
				r = 'a'
			}
			sb.WriteRune(r)
		}
		return sb.String()
	}
	fixed := [][2]string{
		{"*.evil.example", "a.evil.example"}, {"*.evil.example", "evil.example"},
		{"EVIL.example", "evil.EXAMPLE"}, {"?**?**?", "ab"}, {"?**?**?", "abc"},
		{"*", ""}, {"", ""}, {"a*b*c", "aXbYbc"}, {"k", "K"}, {"*", "a\nb"},
	}
	check := func(g, name string) {
		re, err := globToRegex(g)
		if err != nil {
			t.Fatalf("%q: %v", g, err)
		}
		if got, want := glob(g).match(name), re.MatchString(name); got != want {
			t.Errorf("glob %q on %q: %v, regexp says %v", g, name, got, want)
		}
	}
	for _, c := range fixed {
		check(c[0], c[1])
	}
	for range 200_000 {
		check(word(8, true), word(10, false))
	}
}

// A glob the regexp could not represent was skipped, so it still is.
func TestOverlongWildcardRunIsSkipped(t *testing.T) {
	a := acl(t, `{"allow":["*"],"deny":["`+strings.Repeat("?", 1001)+`*"]}`)
	if !a.Allowed(strings.Repeat("a", 2000)) {
		t.Error("an uncompilable deny glob applied")
	}
}
