package synapseauth

import "testing"

func ptr(s string) *string { return &s }

// Each header's outcome is what _parse_auth_header in the Synapse 1.163
// image gives it (run there, 2026-10-26).
func TestParseAuthHeaderAsSynapse(t *testing.T) {
	cases := []struct {
		header           string
		ok               bool
		origin, key, sig string
		dest             *string
	}{
		{"X-Matrix origin=a.org,key=\"ed25519:k\",sig=\"abc\"", true, "a.org", "ed25519:k", "abc", nil},
		{"X-Matrix origin=\"a.org\",key=\"ed25519:k\",sig=\"abc\",destination=\"b.org\"", true, "a.org", "ed25519:k", "abc", ptr("b.org")},
		{"X-Matrix  origin=a.org , key=ed25519:k ,\tsig=abc", true, "a.org", "ed25519:k", "abc", nil},
		{"X-Matrix\torigin=a.org,key=k,sig=s", false, "", "", "", nil},
		{"X-Matrixorigin=a.org,key=k,sig=s", false, "", "", "", nil},
		{"X-Matrix origin=a.org,key=k", false, "", "", "", nil},
		{"X-Matrix origin=a.org,key=k,sig=s,", false, "", "", "", nil},
		{"X-Matrix ORIGIN=a.org,Key=k,SIG=s", true, "a.org", "k", "s", nil},
		{"X-Matrix origin=a.org:8448,key=k,sig=s", true, "a.org:8448", "k", "s", nil},
		{"X-Matrix origin=a.org:,key=k,sig=s", false, "", "", "", nil},
		{"X-Matrix origin=a.org: 80,key=k,sig=s", true, "a.org: 80", "k", "s", nil},
		{"X-Matrix origin=a.org:+8_0,key=k,sig=s", true, "a.org:+8_0", "k", "s", nil},
		{"X-Matrix origin=a_b.org,key=k,sig=s", false, "", "", "", nil},
		{"X-Matrix origin=[::1]:8448,key=k,sig=s", true, "[::1]:8448", "k", "s", nil},
		{"X-Matrix origin=[::1,key=k,sig=s", false, "", "", "", nil},
		{"X-Matrix origin=1.2.3.4,key=k,sig=s", true, "1.2.3.4", "k", "s", nil},
		{"X-Matrix origin=\"a\\.org\",key=\"k\\\"x\",sig=\"s\"", true, "a.org", "k\"x", "s", nil},
		{"X-Matrix origin=\",key=k,sig=s", false, "", "", "", nil},
		{"X-Matrix origin=a.org,key=k,sig=s=x", true, "a.org", "k", "s=x", nil},
		{"X-Matrix origin=a.org.,key=k,sig=s", false, "", "", "", nil},
		{"X-Matrix origin=,key=k,sig=s", false, "", "", "", nil},
		{"X-Matrix origin=a.org,origin=b.org,key=k,sig=s", true, "b.org", "k", "s", nil},
		{"X-Matrix origin=a.org,key=k,sig=s,destination=x", true, "a.org", "k", "s", ptr("x")},
		{"X-Matrix origin=a.org,key=k,sig=\"s", true, "a.org", "k", "", nil},
	}
	for _, c := range cases {
		o, k, s, d, ok := parseAuthHeader(c.header)
		if ok != c.ok || o != c.origin || k != c.key || s != c.sig || (d == nil) != (c.dest == nil) || d != nil && *d != *c.dest {
			t.Errorf("%q: got %v %q %q %q %v, want %v %q %q %q %v", c.header, ok, o, k, s, d, c.ok, c.origin, c.key, c.sig, c.dest)
		}
	}
}
