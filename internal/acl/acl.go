// Package acl evaluates room server ACLs (m.room.server_acl) for inbound EDUs.
package acl

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ServerACL decides whether a remote server may access a room, per the room's
// m.room.server_acl state event.
//
// This is an access control, so it deliberately mirrors Synapse's Rust
// implementation rather than approximating it: deny is evaluated before allow,
// matching is case-insensitive over the whole name, and anything not explicitly
// allowed is rejected.
type ServerACL struct {
	allowIPLiterals bool
	allow           []*regexp.Regexp
	deny            []*regexp.Regexp
}

// aclContent is the parsed event content. Fields are decoded leniently because
// a malformed ACL event must not break the room; Synapse ignores bad values.
type aclContent struct {
	// Decoded as raw so that a value of the wrong type is ignored rather than
	// failing the whole parse, which is what Synapse does.
	AllowIPLiterals json.RawMessage `json:"allow_ip_literals"`
	Allow           json.RawMessage `json:"allow"`
	Deny            json.RawMessage `json:"deny"`
}

// ParseServerACL builds an evaluator from an m.room.server_acl event's JSON.
//
// Bad values are ignored rather than rejected, matching Synapse: a room whose
// ACL event is malformed keeps working.
func ParseServerACL(eventJSON []byte) (*ServerACL, error) {
	var ev struct {
		Content aclContent `json:"content"`
	}
	if err := json.Unmarshal(eventJSON, &ev); err != nil {
		return nil, fmt.Errorf("acl: parse server acl: %w", err)
	}

	acl := &ServerACL{allowIPLiterals: true}
	if len(ev.Content.AllowIPLiterals) > 0 {
		var b bool
		if err := json.Unmarshal(ev.Content.AllowIPLiterals, &b); err == nil {
			acl.allowIPLiterals = b
		}
		// A non-bool is ignored, leaving the default of true.
	}
	acl.allow = compileGlobs(ev.Content.Allow)
	acl.deny = compileGlobs(ev.Content.Deny)
	return acl, nil
}

// compileGlobs decodes a list of glob strings, skipping any non-string entries.
func compileGlobs(raw json.RawMessage) []*regexp.Regexp {
	if len(raw) == 0 {
		return nil
	}
	var items []any
	if err := json.Unmarshal(raw, &items); err != nil {
		// Not a list at all; Synapse logs and ignores it.
		return nil
	}
	out := make([]*regexp.Regexp, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		re, err := globToRegex(s)
		if err != nil {
			continue
		}
		out = append(out, re)
	}
	return out
}

// Allowed reports whether the server may access the room.
//
// serverName must have any port already stripped, as Synapse does before
// calling its evaluator.
func (a *ServerACL) Allowed(serverName string) bool {
	if a == nil {
		// No ACL event means no restriction.
		return true
	}

	if !a.allowIPLiterals {
		// IPv6 literals are bracketed; IPv4 literals parse as an address.
		if strings.HasPrefix(serverName, "[") {
			return false
		}
		if ip := net.ParseIP(serverName); ip != nil && ip.To4() != nil {
			return false
		}
	}

	for _, re := range a.deny {
		if re.MatchString(serverName) {
			return false
		}
	}
	for _, re := range a.allow {
		if re.MatchString(serverName) {
			return true
		}
	}

	// Anything not explicitly allowed is rejected. An ACL event with an empty
	// allow list bans everyone, which is a documented footgun of the spec but
	// must be honoured.
	return false
}

// globToRegex converts a Matrix ACL glob to an anchored, case-insensitive
// regular expression.
//
// Runs of wildcards are collapsed the way Synapse does, so that a pattern like
// "?**?**?" becomes ".{3,}" rather than a backtracking hazard. Only '*' and '?'
// are wildcards; everything else is literal.
func globToRegex(glob string) (*regexp.Regexp, error) {
	var sb strings.Builder
	sb.WriteString(`\A`)

	for i := 0; i < len(glob); {
		// A run of literal characters.
		start := i
		for i < len(glob) && glob[i] != '*' && glob[i] != '?' {
			i++
		}
		if i > start {
			sb.WriteString(regexp.QuoteMeta(glob[start:i]))
		}

		// A run of wildcards, collapsed into a single quantifier.
		questionMarks, hasStar := 0, false
		for i < len(glob) && (glob[i] == '*' || glob[i] == '?') {
			if glob[i] == '?' {
				questionMarks++
			} else {
				hasStar = true
			}
			i++
		}
		switch {
		case hasStar:
			fmt.Fprintf(&sb, ".{%d,}", questionMarks)
		case questionMarks > 0:
			fmt.Fprintf(&sb, ".{%d}", questionMarks)
		}
	}

	sb.WriteString(`\z`)
	return regexp.Compile(`(?i)` + sb.String())
}
