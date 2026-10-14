package push

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tidwall/gjson"
)

// Flat is _flatten_dict's result: dotted keys to a simple value or a list of
// them.
type Flat map[string]FlatValue

// FlatValue is Rust's JsonValue: Array or Value.
type FlatValue struct {
	IsArray bool
	V       Value
	Arr     []Value
}

// Flatten is _flatten_dict (bulk_push_rule_evaluator.py:571) over raw JSON:
// nested objects become dotted keys (with '.' and '\' in keys escaped),
// strings, bools, integers and nulls are kept, lists keep only those, and
// anything else -- floats, lists of objects -- is dropped. Top-level keys
// listed in skip are left out.
func Flatten(raw []byte, skip ...string) Flat {
	out := Flat{}
	skipSet := map[string]bool{}
	for _, s := range skip {
		skipSet[s] = true
	}
	flattenInto(out, gjson.ParseBytes(raw), "", skipSet)
	return out
}

func flattenInto(out Flat, obj gjson.Result, prefix string, skip map[string]bool) {
	obj.ForEach(func(k, v gjson.Result) bool {
		key := k.String()
		if prefix == "" && skip[key] {
			return true
		}
		key = strings.ReplaceAll(key, `\`, `\\`)
		key = strings.ReplaceAll(key, ".", `\.`)
		full := key
		if prefix != "" {
			full = prefix + "." + key
		}
		if sv, ok := flatSimple(v); ok {
			out[full] = FlatValue{V: sv}
			return true
		}
		switch {
		case v.IsArray():
			arr := []Value{}
			for _, e := range v.Array() {
				if sv, ok := flatSimple(e); ok {
					arr = append(arr, sv)
				}
			}
			out[full] = FlatValue{IsArray: true, Arr: arr}
		case v.IsObject():
			flattenInto(out, v, full, nil)
		default:
			// Floats: dropped. A key set earlier by a duplicate stays
			// removed, as reassigning would have overwritten it.
			delete(out, full)
		}
		return true
	})
}

// flatSimple is _is_simple_value: bool, str, an int that is not a float,
// or None.
func flatSimple(v gjson.Result) (Value, bool) {
	if v.Type == gjson.Number && strings.ContainsAny(v.Raw, ".eE") {
		return Value{}, false
	}
	return simpleValue(v)
}

// Evaluator is PushRuleEvaluator (rust/src/push/evaluator.rs).
type Evaluator struct {
	Flat                      Flat
	HasMentions               bool
	RoomMemberCount           uint64
	NotificationLevels        map[string]int64
	SenderPowerLevel          *int64
	Related                   map[string]Flat
	RelatedEventMatch         bool
	RoomVersionFeatures       []string
	MSC3931, MSC4210, MSC4306 bool

	body string
}

// NewEvaluator builds an evaluator; body is content.body when a string.
func NewEvaluator(e Evaluator) *Evaluator {
	if v, ok := e.Flat["content.body"]; ok && !v.IsArray && v.V.Kind == 's' {
		e.body = v.V.S
	}
	return &e
}

var safeExtensibleRules = map[string]bool{
	"global/override/.m.rule.master":            true,
	"global/override/.m.rule.roomnotif":         true,
	"global/content/.m.rule.contains_user_name": true,
}

const extensibleEvents = "org.matrix.msc3932.extensible_events"

// Run is PushRuleEvaluator::run: the actions of the first enabled rule whose
// conditions all match, without dont_notify and coalesce.
func (e *Evaluator) Run(rules *Filtered, userID, displayName string, threadSubscribed *bool) []json.RawMessage {
	supportsExtensible := false
	for _, f := range e.RoomVersionFeatures {
		if f == extensibleEvents {
			supportsExtensible = true
		}
	}
outer:
	for i, r := range rules.rules {
		if !rules.enabled[i] {
			continue
		}
		if (e.HasMentions || e.MSC4210) && (r.ID == "global/override/.m.rule.contains_display_name" ||
			r.ID == "global/content/.m.rule.contains_user_name" || r.ID == "global/override/.m.rule.roomnotif") {
			continue
		}
		hasRver := false
		for _, c := range r.Conditions {
			if c.Known && c.Kind == "org.matrix.msc3931.room_version_supports" {
				hasRver = true
			}
			ok, err := e.Match(c, userID, displayName, threadSubscribed)
			if err != nil || !ok {
				continue outer
			}
		}
		if !hasRver && !safeExtensibleRules[r.ID] && supportsExtensible {
			continue
		}
		var out []json.RawMessage
		for _, a := range r.Actions {
			s := strings.TrimSpace(string(a))
			if s == `"dont_notify"` || s == `"coalesce"` {
				continue
			}
			out = append(out, a)
		}
		return out
	}
	return nil
}

// Match is match_condition. An error means the rule is skipped.
func (e *Evaluator) Match(c Condition, userID, displayName string, threadSubscribed *bool) (bool, error) {
	if !c.Known {
		return false, nil
	}
	pattern := func() (string, bool, error) {
		if userID == "" {
			return "", false, nil
		}
		if c.PatternType == "user_localpart" {
			lp, err := localpart(userID)
			return lp, err == nil, err
		}
		return userID, true, nil
	}
	switch c.Kind {
	case "event_match":
		return e.matchEventMatch(e.Flat, c.Key, c.Pattern)
	case "event_match_type":
		p, ok, err := pattern()
		if !ok {
			return false, err
		}
		return e.matchEventMatch(e.Flat, c.Key, p)
	case "event_property_is":
		v, ok := e.Flat[c.Key]
		if !ok || v.IsArray {
			return false, nil
		}
		return v.V.equal(c.Value), nil
	case "im.nheko.msc3664.related_event_match":
		return e.matchRelated(c.RelType, c.IncludeFallbacks, c.Key, c.HasKey, c.Pattern, c.HasPattern)
	case "related_event_match_type":
		p, ok, err := pattern()
		if !ok {
			return false, err
		}
		return e.matchRelated(c.RelType, c.IncludeFallbacks, c.Key, true, p, true)
	case "event_property_contains":
		return e.matchContains(c.Key, c.Value), nil
	case "exact_event_property_contains_type":
		p, ok, err := pattern()
		if !ok {
			return false, err
		}
		return e.matchContains(c.Key, Value{Kind: 's', S: p}), nil
	case "contains_display_name":
		if displayName == "" {
			return false, nil
		}
		m, err := globMatcher(displayName, true)
		if err != nil {
			return false, err
		}
		return m.match(e.body)
	case "room_member_count":
		if c.Is == nil {
			return false, nil
		}
		return e.matchMemberCount(*c.Is)
	case "sender_notification_permission":
		if e.SenderPowerLevel == nil {
			return false, nil
		}
		required, ok := e.NotificationLevels[c.Key]
		if !ok {
			required = 50
		}
		return *e.SenderPowerLevel >= required, nil
	case "org.matrix.msc3931.room_version_supports":
		if !e.MSC3931 || c.Feature != extensibleEvents {
			return false, nil
		}
		for _, f := range e.RoomVersionFeatures {
			if f == c.Feature {
				return true, nil
			}
		}
		return false, nil
	case "io.element.msc4306.thread_subscription":
		if !e.MSC4306 {
			return false, nil
		}
		return threadSubscribed != nil && *threadSubscribed == c.Subscribed, nil
	}
	return false, nil
}

func (e *Evaluator) matchEventMatch(flat Flat, key, pattern string) (bool, error) {
	v, ok := flat[key]
	if !ok || v.IsArray || v.V.Kind != 's' {
		return false, nil
	}
	m, err := globMatcher(pattern, key == "content.body")
	if err != nil {
		return false, err
	}
	return m.match(v.V.S)
}

func (e *Evaluator) matchRelated(relType string, includeFallbacks *bool, key string, hasKey bool, pattern string, hasPattern bool) (bool, error) {
	if !e.RelatedEventMatch {
		return false, nil
	}
	ev, ok := e.Related[relType]
	if !ok {
		return false, nil
	}
	if (includeFallbacks == nil || !*includeFallbacks) && hasFlatKey(ev, "im.vector.is_falling_back") {
		return false, nil
	}
	switch {
	case !hasKey:
		return true, nil
	case !hasPattern:
		return false, nil
	}
	return e.matchEventMatch(ev, key, pattern)
}

func hasFlatKey(f Flat, k string) bool { _, ok := f[k]; return ok }

func (e *Evaluator) matchContains(key string, want Value) bool {
	v, ok := e.Flat[key]
	if !ok || !v.IsArray {
		return false
	}
	for _, x := range v.Arr {
		if x.equal(want) {
			return true
		}
	}
	return false
}

var inequality = regexp.MustCompile(`^([=<>]*)([0-9]+)$`)

var errBadIs = errors.New("push: bad 'is' clause")

func (e *Evaluator) matchMemberCount(is string) (bool, error) {
	m := inequality.FindStringSubmatch(is)
	if m == nil {
		return false, errBadIs
	}
	rhs, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil {
		return false, err
	}
	n := e.RoomMemberCount
	switch m[1] {
	case "", "==":
		return n == rhs, nil
	case "<":
		return n < rhs, nil
	case ">":
		return n > rhs, nil
	case ">=":
		return n >= rhs, nil
	case "<=":
		return n <= rhs, nil
	}
	return false, nil
}

// localpart is get_localpart_from_id: up to the first colon, without the
// sigil; an empty part before the colon is an error.
func localpart(id string) (string, error) {
	i := strings.IndexByte(id, ':')
	if i < 0 {
		return "", errors.New("push: ID does not contain colon")
	}
	if i == 0 {
		return "", errors.New("push: invalid ID")
	}
	_, size := utf8.DecodeRuneInString(id)
	if size > i {
		return "", errors.New("push: invalid ID")
	}
	return id[size:i], nil
}

// --- globs (rust/src/push/utils.rs) ---

// matcher is utils::Matcher.
type matcher struct {
	word    bool
	literal string         // lowercased glob, when it has no wildcards
	re      *regexp.Regexp // the glob's core, anchored at both ends
}

var wildcardRun = regexp.MustCompile(`([^?*]*)([?*]*)`)

// globCore is glob_to_regex without its anchors: literal runs escaped, and
// each run of wildcards collapsed to .{n} or .{n,}.
func globCore(glob string) string {
	var b strings.Builder
	for _, m := range wildcardRun.FindAllStringSubmatch(glob, -1) {
		b.WriteString(regexp.QuoteMeta(m[1]))
		w := m[2]
		if w == "" {
			continue
		}
		q := strings.Count(w, "?")
		if strings.Contains(w, "*") {
			b.WriteString(".{" + strconv.Itoa(q) + ",}")
		} else {
			b.WriteString(".{" + strconv.Itoa(q) + "}")
		}
	}
	return b.String()
}

// globMatcher is get_glob_matcher. word selects GlobMatchType::Word.
func globMatcher(glob string, word bool) (*matcher, error) {
	m := &matcher{word: word}
	if !strings.ContainsAny(glob, "*?") {
		m.literal = strings.ToLower(glob)
		if !word {
			return m, nil
		}
	}
	// '.' must not match a newline, as in Rust's default: (?s) is off. A
	// repetition count too large for the engine is an error in both.
	re, err := regexp.Compile(`(?i)\A(?:` + globCore(glob) + `)\z`)
	if err != nil {
		return nil, err
	}
	m.re = re
	return m, nil
}

// maxWordScan bounds the brute-force word match over a wildcard glob, which
// is quadratic in the haystack. Synapse has no such bound; a body this long
// with a wildcard rule is reported as uncertain rather than guessed.
const maxWordScan = 4096

// ErrTooLong is a wildcard word match over a haystack too long to scan.
var ErrTooLong = errors.New("push: haystack too long for a wildcard word match")

// match is Matcher::is_match, on the lowercased haystack.
func (m *matcher) match(haystack string) (bool, error) {
	h := strings.ToLower(haystack)
	if !m.word {
		if m.re == nil {
			return m.literal == h, nil
		}
		return m.re.MatchString(h), nil
	}
	if m.literal != "" || m.re == nil {
		if !strings.Contains(h, m.literal) {
			return false, nil
		}
		// A literal word: every occurrence, checked for boundaries.
		for i := 0; ; {
			j := strings.Index(h[i:], m.literal)
			if j < 0 {
				return false, nil
			}
			p := i + j
			if wordBounded(h, p, p+len(m.literal)) {
				return true, nil
			}
			_, size := utf8.DecodeRuneInString(h[p:])
			if size == 0 {
				return false, nil
			}
			i = p + size
		}
	}
	if utf8.RuneCountInString(h) > maxWordScan {
		return false, ErrTooLong
	}
	starts := runeStarts(h)
	for _, p := range starts {
		for k := len(starts); k >= 0; k-- {
			q := len(h)
			if k < len(starts) {
				q = starts[k]
			}
			if q < p {
				break
			}
			if wordBounded(h, p, q) && m.re.MatchString(h[p:q]) {
				return true, nil
			}
		}
	}
	return false, nil
}

func runeStarts(s string) []int {
	var out []int
	for i := range s {
		out = append(out, i)
	}
	return out
}

// wordBounded is whether h[p:q] sits at word boundaries as Rust's Unicode
// `(?:^|\b|\W)…(?:\b|\W|$)` requires: on the left, the start of the text, or
// a non-word character before, or a non-word character first; on the right,
// likewise. Rust's \b and \W are Unicode-aware, Go's are not -- which is why
// this is done by hand.
func wordBounded(h string, p, q int) bool {
	left := p == 0
	if !left {
		prev, _ := utf8.DecodeLastRuneInString(h[:p])
		left = !isWord(prev)
		if !left && q > p {
			first, _ := utf8.DecodeRuneInString(h[p:])
			left = !isWord(first)
		}
	}
	if !left {
		return false
	}
	if q == len(h) {
		return true
	}
	next, _ := utf8.DecodeRuneInString(h[q:])
	if !isWord(next) {
		return true
	}
	if q > p {
		last, _ := utf8.DecodeLastRuneInString(h[:q])
		return !isWord(last)
	}
	return false
}

// isWord is Rust regex's Unicode \w: alphabetic, marks, decimal digits,
// connector punctuation and the joiners.
func isWord(r rune) bool {
	return unicode.IsLetter(r) || unicode.Is(unicode.Nl, r) || unicode.Is(unicode.M, r) ||
		unicode.Is(unicode.Nd, r) || unicode.Is(unicode.Pc, r) || r == 0x200C || r == 0x200D
}

// Notifies reports whether actions include "notify".
func Notifies(actions []json.RawMessage) bool {
	for _, a := range actions {
		if strings.TrimSpace(string(a)) == `"notify"` {
			return true
		}
	}
	return false
}

// Highlights is _action_has_highlight
// (storage/databases/main/event_push_actions.py:1954), which decides the
// stored highlight flag: the FIRST highlight tweak decides, by the Python
// truthiness of its value, which defaults to True.
func Highlights(actions []json.RawMessage) bool {
	for _, a := range actions {
		v := gjson.ParseBytes(a)
		if !v.IsObject() || v.Get("set_tweak").Str != "highlight" {
			continue
		}
		val := v.Get("value")
		if !val.Exists() {
			return true
		}
		return pyTruthy(val)
	}
	return false
}

func pyTruthy(v gjson.Result) bool {
	switch v.Type {
	case gjson.Null, gjson.False:
		return false
	case gjson.Number:
		return v.Float() != 0
	case gjson.String:
		return v.Str != ""
	case gjson.JSON:
		if v.IsArray() {
			return len(v.Array()) > 0
		}
		n := 0
		v.ForEach(func(_, _ gjson.Result) bool { n++; return false })
		return n > 0
	}
	return true
}
