// Package push is a port of Synapse's push rule evaluator
// (rust/src/push/*.rs, synapse/push/bulk_push_rule_evaluator.py): which
// actions an event triggers for a user, given their push rules.
//
// It follows Synapse's Rust code, including its serde semantics for rules
// stored in the database: a condition that does not deserialize as a known
// kind is Unknown, and an unknown condition never matches.
package push

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

// Value is Rust's SimpleJsonValue: a string, an integer, a bool or null.
type Value struct {
	Kind byte // 's', 'i', 'b', 'n'
	S    string
	I    int64
	B    bool
}

func (v Value) equal(o Value) bool {
	if v.Kind != o.Kind {
		return false
	}
	switch v.Kind {
	case 's':
		return v.S == o.S
	case 'i':
		return v.I == o.I
	case 'b':
		return v.B == o.B
	}
	return true
}

// simpleValue converts a JSON value the way serde deserializes
// SimpleJsonValue (untagged Str | Int(i64) | Bool | Null).
func simpleValue(r gjson.Result) (Value, bool) {
	switch r.Type {
	case gjson.String:
		return Value{Kind: 's', S: r.Str}, true
	case gjson.True:
		return Value{Kind: 'b', B: true}, true
	case gjson.False:
		return Value{Kind: 'b', B: false}, true
	case gjson.Null:
		return Value{Kind: 'n'}, true
	case gjson.Number:
		if strings.ContainsAny(r.Raw, ".eE") {
			return Value{}, false
		}
		var n int64
		if _, err := fmt.Sscan(r.Raw, &n); err != nil {
			return Value{}, false
		}
		return Value{Kind: 'i', I: n}, true
	}
	return Value{}, false
}

// Condition is a push rule condition.
type Condition struct {
	// Known is false for a condition that did not deserialize as any known
	// kind; it never matches.
	Known bool
	Kind  string

	Key, Pattern       string
	HasKey, HasPattern bool
	// PatternType is user_id or user_localpart, for the base rules' internal
	// *_type variants; user rules can never set it.
	PatternType      string
	Value            Value
	Is               *string
	Feature          string
	RelType          string
	IncludeFallbacks *bool
	Subscribed       bool
}

// parseCondition deserializes one condition. fromBase allows the internal
// *_type variants, which serde skips when deserializing user data.
func parseCondition(r gjson.Result, fromBase bool) Condition {
	unknown := Condition{}
	if !r.IsObject() {
		return unknown
	}
	kind := r.Get("kind")
	if kind.Type != gjson.String {
		return unknown
	}
	str := func(name string, required bool) (string, bool, bool) {
		v := r.Get(gjson.Escape(name))
		if !v.Exists() || v.Type == gjson.Null {
			return "", false, !required
		}
		if v.Type != gjson.String {
			return "", false, false
		}
		return v.Str, true, true
	}
	c := Condition{Known: true, Kind: kind.Str}
	switch kind.Str {
	case "event_match":
		if fromBase && r.Get("pattern_type").Exists() {
			c.Key, c.HasKey, _ = str("key", true)
			c.PatternType = r.Get("pattern_type").Str
			c.Kind = "event_match_type"
			return c
		}
		var ok bool
		if c.Key, c.HasKey, ok = str("key", true); !ok {
			return unknown
		}
		if c.Pattern, c.HasPattern, ok = str("pattern", true); !ok {
			return unknown
		}
	case "event_property_is", "event_property_contains":
		if fromBase && kind.Str == "event_property_contains" && r.Get("value_type").Exists() {
			c.Key, c.HasKey, _ = str("key", true)
			c.PatternType = r.Get("value_type").Str
			c.Kind = "exact_event_property_contains_type"
			return c
		}
		var ok bool
		if c.Key, c.HasKey, ok = str("key", true); !ok {
			return unknown
		}
		v := r.Get("value")
		if !v.Exists() {
			return unknown
		}
		if c.Value, ok = simpleValue(v); !ok {
			return unknown
		}
	case "im.nheko.msc3664.related_event_match":
		if fromBase && r.Get("pattern_type").Exists() {
			c.Key, c.HasKey, _ = str("key", true)
			c.PatternType = r.Get("pattern_type").Str
			c.RelType, _, _ = str("rel_type", true)
			c.Kind = "related_event_match_type"
			c.IncludeFallbacks = optBool(r.Get("include_fallbacks"))
			return c
		}
		var ok bool
		if c.Key, c.HasKey, ok = str("key", false); !ok {
			return unknown
		}
		if c.Pattern, c.HasPattern, ok = str("pattern", false); !ok {
			return unknown
		}
		var has bool
		if c.RelType, has, ok = str("rel_type", true); !ok || !has {
			return unknown
		}
		f := r.Get("include_fallbacks")
		if f.Exists() && f.Type != gjson.Null && f.Type != gjson.True && f.Type != gjson.False {
			return unknown
		}
		c.IncludeFallbacks = optBool(f)
	case "contains_display_name":
	case "room_member_count":
		is, has, ok := str("is", false)
		if !ok {
			return unknown
		}
		if has {
			c.Is = &is
		}
	case "sender_notification_permission":
		var ok, has bool
		if c.Key, has, ok = str("key", true); !ok || !has {
			return unknown
		}
		c.HasKey = true
	case "org.matrix.msc3931.room_version_supports":
		var ok, has bool
		if c.Feature, has, ok = str("feature", true); !ok || !has {
			return unknown
		}
	case "io.element.msc4306.thread_subscription":
		s := r.Get("subscribed")
		if s.Type != gjson.True && s.Type != gjson.False {
			return unknown
		}
		c.Subscribed = s.Type == gjson.True
	default:
		return unknown
	}
	return c
}

func optBool(r gjson.Result) *bool {
	switch r.Type {
	case gjson.True:
		t := true
		return &t
	case gjson.False:
		f := false
		return &f
	}
	return nil
}

// Rule is a push rule.
type Rule struct {
	ID             string
	PriorityClass  int
	Conditions     []Condition
	Actions        []json.RawMessage
	Default        bool
	DefaultEnabled bool
}

// ErrBadRule is a stored rule Synapse could not load (PushRule.from_db
// raises): unparseable conditions or actions, or an unrecognized action.
var ErrBadRule = errors.New("push: bad push rule")

// RuleFromDB is PushRule.from_db.
func RuleFromDB(id string, priorityClass int, conditions, actions string) (Rule, error) {
	r := Rule{ID: id, PriorityClass: priorityClass, DefaultEnabled: true}
	cs := gjson.Parse(conditions)
	if !gjson.Valid(conditions) || !cs.IsArray() {
		return Rule{}, fmt.Errorf("%w %s: conditions", ErrBadRule, id)
	}
	for _, c := range cs.Array() {
		r.Conditions = append(r.Conditions, parseCondition(c, false))
	}
	as := gjson.Parse(actions)
	if !gjson.Valid(actions) || !as.IsArray() {
		return Rule{}, fmt.Errorf("%w %s: actions", ErrBadRule, id)
	}
	for _, a := range as.Array() {
		if a.Type == gjson.String {
			switch a.Str {
			case "notify", "dont_notify", "coalesce":
			default:
				// ActionDeserializeHelper::Str with an unknown string is an
				// error, not Action::Unknown.
				return Rule{}, fmt.Errorf("%w %s: unrecognized action %q", ErrBadRule, id, a.Str)
			}
		}
		r.Actions = append(r.Actions, json.RawMessage(a.Raw))
	}
	return r, nil
}

//go:embed base_rules.json
var baseRulesJSON []byte

// baseRules are Synapse's server-default rules, in evaluation order, dumped
// from the deployed Synapse (synapse.synapse_rust.push.PushRules([]).rules(),
// version recorded in the file) rather than transcribed from the source: the
// deployed version is what decides.
var baseRules, baseVersion = func() ([]Rule, string) {
	j := gjson.ParseBytes(baseRulesJSON)
	var out []Rule
	for _, r := range j.Get("rules").Array() {
		rule := Rule{
			ID:             r.Get("rule_id").Str,
			PriorityClass:  int(r.Get("priority_class").Int()),
			Default:        true,
			DefaultEnabled: r.Get("default_enabled").Bool(),
		}
		for _, c := range r.Get("conditions").Array() {
			rule.Conditions = append(rule.Conditions, parseCondition(c, true))
		}
		for _, a := range r.Get("actions").Array() {
			rule.Actions = append(rule.Actions, json.RawMessage(a.Raw))
		}
		out = append(out, rule)
	}
	return out, j.Get("synapse_version").Str
}()

// BaseRulesVersion is the Synapse version the base rules were dumped from.
func BaseRulesVersion() string { return baseVersion }

// Ruleset is PushRules: a user's rules, merged with the base rules.
type Ruleset struct {
	overridden map[string]Rule
	override   []Rule
	content    []Rule
	room       []Rule
	sender     []Rule
	underride  []Rule
}

// NewRuleset is PushRules::new. A user rule with a base rule's ID replaces
// only that base rule's actions; the rest are filed by priority class.
func NewRuleset(rules []Rule) *Ruleset {
	rs := &Ruleset{overridden: map[string]Rule{}}
	byID := map[string]Rule{}
	for _, b := range baseRules {
		byID[b.ID] = b
	}
	for _, r := range rules {
		if b, ok := byID[r.ID]; ok {
			b.Actions = r.Actions
			rs.overridden[r.ID] = b
			continue
		}
		switch r.PriorityClass {
		case 5:
			rs.override = append(rs.override, r)
		case 4:
			rs.content = append(rs.content, r)
		case 3:
			rs.room = append(rs.room, r)
		case 2:
			rs.sender = append(rs.sender, r)
		case 1:
			rs.underride = append(rs.underride, r)
		}
	}
	return rs
}

// iter is PushRules::iter: base prepend overrides, user overrides, base
// append overrides, user content, base content, base postcontent, user room,
// user sender, user underride, base underride.
func (rs *Ruleset) iter() []Rule {
	var prepend, appendOverride, content, postcontent, underride []Rule
	for _, b := range baseRules {
		switch {
		case b.ID == "global/override/.m.rule.master":
			prepend = append(prepend, b)
		case b.PriorityClass == 5:
			appendOverride = append(appendOverride, b)
		case b.PriorityClass == 4:
			content = append(content, b)
		case b.PriorityClass == 6:
			postcontent = append(postcontent, b)
		case b.PriorityClass == 1:
			underride = append(underride, b)
		}
	}
	var out []Rule
	for _, part := range [][]Rule{prepend, rs.override, appendOverride, rs.content, content,
		postcontent, rs.room, rs.sender, rs.underride, underride} {
		for _, r := range part {
			if o, ok := rs.overridden[r.ID]; ok {
				r = o
			}
			out = append(out, r)
		}
	}
	return out
}

// Flags are the experimental_features that change which rules apply.
type Flags struct {
	MSC1767              bool // also msc3931_enabled
	MSC3381Polls         bool
	MSC3664              bool
	MSC4028EncryptedPush bool
	MSC4075              bool
	MSC4210              bool
	MSC4306              bool
}

// Filtered is FilteredPushRules: the rules that apply, with whether each is
// enabled.
type Filtered struct {
	rules   []Rule
	enabled []bool
}

// Filter is FilteredPushRules::iter.
func Filter(rs *Ruleset, enabledMap map[string]bool, f Flags) *Filtered {
	out := &Filtered{}
	for _, r := range rs.iter() {
		id := r.ID
		if !f.MSC1767 && (strings.Contains(id, "org.matrix.msc1767") || strings.Contains(id, "org.matrix.msc3933")) {
			continue
		}
		if !f.MSC3664 && id == "global/override/.im.nheko.msc3664.reply" {
			continue
		}
		if !f.MSC3381Polls && strings.Contains(id, "org.matrix.msc3930") {
			continue
		}
		if !f.MSC4028EncryptedPush && id == "global/override/.org.matrix.msc4028.encrypted_event" {
			continue
		}
		if !f.MSC4075 && (id == "global/override/.org.matrix.msc4075.rule.rtc.invite_for_me" ||
			id == "global/override/.org.matrix.msc4075.rule.rtc.invite_for_room") {
			continue
		}
		if f.MSC4210 && (id == "global/override/.m.rule.contains_display_name" ||
			id == "global/content/.m.rule.contains_user_name" || id == "global/override/.m.rule.roomnotif") {
			continue
		}
		if !f.MSC4306 && strings.Contains(id, "/.io.element.msc4306.rule.") {
			continue
		}
		enabled, ok := enabledMap[id]
		if !ok {
			enabled = r.DefaultEnabled
		}
		out.rules = append(out.rules, r)
		out.enabled = append(out.enabled, enabled)
	}
	return out
}
