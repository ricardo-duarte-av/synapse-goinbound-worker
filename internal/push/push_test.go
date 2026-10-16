package push

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// Ports of synapse/tests/push/test_push_rule_evaluator.py.

func flatOf(t *testing.T, v any) Flat {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return Flatten(b)
}

func TestFlattenSimpleAndNested(t *testing.T) {
	if got := flatOf(t, map[string]any{"foo": "abc"}); !reflect.DeepEqual(got, Flat{"foo": {V: Value{Kind: 's', S: "abc"}}}) {
		t.Errorf("simple: %v", got)
	}
	if got := flatOf(t, map[string]any{"foo": map[string]any{"bar": "abc"}}); !reflect.DeepEqual(got, Flat{"foo.bar": {V: Value{Kind: 's', S: "abc"}}}) {
		t.Errorf("nested: %v", got)
	}
	got := flatOf(t, map[string]any{"m.foo": map[string]any{`b\ar`: "abc"}})
	if _, ok := got[`m\.foo.b\\ar`]; !ok || len(got) != 1 {
		t.Errorf("escaping: %v", got)
	}
}

func TestFlattenNonString(t *testing.T) {
	got := Flatten([]byte(`{"woo":"woo","foo":true,"bar":1,"baz":null,"fuzz":["woo",true,1,null,[],{}],"boo":{},"fl":1.5}`))
	want := Flat{
		"woo":  {V: Value{Kind: 's', S: "woo"}},
		"foo":  {V: Value{Kind: 'b', B: true}},
		"bar":  {V: Value{Kind: 'i', I: 1}},
		"baz":  {V: Value{Kind: 'n'}},
		"fuzz": {IsArray: true, Arr: []Value{{Kind: 's', S: "woo"}, {Kind: 'b', B: true}, {Kind: 'i', I: 1}, {Kind: 'n'}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func evaluator(t *testing.T, content any) *Evaluator {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"event_id": "$event_id", "type": "m.room.history_visibility", "sender": "@user:test",
		"state_key": "", "room_id": "#room:test", "content": content,
	})
	zero := int64(0)
	return NewEvaluator(Evaluator{
		Flat: Flatten(b), SenderPowerLevel: &zero, NotificationLevels: map[string]int64{},
		Related: map[string]Flat{}, RelatedEventMatch: true, MSC3931: true,
	})
}

func cond(t *testing.T, j string) Condition {
	t.Helper()
	return parseCondition(gjson.Parse(j), false)
}

func matches(t *testing.T, e *Evaluator, c Condition, displayName string) bool {
	t.Helper()
	ok, err := e.Match(c, "@user:test", displayName, nil)
	return ok && err == nil
}

func TestDisplayName(t *testing.T) {
	e := evaluator(t, map[string]any{"body": "foo bar baz"})
	c := cond(t, `{"kind":"contains_display_name"}`)
	for name, want := range map[string]bool{"": false, "not found": false, "foo": true, "ba": false, "ba[rz]": false, "foo bar": true} {
		if got := matches(t, e, c, name); got != want {
			t.Errorf("display name %q: %v, want %v", name, got, want)
		}
	}
}

type mcase struct {
	content any
	want    bool
	msg     string
}

func check(t *testing.T, condition string, cases []mcase) {
	t.Helper()
	c := cond(t, condition)
	for _, tc := range cases {
		if got := matches(t, evaluator(t, tc.content), c, "display_name"); got != tc.want {
			t.Errorf("%s on %v: %v, want %v (%s)", condition, tc.content, got, tc.want, tc.msg)
		}
	}
}

func body(s string) map[string]any { return map[string]any{"body": s} }
func value(v any) map[string]any   { return map[string]any{"value": v} }

func TestEventMatchBody(t *testing.T) {
	check(t, `{"kind":"event_match","key":"content.body","pattern":"foobaz"}`, []mcase{
		{body("aaa FoobaZ zzz"), true, "case-insensitive"},
		{body("aa xFoobaZ yy"), false, "word boundary"},
		{body("aa foobazx yy"), false, "word boundary"},
	})
	check(t, `{"kind":"event_match","key":"content.body","pattern":"f?o*baz"}`, []mcase{
		{body("aaa FoobarbaZ zzz"), true, "* matches a string"},
		{body("aa foobaz yy"), true, "* matches 0 characters"},
		{body("aa fobbaz yy"), false, "? not 0 characters"},
		{body("aa fiiobaz yy"), false, "? not 2 characters"},
		{body("aa xfooxbaz yy"), false, "word boundary"},
		{body("aa fooxbazx yy"), false, "word boundary"},
	})
	check(t, `{"kind":"event_match","key":"content.body","pattern":"f\\oobaz"}`, []mcase{
		{body(`F\oobaz`), true, "backslash matches itself"},
	})
	check(t, `{"kind":"event_match","key":"content.body","pattern":"f\\?obaz"}`, []mcase{
		{body(`F\oobaz`), true, `? after \ matches any character`},
	})
}

func TestEventMatchNonBody(t *testing.T) {
	check(t, `{"kind":"event_match","key":"content.value","pattern":"foobaz"}`, []mcase{
		{value("FoobaZ"), true, "case-insensitive"},
		{value("xFoobaZ"), false, "whole value"},
		{value("FoobaZz"), false, "whole value"},
	})
	check(t, `{"kind":"event_match","key":"content.value","pattern":"f?o*baz"}`, []mcase{
		{value("FoobarbaZ"), true, "*"},
		{value("foobaz"), true, "* zero"},
		{value("fobbaz"), false, "?"},
		{value("fiiobaz"), false, "?"},
		{value("xfooxbaz"), false, "whole"},
		{value("fooxbazx"), false, "whole"},
		{value("x\nfooxbaz"), false, "not after a newline"},
		{value("fooxbaz\nx"), false, "not before a newline"},
	})
}

func TestEventMatchPatternTypeIsNotUserData(t *testing.T) {
	for _, c := range []string{
		`{"kind":"event_match","key":"content.value","pattern_type":"user_id"}`,
		`{"kind":"event_match_type","key":"content.value","pattern_type":"user_id"}`,
	} {
		check(t, c, []mcase{{value("@user:test"), false, "pattern_type cannot come from user data"}})
	}
}

func TestExactEventMatch(t *testing.T) {
	check(t, `{"kind":"event_property_is","key":"content.value","value":"foobaz"}`, []mcase{
		{value("foobaz"), true, "exact"}, {value("FoobaZ"), false, "case-sensitive"},
		{value("test foobaz test"), false, "exact"}, {value(true), false, "type"}, {value(1), false, "type"},
		{value(1.1), false, "type"}, {value(nil), false, "type"}, {value([]any{}), false, "type"}, {value(map[string]any{}), false, "type"},
	})
	check(t, `{"kind":"event_property_is","key":"content.value","value":true}`, []mcase{
		{value(true), true, ""}, {value(false), false, ""}, {value("foobaz"), false, ""}, {value(1), false, "no int/bool coercion"},
		{value(1.1), false, ""}, {value(nil), false, ""},
	})
	check(t, `{"kind":"event_property_is","key":"content.value","value":false}`, []mcase{
		{value(false), true, ""}, {value(true), false, ""}, {value(""), false, ""}, {value(0), false, "no coercion"}, {value(nil), false, ""},
	})
	check(t, `{"kind":"event_property_is","key":"content.value","value":null}`, []mcase{
		{value(nil), true, ""}, {value("foobaz"), false, ""}, {value(false), false, ""}, {value(1), false, ""},
	})
	check(t, `{"kind":"event_property_is","key":"content.value","value":1}`, []mcase{
		{value(1), true, ""}, {value(1.1), false, ""}, {value(-1), false, ""}, {value(0), false, ""},
		{value("1"), false, ""}, {value(true), false, "no coercion"}, {value(nil), false, ""},
	})
}

func TestExactEventPropertyContains(t *testing.T) {
	check(t, `{"kind":"event_property_contains","key":"content.value","value":"foobaz"}`, []mcase{
		{value([]any{"foobaz"}), true, ""}, {value([]any{"foobaz", "bugz"}), true, ""},
		{value([]any{"FoobaZ"}), false, "case-sensitive"}, {value("foobaz"), false, "not a string search"},
	})
}

func TestNoAndInvalidBody(t *testing.T) {
	c := cond(t, `{"kind":"contains_display_name"}`)
	for _, content := range []any{map[string]any{}, body2(1), body2(true), body2(map[string]any{"foo": "bar"})} {
		if matches(t, evaluator(t, content), c, "foo") {
			t.Errorf("body %v matched a display name", content)
		}
	}
}

func body2(v any) map[string]any { return map[string]any{"body": v} }

func TestUnicodeWordBoundaries(t *testing.T) {
	// Rust's \b is Unicode-aware: accented letters are word characters, so
	// "joão" does not contain the word "jo", and "café" ends a word.
	check(t, `{"kind":"event_match","key":"content.body","pattern":"jo"}`, []mcase{
		{body("olá joão"), false, "ã is a word character"},
		{body("olá jo!"), true, ""},
	})
	check(t, `{"kind":"event_match","key":"content.body","pattern":"café"}`, []mcase{
		{body("um café, por favor"), true, ""},
		{body("cafés"), false, ""},
	})
}

func TestMemberCount(t *testing.T) {
	e := evaluator(t, map[string]any{})
	e.RoomMemberCount = 2
	for is, want := range map[string]bool{"2": true, "==2": true, "<3": true, ">1": true, ">=2": true, "<=1": false, "=2": false} {
		c := Condition{Known: true, Kind: "room_member_count", Is: &is}
		if got, _ := e.Match(c, "@u:test", "", nil); got != want {
			t.Errorf("is %q: %v, want %v", is, got, want)
		}
	}
	bad := "abc"
	if _, err := e.Match(Condition{Known: true, Kind: "room_member_count", Is: &bad}, "@u:test", "", nil); err == nil {
		t.Error("a bad 'is' clause did not fail the rule")
	}
}

func TestRunDefaultRules(t *testing.T) {
	flags := Flags{MSC1767: true, MSC3381Polls: true, MSC3664: true, MSC4028EncryptedPush: true, MSC4210: true}
	rules := Filter(NewRuleset(nil), nil, flags)

	msg := func(content map[string]any, members uint64) []json.RawMessage {
		b, _ := json.Marshal(map[string]any{"type": "m.room.message", "sender": "@a:x", "room_id": "!r:x", "content": content})
		lvl := int64(0)
		e := NewEvaluator(Evaluator{Flat: Flatten(b), RoomMemberCount: members, SenderPowerLevel: &lvl,
			NotificationLevels: map[string]int64{}, HasMentions: gjson.GetBytes(b, "content.m\\.mentions").Exists(),
			MSC3931: true, MSC4210: true, RelatedEventMatch: true})
		return e.Run(rules, "@bob:x", "Bob", nil)
	}
	str := func(a []json.RawMessage) string {
		var parts []string
		for _, x := range a {
			parts = append(parts, string(x))
		}
		return strings.Join(parts, ",")
	}

	if got := msg(map[string]any{"msgtype": "m.text", "body": "hi"}, 5); !Notifies(got) || Highlights(got) {
		t.Errorf("plain message in a group: %s, want notify without highlight (.m.rule.message)", str(got))
	}
	if got := str(msg(map[string]any{"msgtype": "m.text", "body": "hi"}, 2)); !strings.Contains(got, `"sound"`) {
		t.Errorf("one-to-one message: %s, want notify with sound", got)
	}
	if got := msg(map[string]any{"msgtype": "m.notice", "body": "hi"}, 5); len(got) != 0 {
		t.Errorf("notice: %s, want nothing (.m.rule.suppress_notices)", str(got))
	}
	mention := map[string]any{"msgtype": "m.text", "body": "hey", "m.mentions": map[string]any{"user_ids": []any{"@bob:x"}}}
	if got := msg(mention, 5); !Highlights(got) {
		t.Errorf("user mention: %s, want highlight", str(got))
	}
	// MSC4210: the legacy body match on the display name is gone.
	if got := msg(map[string]any{"msgtype": "m.text", "body": "hey Bob"}, 5); Highlights(got) {
		t.Errorf("display name in the body with msc4210: %s, want no highlight", str(got))
	}
}

func TestUserRuleOverridesBaseActions(t *testing.T) {
	r, err := RuleFromDB("global/underride/.m.rule.message", 1, `[]`, `["dont_notify"]`)
	if err != nil {
		t.Fatal(err)
	}
	rules := Filter(NewRuleset([]Rule{r}), nil, Flags{})
	b := []byte(`{"type":"m.room.message","sender":"@a:x","content":{"msgtype":"m.text","body":"hi"}}`)
	e := NewEvaluator(Evaluator{Flat: Flatten(b), RoomMemberCount: 5, NotificationLevels: map[string]int64{}})
	if got := e.Run(rules, "@bob:x", "", nil); len(got) != 0 {
		t.Errorf("a user override of .m.rule.message to dont_notify gave %s", got)
	}
}

func TestRuleFromDBRejectsUnknownStringAction(t *testing.T) {
	if _, err := RuleFromDB("x", 5, `[]`, `["make_coffee"]`); err == nil {
		t.Error("an unrecognized string action was accepted; Synapse's from_db raises")
	}
	if _, err := RuleFromDB("x", 5, `[]`, `[{"set_tweak":"sound","value":"default"},{"anything":1}]`); err != nil {
		t.Errorf("tweaks and unknown object actions must load: %v", err)
	}
}

func TestBaseRulesLoaded(t *testing.T) {
	if len(baseRules) < 30 || BaseRulesVersion() == "" {
		t.Fatalf("%d base rules from %q", len(baseRules), BaseRulesVersion())
	}
	if baseRules[0].ID != "global/override/.m.rule.master" || baseRules[0].DefaultEnabled {
		t.Errorf("first base rule %+v, want the disabled master rule", baseRules[0])
	}
	for _, r := range baseRules {
		for _, c := range r.Conditions {
			if !c.Known {
				t.Errorf("base rule %s has a condition that did not parse", r.ID)
			}
		}
	}
}

func relatedFlat(extra map[string]any) Flat {
	m := map[string]any{"event_id": "$parent_event_id", "type": "m.room.message", "sender": "@other_user:test",
		"room_id": "!room:test", "content.msgtype": "m.text", "content.body": "Original message"}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	// These are given already flattened, as in Synapse's test: no escaping.
	f := Flat{}
	gjson.ParseBytes(b).ForEach(func(k, v gjson.Result) bool {
		sv, _ := simpleValue(v)
		f[k.String()] = FlatValue{V: sv}
		return true
	})
	return f
}

func TestRelatedEventMatch(t *testing.T) {
	e := evaluator(t, map[string]any{"m.relates_to": map[string]any{"event_id": "$parent_event_id", "rel_type": "m.annotation"}})
	e.Related = map[string]Flat{"m.in_reply_to": relatedFlat(nil), "m.annotation": relatedFlat(nil)}
	for _, tc := range []struct {
		c    string
		user string
		want bool
	}{
		{`{"kind":"im.nheko.msc3664.related_event_match","key":"sender","rel_type":"m.in_reply_to","pattern":"@other_user:test"}`, "@user:test", true},
		{`{"kind":"im.nheko.msc3664.related_event_match","key":"sender","rel_type":"m.in_reply_to","pattern":"@user:test"}`, "@other_user:test", false},
		{`{"kind":"im.nheko.msc3664.related_event_match","key":"sender","rel_type":"m.annotation","pattern":"@other_user:test"}`, "@other_user:test", true},
		{`{"kind":"im.nheko.msc3664.related_event_match","key":"sender","rel_type":"m.in_reply_to"}`, "@user:test", false},
		{`{"kind":"im.nheko.msc3664.related_event_match","rel_type":"m.in_reply_to"}`, "@user:test", true},
		{`{"kind":"im.nheko.msc3664.related_event_match","rel_type":"m.replace"}`, "@other_user:test", false},
	} {
		if got, _ := e.Match(cond(t, tc.c), tc.user, "display_name", nil); got != tc.want {
			t.Errorf("%s as %s: %v, want %v", tc.c, tc.user, got, tc.want)
		}
	}
}

func TestRelatedEventMatchWithFallback(t *testing.T) {
	e := evaluator(t, map[string]any{})
	e.Related = map[string]Flat{
		"m.in_reply_to": relatedFlat(map[string]any{"im.vector.is_falling_back": ""}),
		"m.thread":      relatedFlat(nil),
	}
	base := `"kind":"im.nheko.msc3664.related_event_match","key":"sender","rel_type":"m.in_reply_to","pattern":"@other_user:test"`
	for c, want := range map[string]bool{
		`{` + base + `,"include_fallbacks":true}`:  true,
		`{` + base + `,"include_fallbacks":false}`: false,
		`{` + base + `}`: false,
	} {
		if got, _ := e.Match(cond(t, c), "@user:test", "display_name", nil); got != want {
			t.Errorf("%s: %v, want %v", c, got, want)
		}
	}
}

func TestRelatedEventMatchNoRelatedEvent(t *testing.T) {
	e := evaluator(t, map[string]any{"msgtype": "m.text", "body": "Message without related event"})
	for _, c := range []string{
		`{"kind":"im.nheko.msc3664.related_event_match","key":"sender","rel_type":"m.in_reply_to","pattern":"@other_user:test"}`,
		`{"kind":"im.nheko.msc3664.related_event_match","key":"sender","rel_type":"m.in_reply_to"}`,
		`{"kind":"im.nheko.msc3664.related_event_match","rel_type":"m.in_reply_to"}`,
	} {
		if got, _ := e.Match(cond(t, c), "@user:test", "display_name", nil); got {
			t.Errorf("%s matched without a related event", c)
		}
	}
}

func TestThreadSubscription(t *testing.T) {
	e := evaluator(t, map[string]any{"msgtype": "m.text", "body": "Squawk"})
	e.MSC4306 = true
	tr, fa := true, false
	for _, tc := range []struct {
		subscribed bool
		state      *bool
		want       bool
	}{
		{true, &tr, true}, {false, &tr, false},
		{true, &fa, false}, {false, &fa, true},
		{true, nil, false}, {false, nil, false},
	} {
		c := cond(t, `{"kind":"io.element.msc4306.thread_subscription","subscribed":`+map[bool]string{true: "true", false: "false"}[tc.subscribed]+`}`)
		if got, _ := e.Match(c, "", "", tc.state); got != tc.want {
			t.Errorf("subscribed=%v state=%v: %v, want %v", tc.subscribed, tc.state, got, tc.want)
		}
	}
}

// MSC4075's RTC invite rules (Synapse 1.163), ported from base_rules.rs's
// tests: the generic mention rules are disabled so that they cannot mask
// them, as they have the same actions and come right after.
func TestRTCInviteRules(t *testing.T) {
	const alice, bob = "@alice:example.org", "@bob:example.org"
	const ring = `"notify",{"set_tweak":"sound","value":"ring"}`
	rules := func(msc4075 bool) *Filtered {
		return Filter(NewRuleset(nil), map[string]bool{
			"global/override/.m.rule.is_user_mention": false,
			"global/override/.m.rule.is_room_mention": false,
		}, Flags{MSC4075: msc4075})
	}
	run := func(rs *Filtered, typ string, users []string, room bool, senderLevel int64) string {
		mentions := map[string]any{"user_ids": users}
		if room {
			mentions["room"] = true
		}
		b, _ := json.Marshal(map[string]any{"type": typ, "content": map[string]any{"m.mentions": mentions}})
		e := NewEvaluator(Evaluator{Flat: Flatten(b), HasMentions: true, RoomMemberCount: 10,
			SenderPowerLevel: &senderLevel, NotificationLevels: map[string]int64{}})
		var parts []string
		for _, a := range e.Run(rs, alice, "", nil) {
			var buf bytes.Buffer
			if err := json.Compact(&buf, a); err != nil {
				t.Fatal(err)
			}
			parts = append(parts, buf.String())
		}
		return strings.Join(parts, ",")
	}
	const rtc = "org.matrix.msc4075.rtc.notification"
	for _, c := range []struct {
		name        string
		msc4075     bool
		typ         string
		users       []string
		room        bool
		senderLevel int64
		want        string
	}{
		{"invite for me notifies the mentioned user", true, rtc, []string{alice}, false, 0, ring},
		{"invite for me ignores other users", true, rtc, []string{bob}, false, 0, ""},
		// The default notifications.room level is 50.
		{"invite for the room notifies with permission", true, rtc, nil, true, 50, ring},
		{"invite for the room requires permission", true, rtc, nil, true, 0, ""},
		{"other event types are ignored", true, "org.example.other", []string{alice}, true, 50, ""},
		{"omitted when msc4075 is disabled", false, rtc, []string{alice}, true, 50, ""},
	} {
		if got := run(rules(c.msc4075), c.typ, c.users, c.room, c.senderLevel); got != c.want {
			t.Errorf("%s: got [%s], want [%s]", c.name, got, c.want)
		}
	}
}
