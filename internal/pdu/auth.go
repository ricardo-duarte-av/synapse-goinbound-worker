package pdu

import (
	"crypto/ed25519"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tidwall/gjson"
)

// A port of synapse/event_auth.py. Function names follow Synapse's so each can
// be read beside its original; line references are to that file.

// CreatorPowerLevel is CREATOR_POWER_LEVEL (api/constants.py:92): what an
// MSC4289 creator's power level reads as.
const CreatorPowerLevel int64 = 1 << 53

// AuthState is Synapse's auth_dict: (type, state_key) -> event.
type AuthState map[StateKey]*Event

var createKey = StateKey{Type: "m.room.create"}

// AuthTypesForEvent is auth_types_for_event (:1253).
func AuthTypesForEvent(rv *RoomVersion, ev *Event) ([]StateKey, error) {
	if ev.Type == "m.room.create" {
		return nil, nil
	}
	set := map[StateKey]bool{
		{Type: "m.room.power_levels"}:                true,
		{Type: "m.room.member", StateKey: ev.Sender}: true,
		createKey: true,
	}
	if ev.Type == "m.room.member" {
		membership, err := ev.Membership()
		if err != nil {
			return nil, err
		}
		if membership == "join" || membership == "invite" || membership == "knock" {
			set[StateKey{Type: "m.room.join_rules"}] = true
		}
		if ev.StateKey == nil {
			// event.state_key on a non-state member event.
			return nil, raise("member event without state_key")
		}
		set[StateKey{Type: "m.room.member", StateKey: *ev.StateKey}] = true

		if membership == "invite" && has(ev.Content, "third_party_invite") {
			// content["third_party_invite"]["signed"]["token"]
			tpi := get(ev.Content, "third_party_invite")
			token, ok := field(get(tpi, "signed"), "token")
			if !ok || token.Type != gjson.String {
				return nil, raise("third_party_invite.signed.token missing or not a string")
			}
			set[StateKey{Type: "m.room.third_party_invite", StateKey: token.Str}] = true
		}
		if rv.RestrictedJoinRule && membership == "join" && has(ev.Content, "join_authorised_via_users_server") {
			v, _ := field(ev.Content, "join_authorised_via_users_server")
			if v.Type != gjson.String {
				return nil, raise("join_authorised_via_users_server is not a string")
			}
			set[StateKey{Type: "m.room.member", StateKey: v.Str}] = true
		}
	}
	out := make([]StateKey, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].StateKey < out[j].StateKey
	})
	return out, nil
}

// ComputeAuthEvents is EventAuthHandler.compute_auth_events
// (handlers/event_auth.py:89): the auth types, looked up in the given state.
func ComputeAuthEvents(rv *RoomVersion, ev *Event, state StateMap) ([]string, error) {
	types, err := AuthTypesForEvent(rv, ev)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, k := range types {
		if id, ok := state[k]; ok && id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

// CheckStateIndependentAuthRules is check_state_independent_auth_rules
// (:163). authEvents must hold the event's auth events, rejected or not.
// MSC4242 state DAGs are not handled: no stable room version uses them.
func CheckStateIndependentAuthRules(ev *Event, authEvents map[string]*Event) error {
	if ev.Type == "m.room.create" {
		return checkCreate(ev)
	}
	expected, err := AuthTypesForEvent(ev.Room, ev)
	if err != nil {
		return err
	}
	isExpected := make(map[StateKey]bool, len(expected))
	for _, k := range expected {
		isExpected[k] = true
	}

	authDict := map[StateKey]string{}
	for _, id := range ev.AuthEvents {
		ae := authEvents[id]
		if ae == nil {
			return raise("unknown auth event " + id)
		}
		if ae.RoomID != ev.RoomID {
			return deny("auth event %s is in room %s", id, ae.RoomID)
		}
		if !ae.IsState() {
			// (type, None) is never an expected auth type.
			return deny("unexpected auth_event %s (not state)", id)
		}
		k := ae.Key()
		if prev, dup := authDict[k]; dup {
			return deny("duplicate auth_events for %v: %s and %s", k, prev, id)
		}
		if !isExpected[k] {
			return deny("unexpected auth_event for %v: %s", k, id)
		}
		if ae.Rejected {
			return deny("rejected auth event %s", id)
		}
		authDict[k] = id
	}
	if authDict[createKey] == "" {
		return deny("no create event in auth events")
	}
	return nil
}

// checkCreate is _check_create (:504).
func checkCreate(ev *Event) error {
	if len(ev.PrevEvents) > 0 {
		return deny("create event has prev events")
	}
	rv := ev.Room
	if rv.MSC4291RoomIDsAsHashes {
		if has(gjson.ParseBytes(ev.JSON), "room_id") {
			return deny("create event has a room_id")
		}
	} else {
		senderDomain, err := domainOf(ev.Sender)
		if err != nil {
			return err
		}
		roomDomain, err := domainOf(ev.RoomID)
		if err != nil {
			return err
		}
		if roomDomain != senderDomain {
			return deny("creation event's room_id domain does not match sender's")
		}
	}

	// content.get("room_version", "1") not in KNOWN_ROOM_VERSIONS
	rvProp := gjson.Result{Type: gjson.String, Str: "1"}
	if v, ok := field(ev.Content, "room_version"); ok {
		rvProp = v
	}
	switch {
	case rvProp.Type == gjson.String && KnownRoomVersion(rvProp.Str):
	case rvProp.Type == gjson.String:
		// KNOWN_ROOM_VERSIONS also holds unstable versions this package
		// does not list, so an unknown string is not certainly a reject.
		return raise("create event names room version " + rvProp.Str)
	case rvProp.IsArray() || rvProp.IsObject():
		return raise("room_version is unhashable")
	default:
		return deny("room appears to have unsupported version %s", rvProp.Raw)
	}

	if !rv.ImplicitRoomCreator && !has(ev.Content, "creator") {
		return deny("create event lacks a 'creator' property")
	}
	if rv.MSC4289CreatorPower && has(ev.Content, "additional_creators") {
		v, _ := field(ev.Content, "additional_creators")
		if err := checkValidAdditionalCreators(v); err != nil {
			return err
		}
	}
	return nil
}

// checkValidAdditionalCreators is check_valid_additional_creators (:1298).
func checkValidAdditionalCreators(v gjson.Result) error {
	if !v.IsArray() {
		return deny("additional_creators must be an array")
	}
	for _, e := range v.Array() {
		if e.Type != gjson.String {
			return deny("entry in additional_creators is not a string")
		}
		if !userIDIsValid(e.Str) {
			return deny("entry in additional_creators is not a valid user ID")
		}
		if utf8.RuneCountInString(e.Str) > 255 || len(e.Str) > 255 {
			return deny("entry in additional_creators too long")
		}
	}
	return nil
}

// CheckStateDependentAuthRules is check_state_dependent_auth_rules (:346).
// authEvents is the room state to check against; for duplicate keys the last
// wins, as in Synapse's dict comprehension.
func CheckStateDependentAuthRules(ev *Event, authEvents []*Event) error {
	if ev.Type == "m.room.create" {
		return nil
	}
	auth := AuthState{}
	for _, e := range authEvents {
		if e.IsState() {
			auth[e.Key()] = e
		}
	}
	create := auth[createKey]
	if create == nil {
		return deny("event %s is missing a create event in auth_events", ev.ID)
	}

	creating, err := domainOf(create.Sender)
	if err != nil {
		return err
	}
	originating, err := domainOf(ev.Sender)
	if err != nil {
		return err
	}
	if creating != originating && !canFederate(auth) {
		return deny("this room has been marked as unfederatable")
	}

	rv := ev.Room
	if ev.Type == "m.room.aliases" && rv.SpecialCaseAliasesAuth {
		if !ev.IsState() {
			return deny("alias event must be a state event")
		}
		if *ev.StateKey == "" {
			return deny("alias event must have non-empty state_key")
		}
		if *ev.StateKey != originating {
			return deny("alias event's state_key does not match sender's domain")
		}
		return nil
	}

	if ev.Type == "m.room.member" {
		return isMembershipChangeAllowed(rv, ev, auth)
	}

	if err := checkJoinedRoom(auth[StateKey{Type: "m.room.member", StateKey: ev.Sender}], ev.Sender); err != nil {
		return err
	}

	if ev.Type == "m.room.third_party_invite" {
		userLevel, err := getUserPowerLevel(ev.Sender, auth)
		if err != nil {
			return err
		}
		inviteLevel, err := getNamedLevel(auth, "invite", 0)
		if err != nil {
			return err
		}
		if userLevel < inviteLevel {
			return deny("you don't have permission to invite users")
		}
		return nil
	}

	if err := canSendEvent(ev, auth); err != nil {
		return err
	}
	if ev.Type == "m.room.power_levels" {
		if err := checkPowerLevels(rv, ev, auth); err != nil {
			return err
		}
	}
	if ev.Type == "m.room.redaction" {
		if err := checkRedaction(rv, ev, auth); err != nil {
			return err
		}
	}
	return nil
}

// canFederate is _can_federate (:565): m.federate must be exactly True.
func canFederate(auth AuthState) bool {
	create := auth[createKey]
	if create == nil {
		return false
	}
	v, ok := field(create.Content, "m.federate")
	return !ok || v.Type == gjson.True
}

// isMembershipChangeAllowed is _is_membership_change_allowed (:574).
func isMembershipChangeAllowed(rv *RoomVersion, ev *Event, auth AuthState) error {
	membership, err := ev.Membership()
	if err != nil {
		return err
	}
	if ev.StateKey == nil {
		return raise("member event without state_key")
	}
	target := *ev.StateKey

	// The room creator joining straight after the create event.
	if len(ev.PrevEvents) == 1 && membership == "join" {
		if create := auth[createKey]; create != nil && ev.PrevEvents[0] == create.ID {
			var creator gjson.Result
			if rv.ImplicitRoomCreator {
				creator = gjson.Result{Type: gjson.String, Str: create.Sender}
			} else {
				c, ok := field(create.Content, "creator")
				if !ok {
					return raise("KeyError: creator")
				}
				creator = c
			}
			if pyEqualString(creator, target) {
				return nil
			}
		}
	}

	create := auth[createKey]
	if create == nil {
		return deny("create event missing from auth_events")
	}
	creating, err := domainOf(create.Sender)
	if err != nil {
		return err
	}
	targetDomain, err := domainOf(target)
	if err != nil {
		return err
	}
	if creating != targetDomain && !canFederate(auth) {
		return deny("this room has been marked as unfederatable")
	}

	memberOf := func(e *Event) (string, bool, error) {
		if e == nil {
			return "", false, nil
		}
		m, err := e.Membership()
		return m, true, err
	}

	callerMembership, callerExists, err := memberOf(auth[StateKey{Type: "m.room.member", StateKey: ev.Sender}])
	if err != nil {
		return err
	}
	callerInRoom := callerExists && callerMembership == "join"
	callerInvited := callerExists && callerMembership == "invite"
	callerKnocked := callerExists && rv.KnockJoinRule && callerMembership == "knock"

	targetMembership, targetExists, err := memberOf(auth[StateKey{Type: "m.room.member", StateKey: target}])
	if err != nil {
		return err
	}
	targetInRoom := targetExists && targetMembership == "join"
	targetBanned := targetExists && targetMembership == "ban"

	// join_rule_event.content.get("join_rule", "invite"); a present null is
	// None, which equals no rule.
	joinRule := gjson.Result{Type: gjson.String, Str: "invite"}
	if jr := auth[StateKey{Type: "m.room.join_rules"}]; jr != nil {
		if v, ok := field(jr.Content, "join_rule"); ok {
			joinRule = v
		}
	}
	isRule := func(r string) bool { return pyEqualString(joinRule, r) }

	userLevel, err := getUserPowerLevel(ev.Sender, auth)
	if err != nil {
		return err
	}
	targetLevel, err := getUserPowerLevel(target, auth)
	if err != nil {
		return err
	}
	inviteLevel, err := getNamedLevel(auth, "invite", 0)
	if err != nil {
		return err
	}
	banLevel, err := getNamedLevel(auth, "ban", 50)
	if err != nil {
		return err
	}

	if membership == "invite" && has(ev.Content, "third_party_invite") {
		ok, err := verifyThirdPartyInvite(ev, auth)
		if err != nil {
			return err
		}
		if !ok {
			return deny("you are not invited to this room")
		}
		if targetBanned {
			return deny("%s is banned from the room", target)
		}
		return nil
	}

	if membership != "join" && membership != "knock" {
		if (callerInvited || callerKnocked) && membership == "leave" && target == ev.Sender {
			return nil
		}
		if !callerInRoom {
			return deny("%s not in room %s", ev.Sender, ev.RoomID)
		}
	}

	switch {
	case membership == "invite":
		switch {
		case targetBanned:
			return deny("%s is banned from the room", target)
		case targetInRoom:
			return deny("%s is already in the room", target)
		case userLevel < inviteLevel:
			return deny("you don't have permission to invite users")
		}
	case membership == "join":
		switch {
		case ev.Sender != target:
			return deny("cannot force another user to join")
		case targetBanned:
			return deny("you are banned from this room")
		case isRule("public"):
		case (rv.RestrictedJoinRule && isRule("restricted")) || (rv.KnockRestrictedJoinRule && isRule("knock_restricted")):
			if !callerInRoom && !callerInvited {
				au := get(ev.Content, "join_authorised_via_users_server")
				if isNone(au) {
					return deny("join event is missing authorising user")
				}
				if au.Type != gjson.String {
					return raise("join_authorised_via_users_server is not a string")
				}
				if err := checkJoinedRoom(auth[StateKey{Type: "m.room.member", StateKey: au.Str}], au.Str); err != nil {
					return err
				}
				auLevel, err := getUserPowerLevel(au.Str, auth)
				if err != nil {
					return err
				}
				if auLevel < inviteLevel {
					return deny("join event authorised by invalid server")
				}
			}
		case isRule("invite") || (rv.KnockJoinRule && isRule("knock")) || (rv.KnockRestrictedJoinRule && isRule("knock_restricted")):
			if !(callerInRoom || callerInvited) {
				return deny("you are not invited to this room")
			}
		default:
			return deny("you are not allowed to join this room")
		}
	case membership == "leave":
		if targetBanned && userLevel < banLevel {
			return deny("you cannot unban user %s", target)
		} else if target != ev.Sender {
			kickLevel, err := getNamedLevel(auth, "kick", 50)
			if err != nil {
				return err
			}
			if userLevel < kickLevel || userLevel <= targetLevel {
				return deny("you cannot kick user %s", target)
			}
		}
	case membership == "ban":
		if userLevel < banLevel {
			return deny("you don't have permission to ban")
		} else if userLevel <= targetLevel {
			return deny("you don't have permission to ban this user")
		}
	case rv.KnockJoinRule && membership == "knock":
		switch {
		case !isRule("knock") && (!rv.KnockRestrictedJoinRule || !isRule("knock_restricted")):
			return deny("you don't have permission to knock")
		case target != ev.Sender:
			return deny("you cannot knock for other users")
		case targetInRoom:
			return deny("you cannot knock on a room you are already in")
		case callerInvited:
			return deny("you are already invited to this room")
		case targetBanned:
			return deny("you are banned from this room")
		}
	default:
		// AuthError(500, ...) is still an AuthError.
		return deny("unknown membership %s", membership)
	}
	return nil
}

// checkJoinedRoom is _check_joined_room (:832).
func checkJoinedRoom(member *Event, userID string) error {
	if member == nil {
		return deny("user %s not in room", userID)
	}
	m, err := member.Membership()
	if err != nil {
		return err
	}
	if m != "join" {
		return deny("user %s not in room (%s)", userID, m)
	}
	return nil
}

// pyDictGet is Python's obj.get(key, {}) followed by use as a mapping: an
// absent key is an empty mapping, a present object is itself, and anything
// else -- including a present null, which .get returns as None -- raises at
// the next .get/.items/in.
func pyDictGet(obj gjson.Result, key string) (gjson.Result, error) {
	v, ok := field(obj, key)
	if !ok {
		return gjson.Parse("{}"), nil
	}
	if !v.IsObject() {
		return gjson.Result{}, raise(key + " is not a mapping")
	}
	return v, nil
}

// getUserPowerLevel is get_user_power_level (:1116).
func getUserPowerLevel(userID string, auth AuthState) (int64, error) {
	create := auth[createKey]
	if create == nil {
		return 0, raise("AssertionError: no create event to compute power levels")
	}
	if create.Room.MSC4289CreatorPower {
		is, err := isCreator(create, userID)
		if err != nil {
			return 0, err
		}
		if is {
			return CreatorPowerLevel, nil
		}
	}
	if pl := auth[StateKey{Type: "m.room.power_levels"}]; pl != nil {
		users, err := pyDictGet(pl.Content, "users")
		if err != nil {
			return 0, err
		}
		level := get(users, userID)
		if isNone(level) {
			level = gjson.Result{Type: gjson.Number, Raw: "0", Num: 0}
			if v, ok := field(pl.Content, "users_default"); ok {
				level = v
			}
		}
		if isNone(level) {
			return 0, nil
		}
		return intOf(level)
	}
	// No power levels: the creator has 100, everyone else 0.
	var creator gjson.Result
	if create.Room.ImplicitRoomCreator {
		creator = gjson.Result{Type: gjson.String, Str: create.Sender}
	} else {
		c, ok := field(create.Content, "creator")
		if !ok {
			return 0, raise("KeyError: creator")
		}
		creator = c
	}
	if pyEqualString(creator, userID) {
		return 100, nil
	}
	return 0, nil
}

// isCreator is synapse.events.is_creator.
func isCreator(create *Event, userID string) (bool, error) {
	if create.Sender == userID {
		return true, nil
	}
	if !create.Room.MSC4289CreatorPower {
		return false, nil
	}
	// set(content.get("additional_creators", []))
	v, ok := field(create.Content, "additional_creators")
	if !ok {
		return false, nil
	}
	switch {
	case v.IsArray():
		for _, e := range v.Array() {
			if e.IsArray() || e.IsObject() {
				return false, raise("unhashable entry in additional_creators")
			}
			if pyEqualString(e, userID) {
				return true, nil
			}
		}
		return false, nil
	case v.Type == gjson.String:
		// set("...") is its characters; a user ID is never one character.
		return false, nil
	case v.IsObject():
		// set(dict) is its keys.
		return has(v, userID), nil
	default:
		return false, raise("additional_creators is not iterable")
	}
}

// getNamedLevel is get_named_level (:1158).
func getNamedLevel(auth AuthState, name string, def int64) (int64, error) {
	pl := auth[StateKey{Type: "m.room.power_levels"}]
	if pl == nil {
		return def, nil
	}
	level := get(pl.Content, name)
	if isNone(level) {
		return def, nil
	}
	return intOf(level)
}

// getSendLevel is get_send_level (:841).
func getSendLevel(evType string, stateKey *string, pl *Event) (int64, error) {
	content := gjson.Parse("{}")
	if pl != nil {
		content = pl.Content
	}
	events, err := pyDictGet(content, "events")
	if err != nil {
		return 0, err
	}
	level := get(events, evType)
	if isNone(level) {
		name, def := "events_default", int64(0)
		if stateKey != nil {
			name, def = "state_default", 50
		}
		v, ok := field(content, name)
		if !ok {
			return def, nil
		}
		if v.Type == gjson.Null {
			return 0, raise("int(None)")
		}
		level = v
	}
	return intOf(level)
}

// canSendEvent is _can_send_event (:879). MSC3757 is not enabled in any
// stable room version.
func canSendEvent(ev *Event, auth AuthState) error {
	sendLevel, err := getSendLevel(ev.Type, ev.StateKey, auth[StateKey{Type: "m.room.power_levels"}])
	if err != nil {
		return err
	}
	userLevel, err := getUserPowerLevel(ev.Sender, auth)
	if err != nil {
		return err
	}
	if userLevel < sendLevel {
		return deny("user_level (%d) < send_level (%d)", userLevel, sendLevel)
	}
	if ev.StateKey != nil && strings.HasPrefix(*ev.StateKey, "@") && *ev.StateKey != ev.Sender {
		if ev.Room.MSC3757 {
			return raise("MSC3757 is not implemented")
		}
		return deny("you are not allowed to set others state")
	}
	return nil
}

// checkRedaction is check_redaction (:926).
func checkRedaction(rv *RoomVersion, ev *Event, auth AuthState) error {
	userLevel, err := getUserPowerLevel(ev.Sender, auth)
	if err != nil {
		return err
	}
	redactLevel, err := getNamedLevel(auth, "redact", 50)
	if err != nil {
		return err
	}
	if userLevel >= redactLevel {
		return nil
	}
	if rv.EventFormat != FormatV1V2 {
		// Rechecked when the redaction is applied.
		ev.RecheckRedaction = true
		return nil
	}
	redacter, err := domainOf(ev.ID)
	if err != nil {
		return err
	}
	if ev.Redacts == nil {
		// not isinstance(event.redacts, str): allowed, nothing to redact.
		return nil
	}
	redactee, err := domainOf(*ev.Redacts)
	if err != nil {
		return err
	}
	if redacter == redactee {
		return nil
	}
	return deny("you don't have permission to redact events")
}

var intLevelKeys = map[string]bool{
	"users_default": true, "events_default": true, "state_default": true,
	"ban": true, "redact": true, "kick": true, "invite": true,
}

// checkPowerLevels is _check_power_levels (:964).
func checkPowerLevels(rv *RoomVersion, ev *Event, auth AuthState) error {
	userList, err := pyDictGet(ev.Content, "users")
	if err != nil {
		return err
	}
	for _, k := range keys(userList) {
		if !userIDParses(k) {
			return raise("SynapseError: not a valid user_id: " + k)
		}
		// int(v), with null meaning int(None): any failure is the same
		// SynapseError.
		if v, _ := field(userList, k); true {
			if _, err := pyInt(v); err != nil {
				return raise("SynapseError: not a valid power level for " + k)
			}
		}
	}

	if rv.MSC4289CreatorPower {
		create := auth[createKey]
		if create == nil {
			return raise("SynapseError: cannot check power levels without a create event")
		}
		if has(userList, create.Sender) {
			return raise("SynapseError: creator must not appear in content.users")
		}
		if v, ok := field(create.Content, "additional_creators"); ok && pyTruthy(v) {
			if !v.IsArray() {
				return raise("additional_creators is not a list")
			}
			for _, e := range v.Array() {
				if e.Type == gjson.String && has(userList, e.Str) {
					return raise("SynapseError: additional creators must not appear in content.users")
				}
			}
		}
	}

	if ev.Type == "m.room.power_levels" && rv.EnforceIntPowerLevels {
		var bad error
		ev.Content.ForEach(func(k, v gjson.Result) bool {
			key := k.String()
			if intLevelKeys[key] && !isPyInt(v) {
				bad = raise("SynapseError: " + key + " must be an integer")
				return false
			}
			if key == "events" || key == "notifications" || key == "users" {
				if !v.IsObject() {
					bad = raise("SynapseError: " + key + " must be a dict")
					return false
				}
				v.ForEach(func(_, iv gjson.Result) bool {
					if !isPyInt(iv) {
						bad = raise("SynapseError: " + key + " values must be integers")
						return false
					}
					return true
				})
				if bad != nil {
					return false
				}
			}
			return true
		})
		if bad != nil {
			return bad
		}
	}

	// auth_events.get((event.type, event.state_key)): for a non-state event
	// the state_key is None, which no state entry has.
	if ev.StateKey == nil {
		return nil
	}
	current := auth[StateKey{Type: ev.Type, StateKey: *ev.StateKey}]
	if current == nil {
		return nil
	}

	userLevel, err := getUserPowerLevel(ev.Sender, auth)
	if err != nil {
		return err
	}

	type check struct{ name, dir string }
	var levels []check
	for _, n := range []string{"users_default", "events_default", "state_default", "ban", "redact", "kick", "invite"} {
		levels = append(levels, check{n, ""})
	}
	for _, dir := range []string{"users", "events", "notifications"} {
		if dir == "notifications" && !rv.LimitNotificationsPowerLevels {
			continue
		}
		oldList, err := pyDictGet(current.Content, dir)
		if err != nil {
			return err
		}
		newList, err := pyDictGet(ev.Content, dir)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		names := append(keys(oldList), keys(newList)...)
		sort.Strings(names)
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				levels = append(levels, check{n, dir})
			}
		}
	}

	for _, c := range levels {
		oldLoc, newLoc := current.Content, ev.Content
		if c.dir != "" {
			if oldLoc, err = pyDictGet(oldLoc, c.dir); err != nil {
				return err
			}
			if newLoc, err = pyDictGet(newLoc, c.dir); err != nil {
				return err
			}
		}
		var oldLevel, newLevel *int64
		if v, ok := field(oldLoc, c.name); ok {
			n, err := intOf(v)
			if err != nil {
				return err
			}
			oldLevel = &n
		}
		if v, ok := field(newLoc, c.name); ok {
			n, err := intOf(v)
			if err != nil {
				return err
			}
			newLevel = &n
		}
		if oldLevel != nil && newLevel != nil && *oldLevel == *newLevel {
			continue
		}
		if c.dir == "users" && c.name != ev.Sender && oldLevel != nil && *oldLevel == userLevel {
			return deny("you don't have permission to remove ops level equal to your own")
		}
		if (oldLevel != nil && *oldLevel > userLevel) || (newLevel != nil && *newLevel > userLevel) {
			return deny("you don't have permission to add ops level greater than your own")
		}
	}
	return nil
}

// pyTruthy is Python truthiness for a decoded JSON value.
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
		return len(keys(v)) > 0
	}
	return true
}

// userIDParses is UserID.from_string succeeding: "@" then a localpart, a
// colon, and a domain -- with no validation of either (types/__init__.py:384).
func userIDParses(s string) bool {
	if !strings.HasPrefix(s, "@") {
		return false
	}
	return strings.Contains(s[1:], ":")
}

var validHost = regexp.MustCompile(`\A[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*\z`)

// userIDIsValid is UserID.is_valid: from_string plus
// parse_and_validate_server_name on the domain (util/stringutils.py:143).
func userIDIsValid(s string) bool {
	if !userIDParses(s) {
		return false
	}
	return ValidServerName(s[1:][strings.IndexByte(s[1:], ':')+1:])
}

// Get is Python's obj.get(key) over event content: None (a zero Result) when
// absent or null.
func Get(obj gjson.Result, key string) gjson.Result { return get(obj, key) }

// IsCreator is synapse.events.is_creator.
func IsCreator(create *Event, userID string) (bool, error) { return isCreator(create, userID) }

// UserLevelFromPowerLevels is how state resolution reads a sender's level
// from a power levels event (v2.py:436):
//
//	level = pl.content.get("users", {}).get(sender)
//	if level is None: level = pl.content.get("users_default", 0)
//	return 0 if level is None else int(level)
func UserLevelFromPowerLevels(pl *Event, userID string) (int64, error) {
	users, err := pyDictGet(pl.Content, "users")
	if err != nil {
		return 0, err
	}
	level := get(users, userID)
	if isNone(level) {
		v, ok := field(pl.Content, "users_default")
		if !ok {
			return 0, nil
		}
		level = v
	}
	if isNone(level) {
		return 0, nil
	}
	return intOf(level)
}

// verifyThirdPartyInvite is _verify_third_party_invite (event_auth.py:1171).
//
// Its control flow is reproduced exactly: for each public key of the
// m.room.third_party_invite event, the FIRST ed25519 signature in the signed
// block decides -- a failing one abandons that public key altogether (the
// exception escapes both inner loops) -- and a public key that is not valid
// base64 raises out of the auth check entirely.
func verifyThirdPartyInvite(ev *Event, auth AuthState) (bool, error) {
	tpi, ok := field(ev.Content, "third_party_invite")
	if !ok || !tpi.IsObject() {
		return false, nil
	}
	signed, ok := field(tpi, "signed")
	if !ok || !signed.IsObject() {
		return false, nil
	}
	for _, k := range []string{"mxid", "token", "signatures"} {
		if !has(signed, k) {
			return false, nil
		}
	}
	token, _ := field(signed, "token")
	if token.Type != gjson.String {
		// A non-string token cannot name a state key here.
		return false, raise("third_party_invite token is not a string")
	}
	invite := auth[StateKey{Type: "m.room.third_party_invite", StateKey: token.Str}]
	if invite == nil || invite.Sender != ev.Sender {
		return false, nil
	}
	mxid, _ := field(signed, "mxid")
	if ev.StateKey == nil || !pyEqualString(mxid, *ev.StateKey) {
		return false, nil
	}

	keys, err := publicKeys(invite)
	if err != nil {
		return false, err
	}
	sigs, _ := field(signed, "signatures")
	message, err := signedMessage([]byte(signed.Raw))
	if err != nil {
		return false, err
	}
	for _, pk := range keys {
		// try: ... except (KeyError, SignatureVerifyException): continue
		raw, ok := field(pk, "public_key")
		if !ok {
			continue // KeyError
		}
		if raw.Type != gjson.String {
			return false, raise("public_key is not a string")
		}
		keyBytes, err := decodeUnpaddedBase64(raw.Str)
		if err != nil {
			// binascii.Error is not caught.
			return false, raise("public_key is not base64")
		}
		if !sigs.IsObject() {
			return false, raise("signatures is not a mapping")
		}
		verified, abandon, notDict := false, false, false
		sigs.ForEach(func(server, block gjson.Result) bool {
			if !block.IsObject() {
				notDict = true // .keys() on a non-dict raises, uncaught
				return false
			}
			block.ForEach(func(keyName, sig gjson.Result) bool {
				if !strings.HasPrefix(keyName.String(), "ed25519:") {
					return true
				}
				// verify_signed_json(signed, server, verify_key): the
				// signature for this key name must exist and verify.
				sb, err := decodeUnpaddedBase64(sig.String())
				if err != nil || sig.Type != gjson.String || len(keyBytes) != 32 ||
					!ed25519Verify(keyBytes, message, sb) {
					abandon = true
					return false
				}
				verified = true
				return false
			})
			return !verified && !abandon
		})
		if notDict {
			return false, raise("a signature block is not a mapping")
		}
		if verified {
			return true, nil
		}
	}
	return false, nil
}

// publicKeys is get_public_keys (event_auth.py:1242).
func publicKeys(invite *Event) ([]gjson.Result, error) {
	var out []gjson.Result
	if v, ok := field(invite.Content, "public_key"); ok {
		obj := `{"public_key":` + v.Raw
		if u, ok := field(invite.Content, "key_validity_url"); ok {
			obj += `,"key_validity_url":` + u.Raw
		}
		out = append(out, gjson.Parse(obj+"}"))
	}
	list := get(invite.Content, "public_keys")
	switch {
	case isNone(list):
		if v, ok := field(invite.Content, "public_keys"); ok && v.Type == gjson.Null {
			return nil, raise("public_keys is None")
		}
	case list.IsArray():
		for _, e := range list.Array() {
			if !e.IsObject() {
				// public_key_object["public_key"] on a non-dict.
				return nil, raise("public_keys entry is not an object")
			}
			out = append(out, e)
		}
	default:
		return nil, raise("public_keys is not a list")
	}
	return out, nil
}

// signedMessage is what verify_signed_json checks a signature over: the
// object without signatures and unsigned, canonicalized.
func signedMessage(raw []byte) ([]byte, error) {
	m, err := without(raw, "signatures", "unsigned")
	if err != nil {
		return nil, err
	}
	return Canonical(m)
}

func ed25519Verify(key, message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(key), message, sig)
}

// UserPowerLevel is get_user_power_level (event_auth.py:1116), for callers
// outside the auth rules: push evaluation reads the sender's level with it.
func UserPowerLevel(userID string, auth AuthState) (int64, error) {
	return getUserPowerLevel(userID, auth)
}

// ValidServerName is parse_and_validate_server_name succeeding
// (util/stringutils.py:143).
func ValidServerName(name string) bool {
	host := name
	if !strings.HasSuffix(name, "]") {
		if i := strings.LastIndexByte(name, ':'); i >= 0 {
			host = name[:i]
			if _, err := pyIntString(name[i+1:]); err != nil {
				return false
			}
		}
	}
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") || len(host) < 3 {
			return false
		}
		a, err := netip.ParseAddr(host[1 : len(host)-1])
		return err == nil && a.Is6()
	}
	return validHost.MatchString(host)
}
