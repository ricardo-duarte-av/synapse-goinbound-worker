package pdu

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

// Event is a PDU as Synapse's EventBase presents it to the auth rules and to
// state resolution.
type Event struct {
	ID       string
	RoomID   string
	Type     string
	StateKey *string
	Sender   string
	// Content is the event's content object, raw.
	Content        gjson.Result
	AuthEvents     []string
	PrevEvents     []string
	OriginServerTS int64
	Depth          int64
	// Redacts is the redacted event, from the top level (or, in room
	// versions with updated redaction rules, content).
	Redacts *string
	// Signatures is the "signatures" object: server name -> key id -> sig.
	Signatures gjson.Result
	// Rejected is Synapse's rejected_reason being set.
	Rejected bool
	Room     *RoomVersion
	// JSON is the stored event JSON.
	JSON []byte
	// RecheckRedaction is set by event auth, as Synapse sets the internal
	// metadata flag of the same name: a redaction whose sender may only
	// redact their own events, in a room version that checks that later.
	RecheckRedaction bool
}

// ErrMalformed is an event Synapse would not have accepted in this shape,
// or whose shape this package does not reproduce Synapse's handling of.
var ErrMalformed = errors.New("pdu: malformed event")

// ParseEvent reads a stored event. eventID is required for formats where the
// ID is not in the JSON (v3 and later); for v1/v2 the JSON's event_id is used.
func ParseEvent(raw []byte, eventID string, rv *RoomVersion, rejected bool) (*Event, error) {
	if !gjson.ValidBytes(raw) {
		return nil, fmt.Errorf("%w: invalid JSON", ErrMalformed)
	}
	j := gjson.ParseBytes(raw)
	if !j.IsObject() {
		return nil, fmt.Errorf("%w: not an object", ErrMalformed)
	}
	ev := &Event{Room: rv, Rejected: rejected, JSON: raw}

	str := func(key string) (string, error) {
		v, ok := field(j, key)
		if !ok || v.Type != gjson.String {
			return "", fmt.Errorf("%w: %s is not a string", ErrMalformed, key)
		}
		return v.Str, nil
	}

	var err error
	if ev.Type, err = str("type"); err != nil {
		return nil, err
	}
	if ev.Sender, err = str("sender"); err != nil {
		return nil, err
	}

	ev.ID = eventID
	if rv.EventFormat == FormatV1V2 {
		if ev.ID, err = str("event_id"); err != nil {
			return nil, err
		}
	} else if ev.ID == "" {
		return nil, fmt.Errorf("%w: no event id given for room version %s", ErrMalformed, rv.ID)
	}

	if v, ok := field(j, "room_id"); ok {
		if v.Type != gjson.String {
			return nil, fmt.Errorf("%w: room_id is not a string", ErrMalformed)
		}
		ev.RoomID = v.Str
	} else if rv.MSC4291RoomIDsAsHashes && ev.Type == "m.room.create" {
		// The create event of a v12 room has no room_id: the room ID is
		// its event ID with the sigil swapped (MSC4291).
		ev.RoomID = "!" + strings.TrimPrefix(ev.ID, "$")
	} else {
		return nil, fmt.Errorf("%w: no room_id", ErrMalformed)
	}

	if v, ok := field(j, "state_key"); ok {
		if v.Type != gjson.String {
			return nil, fmt.Errorf("%w: state_key is not a string", ErrMalformed)
		}
		sk := v.Str
		ev.StateKey = &sk
	}

	content, ok := field(j, "content")
	if !ok || !content.IsObject() {
		return nil, fmt.Errorf("%w: content is not an object", ErrMalformed)
	}
	ev.Content = content

	if ev.AuthEvents, err = eventRefs(j, "auth_events", rv); err != nil {
		return nil, err
	}
	if ev.PrevEvents, err = eventRefs(j, "prev_events", rv); err != nil {
		return nil, err
	}
	if rv.EventFormat == FormatV11HydraPlus && !(ev.Type == "m.room.create" && ev.StateKey != nil && *ev.StateKey == "") {
		// The create event is implicitly an auth event of every other
		// event, and must not be listed (rust/src/events/formats/v4.rs
		// auth_event_ids). Synapse's auth_event_ids() appends it, and
		// everything downstream -- auth checks, auth chains, state
		// resolution -- sees it there.
		createID := "$" + strings.TrimPrefix(ev.RoomID, "!")
		for _, id := range ev.AuthEvents {
			if id == createID {
				return nil, fmt.Errorf("%w: create event listed explicitly in auth_events", ErrMalformed)
			}
		}
		ev.AuthEvents = append(ev.AuthEvents, createID)
	}

	ev.OriginServerTS = get(j, "origin_server_ts").Int()
	ev.Depth = get(j, "depth").Int()
	ev.Signatures = get(j, "signatures")

	if rv.UpdatedRedactionRules && ev.Type == "m.room.redaction" {
		if v := get(content, "redacts"); v.Type == gjson.String {
			r := v.Str
			ev.Redacts = &r
		}
	}
	if ev.Redacts == nil {
		if v := get(j, "redacts"); v.Type == gjson.String {
			r := v.Str
			ev.Redacts = &r
		}
	}
	return ev, nil
}

// eventRefs reads auth_events or prev_events. Format v1/v2 lists
// [event_id, {hashes}] pairs; later formats list bare IDs.
func eventRefs(j gjson.Result, key string, rv *RoomVersion) ([]string, error) {
	v, ok := field(j, key)
	if !ok {
		return nil, nil
	}
	if !v.IsArray() {
		return nil, fmt.Errorf("%w: %s is not a list", ErrMalformed, key)
	}
	var out []string
	var bad bool
	v.ForEach(func(_, e gjson.Result) bool {
		if rv.EventFormat == FormatV1V2 {
			if !e.IsArray() || len(e.Array()) < 1 || e.Array()[0].Type != gjson.String {
				bad = true
				return false
			}
			out = append(out, e.Array()[0].Str)
			return true
		}
		if e.Type != gjson.String {
			bad = true
			return false
		}
		out = append(out, e.Str)
		return true
	})
	if bad {
		return nil, fmt.Errorf("%w: %s holds something other than event references", ErrMalformed, key)
	}
	return out, nil
}

// IsState is Synapse's event.is_state().
func (e *Event) IsState() bool { return e.StateKey != nil }

// Key is the event's (type, state_key), for a state event.
func (e *Event) Key() StateKey {
	if e.StateKey == nil {
		return StateKey{Type: e.Type}
	}
	return StateKey{Type: e.Type, StateKey: *e.StateKey}
}

// Membership is Synapse's event.membership, which reads content["membership"]
// and so raises when it is absent.
func (e *Event) Membership() (string, error) {
	v, ok := field(e.Content, "membership")
	if !ok {
		return "", raise("KeyError: membership")
	}
	if v.Type != gjson.String {
		// Synapse compares it with string constants, so a non-string
		// matches none of them -- but this package does not try to follow
		// such an event through every comparison.
		return "", raise("membership is not a string")
	}
	return v.Str, nil
}

// StateKey is a (type, state_key) pair.
type StateKey struct {
	Type     string
	StateKey string
}

// StateMap is room state: (type, state_key) -> event ID.
type StateMap map[StateKey]string

// domainOf is Synapse's get_domain_from_id: everything after the first colon.
func domainOf(s string) (string, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", raise("SynapseError: invalid ID " + s)
	}
	return s[i+1:], nil
}
