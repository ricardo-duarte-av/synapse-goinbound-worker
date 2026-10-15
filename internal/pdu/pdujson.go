package pdu

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

// ErrIgnoredPDU is event_from_pdu_json raising a SynapseError:
// _handle_pdus_in_txn ignores such a PDU ("Ignoring PDU for failing to
// deserialize"), giving it no entry in the /send answer.
var ErrIgnoredPDU = errors.New("pdu: fails event_from_pdu_json")

// canonicalJSONMaxInt is CANONICALJSON_MAX_INT, also MAX_DEPTH.
const canonicalJSONMaxInt = 1<<53 - 1

// CheckPDUJSON is the checks event_from_pdu_json (federation_base.py) makes
// before make_event_from_dict: "type" and "depth" present, an object
// unsigned, an integer depth in [0, 2^53-1], canonical JSON in rooms that
// enforce it (after unsigned is stripped to its whitelist), and no create
// event among a v12 event's auth events. An error wrapping ErrIgnoredPDU is
// one of those; any other error is a PDU we do not parse as Synapse would.
func CheckPDUJSON(raw []byte, rv *RoomVersion) error {
	j := gjson.ParseBytes(raw)
	if !j.IsObject() {
		return fmt.Errorf("pdu: not an object")
	}
	for _, k := range []string{"type", "depth"} {
		if !get(j, k).Exists() {
			return fmt.Errorf("%w: missing %s", ErrIgnoredPDU, k)
		}
	}
	unsigned := get(j, "unsigned")
	if unsigned.Exists() && !unsigned.IsObject() {
		// .items() on it raises AttributeError, not a SynapseError.
		return fmt.Errorf("pdu: unsigned is not an object")
	}
	depth := get(j, "depth")
	if !isJSONInt(depth) {
		return fmt.Errorf("%w: depth %s not an integer", ErrIgnoredPDU, depth.Raw)
	}
	if strings.HasPrefix(depth.Raw, "-") && depth.Raw != "-0" {
		return fmt.Errorf("%w: depth too small", ErrIgnoredPDU)
	}
	if !intInRange(depth.Raw) {
		return fmt.Errorf("%w: depth too large", ErrIgnoredPDU)
	}
	if rv.StrictCanonicalJSON {
		var bad error
		j.ForEach(func(k, v gjson.Result) bool {
			if k.Str == "unsigned" {
				// Only what the whitelist keeps is validated.
				keep := map[string]bool{"age": true}
				if get(j, "type").Str == "m.room.member" && get(j, "type").Type == gjson.String {
					keep["knock_room_state"], keep["invite_room_state"] = true, true
				}
				v.ForEach(func(uk, uv gjson.Result) bool {
					if keep[uk.Str] {
						bad = validateCanonical(uv)
					}
					return bad == nil
				})
				return bad == nil
			}
			bad = validateCanonical(v)
			return bad == nil
		})
		if bad != nil {
			return bad
		}
	}
	if rv.MSC4291RoomIDsAsHashes {
		room := get(j, "room_id")
		if room.Type == gjson.String && room.Str != "" {
			create := "$" + room.Str[1:]
			auth := get(j, "auth_events")
			// `create_event_id in auth_events`: a list's members, or a
			// dict's keys, or a string's substrings.
			found := false
			switch {
			case auth.IsArray():
				for _, a := range auth.Array() {
					if a.Type == gjson.String && a.Str == create {
						found = true
					}
				}
			case auth.IsObject():
				found = get(auth, create).Exists()
			case auth.Type == gjson.String:
				found = auth.Str != "" && strings.Contains(auth.Str, create)
			}
			if found && pyTruthy(auth) {
				return fmt.Errorf("%w: auth_events must not contain the create event", ErrIgnoredPDU)
			}
		}
	}
	return nil
}

// isJSONInt is Python's type(v) is int for a decoded JSON value: an integer
// literal (no fraction or exponent), not a bool.
func isJSONInt(v gjson.Result) bool {
	if v.Type != gjson.Number {
		return false
	}
	return !strings.ContainsAny(v.Raw, ".eE")
}

// intInRange says an integer literal is within ±(2^53-1).
func intInRange(raw string) bool {
	s := strings.TrimPrefix(raw, "-")
	s = strings.TrimLeft(s, "0")
	const max = "9007199254740991"
	if len(s) != len(max) {
		return len(s) < len(max)
	}
	return s <= max
}

// validateCanonical is validate_canonicaljson.
func validateCanonical(v gjson.Result) error {
	switch {
	case v.Type == gjson.Number:
		if !isJSONInt(v) {
			return fmt.Errorf("%w: Bad JSON value: float", ErrIgnoredPDU)
		}
		if !intInRange(v.Raw) {
			return fmt.Errorf("%w: JSON integer out of range", ErrIgnoredPDU)
		}
	case v.IsObject(), v.IsArray():
		var bad error
		v.ForEach(func(_, x gjson.Result) bool {
			bad = validateCanonical(x)
			return bad == nil
		})
		return bad
	}
	return nil
}
