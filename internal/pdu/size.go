package pdu

import "unicode/utf8"

// MaxPDUSize is MAX_PDU_SIZE (api/constants.py): the canonical JSON of a PDU
// may be no larger.
const MaxPDUSize = 65536

// SizeError is EventSizeError. Unpersistable is true when Synapse never
// accepted such an event, so it is dropped; otherwise the event is persisted
// as rejected ("oversized_event"), as older Synapses accepted it.
type SizeError struct {
	Msg           string
	Unpersistable bool
}

func (e *SizeError) Error() string { return e.Msg }

// CheckFieldSizes is _check_size_limits (event_auth.py:451) without the
// whole-PDU check, which needs the PDU as received: see CheckPDUSize.
//
// Python's len() counts codepoints, and Synapse always enforced 255 of them,
// so that limit is strict. The 255-byte limit is strict only in room versions
// with strict_event_byte_limits_room_versions.
func CheckFieldSizes(ev *Event) *SizeError {
	fields := []struct{ name, v string }{
		{"sender", ev.Sender}, {"room_id", ev.RoomID}, {"state_key", ""}, {"type", ev.Type}, {"event_id", ev.ID},
	}
	if ev.StateKey != nil {
		fields[2].v = *ev.StateKey
	}
	for _, f := range fields {
		if utf8.RuneCountInString(f.v) > 255 {
			return &SizeError{Msg: "'" + f.name + "' too large", Unpersistable: true}
		}
	}
	for _, f := range fields {
		if len(f.v) > 255 {
			return &SizeError{Msg: "'" + f.name + "' too large", Unpersistable: ev.Room.StrictEventByteLimits}
		}
	}
	return nil
}

// CheckPDUSize is the whole-PDU part of _check_size_limits, over the PDU as
// received: len(encode_canonical_json(event.get_pdu_json())) > MAX_PDU_SIZE.
// get_pdu_json is the received JSON with unsigned reduced to what federation
// keeps (age), so this is close but not exact for a PDU within a few bytes of
// the limit.
func CheckPDUSize(raw []byte) *SizeError {
	c, err := Canonical(raw)
	if err != nil {
		return nil
	}
	if len(c) > MaxPDUSize {
		return &SizeError{Msg: "event too large", Unpersistable: true}
	}
	return nil
}
