// Package pdu holds what PDU handling needs to agree with Synapse: room
// versions, events as Synapse sees them, and Synapse's authorization rules.
//
// It is a port of Synapse, not an implementation of the spec. Where the two
// differ, Synapse wins, because the point is to reach the decision Synapse
// reached. Each rule cites the Synapse source it comes from.
package pdu

// Event formats (rust/src/room_versions.rs EventFormatVersions).
const (
	FormatV1V2         = 1 // event IDs are chosen by the origin
	FormatV3           = 2 // event IDs are reference hashes
	FormatV4Plus       = 3 // ... url-safe
	FormatV11HydraPlus = 4 // room ID is the create event's ID (MSC4291)
)

// State resolution algorithms (StateResolutionVersions).
const (
	StateResV1  = 1
	StateResV2  = 2
	StateResV21 = 3 // MSC4297
)

// RoomVersion is the subset of Synapse's RoomVersion that authorization and
// state resolution depend on.
type RoomVersion struct {
	ID                            string
	EventFormat                   int
	StateRes                      int
	EnforceKeyValidity            bool
	SpecialCaseAliasesAuth        bool
	StrictCanonicalJSON           bool
	LimitNotificationsPowerLevels bool
	ImplicitRoomCreator           bool
	UpdatedRedactionRules         bool
	RestrictedJoinRule            bool
	RestrictedJoinRuleFix         bool
	KnockJoinRule                 bool
	KnockRestrictedJoinRule       bool
	EnforceIntPowerLevels         bool
	MSC3757                       bool
	MSC4289CreatorPower           bool
	MSC4291RoomIDsAsHashes        bool
	StrictEventByteLimits         bool
}

// The stable room versions, each built on the previous exactly as
// rust/src/room_versions.rs builds them (`..Self::Vn`).
var roomVersions = func() map[string]*RoomVersion {
	v1 := RoomVersion{ID: "1", EventFormat: FormatV1V2, StateRes: StateResV1, SpecialCaseAliasesAuth: true}
	v2 := v1
	v2.ID, v2.StateRes = "2", StateResV2
	v3 := v2
	v3.ID, v3.EventFormat = "3", FormatV3
	v4 := v3
	v4.ID, v4.EventFormat = "4", FormatV4Plus
	v5 := v4
	v5.ID, v5.EnforceKeyValidity = "5", true
	v6 := v5
	v6.ID, v6.SpecialCaseAliasesAuth, v6.StrictCanonicalJSON, v6.LimitNotificationsPowerLevels = "6", false, true, true
	v7 := v6
	v7.ID, v7.KnockJoinRule = "7", true
	v8 := v7
	v8.ID, v8.RestrictedJoinRule = "8", true
	v9 := v8
	v9.ID, v9.RestrictedJoinRuleFix = "9", true
	v10 := v9
	v10.ID, v10.KnockRestrictedJoinRule, v10.EnforceIntPowerLevels = "10", true, true
	v11 := v10
	v11.ID, v11.ImplicitRoomCreator, v11.UpdatedRedactionRules, v11.StrictEventByteLimits = "11", true, true, true
	v12 := v11
	v12.ID, v12.EventFormat, v12.StateRes, v12.MSC4289CreatorPower, v12.MSC4291RoomIDsAsHashes =
		"12", FormatV11HydraPlus, StateResV21, true, true

	out := map[string]*RoomVersion{}
	for _, v := range []RoomVersion{v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12} {
		v := v
		out[v.ID] = &v
	}
	return out
}()

// LookupRoomVersion returns a known room version. Unstable and MSC versions
// are deliberately absent: anything not listed is left to Synapse.
func LookupRoomVersion(id string) (*RoomVersion, bool) {
	v, ok := roomVersions[id]
	return v, ok
}

// KnownRoomVersion reports whether Synapse knows the version, for the create
// event's room_version check. Synapse's KNOWN_ROOM_VERSIONS also holds
// unstable MSC versions; an event naming one of those is uncertain here rather
// than rejected, see checkCreate.
func KnownRoomVersion(id string) bool {
	_, ok := roomVersions[id]
	return ok
}
