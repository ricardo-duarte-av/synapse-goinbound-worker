package pduverify

import (
	"bytes"
	"encoding/json"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// OutlierVerdict is _auth_and_persist_outliers' prep for one event: drop
// when one of its auth events cannot be found ("Dropping event ... which
// relies on auth_event ..."), else rejected or not. authMap holds the batch's
// events and those already held; a batch event rejected earlier in the batch
// is there unrejected, as in Synapse, where only its context records it. An
// error is an exception Synapse would raise, failing the batch.
func OutlierVerdict(ev *pdu.Event, authMap map[string]*pdu.Event) (rejected string, drop bool, err error) {
	auth := make([]*pdu.Event, 0, len(ev.AuthEvents))
	for _, id := range ev.AuthEvents {
		ae := authMap[id]
		if ae == nil {
			return "", true, nil
		}
		auth = append(auth, ae)
	}
	if se := pdu.CheckFieldSizes(ev); se != nil {
		if se.Unpersistable {
			return "", false, &pdu.RaiseError{Msg: "unpersistable: " + se.Msg}
		}
		return RejectedOversized, false, nil
	}
	if why := validateSignatures(ev); why != "" {
		return RejectedAuthError, false, nil
	}
	if err := pdu.CheckStateIndependentAuthRules(ev, authMap); err != nil {
		if pdu.IsAuthError(err) {
			return RejectedAuthError, false, nil
		}
		return "", false, err
	}
	if err := pdu.CheckStateDependentAuthRules(ev, auth); err != nil {
		if pdu.IsAuthError(err) {
			return RejectedAuthError, false, nil
		}
		return "", false, err
	}
	return "", false, nil
}

// outlierContext is EventContext.for_outlier, serialized.
type outlierContext struct {
	StateGroup            *int64       `json:"state_group"`
	StateGroupBeforeEvent *int64       `json:"state_group_before_event"`
	Rejected              *string      `json:"rejected"`
	StateGroupDeltas      []groupDelta `json:"state_group_deltas"`
	StateDeltaDueToEvent  []stateRow   `json:"state_delta_due_to_event"`
	AppServiceID          *string      `json:"app_service_id"`
	PartialState          bool         `json:"partial_state"`
}

// OutlierEntry is the fed_send_events entry for an outlier: the event as
// pulled, outlier set in its metadata, and an outlier's context (no state
// groups; state_delta_due_to_event null).
func OutlierEntry(raw []byte, ev *pdu.Event, metadata map[string]any, rejected string) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var evDict map[string]any
	if err := dec.Decode(&evDict); err != nil {
		return nil, err
	}
	meta := map[string]any{}
	for k, v := range metadata {
		meta[k] = v
	}
	meta["outlier"] = true
	var rej *string
	if rejected != "" {
		rej = &rejected
	}
	return json.Marshal(struct {
		Event              map[string]any `json:"event"`
		RoomVersion        string         `json:"room_version"`
		EventFormatVersion int            `json:"event_format_version"`
		InternalMetadata   map[string]any `json:"internal_metadata"`
		Outlier            bool           `json:"outlier"`
		RejectedReason     *string        `json:"rejected_reason"`
		Context            outlierContext `json:"context"`
	}{evDict, ev.Room.ID, ev.Room.EventFormat, meta, true, rej,
		outlierContext{Rejected: rej, StateGroupDeltas: []groupDelta{}}})
}
