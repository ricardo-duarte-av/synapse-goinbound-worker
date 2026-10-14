// Package edutype names the EDU types Synapse knows (api/constants.py
// EduTypes), and bounds the label set used for them in metrics.
package edutype

const (
	Presence                 = "m.presence"
	Typing                   = "m.typing"
	Receipt                  = "m.receipt"
	DeviceListUpdate         = "m.device_list_update"
	SigningKeyUpdate         = "m.signing_key_update"
	UnstableSigningKeyUpdate = "org.matrix.signing_key_update"
	DirectToDevice           = "m.direct_to_device"
)

// Other is the label for every EDU type Synapse does not know.
const Other = "other"

// Label returns the metric label for an EDU type.
//
// An EDU type is chosen by the remote server, so using it raw as a label would
// let anyone create unbounded series. Types Synapse knows keep their name; the
// rest share Other, and the edu package logs the actual names instead.
func Label(t string) string {
	if Known(t) {
		return t
	}
	return Other
}

// Known reports whether Synapse registers a handler for the type.
func Known(t string) bool {
	switch t {
	case Presence, Typing, Receipt, DeviceListUpdate, SigningKeyUpdate,
		UnstableSigningKeyUpdate, DirectToDevice:
		return true
	}
	return false
}
