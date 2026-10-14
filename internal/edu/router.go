// Package edu decides what happens to each EDU of an inbound transaction, and
// makes it happen by forwarding to the instance Synapse would forward it to.
//
// It reproduces FederationHandlerRegistry.on_edu (federation_server.py:1685)
// as it behaves on a generic worker, which registers no EDU handler of its own
// and so forwards everything: presence is dropped when not tracked, a type
// with registered writer instances goes to one of them, and anything else goes
// to the main process.
package edu

import (
	"fmt"
	"math/rand/v2"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edutype"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// Router maps an EDU type to the instances that handle it.
type Router struct {
	byType map[string][]string
	// pick chooses among several instances; replaced in tests.
	pick func(n int) int
}

// NewRouter builds the routing table Synapse builds through
// register_instances_for_edu on a generic worker:
//
//	m.typing                      writers.typing        handlers/typing.py:95
//	m.receipt                     writers.receipts      handlers/receipts.py:70
//	m.direct_to_device            writers.to_device     handlers/devicemessage.py:99
//	m.presence                    writers.presence      handlers/presence.py:526
//	m.device_list_update          writers.device_lists[0]  handlers/device.py:196
//	m.signing_key_update (+unstable) writers.device_lists[0]  handlers/e2e_keys.py:111
//
// Every other type falls back to ["master"] (federation_server.py:1698).
//
// This is the table as Synapse's handlers DEFINE it, which is not quite what a
// federation-only Python worker does. Those registrations happen in handler
// constructors, and such a worker never constructs ReceiptsHandler or
// DeviceMessageHandler -- only client servlets do (rest/client/receipts.py,
// sendtodevice.py). So on the Python inbound worker, receipts and to-device
// EDUs fall back to main, and main, which does register them, forwards them
// on to the writer. That hop changes nothing but load on main, the most
// contended process, so it is deliberately not reproduced: they go straight
// to their writer. It is what the "24k/day to main" measured in October 2026
// was.
func NewRouter(w synapsecfg.Writers) *Router {
	first := func(l []string) []string { return l[:1] }
	return &Router{
		byType: map[string][]string{
			edutype.Typing:                   w.Typing,
			edutype.Receipt:                  w.Receipts,
			edutype.DirectToDevice:           w.ToDevice,
			edutype.Presence:                 w.Presence,
			edutype.DeviceListUpdate:         first(w.DeviceLists),
			edutype.SigningKeyUpdate:         first(w.DeviceLists),
			edutype.UnstableSigningKeyUpdate: first(w.DeviceLists),
		},
		pick: rand.IntN,
	}
}

// Instance returns where an EDU of this type is forwarded. Synapse picks one
// of several instances at random "so that we don't overload one".
func (r *Router) Instance(eduType string) string {
	instances, ok := r.byType[eduType]
	if !ok {
		return synapsecfg.MainProcessInstanceName
	}
	if len(instances) == 1 {
		return instances[0]
	}
	return instances[r.pick(len(instances))]
}

// Instances returns every instance this router can forward to, for startup
// validation against the instance map.
func (r *Router) Instances() []string {
	seen := map[string]bool{synapsecfg.MainProcessInstanceName: true}
	out := []string{synapsecfg.MainProcessInstanceName}
	for _, t := range []string{
		edutype.Typing, edutype.Receipt, edutype.DirectToDevice, edutype.Presence,
		edutype.DeviceListUpdate, edutype.SigningKeyUpdate, edutype.UnstableSigningKeyUpdate,
	} {
		for _, inst := range r.byType[t] {
			if !seen[inst] {
				seen[inst] = true
				out = append(out, inst)
			}
		}
	}
	return out
}

// Validate checks that every instance the router can choose is reachable.
// Synapse fails such an EDU at the moment it arrives ("Instance %r not in
// 'instance_map' config"); failing at startup is the same answer, earlier.
func (r *Router) Validate(has func(string) bool) error {
	for _, inst := range r.Instances() {
		if !has(inst) {
			return fmt.Errorf("edu: instance %q handles EDUs but is not in homeserver.yaml's instance_map", inst)
		}
	}
	return nil
}
