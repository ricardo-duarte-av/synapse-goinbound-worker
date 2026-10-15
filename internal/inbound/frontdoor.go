package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/acl"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
)

// The /send side of write mode: FederationServer._handle_pdus_in_txn
// (federation_server.py) up to staging, in two steps. Plan does every check
// that decides a PDU's entry in the /send answer, and writes nothing; when
// one of them is not certain to come out as Synapse's would, the whole
// transaction is Synapse's. Run then asks policy servers, stages each PDU
// and starts its room.

// transactionConcurrency is TRANSACTION_CONCURRENCY_LIMIT: rooms at once.
const transactionConcurrency = 10

// aclDenied is check_server_matches_acl's AuthError, as error_dict gives it.
var aclDenied = json.RawMessage(`{"errcode":"M_FORBIDDEN","error":"Server is banned from room"}`)

// FrontDoorDeps is what the front door reads and calls.
type FrontDoorDeps struct {
	Store     *pdustore.Store
	Verifier  *pduverify.Verifier
	ACL       *acl.Checker
	Policy    pduverify.PolicyAsker // nil: never ask (and so never certain)
	Processor *Processor
	Server    string
}

// FrontDoor plans and runs transactions' PDUs.
type FrontDoor struct{ d FrontDoorDeps }

// NewFrontDoor builds a front door.
func NewFrontDoor(d FrontDoorDeps) *FrontDoor { return &FrontDoor{d: d} }

// Plan is a transaction's PDUs, checked.
type Plan struct {
	f       *FrontDoor
	origin  string
	at      time.Time
	rooms   []string
	byRoom  map[string][]*plannedPDU
	results map[string]json.RawMessage
}

type plannedPDU struct {
	raw    []byte
	ev     *pdu.Event
	id     string
	room   string
	rv     *pdu.RoomVersion
	policy pduverify.PolicyVerdict
}

// PlanPDUs checks a transaction's PDUs as _handle_pdus_in_txn and
// _check_sigs_and_hash would. reason is set when Synapse must answer the
// transaction instead.
func (f *FrontDoor) PlanPDUs(ctx context.Context, origin string, pdus []json.RawMessage, requestTime time.Time) (*Plan, string) {
	p := &Plan{f: f, origin: origin, at: requestTime, byRoom: map[string][]*plannedPDU{}, results: map[string]json.RawMessage{}}
	for _, raw := range pdus {
		room := gjson.GetBytes(raw, "room_id")
		if !room.Exists() || room.Type == gjson.Null || (room.Type == gjson.String && room.Str == "") {
			// "Ignoring PDU as does not have a room_id".
			continue
		}
		if room.Type != gjson.String {
			return nil, "pdu_room_id_not_string"
		}
		rvID, err := f.d.Store.RoomVersion(ctx, room.Str)
		if errors.Is(err, pdustore.ErrUnknownRoom) {
			continue
		}
		if err != nil {
			return nil, "pdu_db_error"
		}
		rv, ok := pdu.LookupRoomVersion(rvID)
		if !ok {
			// UnsupportedRoomVersionError: ignored.
			continue
		}
		// event_from_pdu_json: what it rejects is ignored; anything we
		// would parse differently from Synapse makes the transaction
		// Synapse's.
		if err := pdu.CheckPDUJSON(raw, rv); errors.Is(err, pdu.ErrIgnoredPDU) {
			continue
		} else if err != nil {
			return nil, "pdu_unparseable"
		}
		id := gjson.GetBytes(raw, "event_id").Str
		if rv.EventFormat != pdu.FormatV1V2 {
			if id, err = pdu.CalculateEventID(raw, rv); err != nil {
				return nil, "pdu_event_id"
			}
		}
		if id == "" {
			return nil, "pdu_event_id"
		}
		if _, err := pduverify.StagedEvent(raw, requestTime, "", nil); err != nil {
			return nil, "pdu_unsigned"
		}
		ev, err := pdu.ParseEvent(raw, id, rv, false)
		if err != nil {
			return nil, "pdu_unparseable"
		}
		if _, ok := p.byRoom[room.Str]; !ok {
			p.rooms = append(p.rooms, room.Str)
		}
		p.byRoom[room.Str] = append(p.byRoom[room.Str], &plannedPDU{raw: raw, ev: ev, id: id, room: room.Str, rv: rv})
	}

	host := acl.ServerHost(origin)
	for _, room := range p.rooms {
		allowed, err := f.d.ACL.Allowed(ctx, host, room)
		switch {
		case errors.Is(err, acl.ErrUncertain):
			return nil, "pdu_acl_uncertain"
		case err != nil:
			return nil, "pdu_db_error"
		case !allowed:
			for _, pp := range p.byRoom[room] {
				p.results[pp.id] = aclDenied
			}
			delete(p.byRoom, room)
			continue
		}
		for _, pp := range p.byRoom[room] {
			if reason := f.checkSigs(ctx, pp); reason != "" {
				return nil, reason
			}
		}
	}
	return p, ""
}

// checkSigs is _check_sigs_and_hash, for the outcomes we reproduce: valid,
// and either no policy server or a decided one.
func (f *FrontDoor) checkSigs(ctx context.Context, pp *plannedPDU) string {
	ok, err := pdu.CheckContentHash(pp.raw)
	if err != nil || !ok {
		// Synapse redacts it and stages the pruned copy; not ported.
		return "pdu_content_hash"
	}
	ev := pp.ev
	lookup := func(server string, keyIDs []string) (map[string]pdu.VerifyKey, error) {
		return f.d.Store.VerifyKeys(ctx, server, keyIDs)
	}
	if err := pdu.CheckSignatures(ev, pp.raw, lookup); err != nil {
		if errors.Is(err, pdu.ErrKeyUnknown) {
			// Synapse would fetch the key.
			return "pdu_key_unknown"
		}
		// Synapse's error text is its own to write.
		return "pdu_bad_signature"
	}
	v, err := f.d.Verifier.Policy(ctx, pp.raw, ev, f.d.Server)
	if err != nil {
		return "pdu_db_error"
	}
	if v.Skip != "" {
		return "pdu_policy_uncertain"
	}
	if v.Verdict == pduverify.PolicyAsk && f.d.Policy == nil {
		return "pdu_policy_unasked"
	}
	pp.policy = v
	return ""
}

// Run asks policy servers, stages each PDU and starts its room, returning
// every PDU's entry for the /send answer: {} once staged, or the error.
func (p *Plan) Run(ctx context.Context) map[string]json.RawMessage {
	var mu sync.Mutex
	sem := make(chan struct{}, transactionConcurrency)
	var wg sync.WaitGroup
	for _, room := range p.rooms {
		pps, ok := p.byRoom[room]
		if !ok {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			for _, pp := range pps {
				res := p.stage(ctx, pp)
				mu.Lock()
				p.results[pp.id] = res
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return p.results
}

func (p *Plan) stage(ctx context.Context, pp *plannedPDU) json.RawMessage {
	f := p.f
	meta := []byte(`{}`)
	var sigs map[string]string
	if pp.policy.Verdict == pduverify.PolicyAsk {
		a := f.d.Verifier.AskPolicy(ctx, f.d.Policy, pp.raw, p.at, pp.rv, pp.policy)
		if a.Sigs == nil {
			meta = []byte(`{"soft_failed":true,"policy_server_spammy":true}`)
		} else {
			sigs = a.Sigs
		}
	}
	staged, err := pduverify.StagedEvent(pp.raw, p.at, pp.policy.Server, sigs)
	if err != nil {
		return errorEntry(err)
	}
	if err := f.d.Processor.Received(ctx, p.origin, pp.room, pp.id, staged, meta); err != nil {
		return errorEntry(err)
	}
	return json.RawMessage(`{}`)
}

// errorEntry is {"error": str(e)}.
func errorEntry(err error) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return b
}
