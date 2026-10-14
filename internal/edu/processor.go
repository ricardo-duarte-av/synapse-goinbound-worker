package edu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/acl"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edutype"
)

// EDU is one EDU of a transaction. Content is always a JSON object: the
// transaction parser leaves anything else to Synapse.
type EDU struct {
	Type    string
	Content json.RawMessage
}

// Action is what happens to one EDU.
type Action string

const (
	// Forward sends the EDU to Step.Instance.
	Forward Action = "forward"
	// DropPresenceUntracked drops a presence EDU because track_presence is
	// off (federation_server.py:1686).
	DropPresenceUntracked Action = "drop_presence_untracked"
	// DropACL drops a typing EDU, or a receipt EDU every room of which the
	// origin is banned from, per MSC4163 (federation_server.py:586-624).
	DropACL Action = "drop_acl"
)

// Step is the decision for one EDU.
type Step struct {
	Type     string
	Action   Action
	Instance string
	// Content is what is forwarded. For a receipt EDU with some rooms
	// removed by ACL it is the filtered content, otherwise the original.
	Content json.RawMessage
	// RemovedRooms counts receipt rooms dropped by ACL.
	RemovedRooms int
}

// ErrUncertain means an EDU cannot be decided the way Synapse would decide it.
// The whole transaction must then go to Synapse, which is always correct.
var ErrUncertain = errors.New("edu: transaction must be left to Synapse")

// ACL answers whether a server host may send EDUs for a room.
type ACL interface {
	Allowed(ctx context.Context, serverHost, roomID string) (bool, error)
}

// Sender forwards one EDU to an instance.
type Sender interface {
	SendEDU(ctx context.Context, instance, eduType, origin string, content json.RawMessage) error
}

// Processor plans and executes the EDUs of one transaction.
type Processor struct {
	router        *Router
	acl           ACL
	send          Sender
	trackPresence bool
	log           zerolog.Logger

	unknownMu sync.Mutex
	unknown   map[string]bool
}

// NewProcessor builds a Processor. send may be nil for a processor that only
// plans, as in shadow mode.
func NewProcessor(router *Router, aclChecker ACL, send Sender, trackPresence bool, log zerolog.Logger) *Processor {
	return &Processor{
		router:        router,
		acl:           aclChecker,
		send:          send,
		trackPresence: trackPresence,
		log:           log,
		unknown:       make(map[string]bool),
	}
}

// Plan decides what happens to each EDU, in order, without doing any of it.
//
// It returns ErrUncertain -- or a database error, which callers treat the same
// way -- whenever Synapse's answer cannot be reproduced exactly. Because Plan
// has no effects, the transaction can still be handed to Synapse untouched.
func (p *Processor) Plan(ctx context.Context, origin string, edus []EDU) ([]Step, error) {
	host := acl.ServerHost(origin)
	steps := make([]Step, 0, len(edus))
	for _, e := range edus {
		s := Step{Type: e.Type, Content: e.Content}

		if !p.trackPresence && e.Type == edutype.Presence {
			s.Action = DropPresenceUntracked
			steps = append(steps, s)
			continue
		}

		switch e.Type {
		case edutype.Typing:
			allowed, err := p.typingAllowed(ctx, host, e.Content)
			if err != nil {
				return nil, err
			}
			if !allowed {
				s.Action = DropACL
				steps = append(steps, s)
				continue
			}
		case edutype.Receipt:
			filtered, removed, err := p.filterReceipts(ctx, host, e.Content)
			if err != nil {
				return nil, err
			}
			if filtered == nil {
				s.Action, s.RemovedRooms = DropACL, removed
				steps = append(steps, s)
				continue
			}
			s.Content, s.RemovedRooms = filtered, removed
		default:
			if !edutype.Known(e.Type) {
				p.noteUnknown(origin, e.Type)
			}
		}

		s.Action = Forward
		s.Instance = p.router.Instance(e.Type)
		steps = append(steps, s)
	}
	return steps, nil
}

// typingAllowed applies the ACL to a typing EDU's room_id.
//
// Synapse reads edu.content["room_id"] inside its error handler, so a missing
// or non-string room_id fails the whole transaction with a 500. That is
// Synapse's answer to give, so it is left to Synapse.
func (p *Processor) typingAllowed(ctx context.Context, host string, content json.RawMessage) (bool, error) {
	var c struct {
		RoomID *string `json:"room_id"`
	}
	if err := json.Unmarshal(content, &c); err != nil || c.RoomID == nil {
		return false, ErrUncertain
	}
	return p.allowed(ctx, host, *c.RoomID)
}

// filterReceipts removes the rooms the origin is banned from. It returns nil
// content when no room is left, which Synapse treats as "ignore the whole
// EDU" (federation_server.py:622).
func (p *Processor) filterReceipts(ctx context.Context, host string, content json.RawMessage) (json.RawMessage, int, error) {
	var rooms map[string]json.RawMessage
	if err := json.Unmarshal(content, &rooms); err != nil {
		return nil, 0, ErrUncertain
	}
	removed := 0
	for roomID := range rooms {
		ok, err := p.allowed(ctx, host, roomID)
		if err != nil {
			return nil, 0, err
		}
		if !ok {
			delete(rooms, roomID)
			removed++
		}
	}
	if removed == 0 {
		// Forward exactly what arrived.
		return content, 0, nil
	}
	if len(rooms) == 0 {
		return nil, removed, nil
	}
	b, err := json.Marshal(rooms)
	if err != nil {
		return nil, 0, fmt.Errorf("edu: re-encode receipts: %w", err)
	}
	return b, removed, nil
}

func (p *Processor) allowed(ctx context.Context, host, roomID string) (bool, error) {
	ok, err := p.acl.Allowed(ctx, host, roomID)
	if errors.Is(err, acl.ErrUncertain) {
		return false, ErrUncertain
	}
	return ok, err
}

// noteUnknown logs the first sighting of each EDU type Synapse has no handler
// for. Such EDUs are forwarded to the main process, as Synapse does, where
// they are logged and dropped -- so the type name in this log line is the only
// record of what they were.
func (p *Processor) noteUnknown(origin, eduType string) {
	p.unknownMu.Lock()
	defer p.unknownMu.Unlock()
	if p.unknown[eduType] || len(p.unknown) >= 256 {
		return
	}
	p.unknown[eduType] = true
	p.log.Info().Str("edu_type", eduType).Str("origin", origin).
		Msg("First EDU of a type Synapse has no handler for; forwarding to main as Synapse does")
}

// ForwardError is a failure to forward an EDU. The transaction fails with a
// 500 so that the sender retries it: Synapse does the same
// (federation_server.py:639), because some EDUs -- to-device messages above
// all -- must be delivered reliably, and an HTTP error is the only way the
// protocol has to say one was not.
type ForwardError struct {
	Type string
	Err  error
}

func (e *ForwardError) Error() string {
	return fmt.Sprintf("Error handing EDU of type %s", e.Type)
}

func (e *ForwardError) Unwrap() error { return e.Err }

// Execute carries out a plan.
//
// EDUs of the same type are forwarded one after another in transaction order;
// different types go concurrently. Synapse runs up to ten EDUs at once with no
// ordering between them (TRANSACTION_CONCURRENCY_LIMIT), so this is slightly
// stricter than Synapse, and the difference matters for the EDUs where order
// has meaning: device list updates chain through prev_id, and of two typing
// updates for the same room the second must win.
func (p *Processor) Execute(ctx context.Context, origin string, steps []Step) error {
	if p.send == nil {
		return errors.New("edu: processor has no sender")
	}

	// Group by type in order of first appearance. The map only indexes into
	// the slice: iterating a Go map would randomise the order.
	var groups [][]Step
	index := make(map[string]int)
	for _, s := range steps {
		if s.Action != Forward {
			continue
		}
		i, ok := index[s.Type]
		if !ok {
			i = len(groups)
			index[s.Type] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], s)
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	for _, g := range groups {
		wg.Add(1)
		go func(g []Step) {
			defer wg.Done()
			for _, s := range g {
				err := p.send.SendEDU(ctx, s.Instance, s.Type, origin, s.Content)
				if err != nil {
					p.log.Warn().Err(err).Str("edu_type", s.Type).Str("instance", s.Instance).
						Str("origin", origin).Msg("Failed to forward EDU")
					mu.Lock()
					if firstErr == nil {
						firstErr = &ForwardError{Type: s.Type, Err: err}
					}
					mu.Unlock()
					// Later EDUs of this type would be applied out of
					// order relative to this one; the sender retries the
					// whole transaction anyway.
					return
				}
			}
		}(g)
	}
	wg.Wait()
	return firstErr
}

// Record counts a plan's decisions. path is "native" for EDUs actually
// handled, "shadow" for what shadow mode would have done.
func Record(path string, steps []Step) {
	for _, s := range steps {
		edusDecided.WithLabelValues(path, edutype.Label(s.Type), string(s.Action), s.Instance).Inc()
		if s.RemovedRooms > 0 {
			receiptRoomsRemoved.WithLabelValues(path).Add(float64(s.RemovedRooms))
		}
	}
}

var (
	edusDecided = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_edus_total",
		Help: "Inbound EDUs by path (native or shadow), type, action and destination instance.",
	}, []string{"path", "edu_type", "action", "instance"})
	receiptRoomsRemoved = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_receipt_rooms_removed_by_acl_total",
		Help: "Rooms removed from receipt EDUs because the origin is banned by the room's server ACL.",
	}, []string{"path"})
)
