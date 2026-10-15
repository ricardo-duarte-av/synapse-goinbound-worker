package acl

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

// ErrUncertain means the ACL cannot be evaluated the way Synapse would, and the
// transaction must be left to Synapse.
var ErrUncertain = errors.New("acl: cannot evaluate this room's ACL as Synapse would")

// Lookup reads a room's current server ACL event.
type Lookup interface {
	CurrentServerACL(ctx context.Context, roomID string) (*store.ServerACLEvent, error)
}

// Checker answers Synapse's check_server_matches_acl
// (federation_server.py:1597) for the room's CURRENT state, which is what
// Synapse checks typing and receipt EDUs against (MSC4163).
//
// A room's result is cached for a few seconds. Synapse's own cache is
// invalidated over replication instead; the difference is that an ACL change
// can take up to TTL to apply to typing notifications and read receipts here,
// which is the least consequential place a stale ACL could be.
type Checker struct {
	db  Lookup
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	rooms map[string]roomEntry
}

// roomEntry is a room's current ACL. The evaluator is kept while the room's
// ACL event stays the same, and replaced with it: moderation bots send ~800
// ACL events a day here, of up to 1,600 globs each, so evaluators kept by
// event ID pile up.
type roomEntry struct {
	at       time.Time
	eventID  string
	acl      *ServerACL // nil: the room has no ACL
	redacted bool
}

// maxRooms bounds the cache. Exceeding it clears it: rebuilding is a
// lookup and a parse per room, and an LRU would be machinery for nothing.
const maxRooms = 10000

// NewChecker builds a Checker. A ttl of zero uses 5s.
func NewChecker(db Lookup, ttl time.Duration) *Checker {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &Checker{
		db:    db,
		ttl:   ttl,
		now:   time.Now,
		rooms: make(map[string]roomEntry),
	}
}

// Allowed reports whether serverHost -- a server name WITHOUT its port -- may
// send EDUs for roomID.
//
// ErrUncertain is returned when the room's ACL event has been redacted. Synapse
// would evaluate the redacted event, but whether a given redaction applies
// depends on the room version, and the redacted ACL bans everyone -- too
// consequential to guess at.
func (c *Checker) Allowed(ctx context.Context, serverHost, roomID string) (bool, error) {
	e, err := c.lookup(ctx, roomID)
	if err != nil {
		return false, err
	}
	if e.redacted {
		aclLookups.WithLabelValues("redacted").Inc()
		return false, ErrUncertain
	}
	return e.acl.Allowed(serverHost), nil
}

func (c *Checker) lookup(ctx context.Context, roomID string) (roomEntry, error) {
	now := c.now()

	c.mu.Lock()
	old, had := c.rooms[roomID]
	c.mu.Unlock()
	if had && now.Sub(old.at) < c.ttl {
		aclLookups.WithLabelValues("cached").Inc()
		return old, nil
	}

	ev, err := c.db.CurrentServerACL(ctx, roomID)
	if err != nil {
		aclLookups.WithLabelValues("error").Inc()
		return roomEntry{}, err
	}
	aclLookups.WithLabelValues("db").Inc()

	e := roomEntry{at: now}
	if ev != nil {
		e.eventID, e.redacted = ev.EventID, ev.Redacted
		if had && old.eventID == ev.EventID && old.redacted == ev.Redacted {
			e.acl = old.acl
		} else {
			e.acl = parse(ev)
		}
	}

	c.mu.Lock()
	if len(c.rooms) >= maxRooms {
		c.rooms = make(map[string]roomEntry)
	}
	c.rooms[roomID] = e
	c.mu.Unlock()
	return e, nil
}

// parse returns the evaluator for an ACL event.
//
// An event that does not parse yields an evaluator that allows everyone. The
// stored JSON of a persisted event always parses, so this is unreachable in
// practice. Malformed VALUES inside a parseable event are ignored field by
// field, as Synapse does (storage/controllers/state.py:920).
func parse(ev *store.ServerACLEvent) *ServerACL {
	a, err := ParseServerACL(ev.JSON)
	if err != nil {
		a = &ServerACL{allowIPLiterals: true, allow: allowAll}
	}
	return a
}

// allowAll is the allow list of an evaluator that restricts nobody.
var allowAll = compileGlobs([]byte(`["*"]`))

// ServerHost strips the port from a server name, as Synapse's
// parse_server_name does before an ACL check (federation_server.py:587):
// a name ending in "]" is an IPv6 literal with no port, and otherwise anything
// after the LAST colon is the port.
func ServerHost(serverName string) string {
	if strings.HasSuffix(serverName, "]") {
		return serverName
	}
	if i := strings.LastIndexByte(serverName, ':'); i >= 0 {
		return serverName[:i]
	}
	return serverName
}

var aclLookups = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "goinbound_acl_lookups_total",
	Help: "Room server ACL lookups for typing and receipt EDUs, by source.",
}, []string{"source"})
