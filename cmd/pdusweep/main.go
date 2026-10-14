// Command pdusweep replays stored events through the Go port of Synapse's
// state resolution and auth rules, and compares the outcome with what Synapse
// decided and stored.
//
// For each sampled event it:
//
//  1. loads the state after each prev event (Synapse's stored state groups);
//  2. resolves them with package stateres, giving the state before the event;
//  3. runs Synapse's receive-path auth pipeline (federation_event.py
//     _check_event_auth) with package pdu: checks against the event's own auth
//     events, then against auth events computed from the state before;
//  4. compares the verdict with Synapse's rejection record, and the state after
//     (state before, plus the event if it is accepted state) with the state
//     group Synapse stored for the event.
//
// It only reads. It needs SELECT on pdustore.Tables, which the homeserver's
// own role has; it is a tool to run by hand, not part of the worker.
//
//	go run ./cmd/pdusweep -dsn "host=/var/sockets user=synapse dbname=synapse-db" -n 200 -forks
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/stateres"
)

func main() {
	dsn := flag.String("dsn", "host=/var/sockets user=synapse dbname=synapse-db", "Synapse database")
	n := flag.Int("n", 100, "events to sample per room version")
	versions := flag.String("versions", "2,3,4,5,6,7,8,9,10,11,12", "room versions to sample")
	forks := flag.Bool("forks", false, "only events with two or more prev_events, where state resolution runs")
	rejected := flag.Bool("rejected", false, "only events Synapse rejected")
	window := flag.Int64("window", 2_000_000, "sample from the most recent N stream orderings")
	workers := flag.Int("workers", 4, "events replayed concurrently")
	out := flag.String("out", "", "write one JSON line per mismatch or error to this file")
	event := flag.String("event", "", "replay this one event and print everything, with a state resolution trace")
	walk := flag.Bool("walk", false, "compute auth chain differences by walking the DAG instead of the chain cover index")
	cross := flag.Bool("crosscheck", false, "compute auth chain differences both ways and report any disagreement as an error")
	idsFile := flag.String("ids", "", "replay the event IDs in this file (one per line) instead of sampling")
	sigs := flag.Bool("sigs", false, "check event IDs, content hashes and signatures instead of auth and state")
	flag.Parse()

	ctx := context.Background()
	st, err := pdustore.Open(ctx, *dsn, int32(*workers*2))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer st.Close()
	sw := &sweeper{st: st, groups: newGroupCache(2000), opts: stateres.Options{WalkDAG: *walk, CrossCheck: *cross}, sigs: *sigs}

	if *event != "" {
		sw.opts.Trace = func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
		res := sw.replay(ctx, *event)
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return
	}

	var sink *json.Encoder
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		sink = json.NewEncoder(f)
	}

	if *idsFile != "" {
		b, err := os.ReadFile(*idsFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ids := strings.Fields(string(b))
		start := time.Now()
		results := sw.replayAll(ctx, ids, *workers)
		report("ids", results, time.Since(start))
		if sink != nil {
			for _, r := range results {
				if r.Outcome != outcomeMatch && r.Outcome != outcomeSkipped {
					_ = sink.Encode(r)
				}
			}
		}
		return
	}

	for _, v := range strings.Split(*versions, ",") {
		v = strings.TrimSpace(v)
		ids, err := sample(ctx, st, v, *n, *window, *forks, *rejected)
		if err != nil {
			fmt.Fprintf(os.Stderr, "v%s: sample: %v\n", v, err)
			continue
		}
		start := time.Now()
		results := sw.replayAll(ctx, ids, *workers)
		report(v, results, time.Since(start))
		if sink != nil {
			for _, r := range results {
				if r.Outcome != outcomeMatch && r.Outcome != outcomeSkipped {
					_ = sink.Encode(r)
				}
			}
		}
	}
}

// Outcomes, in increasing order of interest.
const (
	outcomeMatch    = "match"
	outcomeSkipped  = "skipped"
	outcomeRaise    = "raise"    // Synapse would have raised; not comparable
	outcomeError    = "error"    // failed here
	outcomeMismatch = "mismatch" // disagrees with Synapse
)

type result struct {
	EventID      string   `json:"event_id"`
	RoomID       string   `json:"room_id,omitempty"`
	Type         string   `json:"type,omitempty"`
	Version      string   `json:"room_version,omitempty"`
	Prevs        int      `json:"prevs,omitempty"`
	Resolved     bool     `json:"resolved,omitempty"` // state resolution ran
	Outcome      string   `json:"outcome"`
	Reason       string   `json:"reason,omitempty"`
	SynapseRej   bool     `json:"synapse_rejected"`
	OurRej       bool     `json:"our_rejected"`
	OurReason    string   `json:"our_reason,omitempty"`
	StateDiff    []string `json:"state_diff,omitempty"`
	ResolveMS    int64    `json:"resolve_ms,omitempty"`
	AuthMismatch bool     `json:"auth_mismatch,omitempty"`
}

type sweeper struct {
	st     *pdustore.Store
	groups *groupCache
	opts   stateres.Options
	sigs   bool
}

func (s *sweeper) replayAll(ctx context.Context, ids []string, workers int) []*result {
	out := make([]*result, len(ids))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i] = s.replay(ctx, ids[i])
			}
		}()
	}
	for i := range ids {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

func (s *sweeper) replay(ctx context.Context, id string) *result {
	if s.sigs {
		return s.checkSigs(ctx, id)
	}
	res := &result{EventID: id}
	got, bad, err := s.st.GetStoredEvents(ctx, []string{id})
	if err != nil {
		return res.fail(outcomeError, err.Error())
	}
	if e := bad[id]; e != nil {
		return res.fail(outcomeSkipped, "unparseable: "+e.Error())
	}
	se := got[id]
	if se == nil {
		return res.fail(outcomeSkipped, "not found")
	}
	ev := se.Event
	res.RoomID, res.Type, res.Version, res.Prevs = ev.RoomID, ev.Type, ev.Room.ID, len(ev.PrevEvents)
	res.SynapseRej = ev.Rejected
	if se.Outlier {
		return res.fail(outcomeSkipped, "outlier")
	}
	if ev.Type == "m.room.create" {
		return res.fail(outcomeSkipped, "create event")
	}

	// The event's own state group, first: it dates the computation.
	ownGroup, err := s.st.StateGroupForEvent(ctx, id)
	if errors.Is(err, pdustore.ErrNoStateGroup) {
		return res.fail(outcomeSkipped, "no state group for the event")
	}
	if err != nil {
		return res.fail(outcomeError, err.Error())
	}

	// 1. State after each prev event, deduplicated by state group as
	// Synapse does before resolving.
	var sets []pdu.StateMap
	seen := map[int64]bool{}
	for _, p := range ev.PrevEvents {
		g, err := s.st.StateGroupForEvent(ctx, p)
		if errors.Is(err, pdustore.ErrNoStateGroup) {
			// A prev we hold only as an outlier, or not at all: Synapse
			// computed this event's state from a remote's /state_ids.
			return res.fail(outcomeSkipped, "prev event without state group")
		}
		if err != nil {
			return res.fail(outcomeError, err.Error())
		}
		if g > ownGroup {
			// State groups are allocated in order, so this prev's state
			// was computed AFTER the event's: when Synapse handled the
			// event the prev had none, and the state came from elsewhere
			// (a remote's /state_ids for a missing prev). Not replayable
			// from what is stored now.
			return res.fail(outcomeSkipped, "a prev's state was computed after the event's")
		}
		if seen[g] {
			continue
		}
		seen[g] = true
		m, err := s.groups.get(ctx, s.st, g)
		if err != nil {
			return res.fail(outcomeError, err.Error())
		}
		sets = append(sets, m)
	}

	// 2. The state before the event.
	var before pdu.StateMap
	if len(sets) == 1 {
		before = sets[0]
	} else {
		res.Resolved = true
		start := time.Now()
		before, err = stateres.ResolveWith(ctx, ev.RoomID, ev.Room, sets, s.st, s.opts)
		res.ResolveMS = time.Since(start).Milliseconds()
		if errors.Is(err, stateres.ErrUnsupported) {
			return res.fail(outcomeSkipped, "state resolution v1")
		}
		if err != nil {
			var re *pdu.RaiseError
			if errors.As(err, &re) {
				return res.fail(outcomeRaise, "state resolution: "+err.Error())
			}
			return res.fail(outcomeError, "state resolution: "+err.Error())
		}
	}

	// 3. Auth, as _check_event_auth does it.
	rej, why, err := s.checkEventAuth(ctx, ev, before)
	if err != nil {
		var re *pdu.RaiseError
		if errors.As(err, &re) {
			return res.fail(outcomeRaise, "auth: "+err.Error())
		}
		return res.fail(outcomeError, "auth: "+err.Error())
	}
	res.OurRej, res.OurReason = rej, why

	// 4. State after, against Synapse's.
	stored, err := s.groups.get(ctx, s.st, ownGroup)
	if err != nil {
		return res.fail(outcomeError, err.Error())
	}
	after := make(pdu.StateMap, len(before)+1)
	for k, v := range before {
		after[k] = v
	}
	if ev.IsState() && !ev.Rejected {
		// Synapse's own verdict decides whether the event entered its
		// state; ours is compared separately, so one disagreement does
		// not show up twice.
		after[ev.Key()] = ev.ID
	}
	res.StateDiff = diff(after, stored)

	res.AuthMismatch = rej != ev.Rejected
	if res.AuthMismatch || len(res.StateDiff) > 0 {
		res.Outcome = outcomeMismatch
	} else {
		res.Outcome = outcomeMatch
	}
	return res
}

func (r *result) fail(outcome, reason string) *result {
	r.Outcome, r.Reason = outcome, reason
	return r
}

// checkEventAuth reproduces FederationEventHandler._check_event_auth
// (federation_event.py:1830) for a fully stated room: rejected or not, and why.
// Size limits are not checked; validate_event_for_room_version's signature
// presence checks are.
func (s *sweeper) checkEventAuth(ctx context.Context, ev *pdu.Event, before pdu.StateMap) (bool, string, error) {
	if why := validateSignatures(ev); why != "" {
		return true, "validate: " + why, nil
	}

	claimed, err := s.st.GetEvents(ctx, ev.AuthEvents)
	if err != nil {
		return false, "", err
	}
	if len(claimed) != len(uniq(ev.AuthEvents)) {
		// _load_or_fetch_auth_events_for_event would have fetched them
		// from the origin; we cannot follow that.
		return false, "", &pdu.RaiseError{Msg: "missing auth events"}
	}
	if err := pdu.CheckStateIndependentAuthRules(ev, claimed); err != nil {
		if pdu.IsAuthError(err) {
			return true, "auth events: " + err.Error(), nil
		}
		return false, "", err
	}
	claimedList := make([]*pdu.Event, 0, len(ev.AuthEvents))
	for _, id := range ev.AuthEvents {
		claimedList = append(claimedList, claimed[id])
	}
	if err := pdu.CheckStateDependentAuthRules(ev, claimedList); err != nil {
		if pdu.IsAuthError(err) {
			return true, "auth events: " + err.Error(), nil
		}
		return false, "", err
	}

	calculated, err := pdu.ComputeAuthEvents(ev.Room, ev, before)
	if err != nil {
		return false, "", err
	}
	if sameMultiset(calculated, ev.AuthEvents) {
		return false, "", nil
	}
	calc, err := s.st.GetEvents(ctx, calculated)
	if err != nil {
		return false, "", err
	}
	calcList := make([]*pdu.Event, 0, len(calculated))
	for _, id := range calculated {
		if e := calc[id]; e != nil {
			calcList = append(calcList, e)
		}
	}
	if err := pdu.CheckStateDependentAuthRules(ev, calcList); err != nil {
		if pdu.IsAuthError(err) {
			return true, "state before: " + err.Error(), nil
		}
		return false, "", err
	}
	return false, "", nil
}

// validateSignatures is the signature-presence part of
// validate_event_for_room_version (event_auth.py:96).
func validateSignatures(ev *pdu.Event) string {
	signedBy := func(server string) bool { return pdu.Get(ev.Signatures, server).IsObject() }
	senderDomain := domain(ev.Sender)
	tpi := false
	if ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "invite" && pdu.Get(ev.Content, "third_party_invite").Exists() {
			tpi = true
		}
	}
	if !signedBy(senderDomain) && !tpi {
		return "not signed by sender's server"
	}
	if ev.Room.EventFormat == pdu.FormatV1V2 && !signedBy(domain(ev.ID)) {
		return "not signed by sending server"
	}
	if ev.Room.RestrictedJoinRule && ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "join" {
			if au := pdu.Get(ev.Content, "join_authorised_via_users_server"); au.Exists() {
				if !signedBy(domain(au.String())) {
					return "not signed by authorising server"
				}
			}
		}
	}
	return ""
}

func domain(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		return id[i+1:]
	}
	return id
}

func uniq(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func sameMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, x := range a {
		count[x]++
	}
	for _, x := range b {
		count[x]--
	}
	for _, c := range count {
		if c != 0 {
			return false
		}
	}
	return true
}

// diff lists the keys whose event differs, as "type|state_key: ours != stored".
func diff(ours, stored pdu.StateMap) []string {
	var out []string
	for k, v := range ours {
		if stored[k] != v {
			out = append(out, fmt.Sprintf("%s|%s: ours=%s stored=%s", k.Type, k.StateKey, v, stored[k]))
		}
	}
	for k, v := range stored {
		if _, ok := ours[k]; !ok {
			out = append(out, fmt.Sprintf("%s|%s: ours=<none> stored=%s", k.Type, k.StateKey, v))
		}
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = append(out[:20], fmt.Sprintf("... and %d more", len(out)-20))
	}
	return out
}

func sample(ctx context.Context, st *pdustore.Store, version string, n int, window int64, forks, rejected bool) ([]string, error) {
	return st.SampleEvents(ctx, version, n, window, forks, rejected)
}

func report(version string, results []*result, took time.Duration) {
	counts := map[string]int{}
	reasons := map[string]int{}
	resolved, authMis, stateMis := 0, 0, 0
	var resolveMS []int64
	for _, r := range results {
		counts[r.Outcome]++
		if r.Resolved {
			resolved++
			resolveMS = append(resolveMS, r.ResolveMS)
		}
		if r.Outcome == outcomeMismatch {
			if r.AuthMismatch {
				authMis++
			}
			if len(r.StateDiff) > 0 {
				stateMis++
			}
		}
		if r.Outcome == outcomeSkipped || r.Outcome == outcomeRaise || r.Outcome == outcomeError {
			reasons[r.Outcome+": "+short(r.Reason)]++
		}
	}
	fmt.Printf("v%-3s n=%-4d match=%-4d mismatch=%-3d (auth %d, state %d) raise=%-3d error=%-3d skipped=%-4d resolved=%-4d %s\n",
		version, len(results), counts[outcomeMatch], counts[outcomeMismatch], authMis, stateMis,
		counts[outcomeRaise], counts[outcomeError], counts[outcomeSkipped], resolved, took.Round(time.Millisecond))
	if len(resolveMS) > 0 {
		sort.Slice(resolveMS, func(i, j int) bool { return resolveMS[i] < resolveMS[j] })
		var sum int64
		for _, ms := range resolveMS {
			sum += ms
		}
		fmt.Printf("      state resolution ms: median %d, p90 %d, max %d, total %d\n",
			resolveMS[len(resolveMS)/2], resolveMS[len(resolveMS)*9/10], resolveMS[len(resolveMS)-1], sum)
	}
	var rs []string
	for k := range reasons {
		rs = append(rs, k)
	}
	sort.Strings(rs)
	for _, k := range rs {
		fmt.Printf("      %4d  %s\n", reasons[k], k)
	}
}

func short(s string) string {
	if i := strings.Index(s, " $"); i > 0 {
		s = s[:i]
	}
	if len(s) > 90 {
		s = s[:90]
	}
	return s
}

// groupCache holds resolved state groups. A group's contents never change.
type groupCache struct {
	mu   sync.Mutex
	max  int
	data map[int64]pdu.StateMap
}

func newGroupCache(max int) *groupCache {
	return &groupCache{max: max, data: map[int64]pdu.StateMap{}}
}

func (c *groupCache) get(ctx context.Context, st *pdustore.Store, g int64) (pdu.StateMap, error) {
	c.mu.Lock()
	m, ok := c.data[g]
	c.mu.Unlock()
	if ok {
		return m, nil
	}
	m, err := st.StateForGroup(ctx, g)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.data) >= c.max {
		c.data = map[int64]pdu.StateMap{}
	}
	c.data[g] = m
	c.mu.Unlock()
	return m, nil
}

// checkSigs recomputes what Synapse checked when the event arrived: its event
// ID (v3 and later), its content hash, and its signatures, against the keys
// Synapse holds. Every persisted event passed the signature check, rejected
// ones included, so any failure here is ours.
func (s *sweeper) checkSigs(ctx context.Context, id string) *result {
	res := &result{EventID: id}
	got, bad, err := s.st.GetStoredEvents(ctx, []string{id})
	if err != nil {
		return res.fail(outcomeError, err.Error())
	}
	if e := bad[id]; e != nil {
		return res.fail(outcomeSkipped, "unparseable: "+e.Error())
	}
	se := got[id]
	if se == nil {
		return res.fail(outcomeSkipped, "not found")
	}
	ev := se.Event
	res.RoomID, res.Type, res.Version = ev.RoomID, ev.Type, ev.Room.ID

	if ev.Room.EventFormat != pdu.FormatV1V2 {
		calc, err := pdu.CalculateEventID(ev.JSON, ev.Room)
		if err != nil {
			return res.fail(outcomeError, "event id: "+err.Error())
		}
		if calc != id {
			res.Outcome, res.Reason = outcomeMismatch, "event id: computed "+calc
			return res
		}
	}

	ok, err := pdu.CheckContentHash(ev.JSON)
	if err != nil {
		return res.fail(outcomeRaise, "content hash: "+err.Error())
	}
	if !ok {
		redacted, err := s.st.IsRedacted(ctx, id)
		if err != nil {
			return res.fail(outcomeError, err.Error())
		}
		if !redacted {
			// Synapse redacts an event whose hash fails and stores the
			// redacted form, which can no longer match its hash. So a
			// failing event must already be in redacted form.
			pruned, err := pdu.IsRedactedForm(ev.JSON, ev.Room)
			if err != nil {
				return res.fail(outcomeError, err.Error())
			}
			if !pruned {
				res.Outcome, res.Reason = outcomeMismatch, "content hash does not match, and the event is not in redacted form"
				return res
			}
		}
	}

	lookup := func(server string, keyIDs []string) (map[string]pdu.VerifyKey, error) {
		return s.st.VerifyKeys(ctx, server, keyIDs)
	}
	if err := pdu.CheckSignatures(ev, ev.JSON, lookup); err != nil {
		switch {
		case errors.Is(err, pdu.ErrKeyUnknown):
			return res.fail(outcomeSkipped, "signing key not held")
		case isSignatureError(err):
			var sigErr *pdu.SignatureError
			errors.As(err, &sigErr)
			if sigErr.Key != nil && sigErr.Key.AddedMS > se.ReceivedTS {
				// The key Synapse holds now was stored after the event
				// arrived: the server reissued a key ID, and Synapse
				// checked the event with the one it replaced.
				return res.fail(outcomeSkipped, "signing key replaced since the event arrived")
			}
			res.Outcome, res.Reason = outcomeMismatch, err.Error()
			return res
		default:
			return res.fail(outcomeRaise, "signatures: "+err.Error())
		}
	}
	res.Outcome = outcomeMatch
	return res
}

func isSignatureError(err error) bool {
	var se *pdu.SignatureError
	return errors.As(err, &se)
}
