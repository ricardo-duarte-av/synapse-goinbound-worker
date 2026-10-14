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
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/stateres"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
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
	pushFlag := flag.Bool("push", false, "check push actions against event_push_actions instead of auth and state (recent events: rows are pruned after a day or so)")
	homeserver := flag.String("homeserver", "/opt/matrix/synapse/synapse/homeserver.yaml", "homeserver.yaml, for -push")
	flag.Parse()

	ctx := context.Background()
	st, err := pdustore.Open(ctx, *dsn, int32(*workers*2))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer st.Close()
	opts := stateres.Options{WalkDAG: *walk, CrossCheck: *cross}

	if *event != "" {
		opts.Trace = func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	}
	sw := pduverify.New(st, opts)
	check := sw.Replay
	if *sigs {
		check = sw.CheckSigs
	}
	if *pushFlag {
		hs, err := synapsecfg.Load(*homeserver)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pc, err := pduverify.PushConfigFor(hs)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sw.EnablePush(pc)
		check = func(ctx context.Context, id string) *pduverify.Result {
			r := sw.Replay(ctx, id)
			var before pdu.StateMap
			if r.Outcome == pduverify.OutcomeMatch {
				before = r.Before()
			}
			return sw.Push(ctx, id, before, nil)
		}
	}

	if *event != "" {
		res := check(ctx, *event)
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
		results := replayAll(ctx, check, ids, *workers)
		report("ids", results, time.Since(start))
		if sink != nil {
			for _, r := range results {
				if r.Outcome != pduverify.OutcomeMatch && r.Outcome != pduverify.OutcomeSkipped {
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
		results := replayAll(ctx, check, ids, *workers)
		report(v, results, time.Since(start))
		if sink != nil {
			for _, r := range results {
				if r.Outcome != pduverify.OutcomeMatch && r.Outcome != pduverify.OutcomeSkipped {
					_ = sink.Encode(r)
				}
			}
		}
	}
}

func replayAll(ctx context.Context, check func(context.Context, string) *pduverify.Result, ids []string, workers int) []*pduverify.Result {
	out := make([]*pduverify.Result, len(ids))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i] = check(ctx, ids[i])
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

func sample(ctx context.Context, st *pdustore.Store, version string, n int, window int64, forks, rejected bool) ([]string, error) {
	return st.SampleEvents(ctx, version, n, window, forks, rejected)
}

func report(version string, results []*pduverify.Result, took time.Duration) {
	counts := map[string]int{}
	reasons := map[string]int{}
	resolved, authMis, stateMis := 0, 0, 0
	pushEvents, pushRows, pushNotify := 0, 0, 0
	var resolveMS []int64
	for _, r := range results {
		counts[r.Outcome]++
		if r.Outcome == pduverify.OutcomeMatch && r.PushRows > 0 {
			pushEvents++
			pushRows += r.PushRows
			pushNotify += r.PushNotify
		}
		if r.Resolved {
			resolved++
			resolveMS = append(resolveMS, r.ResolveMS)
		}
		if r.Outcome == pduverify.OutcomeMismatch {
			if r.AuthMismatch {
				authMis++
			}
			if len(r.StateDiff) > 0 {
				stateMis++
			}
		}
		if r.Outcome == pduverify.OutcomeSkipped || r.Outcome == pduverify.OutcomeRaise || r.Outcome == pduverify.OutcomeError {
			reasons[r.Outcome+": "+short(r.Reason)]++
		}
	}
	fmt.Printf("v%-3s n=%-4d match=%-4d mismatch=%-3d (auth %d, state %d) raise=%-3d error=%-3d skipped=%-4d resolved=%-4d %s\n",
		version, len(results), counts[pduverify.OutcomeMatch], counts[pduverify.OutcomeMismatch], authMis, stateMis,
		counts[pduverify.OutcomeRaise], counts[pduverify.OutcomeError], counts[pduverify.OutcomeSkipped], resolved, took.Round(time.Millisecond))
	if pushEvents > 0 {
		fmt.Printf("      push: %d matching events had rows: %d rows, %d notifying\n", pushEvents, pushRows, pushNotify)
	}
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
