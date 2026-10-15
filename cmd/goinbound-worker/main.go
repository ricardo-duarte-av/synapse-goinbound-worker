// Command goinbound-worker is the front door for Synapse's inbound federation
// transactions: it answers EDU-only /send transactions itself, by forwarding
// each EDU to its stream writer, and proxies everything else to the Python
// inbound federation worker.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/inbound"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/acl"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/config"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/dbrole"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/fedauth"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/policysign"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/proxy"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/replication"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/stateres"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/txn"
)

// Set at build time.
var (
	tag       = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "/data/goinbound-worker.yaml", "path to the worker config")
	probe := flag.Bool("healthcheck", false, "probe the running worker's /health and exit")
	version := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("goinbound-worker %s (%s, built %s)\n", tag, commit, buildTime)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *probe {
		if err := healthcheck(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	log, err := newLogger(cfg.Log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := run(cfg, log); err != nil {
		log.Fatal().Err(err).Msg("Worker stopped")
	}
}

func run(cfg *config.Config, log zerolog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info().Str("version", tag).Str("commit", commit).
		Stringer("edu_mode", cfg.Modes.EDU).Stringer("pdu_mode", cfg.Modes.PDU).
		Msg("Starting goinbound-worker")
	txn.RecordModes(cfg.Modes)

	up, err := proxy.New(cfg.Upstream, log)
	if err != nil {
		return err
	}

	handler, cleanup, err := buildHandler(ctx, cfg, up, log)
	if err != nil {
		return err
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})
	mux.Handle("/", handler)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No write timeout: a proxied transaction with PDUs that need missing
		// events fetched can take minutes, and the upstream timeout bounds it.
	}
	ln, err := listen(cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	// Profiles, on the metrics listener only: it is reachable from the
	// container networks, never from federation.
	metricsMux.HandleFunc("/debug/pprof/", pprof.Index)
	metricsMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	metricsMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	metricsMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	metricsMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	metricsSrv := &http.Server{Addr: cfg.Metrics.Addr, Handler: metricsMux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("Metrics server failed")
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("socket", cfg.Listen.Socket).Str("addr", cfg.Listen.Addr).
			Strs("upstreams", up.Backends()).Msg("Serving")
		errCh <- srv.Serve(ln)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Info().Msg("Shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = metricsSrv.Shutdown(shutdownCtx)
	return srv.Shutdown(shutdownCtx)
}

// buildHandler wires the /send handler for the configured mode.
//
// Proxy mode needs nothing but the upstream, and deliberately does not insist
// on anything else: it is the first thing deployed, and must work even if
// homeserver.yaml or the database is not reachable from here yet.
func buildHandler(ctx context.Context, cfg *config.Config, up *proxy.Proxy, log zerolog.Logger) (*txn.Handler, func(), error) {
	noop := func() {}
	if cfg.Modes.EDU.Kind == config.ModeProxy && cfg.Modes.PDU.Kind == config.ModeProxy {
		if hs, err := synapsecfg.Load(cfg.HomeserverYAML); err != nil {
			log.Warn().Err(err).Msg("Cannot read homeserver.yaml; fine in proxy mode, required for any other")
		} else {
			log.Info().Str("server_name", hs.ServerName).Msg("Read homeserver.yaml")
		}
		return txn.NewHandler(txn.Options{EDUMode: cfg.Modes.EDU, Upstream: up, Log: log}), noop, nil
	}

	hs, err := synapsecfg.Load(cfg.HomeserverYAML)
	if err != nil {
		return nil, noop, err
	}

	db, dbCfg, err := openDatabase(ctx, cfg, hs, log)
	if err != nil {
		return nil, noop, err
	}

	notaries := hs.TrustedKeyServers
	if len(cfg.Auth.TrustedKeyServers) > 0 {
		notaries = cfg.Auth.TrustedKeyServers
	}
	verifier := fedauth.New(hs.ServerName, fedauth.Options{
		KeyRefetchDelay: time.Duration(cfg.Auth.KeyRefetchMinutes) * time.Minute,
		Timeout:         time.Duration(cfg.Auth.TimeoutSeconds) * time.Second,
		Notaries:        notaries,
		DB:              db,
		MaxBodySize:     cfg.MaxBodyBytes(),
		Log:             log,
	})

	router := edu.NewRouter(hs.Writers)
	repl := replication.NewClient(hs)
	if err := router.Validate(repl.Has); err != nil {
		db.Close()
		return nil, noop, err
	}
	var sender edu.Sender
	if cfg.Modes.EDU.ServesNatively() {
		sender = repl
	}
	acls := acl.NewChecker(db, 0)
	processor := edu.NewProcessor(router, acls, sender, hs.TrackPresence, log)

	log.Info().
		Str("server_name", hs.ServerName).
		Bool("track_presence", hs.TrackPresence).
		Strs("typing", hs.Writers.Typing).
		Strs("receipts", hs.Writers.Receipts).
		Strs("to_device", hs.Writers.ToDevice).
		Strs("presence", hs.Writers.Presence).
		Strs("device_lists", hs.Writers.DeviceLists).
		Strs("notaries", notaries).
		Bool("replication_secret", hs.ReplicationSecret != "").
		Msg("EDU routing from homeserver.yaml")

	var live *pduverify.Live
	var pst *pdustore.Store
	var pv *pduverify.Verifier
	var asker pduverify.PolicyAsker
	if cfg.Modes.PDU.Kind == config.ModeShadow || cfg.Modes.PDU.ServesNatively() {
		maxConns := int32(cfg.PDUShadow.MaxConns)
		if maxConns == 0 {
			maxConns = 4
		}
		pst, err = pdustore.OpenAs(ctx, dbCfg.DSN, dbCfg.User, dbCfg.Password, maxConns)
		if err != nil {
			db.Close()
			return nil, noop, fmt.Errorf("pdu shadow: %w", err)
		}
		pv = pduverify.New(pst, stateres.Options{})
		if cfg.PDUShadow.StateCacheEntries > 0 {
			pv.SetStateCacheEntries(cfg.PDUShadow.StateCacheEntries)
		}
		if pc, err := pduverify.PushConfigFor(hs); err != nil {
			// The other checks do not need it.
			log.Warn().Err(err).Msg("PDU shadow: push check off")
		} else {
			pv.EnablePush(pc)
		}
		// The policy servers Synapse asks are asked too, signed as us.
		var allow func(string) bool
		if hs.DomainWhitelist != nil {
			allow = func(s string) bool { return hs.DomainWhitelist[s] }
		}
		if line, err := hs.SigningKeyLine(); err != nil {
			log.Warn().Err(err).Msg("PDU shadow: policy_ask check off")
		} else if pc, err := policysign.New(hs.ServerName, line, allow); err != nil {
			log.Warn().Err(err).Msg("PDU shadow: policy_ask check off")
		} else {
			asker = pc
		}
		live = pduverify.NewLive(pv, pst, pduverify.LiveOptions{
			Concurrency: cfg.PDUShadow.Concurrency,
			Queue:       cfg.PDUShadow.Queue,
			MaxWait:     time.Duration(cfg.PDUShadow.MaxWaitSeconds) * time.Second,
			PrevWait:    time.Duration(cfg.PDUShadow.PrevWaitSeconds) * time.Second,
			ServerName:  hs.ServerName,
			ACL:         acls,
			Policy:      asker,
		}, log)
		log.Info().Msg("PDU shadow on: PDUs Synapse accepts are checked once it has persisted them")
	}

	opts := txn.Options{
		EDUMode:         cfg.Modes.EDU,
		Verifier:        verifier,
		Upstream:        up,
		Store:           db,
		EDUs:            processor,
		DomainWhitelist: hs.DomainWhitelist,
		MaxBody:         cfg.MaxBodyBytes(),
		ForwardTimeout:  cfg.EDU.ForwardTimeout(),
		Shadow:          cfg.Shadow,
		Log:             log,
	}
	if live != nil {
		opts.PDUs = pduSink{live}
	}
	var proc *inbound.Processor
	var wdb *inbound.DB
	if cfg.Modes.PDU.ServesNatively() {
		wdb, err = openWriteDatabase(ctx, cfg, hs, log)
		if err != nil {
			db.Close()
			return nil, noop, err
		}
		proc = inbound.NewProcessor(wdb, pv, persister{repl, hs.Writers}, pst, hs.ServerName, log)
		fd := inbound.NewFrontDoor(inbound.FrontDoorDeps{
			Store: pst, Verifier: pv, ACL: acls, Policy: asker, Processor: proc, Server: hs.ServerName,
		})
		opts.PDUMode, opts.PDUServer, opts.Responses = cfg.Modes.PDU, frontDoor{fd}, wdb
		proc.Start()
		log.Warn().Str("mode", cfg.Modes.PDU.String()).Str("instance", cfg.Write.InstanceName).
			Msg("Write mode on: PDUs of the selected origins are persisted here")
	}
	h := txn.NewHandler(opts)
	return h, func() {
		h.Close()
		if proc != nil {
			proc.Close()
			wdb.Close()
		}
		if live != nil {
			live.Close()
			pst.Close()
		}
		db.Close()
	}, nil
}

// openDatabase connects as the read-only role, making sure first that the role
// exists and has exactly what it needs.
//
// On every start: connect as the role and check its grants. If that fails --
// no such role, a wrong password, a missing grant -- create or repair the role
// with homeserver.yaml's credentials and try once more. Those credentials are
// used for nothing else, and the connection made with them is closed before
// serving starts.
func openDatabase(ctx context.Context, cfg *config.Config, hs *synapsecfg.Config, log zerolog.Logger) (*store.Store, store.Config, error) {
	role := cfg.Database.RoleName()
	password := dbrole.Password(hs.Database.Password, role)

	dsn := cfg.Database.DSN
	if dsn == "" {
		if !hs.Database.Present {
			return nil, store.Config{}, errors.New("no database: set database.dsn, or give homeserver.yaml a database block")
		}
		serving := hs.Database
		serving.User, serving.Password = role, password
		dsn = serving.DSN()
	}

	maxConns := int32(cfg.Database.MaxConns)
	if maxConns == 0 {
		maxConns = 4
	}
	connect := time.Duration(cfg.Database.ConnectTimeoutSeconds) * time.Second
	if connect == 0 {
		connect = 10 * time.Second
	}
	storeCfg := store.Config{
		DSN:            dsn,
		User:           role,
		Password:       password,
		MaxConns:       maxConns,
		ConnectTimeout: connect,
		QueryTimeout:   cfg.Database.QueryTimeout(),
	}

	db, problem := openChecked(ctx, storeCfg, connect)
	if problem == nil {
		log.Info().Str("role", role).Msg("Connected to the database as the read-only role")
		return db, storeCfg, nil
	}
	if !cfg.Database.ManagesRole() {
		return nil, store.Config{}, fmt.Errorf("database role %s: %w (database.manage_role is false; create it with deploy/readonly-role.sql)", role, problem)
	}
	if !hs.Database.Present {
		return nil, store.Config{}, fmt.Errorf("database role %s: %w, and homeserver.yaml has no database block to create it with", role, problem)
	}

	log.Warn().Err(problem).Str("role", role).Str("admin", hs.Database.Redacted()).
		Msg("Read-only role is missing or incomplete; creating or repairing it with homeserver.yaml's credentials")
	ensureCtx, cancel := context.WithTimeout(ctx, connect+20*time.Second)
	err := dbrole.Ensure(ensureCtx, hs.Database.DSN(), dbrole.Spec{Role: role, Password: password, Tables: roleTables()})
	cancel()
	if err != nil {
		return nil, store.Config{}, fmt.Errorf("database role %s: %w; and could not fix it: %w", role, problem, err)
	}

	db, err = openChecked(ctx, storeCfg, connect)
	if err != nil {
		// The role is right now, so the connection itself is the problem.
		// The usual cause is a pooler that only knows the users in its own
		// config.
		return nil, store.Config{}, fmt.Errorf("database role %s was created, but connecting as it still fails: %w "+
			"(if database.dsn goes through pgcat or pgbouncer, add the role there, or point database.dsn "+
			"at PostgreSQL directly, e.g. host=/var/sockets dbname=%s)", role, err, hs.Database.DBName)
	}
	log.Info().Str("role", role).Msg("Created or repaired the read-only role, and connected as it")
	return db, storeCfg, nil
}

// persister sends events to the room's event persister.
type persister struct {
	c       *replication.Client
	writers synapsecfg.Writers
}

func (p persister) SendEvents(ctx context.Context, roomID string, entries []json.RawMessage) error {
	_, err := p.c.SendEvents(ctx, p.writers.EventsWriter(roomID), roomID, entries, false)
	return err
}

// frontDoor adapts write mode's front door to txn.PDUServer.
type frontDoor struct{ f *inbound.FrontDoor }

func (f frontDoor) PlanPDUs(ctx context.Context, origin string, pdus []json.RawMessage, at time.Time) (txn.PDURun, string) {
	p, why := f.f.PlanPDUs(ctx, origin, pdus, at)
	if why != "" {
		return nil, why
	}
	return p, ""
}

// openWriteDatabase connects as the write role, creating or repairing it
// first with homeserver.yaml's credentials: every start, since the grants
// must be exactly inbound.Grants and Ensure makes them so.
func openWriteDatabase(ctx context.Context, cfg *config.Config, hs *synapsecfg.Config, log zerolog.Logger) (*inbound.DB, error) {
	role := cfg.Write.RoleName()
	if !hs.Database.Present {
		return nil, errors.New("write mode: homeserver.yaml has no database block")
	}
	password := dbrole.Password(hs.Database.Password, role)
	ensureCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := dbrole.Ensure(ensureCtx, hs.Database.DSN(), dbrole.Spec{
		Role: role, Password: password, Writes: inbound.Grants, Sequences: inbound.Sequences,
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("write role %s: %w", role, err)
	}
	serving := hs.Database
	serving.User, serving.Password = role, password
	dsn := serving.DSN()
	if cfg.Database.DSN != "" {
		// The read-only role's direct connection, as the write role.
		c, err := pgx.ParseConfig(cfg.Database.DSN)
		if err != nil {
			return nil, err
		}
		dsn = fmt.Sprintf("host=%s port=%d dbname=%s user=%s", c.Host, c.Port, c.Database, role)
		if password != "" {
			dsn += " password=" + password
		}
	}
	db, err := inbound.Open(ctx, dsn, cfg.Write.InstanceName)
	if err != nil {
		return nil, fmt.Errorf("write role %s: %w", role, err)
	}
	log.Info().Str("role", role).Msg("Connected to the database as the write role")
	return db, nil
}

// pduSink adapts the PDU shadow to txn.PDUSink.
type pduSink struct{ l *pduverify.Live }

func (p pduSink) Prepare(origin string, body []byte) txn.PDUPending {
	return p.l.Prepare(origin, body)
}

// roleTables is every table the read-only role is granted: those the EDU path
// reads (package store) and those the PDU checker reads (package pdustore).
func roleTables() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range append(append([]string{}, store.Tables...), pdustore.Tables...) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// openChecked connects and verifies the role's grants, returning why not.
func openChecked(ctx context.Context, cfg store.Config, connect time.Duration) (*store.Store, error) {
	openCtx, cancel := context.WithTimeout(ctx, connect+5*time.Second)
	defer cancel()
	db, err := store.Open(openCtx, cfg)
	if err != nil {
		return nil, err
	}
	missing, err := db.MissingPrivileges(openCtx, roleTables())
	if err != nil {
		db.Close()
		return nil, err
	}
	if len(missing) > 0 {
		db.Close()
		return nil, fmt.Errorf("role lacks %s", strings.Join(missing, ", "))
	}
	return db, nil
}

func newLogger(cfg config.Log) (zerolog.Logger, error) {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		return zerolog.Nop(), fmt.Errorf("log: %w", err)
	}
	logger := zerolog.New(os.Stdout).Level(level).With().Timestamp().Logger()
	if cfg.Pretty {
		logger = logger.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"})
	}
	return logger, nil
}

// listen opens the configured listener. For a unix socket it removes a stale
// socket left by an unclean shutdown and applies the configured permissions so
// nginx can connect.
func listen(cfg config.Listen) (net.Listener, error) {
	if cfg.Addr != "" {
		return net.Listen("tcp", cfg.Addr)
	}
	if err := os.Remove(cfg.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket %s: %w", cfg.Socket, err)
	}
	l, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		return nil, err
	}
	mode, err := cfg.ParsedSocketMode()
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	if err := os.Chmod(cfg.Socket, mode); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return l, nil
}
