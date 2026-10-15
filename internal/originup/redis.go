package originup

import (
	"context"
	"strings"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// Bus is Synapse's replication bus: one Redis channel, named server_name,
// carrying one command per message (replication/tcp/redis.py).
type Bus struct {
	client  *redis.Client
	channel string
	log     zerolog.Logger
}

// NewBus connects as homeserver.yaml's redis section says.
func NewBus(cfg synapsecfg.Redis, channel string, log zerolog.Logger) *Bus {
	opts := &redis.Options{
		Addr:     cfg.Addr,
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.DBID,
	}
	if cfg.Socket != "" {
		opts.Network = "unix"
		opts.Addr = cfg.Socket
	}
	return &Bus{client: redis.NewClient(opts), channel: channel, log: log}
}

// Publish sends one command line, as _async_send_command does.
func (b *Bus) Publish(ctx context.Context, line string) error {
	return b.client.Publish(ctx, b.channel, line).Err()
}

// Ping checks the bus can be reached.
func (b *Bus) Ping(ctx context.Context) error { return b.client.Ping(ctx).Err() }

// Listen calls onReplicate for every REPLICATE on the bus until ctx ends.
// Nothing else is read. The client resubscribes by itself after a drop.
func (b *Bus) Listen(ctx context.Context, onReplicate func()) {
	sub := b.client.Subscribe(ctx, b.channel)
	go func() {
		<-ctx.Done()
		_ = sub.Close()
	}()
	for msg := range sub.Channel() {
		// "REPLICATE " + to_line(), which is empty.
		if strings.TrimSpace(msg.Payload) == "REPLICATE" {
			onReplicate()
		}
	}
}

// Close closes the connection.
func (b *Bus) Close() error { return b.client.Close() }
