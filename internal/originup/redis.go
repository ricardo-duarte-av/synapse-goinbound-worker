package originup

import (
	"context"

	"github.com/redis/go-redis/v9"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// RedisPublisher publishes on Synapse's replication bus. It only ever
// PUBLISHes commands: it subscribes to nothing and writes no stream, so it
// has no stream position for Synapse to wait on.
type RedisPublisher struct {
	client *redis.Client
}

// NewRedisPublisher connects as homeserver.yaml's redis section says.
func NewRedisPublisher(cfg synapsecfg.Redis) *RedisPublisher {
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
	return &RedisPublisher{client: redis.NewClient(opts)}
}

// Publish sends line, as redis.py's _async_send_command does.
func (p *RedisPublisher) Publish(ctx context.Context, channel, line string) error {
	return p.client.Publish(ctx, channel, line).Err()
}

// Close closes the connection.
func (p *RedisPublisher) Close() error { return p.client.Close() }
