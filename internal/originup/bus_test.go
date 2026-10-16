package originup

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// Against a throwaway Redis (never the live bus):
//
//	docker run -d --rm --name goinbound-testredis -p 127.0.0.1:56379:6379 redis:7-alpine
//	ORIGINUP_TEST_REDIS=127.0.0.1:56379 go test ./internal/originup/
func TestBusEndToEnd(t *testing.T) {
	addr := os.Getenv("ORIGINUP_TEST_REDIS")
	if addr == "" {
		t.Skip("ORIGINUP_TEST_REDIS not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bus := NewBus(synapsecfg.Redis{Addr: addr}, "hs.test", zerolog.Nop())
	defer bus.Close()

	// A Synapse process listening on the channel.
	peer := redis.NewClient(&redis.Options{Addr: addr})
	defer peer.Close()
	sub := peer.Subscribe(ctx, "hs.test")
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil {
		t.Fatal(err)
	}
	got := sub.Channel()

	r := New(Options{Store: &fakeStore{}, Publisher: bus, Instance: "goinbound-worker", Log: zerolog.Nop()})
	go bus.Listen(ctx, r.OnReplicate)
	r.Reset("down.example", "")
	want := []string{
		`RDATA caches goinbound-worker 101 ["get_destination_retry_timings",["down.example"],1700000000000]`,
		`REMOTE_SERVER_UP down.example`,
		`REPLICATE `,
		`POSITION caches goinbound-worker 101 101`,
	}
	for i, w := range want {
		if i == 2 {
			// A process connects and asks every writer for its positions.
			time.Sleep(100 * time.Millisecond)
			if err := peer.Publish(ctx, "hs.test", "REPLICATE ").Err(); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case m := <-got:
			if m.Payload != w {
				t.Errorf("message %d = %q, want %q", i, m.Payload, w)
			}
		case <-ctx.Done():
			t.Fatalf("no message %d (%q)", i, w)
		}
	}
}
