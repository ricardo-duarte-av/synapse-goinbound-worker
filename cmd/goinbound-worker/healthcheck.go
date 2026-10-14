package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/config"
)

// healthcheck probes our own listener and reports whether it is serving.
//
// It exists because the runtime image is distroless: there is no shell and no
// curl, so the socket-based healthcheck pattern used by the Synapse containers
// cannot work. The binary probes itself instead.
func healthcheck(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://localhost/health"

	if cfg.Listen.Socket != "" {
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", cfg.Listen.Socket)
			},
		}
	} else {
		url = "http://" + localAddr(cfg.Listen.Addr) + "/health"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health returned %s", resp.Status)
	}
	return nil
}

// localAddr turns a listen address into one that can be dialled from inside
// the container: ":9000" and "0.0.0.0:9000" both become "127.0.0.1:9000".
func localAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}
