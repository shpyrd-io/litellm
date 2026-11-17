// litellm-door is the web process of the LiteLLM project on shpyrd. It
// listens on PORT and runs LiteLLM on loopback behind itself. Every request
// goes to LiteLLM untouched, except a browser opening the admin UI as a
// person the platform has identified as an admin or developer of the
// project: that person is signed in to LiteLLM as its default admin, so
// that signing in once, to the platform, is enough.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(0)
	port := envOr("PORT", "4000")
	up := envOr("LITELLM_UPSTREAM_PORT", "4001")
	if up == port {
		up = "4002"
	}
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatalf("litellm-door: PORT %q is not a port", port)
	}
	if _, err := strconv.Atoi(up); err != nil {
		log.Fatalf("litellm-door: LITELLM_UPSTREAM_PORT %q is not a port", up)
	}

	p, err := New(Options{
		Upstream:   "http://" + net.JoinHostPort("127.0.0.1", up),
		Issuer:     os.Getenv("SHPYRD_ISSUER"),
		Project:    os.Getenv("SHPYRD_PROJECT"),
		UIUsername: os.Getenv("UI_USERNAME"),
		UIPassword: os.Getenv("UI_PASSWORD"),
	})
	if err != nil {
		log.Fatalf("litellm-door: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	bin := envOr("LITELLM_BIN", "/app/docker/prod_entrypoint.sh")
	lite, err := startChild([]string{bin, "--host", "127.0.0.1", "--port", up}, os.Environ(), os.Stdout)
	if err != nil {
		log.Fatalf("litellm-door: cannot start LiteLLM: %v", err)
	}
	go p.Watch(ctx, time.Second)

	srv := newServer(":"+port, p.Handler())
	failed := make(chan error, 1)
	go func() { failed <- srv.ListenAndServe() }()
	log.Printf("litellm-door: listening on :%s, LiteLLM on 127.0.0.1:%s", port, up)

	code := 0
	select {
	case <-ctx.Done():
	case err := <-lite.done:
		log.Printf("litellm-door: LiteLLM ended (%s); ending too, so that the platform starts the container again", exitWords(err))
		code = 1
	case err := <-failed:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("litellm-door: %v", err)
			code = 1
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(shutdown)
	cancel()
	lite.Stop(6 * time.Second)
	os.Exit(code)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func exitWords(err error) string {
	if err == nil {
		return "status 0"
	}
	return err.Error()
}
