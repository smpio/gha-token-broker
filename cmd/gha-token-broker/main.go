package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smpio/gha-token-broker/internal/broker"
)

func main() {
	if err := run(); err != nil {
		slog.Error("broker stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/gha-token-broker/config.json", "policy configuration")
	keyPath := flag.String("private-key", "/etc/gha-token-broker/private-key.pem", "GitHub App RSA key")
	listen := flag.String("listen", ":8080", "HTTP listen address; terminate TLS at ingress")
	flag.Parse()
	config, err := broker.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	key, err := broker.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are forbidden") }}
	v := broker.NewOIDCVerifier(ctx, config.Audience, client)
	g := &broker.GitHub{Config: config, Key: key, Client: client}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	s := &http.Server{Addr: *listen, Handler: broker.NewServer(config, v, g, logger).Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 25 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	go func() { logger.Info("broker listening", "address", *listen); done <- s.ListenAndServe() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.Shutdown(shutdown)
	}
}
