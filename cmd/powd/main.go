// Command powd is a minimal proof-of-work reverse proxy.
//
// Usage:
//
//	powd -c /etc/powd.toml     run the daemon
//	powd -t -c /etc/powd.toml  test the configuration and exit
//	powd -v                    print the version and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/solipsismes/powd/internal/config"
	"github.com/solipsismes/powd/internal/server"
	"github.com/solipsismes/powd/internal/token"
)

// version is stamped by the Makefile via -ldflags.
var version = "dev"

func main() {
	configPath := flag.String("c", "/etc/powd.toml", "path to configuration file")
	testConfig := flag.Bool("t", false, "test configuration and exit")
	showVersion := flag.Bool("v", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("powd " + version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "powd: %v\n", err)
		os.Exit(1)
	}
	if *testConfig {
		fmt.Println("configuration OK")
		return
	}

	logger := log.New(os.Stderr, "powd: ", log.LstdFlags)

	var secret []byte
	if cfg.SecretFile != "" {
		secret, err = token.LoadSecret(cfg.SecretFile)
		if err != nil {
			logger.Fatal(err)
		}
	} else {
		secret = token.RandomSecret()
		logger.Print("no secret_file configured; using an ephemeral secret (a restart re-challenges all clients)")
	}
	signer, err := token.New(secret)
	if err != nil {
		logger.Fatal(err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(cfg, signer, logger),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Printf("%s listening on %s, proxying to %s", version, cfg.Listen, cfg.Upstream)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		logger.Fatal(err)
	case s := <-sig:
		logger.Printf("received %s, shutting down", s)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Printf("shutdown: %v", err)
		}
	}
}
