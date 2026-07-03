// Command powd is a minimal proof-of-work reverse proxy.
//
// Usage:
//
//	powd -c /etc/powd.toml     run the daemon
//	powd -t -c /etc/powd.toml  test the configuration and exit
//	powd -v                    print the version and exit
package main

import (
	"flag"
	"fmt"
	"os"

	"powd/internal/config"
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

	// The server is built in a later step of the implementation plan.
	_ = cfg
	fmt.Fprintln(os.Stderr, "powd: server not implemented yet")
	os.Exit(1)
}
