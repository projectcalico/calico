package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/projectcalico/calico/goldmane/pkg/daemon"
)

var (
	// Define CLI flags for ready / live checks
	ready = flag.Bool("ready", false, "Check if the server is ready")
	live  = flag.Bool("live", false, "Check if the server is alive")
)

func init() {
	flag.Parse()
}

func main() {
	cfg := daemon.ConfigFromEnv()
	if !cfg.HealthEnabled {
		os.Exit(0)
	}

	var path string
	if *ready {
		path = "readiness"
	} else if *live {
		path = "liveness"
	} else {
		fmt.Println("One of --ready or --live must be set")
		os.Exit(1)
	}

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/%s", cfg.HealthPort, path))
	if err != nil {
		fmt.Printf("Error making health check request: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Health check failed with status code: %d\n", resp.StatusCode)
		os.Exit(1)
	}
	os.Exit(0)
}
