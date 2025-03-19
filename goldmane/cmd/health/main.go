package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"

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
		logrus.Info("Health checking is disabled")
		os.Exit(0)
	}

	var path string
	if *ready {
		path = "readiness"
	} else if *live {
		path = "liveness"
	} else {
		logrus.Error("One of --ready or --live must be set")
		os.Exit(1)
	}

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/%s", cfg.HealthPort, path))
	if err != nil {
		logrus.WithError(err).Error("Failed to get health check")
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			logrus.WithError(err).Error("Failed to read health check response body")
		}
		logrus.WithFields(logrus.Fields{
			"code": resp.StatusCode,
			"body": b,
		}).Error("Health check failed")
		os.Exit(1)
	}
	os.Exit(0)
}
