package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/server"
	"github.com/projectcalico/calico/guardian/pkg/version"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "GUARDIAN"
)

var (
	versionFlag = flag.Bool("version", false, "Print version information")
)

func main() {
	// Parse all command-line flags
	flag.Parse()

	// For --version use case
	if *versionFlag {
		version.Version()
		os.Exit(0)
	}

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatal(err)
	}

	cfg.ConfigureLogging()

	log.Infof("Starting %s with %s", EnvConfigPrefix, cfg)

	cert := fmt.Sprintf("%s/managed-cluster.crt", cfg.CertPath)
	key := fmt.Sprintf("%s/managed-cluster.key", cfg.CertPath)
	log.Infof("Voltron Address: %s", cfg.VoltronURL)

	pemCert, err := os.ReadFile(cert)
	if err != nil {
		log.Fatalf("Failed to load cert: %s", err)
	}
	pemKey, err := os.ReadFile(key)
	if err != nil {
		log.Fatalf("Failed to load key: %s", err)
	}

	serverName, ca, err := cfg.Cert()
	if err != nil {
		log.Fatalf("Failed to load cert: %s", err)
	}

	health, err := server.NewHealth()
	if err != nil {
		log.Fatalf("Failed to create health server: %s.", err)
	}

	targets, err := server.ParseTargets([]server.TargetParam{
		{
			Path:         "/api/",
			Dest:         cfg.K8sEndpoint + ":6443",
			TokenPath:    "/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/token",
			CABundlePath: "/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/ca.crt",
		},
		{
			Path:         "/apis/",
			Dest:         cfg.K8sEndpoint + ":6443",
			TokenPath:    "/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/token",
			CABundlePath: "/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/ca.crt",
		},
	})
	if err != nil {
		log.Fatalf("Failed to parse default proxy targets: %s", err)
	}

	proxyURL, err := cfg.GetHTTPProxyURL()
	if err != nil {
		log.Fatalf("Failed to resolve proxy URL: %s", err)
	}

	srv, err := server.New(
		cfg.VoltronURL,
		serverName,
		server.WithKeepAliveSettings(cfg.KeepAliveEnable, cfg.KeepAliveInterval),
		server.WithProxyTargets(targets),
		server.WithTunnelCreds(pemCert, pemKey),
		server.WithTunnelRootCA(ca),
		server.WithTunnelDialRetryAttempts(cfg.TunnelDialRetryAttempts),
		server.WithTunnelDialRetryInterval(cfg.TunnelDialRetryInterval),
		server.WithTunnelDialTimeout(cfg.TunnelDialTimeout),
		server.WithConnectionRetryAttempts(cfg.ConnectionRetryAttempts),
		server.WithConnectionRetryInterval(cfg.ConnectionRetryInterval),
		server.WithHTTPProxyURL(proxyURL),
	)

	if err != nil {
		log.Fatalf("Failed to create server: %s", err)
	}

	go func() {
		// Health checks start, meaning everything before has worked.
		if err = health.ListenAndServeHTTP(); err != nil {
			log.Fatalf("Health exited with error: %s", err)
		}
	}()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.ListenAndServeToVoltron(); err != nil {
			log.WithError(err).Fatal("Serving the tunnel exited")
		}
	}()

	if cfg.Listen {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := srv.ListenAndServeToCluster(); err != nil {
				log.WithError(err).Fatal("proxy tunnel exited with an error")
			}
		}()
	}

	wg.Wait()
}
