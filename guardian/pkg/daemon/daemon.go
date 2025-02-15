package daemon

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/server"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	"github.com/projectcalico/calico/guardian/pkg/version"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "GUARDIAN"
)

var (
	versionFlag = flag.Bool("version", false, "Print version information")
)

type configOpts struct {
	proxyTargets []server.Target
}

func Run(opts ...Option) {
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
	cfgOpts := &configOpts{}
	for _, opt := range opts {
		opt(cfgOpts)
	}

	log.Infof("Starting %s with %s", EnvConfigPrefix, cfg)

	if err != nil {
		log.Fatalf("Failed to parse default proxy targets: %s", err)
	}

	tunnelDialOpts := []tunnel.DialerOption{
		tunnel.WithDialerTimeout(cfg.TunnelDialTimeout),
		tunnel.WithDialerRetryInterval(cfg.TunnelDialRetryInterval),
		tunnel.WithDialerTimeout(cfg.TunnelDialTimeout),
		tunnel.WithDialerKeepAliveSettings(cfg.KeepAliveEnable, time.Duration(cfg.KeepAliveInterval)*time.Millisecond),
	}

	proxyURL, err := cfg.GetHTTPProxyURL()
	if err != nil {
		log.Fatalf("Failed to resolve proxy URL: %s", err)
	} else if proxyURL != nil {
		tunnelDialOpts = append(tunnelDialOpts, tunnel.WithDialerHTTPProxyURL(proxyURL))
	}
	defaultTokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCABundlePath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	targets := []server.Target{
		server.MustCreateTarget("/api/", cfg.K8sEndpoint+":6443",
			server.WithToken(defaultTokenPath),
			server.WithCAPem(defaultCABundlePath)),
		server.MustCreateTarget("/apis/", cfg.K8sEndpoint+":6443",
			server.WithToken(defaultTokenPath),
			server.WithCAPem(defaultCABundlePath)),
	}

	if cfgOpts.proxyTargets != nil {
		targets = append(targets, cfgOpts.proxyTargets...)
	}

	srvOpts := []server.Option{
		server.WithProxyTargets(targets),
		server.WithConnectionRetryAttempts(cfg.ConnectionRetryAttempts),
		server.WithConnectionRetryInterval(cfg.ConnectionRetryInterval),
		server.WithTunnelDialerOptions(tunnelDialOpts...),
	}

	cert := fmt.Sprintf("%s/managed-cluster.crt", cfg.CertPath)
	key := fmt.Sprintf("%s/managed-cluster.key", cfg.CertPath)
	opt, err := server.WithTunnelCertificatesFromFile(cert, key)
	if err != nil {
		log.Fatalf("Failed to load tunnel cert: %s", err)
	} else if opt != nil {
		srvOpts = append(srvOpts, opt)
	}

	if strings.ToLower(cfg.VoltronCAType) != "public" {
		opt, err := server.WithTunnelRootCAFromFile(fmt.Sprintf("%s/management-cluster.crt", cfg.CertPath))
		if err != nil {
			log.Fatalf("Failed to load tunnel root CA: %s", err)
		} else if opt != nil {
			srvOpts = append(srvOpts, opt)
		}
	}

	srv, err := server.New(cfg.VoltronURL, srvOpts...)
	if err != nil {
		log.Fatalf("Failed to create server: %s", err)
	}

	health, err := server.NewHealth()
	if err != nil {
		log.Fatalf("Failed to create health server: %s.", err)
	}

	ctx := GetShutdownContext()
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
		// Allow requests to come down from the management cluster.
		if err := srv.ListenAndServeManagementCluster(ctx); err != nil {
			log.WithError(err).Fatal("Serving the tunnel exited.")
		}
	}()

	// Allow requests from the cluster to be sent up to the management cluster.
	if cfg.Listen {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := srv.ListenAndServeCluster(ctx); err != nil {
				log.WithError(err).Fatal("proxy tunnel exited with an error")
			}
		}()
	}

	wg.Wait()
}

// GetShutdownContext creates a context that's done when either syscall.SIGINT or syscall.SIGTERM notified.
func GetShutdownContext() context.Context {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signalChan
		cancel()
	}()

	return ctx
}
