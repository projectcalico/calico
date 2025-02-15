package daemon

import (
	"context"
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
)

type configOpts struct {
	proxyTargets []server.Target
}

func Run(cfg config.Config, proxyTargets []server.Target, opts ...Option) {
	cfgOpts := &configOpts{}
	for _, opt := range opts {
		if err := opt(cfgOpts); err != nil {
			log.Fatalf("Failed to apply option: %s", err)
		}
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

	srvOpts := []server.Option{
		server.WithProxyTargets(proxyTargets),
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
