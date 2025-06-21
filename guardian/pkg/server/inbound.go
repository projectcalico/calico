package server

import (
	"context"
	"crypto/tls"
	"fmt"
	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/guardian/pkg/bimux"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/sirupsen/logrus"
	"net/http"
)

// InboundProxyServer is an interface for a server that proxies connections from outside the cluster to within the cluster.
type InboundProxyServer interface {
	ListenAndProxy(ctx context.Context, tlsCert tls.Certificate) error
	WaitForShutdown() <-chan struct{}
}

type inboundProxyServer struct {
	http    *http.Server
	targets []Target

	bimuxMgr bimux.SessionPool

	shutdownCh chan struct{}
}

func NewInboundProxyServer(sessionManager bimux.SessionPool, opts ...InboundProxyServerOption) (InboundProxyServer, error) {
	srv := &inboundProxyServer{
		bimuxMgr:   sessionManager,
		http:       new(http.Server),
		shutdownCh: make(chan struct{}),
	}

	for _, o := range opts {
		if err := o(srv); err != nil {
			return nil, fmt.Errorf("applying option failed: %w", err)
		}
	}

	proxyMux := http.NewServeMux()
	handler, err := NewProxy(srv.targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy: %w", err)
	}
	proxyMux.Handle("/", handler)
	srv.http.Handler = proxyMux

	return srv, nil
}

func (srv *inboundProxyServer) ListenAndProxy(ctx context.Context, tlsCert tls.Certificate) error {
	defer close(srv.shutdownCh)

	// We need to upgrade the tunnel to a TLS listener to support HTTP2 on this side.
	tlsConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to create TLS Config: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	tlsConfig.NextProtos = []string{"h2"}

	go func() {
		<-ctx.Done()
		_ = srv.http.Shutdown(ctx)
	}()

	for {
		result, err := chanutil.Read(ctx, srv.bimuxMgr.Get())
		if err != nil {
			// Either the channel is closed or the context is cancelled. Either way, this is an intentional shutdown.
			return nil
		}

		if result.Err != nil {
			return fmt.Errorf("failed to get session: %w", result.Err)
		}

		logrus.Infof("Starting to serve tunneled HTTP.")
		if err := srv.http.Serve(tls.NewListener(result.Value, tlsConfig)); err != nil {
			logrus.WithError(err).Debug("server closed")
		}
	}
}

func (srv *inboundProxyServer) WaitForShutdown() <-chan struct{} {
	return srv.shutdownCh
}
