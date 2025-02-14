package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/guardian/pkg/conn"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
)

type Server interface {
	ListenAndServeCluster(ctx context.Context) error
	ListenAndServeManagementCluster(ctx context.Context) error
}

// Client is the voltron client. It is used by Guardian to establish a secure tunnel connection to the Voltron server and
// then enable managed cluster services and management cluster services to communicate with one another.
type server struct {
	http      *http.Server
	proxyMux  *http.ServeMux
	targets   []Target
	closeOnce sync.Once

	tunnelAddr string
	tunnelCert *tls.Certificate

	// tunnelRootCAs defines the set of root certificate authorities that guardian will use when verifying voltron certificates.
	// if nil, dialer will use the host's CA set.
	tunnelRootCAs *x509.CertPool
	// TunnelServerName defines the server name to be used when connecting to Voltron
	tunnelServerName string

	tunnel tunnel.Tunnel

	connRetryAttempts int
	connRetryInterval time.Duration

	listenPort string
	listenHost string

	// If set, the default tunnel dialer will issue an HTTP CONNECT to this URL to establish a TCP passthrough connection to Voltron.
	httpProxyURL *url.URL

	tunnelDialerOptions []tunnel.DialerOption
}

func New(addr string, opts ...Option) (Server, error) {
	var err error
	srv := &server{
		http: new(http.Server),

		tunnelAddr:        addr,
		tunnelServerName:  strings.Split(addr, ":")[0],
		connRetryAttempts: 5,
		connRetryInterval: 2 * time.Second,
		listenPort:        "8080",
	}

	log.Infof("Tunnel Address: %s", srv.tunnelAddr)
	for _, o := range opts {
		if err := o(srv); err != nil {
			return nil, fmt.Errorf("applying option failed: %w", err)
		}
	}

	log.Debug("expecting TLS server name: ", srv.tunnelServerName)

	// set the dialer for the tunnel manager if one hasn't been specified
	tunnelAddress := srv.tunnelAddr

	var dialer tunnel.SessionDialer
	if srv.tunnelCert == nil {
		log.Warnf("No tunnel creds, using unsecured tunnel")
		dialer, err = tunnel.NewSessionDialer(tunnelAddress, srv.tunnelDialerOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create tunnel dialer: %w", err)
		}
	} else {
		tunnelCert := srv.tunnelCert
		tunnelRootCAs := srv.tunnelRootCAs

		tlsConfig := calicotls.NewTLSConfig()
		tlsConfig.Certificates = []tls.Certificate{*tunnelCert}
		tlsConfig.RootCAs = tunnelRootCAs
		tlsConfig.ServerName = srv.tunnelServerName

		dialer, err = tunnel.NewTLSSessionDialer(tunnelAddress, tlsConfig, srv.tunnelDialerOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create tunnel dialer: %w", err)
		}
	}

	for _, target := range srv.targets {
		log.Infof("Will route traffic to %s for requests matching %s", target.Dest, target.Path)
	}

	srv.proxyMux = http.NewServeMux()
	srv.http.Handler = srv.proxyMux

	handler, err := NewProxy(srv.targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy: %w", err)
	}
	srv.proxyMux.Handle("/", handler)

	srv.tunnel, err = tunnel.NewTunnel(dialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	return srv, nil
}

func (srv *server) ListenAndServeManagementCluster(ctx context.Context) error {
	if err := srv.tunnel.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to tunnel: %w", err)
	}

	log.Debug("Getting listener for tunnel.")
	listener, err := srv.tunnel.Listener(ctx)
	if err != nil {
		return err
	}

	if srv.tunnelCert != nil {
		// we need to upgrade the tunnel to a TLS listener to support HTTP2 on this side.
		tlsConfig := calicotls.NewTLSConfig()
		tlsConfig.Certificates = []tls.Certificate{*srv.tunnelCert}
		tlsConfig.NextProtos = []string{"h2"}
		listener = tls.NewListener(listener, tlsConfig)
		log.Infof("serving HTTP/2 enabled")
	}

	log.Infof("Starting to serve tunneled HTTP.")

	return srv.http.Serve(listener)
}

func (srv *server) ListenAndServeCluster(ctx context.Context) error {
	log.Infof("Listening on %s:%s for connections to proxy to voltron", srv.listenHost, srv.listenPort)
	if err := srv.tunnel.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to tunnel: %w", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", srv.listenHost, srv.listenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%s: %w", srv.listenHost, srv.listenPort, err)
	}

	defer wrapErrFunc(listener.Close, "Failed to close listener.")

	for {
		// TODO Consider throttling the number of connections this accepts.
		srcConn, err := listener.Accept()
		if err != nil {
			return err
		}

		dstConn, err := srv.tunnel.Open(ctx)
		if err != nil {
			if err := srcConn.Close(); err != nil {
				log.WithError(err).Error("failed to close source connection")
			}

			log.WithError(err).Error("failed to open connection to the tunnel")
			return err
		}

		go conn.Forward(srcConn, dstConn)
	}
}

func wrapErrFunc(f func() error, errMessage string) {
	if err := f(); err != nil {
		log.WithError(err).Error(errMessage)
	}
}
