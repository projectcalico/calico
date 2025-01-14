package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/guardian/pkg/conn"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
)

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

	tunnelEnableKeepAlive   bool
	tunnelKeepAliveInterval time.Duration

	tunnelManager tunnel.Manager
	tunnelDialer  tunnel.Dialer

	tunnelDialRetryAttempts int
	tunnelDialTimeout       time.Duration
	tunnelDialRetryInterval time.Duration

	connRetryAttempts int
	connRetryInterval time.Duration

	listenPort string
	listenHost string

	// If set, the default tunnel dialer will issue an HTTP CONNECT to this URL to establish a TCP passthrough connection to Voltron.
	httpProxyURL *url.URL
}

func wrapErrFunc(f func() error, errMessage string) {
	if err := f(); err != nil {
		log.WithError(err).Error(errMessage)
	}
}

func (srv *server) ListenAndServeToCluster() error {
	log.Infof("Listening on %s:%s for connections to proxy to voltron", srv.listenHost, srv.listenPort)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", srv.listenHost, srv.listenPort))
	if err != nil {
		log.WithError(err).Fatalf("Failed to listen on %s", srv.listenHost, srv.listenPort)
	}
	defer wrapErrFunc(listener.Close, "Failed to close listener.")

	for {
		srcConn, err := listener.Accept()
		if err != nil {
			return err
		}

		var dstConn net.Conn

		for i := 1; i <= srv.connRetryAttempts; i++ {
			dstConn, err = srv.tunnelManager.Open()
			if err == nil || !errors.Is(err, tunnel.ErrStillDialing) {
				break
			}

			time.Sleep(srv.connRetryInterval)
		}

		if err != nil {
			if err := srcConn.Close(); err != nil {
				log.WithError(err).Error("failed to close source connection")
			}

			log.WithError(err).Error("failed to open connection to the tunnel")
			return err
		}

		// TODO I think we want to throttle the connections
		go conn.Forward(srcConn, dstConn)
	}
}

func (srv *server) ListenAndServeToVoltron() error {
	log.Debug("Getting listener for tunnel.")

	var listener net.Listener
	var err error

	for i := 1; i <= srv.connRetryAttempts; i++ {
		listener, err = srv.tunnelManager.Listener()
		if err == nil || err != tunnel.ErrStillDialing {
			break
		}

		time.Sleep(srv.connRetryInterval)
	}

	if err != nil {
		return err
	}

	if srv.tunnelCert != nil {
		// we need to upgrade the tunnel to a TLS listener to support HTTP2
		// on this side.
		tlsConfig := calicotls.NewTLSConfig()
		tlsConfig.Certificates = []tls.Certificate{*srv.tunnelCert}
		tlsConfig.NextProtos = []string{"h2"}
		listener = tls.NewListener(listener, tlsConfig)
		log.Infof("serving HTTP/2 enabled")
	}

	log.Infof("Starting to serve tunneled HTTP.")

	return srv.http.Serve(listener)
}

type Server interface {
	ListenAndServeToCluster() error
	ListenAndServeToVoltron() error
}

func New(addr string, serverName string, opts ...Option) (Server, error) {
	var err error
	srv := &server{
		http:                    new(http.Server),
		tunnelEnableKeepAlive:   true,
		tunnelKeepAliveInterval: 100 * time.Millisecond,

		tunnelDialRetryAttempts: 5,
		tunnelDialRetryInterval: 2 * time.Second,
		tunnelDialTimeout:       60 * time.Second,

		connRetryAttempts: 5,
		connRetryInterval: 2 * time.Second,
		listenPort:        "8080",
	}

	srv.tunnelAddr = addr
	srv.tunnelServerName = serverName
	log.Infof("Tunnel Address: %s", srv.tunnelAddr)

	for _, o := range opts {
		if err := o(srv); err != nil {
			return nil, fmt.Errorf("applying option failed: %w", err)
		}
	}

	log.Debug("expecting TLS server name: ", srv.tunnelServerName)

	// set the dialer for the tunnel manager if one hasn't been specified
	tunnelAddress := srv.tunnelAddr
	tunnelKeepAlive := srv.tunnelEnableKeepAlive
	tunnelKeepAliveInterval := srv.tunnelKeepAliveInterval
	if srv.tunnelDialer == nil {
		var dialerFunc tunnel.DialerFunc
		if srv.tunnelCert == nil {
			log.Warnf("No tunnel creds, using unsecured tunnel")
			dialerFunc = func() (*tunnel.Tunnel, error) {
				return tunnel.Dial(
					tunnelAddress,
					tunnel.WithKeepAliveSettings(tunnelKeepAlive, tunnelKeepAliveInterval),
				)
			}
		} else {
			tunnelCert := srv.tunnelCert
			tunnelRootCAs := srv.tunnelRootCAs
			dialerFunc = func() (*tunnel.Tunnel, error) {
				log.Debug("Dialing tunnel...")

				tlsConfig := calicotls.NewTLSConfig()
				tlsConfig.Certificates = []tls.Certificate{*tunnelCert}
				tlsConfig.RootCAs = tunnelRootCAs
				tlsConfig.ServerName = srv.tunnelServerName
				return tunnel.DialTLS(
					tunnelAddress,
					tlsConfig,
					srv.tunnelDialTimeout,
					srv.httpProxyURL,
					tunnel.WithKeepAliveSettings(tunnelKeepAlive, tunnelKeepAliveInterval),
				)
			}
		}
		srv.tunnelDialer = tunnel.NewDialer(
			dialerFunc,
			srv.tunnelDialRetryAttempts,
			srv.tunnelDialRetryInterval,
			srv.tunnelDialTimeout,
		)
	}

	srv.tunnelManager = tunnel.NewManagerWithDialer(srv.tunnelDialer)

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

	return srv, nil
}
