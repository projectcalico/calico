package bimux

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/cryptoutils"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/lib/std/clock"
)

const (
	defaultDialTimeout       = 60 * time.Second
	defaultDialRetries       = 20
	defaultDialRetryInterval = 5 * time.Second
	defaultKeepAlive         = true
	defaultKeepAliveInterval = 100 * time.Millisecond
	defaultSessionBacklog    = 1000
)

type ClientSessionResponse = chanutil.Response[*ClientSession]

type SessionDialer interface {
	Dial(ctx context.Context) (<-chan ClientSessionResponse, error)
}

type dialerInterface interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type sessionDialer struct {
	addr string

	// Dial retry on failure settings
	retryAttempts int
	retryInterval time.Duration

	// yamux settings.
	keepAliveEnable   bool
	keepAliveInterval time.Duration

	dialer dialerInterface
}

type dialConfig struct {
	retryAttempts     int
	retryInterval     time.Duration
	timeout           time.Duration
	keepAliveEnable   bool
	keepAliveInterval time.Duration

	// If set, the default tunnel dialer will issue an HTTP CONNECT to this URL to establish a TCP pass-through connection to Voltron.
	httpProxyURL   *url.URL
	proxyTLSConfig *tls.Config
}

func NewSessionDialer(addr string, tlsConfig *tls.Config, opts ...DialerOption) (SessionDialer, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("tlsConfig cannot be nil")
	}
	cfg := &dialConfig{
		retryAttempts:     defaultDialRetries,
		retryInterval:     defaultDialRetryInterval,
		timeout:           defaultDialTimeout,
		keepAliveEnable:   defaultKeepAlive,
		keepAliveInterval: defaultKeepAliveInterval,

		proxyTLSConfig: tlsConfig,
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("applying option failed: %w", err)
		}
	}

	var dialer dialerInterface

	netDialer := &net.Dialer{
		// We need to explicitly set the timeout as it seems it's possible for this to hang indefinitely if we don't.
		Timeout: cfg.timeout,
	}
	if cfg.httpProxyURL == nil {
		dialer = &tls.Dialer{
			Config:    tlsConfig,
			NetDialer: netDialer,
		}
	} else {
		logrus.Infof("HTTP proxy set, will proxy requests to %s via HTTP proxy at %s", addr, cfg.httpProxyURL)

		var innerDialer dialerInterface = netDialer
		if cfg.httpProxyURL.Scheme == "https" {
			innerDialer = &tls.Dialer{
				NetDialer: netDialer,
				Config:    cfg.proxyTLSConfig,
			}
		}

		var encodedCredentials string
		if cfg.httpProxyURL.User != nil {
			username := cfg.httpProxyURL.User.Username()
			password, _ := cfg.httpProxyURL.User.Password()
			encodedCredentials = base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		}
		dialer = &proxyDialer{
			dialer:             innerDialer,
			tlsConfig:          tlsConfig,
			proxyHost:          cfg.httpProxyURL.Host,
			encodedCredentials: encodedCredentials,
		}
	}

	return &sessionDialer{
		dialer: dialer,

		addr: addr,

		retryAttempts:     cfg.retryAttempts,
		retryInterval:     cfg.retryInterval,
		keepAliveEnable:   cfg.keepAliveEnable,
		keepAliveInterval: cfg.keepAliveInterval,
	}, nil
}

func (d *sessionDialer) Dial(ctx context.Context) (<-chan ClientSessionResponse, error) {
	// The channel size is 0 to ensure callers are blocked until the dial is complete.
	responseCh := make(chan ClientSessionResponse)

	go func() {
		defer close(responseCh)
		logrus.Debug("Dialing")
		conn, err := d.dialRetry(ctx)
		if err != nil {
			logrus.WithError(err).Debug("Failed to dial.")

			responseCh <- chanutil.Response[*ClientSession]{Err: err}
			return
		}

		config := yamux.DefaultConfig()
		config.AcceptBacklog = defaultSessionBacklog
		config.EnableKeepAlive = d.keepAliveEnable
		config.KeepAliveInterval = d.keepAliveInterval
		config.LogOutput = &logrusWriter{logrus.WithField("component", "tunnel-yamux")}

		mux, err := yamux.Client(conn, config)
		if err != nil {
			// An error signifies here signifies that the configuration is bad. Since this is a static configuration,
			// it is a developer error.
			panic(err)
		}

		responseCh <- ClientSessionResponse{Value: newClientSession(mux)}
	}()

	return responseCh, nil
}

func (d *sessionDialer) dialRetry(ctx context.Context) (net.Conn, error) {
	for i := 0; ; i++ {
		conn, err := d.dialer.DialContext(ctx, "tcp", d.addr)
		if err != nil {
			if d.retryAttempts > -1 && i > d.retryAttempts {
				return nil, err
			}

			var xerr x509.UnknownAuthorityError
			if errors.Is(err, &xerr) {
				logrus.WithError(err).Infof("TLS dial failed: %s. fingerprint='%s' issuerCommonName='%s' subjectCommonName='%s'", xerr.Error(), cryptoutils.GenerateFingerprint(xerr.Cert), xerr.Cert.Issuer.CommonName, xerr.Cert.Subject.CommonName)
			} else {
				logrus.WithError(err).Infof("TLS dial attempt %d failed, will retry in %s", i, d.retryInterval.String())
			}

			if _, err := chanutil.Read(ctx, clock.After(d.retryInterval)); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil, err
				}
			}

			continue
		}

		if err != nil {
			logrus.Infof("TLS dial to %s succeeded: basis connection for the tunnel has been established", d.addr)
		}
		return conn, err
	}
}

// proxyDialer is a dialer that dials through an HTTP proxy.
type proxyDialer struct {
	addr               string
	proxyHost          string
	dialer             dialerInterface
	encodedCredentials string
	tlsConfig          *tls.Config
}

func (d *proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Establish the TCP connection to the proxy.
	c, err := d.dialer.DialContext(ctx, "tcp", d.proxyHost)
	if err != nil {
		return nil, fmt.Errorf("dialing proxy %q failed: %w", d.proxyHost, err)
	}

	// Build the HTTP CONNECT request.
	var requestBuilder strings.Builder
	requestBuilder.WriteString(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address))
	if len(d.encodedCredentials) > 0 {
		requestBuilder.WriteString(fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", d.encodedCredentials))
	}
	requestBuilder.WriteString("\r\n")

	// Send the HTTP CONNECT request to the proxy.
	_, err = fmt.Fprint(c, requestBuilder.String())
	if err != nil {
		return nil, fmt.Errorf("writing HTTP CONNECT to proxy %s failed: %w", d.proxyHost, err)
	}
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("reading HTTP response from CONNECT to %s via proxy %s failed: %v", d.addr, d.proxyHost, err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("proxy error from %s while dialing %s: %v", d.proxyHost, d.addr, res.Status)
	}
	if br.Buffered() > 0 {
		// After the CONNECT was handled by the server, the client should be the first to talk to initiate the TLS handshake.
		// If we reach this point, the server spoke before the client, so something went wrong.
		return nil, fmt.Errorf("unexpected %d bytes of buffered data from CONNECT proxy %q", br.Buffered(), d.proxyHost)
	}

	// When we've reached this point, the proxy should now passthrough any TCP segments written to our connection to the destination.
	// Any TCP segments sent by the destination should also be readable on our connection.

	// Negotiate mTLS on top of our passthrough connection.
	mtlsC := tls.Client(c, d.tlsConfig)
	if err := mtlsC.HandshakeContext(ctx); err != nil {
		_ = mtlsC.Close()
		return nil, err
	}
	return mtlsC, nil
}
