// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tunnel

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

	calicoTLS "github.com/projectcalico/calico/crypto/pkg/tls"
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

type SessionDialer interface {
	Dial(ctx context.Context) (Session, error)
}

type Session interface {
	Open() (net.Conn, error)
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
}

type sessionDialer struct {
	addr string

	tlsConfig *tls.Config

	retryAttempts     int
	retryInterval     time.Duration
	timeout           time.Duration
	keepAliveEnable   bool
	keepAliveInterval time.Duration

	// If set, the default tunnel dialer will issue an HTTP CONNECT to this URL to establish a TCP pass-through connection to Voltron.
	httpProxyURL *url.URL
}

func NewTLSSessionDialer(addr string, tlsConfig *tls.Config, opts ...DialerOption) (SessionDialer, error) {
	d := &sessionDialer{
		addr:              addr,
		tlsConfig:         tlsConfig,
		retryAttempts:     defaultDialRetries,
		retryInterval:     defaultDialRetryInterval,
		timeout:           defaultDialTimeout,
		keepAliveEnable:   defaultKeepAlive,
		keepAliveInterval: defaultKeepAliveInterval,
	}

	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, fmt.Errorf("applying option failed: %w", err)
		}
	}

	return d, nil
}

func (d *sessionDialer) Dial(ctx context.Context) (Session, error) {
	var dialFunc func() (net.Conn, error)
	if d.tlsConfig == nil {
		dialFunc = func() (net.Conn, error) { return net.Dial("tcp", d.addr) }
	} else {
		dialFunc = d.dialTLS
	}
	conn, err := dialRetry(ctx, dialFunc, d.retryAttempts, d.retryInterval)
	if err != nil {
		return nil, err
	}

	config := yamux.DefaultConfig()
	config.AcceptBacklog = defaultSessionBacklog
	config.EnableKeepAlive = d.keepAliveEnable
	config.KeepAliveInterval = d.keepAliveInterval
	config.LogOutput = &logrusWriter{logrus.WithField("component", "tunnel-yamux")}
	session, err := yamux.Client(conn, config)
	if err != nil {
		return nil, fmt.Errorf("failed creating muxer: %s", err)
	}
	return session, nil
}

// DialTLS creates a TLS connection based on the config, must not be nil.
func (d *sessionDialer) dialTLS() (net.Conn, error) {
	logrus.Infof("Starting TLS dial to %s with a timeout of %v", d.addr, d.timeout)

	// First, establish the mTLS connection that serves as the basis of the tunnel.
	var c net.Conn
	var err error
	dialer := newDialer(d.timeout)
	if d.httpProxyURL != nil {
		// mTLS will be negotiated over a TCP connection to the proxy, which performs TCP passthrough to the target.
		logrus.Infof("Dialing to %s via HTTP proxy at %s", d.addr, d.httpProxyURL)
		var tlsConfig *tls.Config
		tlsConfig, err = calicoTLS.NewTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS Config: %w", err)
		}
		c, err = tlsDialViaHTTPProxy(dialer, d.addr, d.httpProxyURL, d.tlsConfig, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("TLS dial via HTTP proxy failed: %w", err)
		}
	} else {
		// mTLS will be negotiated over a TCP connection directly to the target.
		logrus.Infof("Dialing directly to %s", d.addr)
		c, err = tls.DialWithDialer(dialer, "tcp", d.addr, d.tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("TLS dial failed: %w", err)
		}
	}
	logrus.Infof("TLS dial to %s succeeded: basis connection for the tunnel has been established", d.addr)

	// Then, create the tunnel on top of the mTLS connection.
	return c, nil
}

func newDialer(timeout time.Duration) *net.Dialer {
	// We need to explicitly set the timeout as it seems it's possible for this to hang indefinitely if we don't.
	return &net.Dialer{
		Timeout: timeout,
	}
}

func tlsDialViaHTTPProxy(d *net.Dialer, destination string, proxyTargetURL *url.URL, tunnelTLS *tls.Config, proxyTLS *tls.Config) (net.Conn, error) {
	// Establish the TCP connection to the proxy.
	var c net.Conn
	var err error
	if proxyTargetURL.Scheme == "https" {
		c, err = tls.DialWithDialer(d, "tcp", proxyTargetURL.Host, proxyTLS)
	} else {
		c, err = d.DialContext(context.Background(), "tcp", proxyTargetURL.Host)
	}
	if err != nil {
		return nil, fmt.Errorf("dialing proxy %q failed: %v", proxyTargetURL.Host, err)
	}

	// Build the HTTP CONNECT request.
	var requestBuilder strings.Builder
	requestBuilder.WriteString(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", destination, destination))
	if proxyTargetURL.User != nil {
		username := proxyTargetURL.User.Username()
		password, _ := proxyTargetURL.User.Password()
		encodedCredentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		requestBuilder.WriteString(fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encodedCredentials))
	}
	requestBuilder.WriteString("\r\n")

	// Send the HTTP CONNECT request to the proxy.
	_, err = fmt.Fprint(c, requestBuilder.String())
	if err != nil {
		return nil, fmt.Errorf("writing HTTP CONNECT to proxy %s failed: %v", proxyTargetURL.Host, err)
	}
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("reading HTTP response from CONNECT to %s via proxy %s failed: %v", destination, proxyTargetURL.Host, err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("proxy error from %s while dialing %s: %v", proxyTargetURL.Host, destination, res.Status)
	}
	if br.Buffered() > 0 {
		// After the CONNECT was handled by the server, the client should be the first to talk to initiate the TLS handshake.
		// If we reach this point, the server spoke before the client, so something went wrong.
		return nil, fmt.Errorf("unexpected %d bytes of buffered data from CONNECT proxy %q", br.Buffered(), proxyTargetURL.Host)
	}

	// When we've reached this point, the proxy should now passthrough any TCP segments written to our connection to the destination.
	// Any TCP segments sent by the destination should also be readable on our connection.

	// Negotiate mTLS on top of our passthrough connection.
	mtlsC := tls.Client(c, tunnelTLS)
	if err := mtlsC.HandshakeContext(context.Background()); err != nil {
		mtlsC.Close()
		return nil, err
	}
	return mtlsC, nil
}

func dialRetry(ctx context.Context, connFunc func() (net.Conn, error), retryAttempts int, retryInterval time.Duration) (net.Conn, error) {
	for i := 0; ; i++ {
		conn, err := connFunc()
		if err != nil {
			if retryAttempts > -1 && i > retryAttempts {
				return nil, err
			}

			var xerr x509.UnknownAuthorityError
			if errors.Is(err, &xerr) {
				logrus.WithError(err).Infof("TLS dial failed: %s. fingerprint='%s' issuerCommonName='%s' subjectCommonName='%s'", xerr.Error(), cryptoutils.GenerateFingerprint(xerr.Cert), xerr.Cert.Issuer.CommonName, xerr.Cert.Subject.CommonName)
			} else {
				logrus.WithError(err).Infof("TLS dial attempt %d failed, will retry in %s", i, retryInterval.String())
			}

			if _, err := chanutil.Read(ctx, clock.After(retryInterval)); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil, err
				}
			}

			continue
		}

		return conn, err
	}
}
