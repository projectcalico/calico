// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/projectcalico/calico/guardian/pkg/tunnel"
)

// Option is a common format for New() options
type Option func(*server) error

// WithProxyTargets sets the proxying targets, can be used multiple times to add
// to a union of target.
func WithProxyTargets(tgts []Target) Option {
	return func(c *server) error {
		c.targets = tgts
		return nil
	}
}

// WithDefaultAddr changes the default address where the server accepts
// connections when Listener is not provided.
func WithDefaultAddr(addr string) Option {
	return func(c *server) error {
		c.http.Addr = addr
		return nil
	}
}

// WithTunnelCreds sets the credential to be used when establishing the tunnel
func WithTunnelCreds(certPEM []byte, keyPEM []byte) Option {
	return func(c *server) error {
		if certPEM == nil || keyPEM == nil {
			return errors.New("WithTunnelCreds: cert and key are required")
		}

		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("tls.X509KeyPair: %s", err.Error())
		}

		c.tunnelCert = &cert
		return nil
	}
}

// WithTunnelRootCA sets the cert to be used when verifying the server's identity.
func WithTunnelRootCA(ca *x509.CertPool) Option {
	return func(c *server) error {
		c.tunnelRootCAs = ca
		return nil
	}
}

// WithKeepAliveSettings sets the Keep Alive settings for the tunnel.
func WithKeepAliveSettings(enable bool, intervalMs int) Option {
	return func(c *server) error {
		c.tunnelEnableKeepAlive = enable
		c.tunnelKeepAliveInterval = time.Duration(intervalMs) * time.Millisecond
		return nil
	}
}

// WithTunnelDialer sets the tunnel dialer to the one specified, overwriting the default
func WithTunnelDialer(tunnelDialer tunnel.Dialer) Option {
	return func(c *server) error {
		c.tunnelDialer = tunnelDialer
		return nil
	}
}

// WithTunnelDialRetryAttempts sets number of times the the client should retry creating the tunnel if it fails
func WithTunnelDialRetryAttempts(tunnelDialRetryAttempts int) Option {
	return func(c *server) error {
		c.tunnelDialRetryAttempts = tunnelDialRetryAttempts
		return nil
	}
}

// WithTunnelDialRetryInterval sets the interval that the client should wait before retrying to create the tunnel
func WithTunnelDialRetryInterval(tunnelDialRetryInterval time.Duration) Option {
	return func(c *server) error {
		c.tunnelDialRetryInterval = tunnelDialRetryInterval
		return nil
	}
}

// WithConnectionRetryAttempts sets the number of times the client should retry opening or accepting a connection over
// the tunnel before failing permanently.
func WithConnectionRetryAttempts(connRetryAttempts int) Option {
	return func(c *server) error {
		c.connRetryAttempts = connRetryAttempts
		return nil
	}
}

// WithConnectionRetryInterval sets the interval that the client should wait before retrying to open or accept a connection
// over the tunnel after failing.
func WithConnectionRetryInterval(connRetryInterval time.Duration) Option {
	return func(c *server) error {
		c.connRetryInterval = connRetryInterval
		return nil
	}
}

// WithTunnelDialTimeout sets the timeout for the dialer when the client establishes a connection.
func WithTunnelDialTimeout(tunnelDialTimeout time.Duration) Option {
	return func(c *server) error {
		c.tunnelDialTimeout = tunnelDialTimeout
		return nil
	}
}

// WithHTTPProxyURL sets the URL that will be dialed via HTTP CONNECT to set up a TCP passthrough connection to Voltron.
func WithHTTPProxyURL(httpProxyURL *url.URL) Option {
	return func(c *server) error {
		c.httpProxyURL = httpProxyURL
		return nil
	}
}
