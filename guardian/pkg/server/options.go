// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	"os"
	"time"
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

func WithTunnelCertificatesFromFile(certPath, keyPath string) (Option, error) {
	pemCert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load tunnel cert from path %s: %w", certPath, err)
	}
	pemKey, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load tunnel key from path %s: %w", certPath, err)
	}

	return func(c *server) error {
		cert, err := tls.X509KeyPair(pemCert, pemKey)
		if err != nil {
			return fmt.Errorf("tls.X509KeyPair: %s", err.Error())
		}

		c.tunnelCert = &cert
		return nil
	}, nil
}

func WithTunnelRootCAFromFile(caPath string) (Option, error) {
	pemServerCrt, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read server cert from path %s: %w", caPath, err)
	}

	ca := x509.NewCertPool()
	if ok := ca.AppendCertsFromPEM(pemServerCrt); !ok {
		return nil, fmt.Errorf("failed to append the server cert to cert pool: %w", err)
	}

	serverName, err := extractServerName(pemServerCrt)
	if err != nil {
		return nil, err
	}
	return func(c *server) error {
		c.tunnelServerName = serverName
		c.tunnelRootCAs = ca
		return nil
	}, nil
}

func extractServerName(pemServerCrt []byte) (string, error) {
	certDERBlock, _ := pem.Decode(pemServerCrt)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		return "", errors.New("Cannot decode pem block for server certificate")
	}

	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("cannot decode pem block for server certificate: %w", err)
	}
	if len(cert.DNSNames) != 1 {
		return "", fmt.Errorf("expected a single DNS name registered on the certificate: %w", err)
	}
	return cert.DNSNames[0], nil
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

func WithTunnelOptions(opts ...tunnel.Option) Option {
	return func(c *server) error {
		c.tunnelOptions = opts
		return nil
	}
}
