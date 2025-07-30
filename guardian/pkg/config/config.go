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

package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpproxy"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/lib/std/cryptoutils"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

const (
	defaultTokenPath    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCABundlePath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "GUARDIAN"
)

// Config is the struct to parse the env configuration into.
type Config struct {
	LogLevel      string `default:"INFO"`
	CertPath      string `default:"/certs" split_words:"true" json:"-"`
	VoltronCAType string `default:"Tigera" split_words:"true"`
	VoltronURL    string `required:"true" split_words:"true"`

	// Configuration for health checking.
	HealthEnabled bool `json:"health_enabled" envconfig:"HEALTH_ENABLED" default:"true"`
	HealthPort    int  `json:"health_port" envconfig:"HEALTH_PORT" default:"8080"`

	KeepAliveEnable   bool `default:"true" split_words:"true"`
	KeepAliveInterval int  `default:"100" split_words:"true"`

	K8sEndpoint string `default:"https://kubernetes.default" split_words:"true"`

	// TunnelDialRetryAttempts is the number of times to the tunnel dialer should retry before failing.
	// -1 means dial indefinitely.
	TunnelDialRetryAttempts int           `default:"-1" split_words:"true"`
	TunnelDialRetryInterval time.Duration `default:"5s" split_words:"true"`
	TunnelDialTimeout       time.Duration `default:"10s" split_words:"true"`

	TunnelDialRecreateOnTunnelClose bool          `default:"true" split_words:"true"`
	ConnectionRetryAttempts         int           `default:"25" split_words:"true"`
	ConnectionRetryInterval         time.Duration `default:"5s" split_words:"true"`

	// GoldmaneEndpoint is the endpoint at which Goldmane is listening for gRPC requests.
	GoldmaneEndpoint   string `default:"https://goldmane.calico-system:7443" split_words:"true"`
	GoldmaneClientCert string `default:"" split_words:"true"`
	GoldmaneClientKey  string `default:"" split_words:"true"`

	// CAFile is the path to the CA file used to verify server certificates when
	// proxying connections received from the tunnel.
	CAFile string `default:"/etc/pki/tls/cert.pem" split_words:"true"`

	Listen     bool   `default:"true"`
	ListenHost string `default:"" split_words:"true"`
	ListenPort string `default:"8080" split_words:"true"`
}

func newConfig() (*Config, error) {
	cfg := &Config{}
	if err := envconfig.Process(EnvConfigPrefix, cfg); err != nil {
		return nil, err
	}

	cfg.configureLogging()

	return cfg, nil
}

func (cfg *Config) String() string {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func (cfg *Config) TLSConfig() (*tls.Config, *tls.Certificate, error) {
	certPath := fmt.Sprintf("%s/managed-cluster.crt", cfg.CertPath)
	keyPath := fmt.Sprintf("%s/managed-cluster.key", cfg.CertPath)

	pemCert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load tunnel cert from path %s: %w", certPath, err)
	}
	pemKey, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load tunnel key from path %s: %w", certPath, err)
	}

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create X509 key pair: %w", err)
	}
	tlsConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TLS Config: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	rootCA := x509.NewCertPool()
	if strings.ToLower(cfg.VoltronCAType) != "public" {
		rootCAPath := fmt.Sprintf("%s/management-cluster.crt", cfg.CertPath)
		pemServerCrt, err := os.ReadFile(rootCAPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read server cert from path %s: %w", rootCAPath, err)
		}

		if ok := rootCA.AppendCertsFromPEM(pemServerCrt); !ok {
			return nil, nil, fmt.Errorf("failed to append the server cert to cert pool: %w", err)
		}

		serverName, err := extractServerName(pemServerCrt)
		if err != nil {
			return nil, nil, err
		}
		logrus.Debug("expecting TLS server name: ", serverName)
		tlsConfig.ServerName = serverName
	} else {
		u, err := url.Parse(cfg.VoltronURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse voltron url %s: %w", cfg.VoltronURL, err)
		}

		tlsConfig.ServerName = u.Hostname()
	}

	tlsConfig.RootCAs = rootCA

	return tlsConfig, &cert, nil
}

func (cfg *Config) configureLogging() {
	logutils.ConfigureFormatter("guardian")
	log.SetOutput(os.Stdout)

	// Override with desired log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.Error("Invalid logging level passed in. Will use default level set to WARN")
		// Setting default to WARN
		level = logrus.WarnLevel
	}

	logrus.SetLevel(level)
}

func (cfg *Config) Cert() (string, *x509.CertPool, error) {
	if strings.ToLower(cfg.VoltronCAType) == "public" {
		// leave the ca cert pool as a nil pointer which will cause the tls dialer to load certs from the system.
		logrus.Info("Using system certs.")
		// in this case, the serverName will match the remote address
		// we need to strip the ports
		return strings.Split(cfg.VoltronURL, ":")[0], nil, nil
	} else {
		certPath := fmt.Sprintf("%s/management-cluster.crt", cfg.CertPath)
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return "", nil, fmt.Errorf("failed to read server cert: %w", err)
		}

		cert, err := cryptoutils.ParseCertificateBytes(certBytes)
		if err != nil {
			return "", nil, fmt.Errorf("cannot decode pem block for server certificate: %w", err)
		}
		if len(cert.DNSNames) != 1 {
			return "", nil, errors.New("expected a single DNS name registered on the certificate")
		}
		serverName := cert.DNSNames[0]

		ca := x509.NewCertPool()
		if ok := ca.AppendCertsFromPEM(certBytes); !ok {
			return "", nil, errors.New("failed to append the certificate to ca pool")
		}

		return serverName, ca, nil
	}
}

// GetHTTPProxyURL resolves the proxy URL that should be used for the tunnel target. It respects HTTPS_PROXY and NO_PROXY
// environment variables (case-insensitive).
func (cfg *Config) GetHTTPProxyURL() (*url.URL, error) {
	targetURL := &url.URL{
		// The scheme should be HTTPS, as we are establishing an mTLS session with the target.
		Scheme: "https",

		// We expect `target` to be of the form host:port.
		Host: cfg.VoltronURL,
	}

	proxyURL, err := httpproxy.FromEnvironment().ProxyFunc()(targetURL)
	if err != nil {
		return nil, err
	}

	if proxyURL == nil {
		return nil, nil
	}

	// Validate the URL scheme.
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("proxy URL had invalid scheme (%s) - must be http or https", proxyURL.Scheme)
	}

	// Update the host if we can infer a port number.
	if proxyURL.Port() == "" && proxyURL.Scheme == "http" {
		proxyURL.Host = net.JoinHostPort(proxyURL.Host, "80")
	} else if proxyURL.Port() == "" && proxyURL.Scheme == "https" {
		proxyURL.Host = net.JoinHostPort(proxyURL.Host, "443")
	}

	return proxyURL, nil
}

func extractServerName(pemServerCrt []byte) (string, error) {
	certDERBlock, _ := pem.Decode(pemServerCrt)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		return "", errors.New("cannot decode pem block for server certificate")
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
