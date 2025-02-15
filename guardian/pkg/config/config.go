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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpproxy"

	"github.com/projectcalico/calico/guardian/pkg/cryptoutils"
	"github.com/projectcalico/calico/guardian/pkg/server"
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

// Config is a configuration used for Guardian
type Config struct {
	LogLevel      string `default:"INFO"`
	CertPath      string `default:"/certs" split_words:"true" json:"-"`
	VoltronCAType string `default:"Tigera" split_words:"true"`
	VoltronURL    string `required:"true" split_words:"true"`

	KeepAliveEnable   bool `default:"true" split_words:"true"`
	KeepAliveInterval int  `default:"100" split_words:"true"`
	PProf             bool `default:"false"`

	K8sEndpoint string `default:"https://kubernetes.default" split_words:"true"`

	TunnelDialRetryAttempts int           `default:"20" split_words:"true"`
	TunnelDialRetryInterval time.Duration `default:"5s" split_words:"true"`
	TunnelDialTimeout       time.Duration `default:"60s" split_words:"true"`

	TunnelDialRecreateOnTunnelClose bool          `default:"true" split_words:"true"`
	ConnectionRetryAttempts         int           `default:"25" split_words:"true"`
	ConnectionRetryInterval         time.Duration `default:"5s" split_words:"true"`

	Listen     bool   `default:"true"`
	ListenHost string `default:"" split_words:"true"`
	ListenPort string `default:"8080" split_words:"true"`
}

func NewConfig() (*Config, error) {
	cfg := &Config{}
	if err := envconfig.Process(EnvConfigPrefix, cfg); err != nil {
		return nil, err
	}

	cfg.ConfigureLogging()

	return cfg, nil
}

func (cfg *Config) Targets() []server.Target {
	return []server.Target{
		server.MustCreateTarget("/api/", cfg.K8sEndpoint+":6443",
			server.WithToken(defaultTokenPath),
			server.WithCAPem(defaultCABundlePath)),
		server.MustCreateTarget("/apis/", cfg.K8sEndpoint+":6443",
			server.WithToken(defaultTokenPath),
			server.WithCAPem(defaultCABundlePath)),
	}
}

func (cfg *Config) String() string {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func (cfg *Config) ConfigureLogging() {
	logutils.ConfigureFormatter("guardian")
	log.SetOutput(os.Stdout)

	// Override with desired log level
	level, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Error("Invalid logging level passed in. Will use default level set to WARN")
		// Setting default to WARN
		level = log.WarnLevel
	}

	log.SetLevel(level)
}

func (cfg *Config) Cert() (string, *x509.CertPool, error) {
	if strings.ToLower(cfg.VoltronCAType) == "public" {
		// leave the ca cert pool as a nil pointer which will cause the tls dialer to load certs from the system.
		log.Info("Using system certs.")
		// in this case, the serverName will match the remote address
		// we need to strip the ports
		return strings.Split(cfg.VoltronURL, ":")[0], nil, nil
	} else {
		serverCrt := fmt.Sprintf("%s/management-cluster.crt", cfg.CertPath)
		pemServerCrt, err := os.ReadFile(serverCrt)
		if err != nil {
			return "", nil, fmt.Errorf("failed to read server cert: %w", err)
		}

		ca := x509.NewCertPool()
		if ok := ca.AppendCertsFromPEM(pemServerCrt); !ok {
			return "", nil, errors.New("Cannot append the certificate to ca pool")
		}

		serverName, err := cryptoutils.ExtractServerName(pemServerCrt)
		if err != nil {
			return "", nil, err
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
