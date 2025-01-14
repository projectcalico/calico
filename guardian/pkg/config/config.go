package config

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpproxy"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "GUARDIAN"
)

func NewConfig() (*Config, error) {
	cfg := &Config{}
	all := os.Environ()
	_ = all
	if err := envconfig.Process(EnvConfigPrefix, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Config is a configuration used for Guardian
type Config struct {
	LogLevel                  string `default:"INFO"`
	CertPath                  string `default:"/certs" split_words:"true" json:"-"`
	VoltronCAType             string `default:"Tigera" split_words:"true"`
	VoltronURL                string `required:"true" split_words:"true"`
	PacketCaptureCABundlePath string `default:"/certs/packetcapture/tls.crt" split_words:"true"`
	PacketCaptureEndpoint     string `default:"https://tigera-packetcapture.tigera-packetcapture.svc" split_words:"true"`
	PrometheusCABundlePath    string `default:"/certs/prometheus/tls.crt" split_words:"true"`
	PrometheusPath            string `default:"/api/v1/namespaces/tigera-prometheus/services/calico-node-prometheus:9090/proxy/" split_words:"true"`
	PrometheusEndpoint        string `default:"https://prometheus-http-api.tigera-prometheus.svc:9090" split_words:"true"`
	QueryserverPath           string `default:"/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy/" split_words:"true"`
	QueryserverEndpoint       string `default:"https://tigera-api.tigera-system.svc:8080" split_words:"true"`
	QueryserverCABundlePath   string `default:"/etc/pki/tls/certs/tigera-ca-bundle.crt" split_words:"true"`

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

		serverName, err := extractServerName(pemServerCrt)
		if err != nil {
			return "", nil, err
		}
		return serverName, ca, nil
	}
}

// TODO Move to a different, common, package. This is very much reusable.
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
