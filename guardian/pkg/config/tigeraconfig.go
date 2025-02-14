//go:build tigera

package config

import (
	"github.com/kelseyhightower/envconfig"
)

func NewConfig() (*TigeraConfig, error) {
	cfg := &TigeraConfig{}
	if err := envconfig.Process(EnvConfigPrefix, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

type TigeraConfig struct {
	Config

	PacketCaptureCABundlePath string `default:"/certs/packetcapture/tls.crt" split_words:"true"`
	PacketCaptureEndpoint     string `default:"https://tigera-packetcapture.tigera-packetcapture.svc" split_words:"true"`
	PrometheusCABundlePath    string `default:"/certs/prometheus/tls.crt" split_words:"true"`
	PrometheusPath            string `default:"/api/v1/namespaces/tigera-prometheus/services/calico-node-prometheus:9090/proxy/" split_words:"true"`
	PrometheusEndpoint        string `default:"https://prometheus-http-api.tigera-prometheus.svc:9090" split_words:"true"`
	QueryserverPath           string `default:"/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy/" split_words:"true"`
	QueryserverEndpoint       string `default:"https://tigera-api.tigera-system.svc:8080" split_words:"true"`
	QueryserverCABundlePath   string `default:"/etc/pki/tls/certs/tigera-ca-bundle.crt" split_words:"true"`
}
