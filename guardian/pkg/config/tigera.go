package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"

	"github.com/projectcalico/calico/guardian/pkg/server"
)

func NewTigeraConfig() (*TigeraConfig, error) {
	cfg := &TigeraConfig{}
	if err := envconfig.Process(EnvConfigPrefix, cfg); err != nil {
		return nil, err
	}

	cfg.configureLogging()

	return cfg, nil
}

type TigeraConfig struct {
	CalicoConfig

	PacketCaptureCABundlePath string `default:"/certs/packetcapture/tls.crt" split_words:"true"`
	PacketCaptureEndpoint     string `default:"https://tigera-packetcapture.tigera-packetcapture.svc" split_words:"true"`
	PrometheusCABundlePath    string `default:"/certs/prometheus/tls.crt" split_words:"true"`
	PrometheusPath            string `default:"/api/v1/namespaces/tigera-prometheus/services/calico-node-prometheus:9090/proxy/" split_words:"true"`
	PrometheusEndpoint        string `default:"https://prometheus-http-api.tigera-prometheus.svc:9090" split_words:"true"`
	QueryserverPath           string `default:"/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy/" split_words:"true"`
	QueryserverEndpoint       string `default:"https://tigera-api.tigera-system.svc:8080" split_words:"true"`
	QueryserverCABundlePath   string `default:"/etc/pki/tls/certs/tigera-ca-bundle.crt" split_words:"true"`
}

func (cfg *TigeraConfig) Targets() []server.Target {
	targets := cfg.CalicoConfig.Targets()
	return append(targets,
		server.MustCreateTarget("/packet-capture/", cfg.PacketCaptureEndpoint,
			server.WithAllowInsecureTLS(),
			server.WithPathReplace("/", fmt.Sprintf("^%v/?", "^/packet-capture/?")),
			server.WithToken(defaultTokenPath),
			server.WithCAPem(cfg.PacketCaptureCABundlePath)),
		server.MustCreateTarget(cfg.PrometheusPath, cfg.PrometheusEndpoint,
			server.WithPathReplace("/", fmt.Sprintf("^%v/?", cfg.PrometheusPath)),
			server.WithToken(defaultTokenPath),
			server.WithCAPem(cfg.PrometheusCABundlePath)),
		server.MustCreateTarget(cfg.QueryserverPath, cfg.QueryserverEndpoint,
			server.WithPathReplace("/", fmt.Sprintf("^%v/?", cfg.QueryserverPath)),
			server.WithToken(defaultTokenPath),
			server.WithCAPem(cfg.QueryserverCABundlePath)),
	)
}
