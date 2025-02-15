//go:build tigera

package apply

import (
	"fmt"
	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/server"
)

func ApplyTargets(cfg *config.TigeraConfig) []server.Target {
	tgts := targets(&cfg.Config)
	tgts = append(tgts,
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
	return tgts
}
