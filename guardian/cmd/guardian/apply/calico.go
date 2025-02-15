//go:build calico

package apply

import (
	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/server"
)

func ApplyTargets(cfg *config.CalicoConfig) []server.Target {
	return targets(&cfg.Config)
}
