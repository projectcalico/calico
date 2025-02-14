//go:build calico

package config

import (
	"github.com/kelseyhightower/envconfig"
)

func NewConfig() (*CalicoConfig, error) {
	cfg := &CalicoConfig{}
	if err := envconfig.Process(EnvConfigPrefix, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

type CalicoConfig struct {
	Config
}
