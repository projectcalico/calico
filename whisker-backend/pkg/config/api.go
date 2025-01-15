package config

import (
	"encoding/json"
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	GoldmaneHost string `default:"goldmane.calico-system.svc:7443" split_words:"true"`
	Host         string `default:""`
	Port         string `default:"8080"`
	TlsCertPath  string `default:""`
	TlsKeyPath   string `default:""`
}

func NewConfig() (*Config, error) {
	cfg := &Config{}
	if err := envconfig.Process("", cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (cfg *Config) String() string {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func (cfg *Config) HostAddr() string {
	return fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
}
