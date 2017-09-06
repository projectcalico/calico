package config

import (
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	LogLevel         string `default:"info" split_words:"true"`
	ReconcilerPeriod string `default:"5m" split_words:"true"`
	ControllerType   string `default:"policy" split_words:"true"`
	EndpointWorkers  int    `default:"3" split_words:"true"`
	ProfileWorkers   int    `default:"1" split_words:"true"`
	PolicyWorkers    int    `default:"1" split_words:"true"`
}

// Parse parses envconfig and stores in Config struct
func (c *Config) Parse() error {
	return envconfig.Process("policy", c)
}
