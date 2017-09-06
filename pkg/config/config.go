package config

import (
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// Minimum log level to emit.
	LogLevel string `default:"info" split_words:"true"`

	// Period to perform reconciliation with the Calico datastore.
	ReconcilerPeriod string `default:"5m" split_words:"true"`

	// Which controllers to run.
	ControllerType string `default:"policy" split_words:"true"`

	// Number of workers to run for each controller.
	EndpointWorkers int `default:"3" split_words:"true"`
	ProfileWorkers  int `default:"1" split_words:"true"`
	PolicyWorkers   int `default:"1" split_words:"true"`

	// Path to a kubeconfig file to use for accessing the k8s API.
	Kubeconfig string `default:"" split_words:"false"`
}

// Parse parses envconfig and stores in Config struct
func (c *Config) Parse() error {
	return envconfig.Process("policy", c)
}
