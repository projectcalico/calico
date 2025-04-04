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
	"encoding/json"
	"fmt"

	"github.com/kelseyhightower/envconfig"

	"github.com/projectcalico/calico/lib/std/log"
)

type Config struct {
	GoldmaneHost string `default:"goldmane.calico-system.svc:7443" envconfig:"GOLDMANE_HOST"`
	Host         string `default:""`
	Port         string `default:"8080"`
	LogLevel     string `default:"info" envconfig:"LOG_LEVEL"`

	// TLS certificate and key for both server TLS and Goldmane client mTLS.
	TLSCertPath string `default:"" envconfig:"TLS_CERT_PATH"`
	TLSKeyPath  string `default:"" envconfig:"TLS_KEY_PATH"`
	CACertPath  string `default:"/etc/pki/tls/certs/tigera-ca-bundle.crt" envconfig:"CA_CERT_PATH"`
}

func NewConfig() (*Config, error) {
	cfg := &Config{}
	if err := envconfig.Process("", cfg); err != nil {
		return nil, err
	}

	cfg.ConfigureLogging()
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

func (cfg *Config) ConfigureLogging() {
	// Override with desired log level
	level, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Error("Invalid logging level passed in. Will use default level set to WARN")
		level = log.WarnLevel
	}

	log.Infof("Logging level set to %s", level)

	log.SetLevel(level)
}
