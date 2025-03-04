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
)

type Config struct {
	GoldmaneHost string `default:"goldmane.calico-system.svc:7443" split_words:"true"`
	Host         string `default:""`
	Port         string `default:"8080"`
	TlsCertPath  string `default:""`
	TlsKeyPath   string `default:""`
	LogLevel     string `default:"info" envconfig:"LOG_LEVEL"`
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
