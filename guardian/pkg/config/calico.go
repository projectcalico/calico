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

import "github.com/projectcalico/calico/guardian/pkg/server"

type CalicoConfig struct {
	Config
}

func NewCalicoConfig() (*CalicoConfig, error) {
	cfg, err := newConfig()
	if err != nil {
		return nil, err
	}

	return &CalicoConfig{Config: *cfg}, nil
}

// Targets retrieves the targets needed for guardian.
func (cfg *CalicoConfig) Targets() []server.Target {
	apiServerOpts := []server.TargetOption{
		server.WithToken(defaultTokenPath),
		server.WithCAFile(defaultCABundlePath),
	}
	return []server.Target{
		// Access to the Kubernetes API server.
		server.MustCreateTarget("/api/", cfg.K8sEndpoint, apiServerOpts...),
		server.MustCreateTarget("/apis/", cfg.K8sEndpoint, apiServerOpts...),

		// Access to Goldmane APIs.
		server.MustCreateTarget(
			"/goldmane.Statistics/List",
			cfg.GoldmaneEndpoint,
			server.WithCAFile(cfg.CAFile),
			server.WithCertKeyPair(cfg.GoldmaneClientCert, cfg.GoldmaneClientKey),
		),
	}
}
