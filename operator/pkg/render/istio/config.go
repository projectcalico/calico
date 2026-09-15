// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package istio

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
)

type GlobalConfig struct {
	IstioNamespace         string           `json:"istioNamespace,omitempty"`
	OperatorManageWebhooks bool             `json:"operatorManageWebhooks,omitempty"`
	Proxy                  *ProxyConfig     `json:"proxy,omitempty"`
	ProxyInit              *ProxyInitConfig `json:"proxy_init,omitempty"`
	Platform               string           `json:"platform,omitempty"`
	ImagePullSecrets       []string         `json:"imagePullSecrets,omitempty"`
}

type ProxyConfig struct {
	Image string `json:"image,omitempty"`
}

type ProxyInitConfig struct {
	Image string `json:"image,omitempty"`
}

type GatewaysConfig struct {
	SeccompProfile *corev1.SeccompProfile `json:"seccompProfile,omitempty"`
}

type AmbientConfig struct {
	Enabled                    bool `json:"enabled,omitempty"`
	ReconcileIptablesOnStartup bool `json:"reconcileIptablesOnStartup,omitempty"`
}

type BaseOpts struct {
	Global *GlobalConfig `json:"global,omitempty"`
}

type IstiodOpts struct {
	Image                   string          `json:"image,omitempty"`
	Global                  *GlobalConfig   `json:"global,omitempty"`
	Gateways                *GatewaysConfig `json:"gateways,omitempty"`
	Profile                 string          `json:"profile,omitempty"`
	TrustedZtunnelNamespace string          `json:"trustedZtunnelNamespace,omitempty"`
}

type IstioCNIOpts struct {
	Image   string         `json:"image,omitempty"`
	Global  *GlobalConfig  `json:"global,omitempty"`
	Ambient *AmbientConfig `json:"ambient,omitempty"`
}

type ZTunnelOpts struct {
	Image  string        `json:"image,omitempty"`
	Global *GlobalConfig `json:"global,omitempty"`
}

func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
