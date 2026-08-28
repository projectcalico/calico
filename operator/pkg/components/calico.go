// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

// Components defined here are required to be kept in sync with
// config/calico_versions.yml

package components

var (
	CalicoRelease string = "master"

	ComponentCalicoCNIPlugins = Component{
		Version:   "master",
		Image:     "third-party-cni-plugins",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCNIWindows = Component{
		Version:   "master",
		Image:     "cni-windows",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoNode = Component{
		Version:   "master",
		Image:     "node",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoNodeWindows = Component{
		Version:   "master",
		Image:     "node-windows",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoWhisker = Component{
		Version:   "master",
		Image:     "whisker",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyGateway = Component{
		Version:   "master",
		Image:     "envoy-gateway",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyProxy = Component{
		Version:   "master",
		Image:     "envoy-proxy",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyRatelimit = Component{
		Version:   "master",
		Image:     "envoy-ratelimit",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoIstioPilot = Component{
		Version:   "master",
		Image:     "istio-pilot",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoIstioInstallCNI = Component{
		Version:   "master",
		Image:     "istio-install-cni",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoIstioZTunnel = Component{
		Version:   "master",
		Image:     "istio-ztunnel",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoIstioProxyv2 = Component{
		Version:   "master",
		Image:     "istio-proxyv2",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalico = Component{
		Version:   "master",
		Image:     "calico",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	CalicoImages = []Component{
		ComponentCalicoCNIPlugins,
		ComponentCalicoCNIWindows,
		ComponentCalicoNode,
		ComponentCalicoNodeWindows,
		ComponentCalicoWhisker,
		ComponentCalicoEnvoyGateway,
		ComponentCalicoEnvoyProxy,
		ComponentCalicoEnvoyRatelimit,
		ComponentCalicoIstioPilot,
		ComponentCalicoIstioInstallCNI,
		ComponentCalicoIstioZTunnel,
		ComponentCalicoIstioProxyv2,
		ComponentCalico,
	}
)
