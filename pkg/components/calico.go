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
	CalicoRelease string = "v3.32.0"

	ComponentCalicoCNI = Component{
		Version:   "v3.32.0",
		Image:     "cni",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCNIWindows = Component{
		Version:   "v3.32.0",
		Image:     "cni-windows",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCSRInitContainer = Component{
		Version:   "v3.32.0",
		Image:     "key-cert-provisioner",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoKubeControllers = Component{
		Version:   "v3.32.0",
		Image:     "kube-controllers",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoNode = Component{
		Version:   "v3.32.0",
		Image:     "node",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoNodeWindows = Component{
		Version:   "v3.32.0",
		Image:     "node-windows",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoTypha = Component{
		Version:   "v3.32.0",
		Image:     "typha",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoFlexVolume = Component{
		Version:   "v3.32.0",
		Image:     "pod2daemon-flexvol",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoAPIServer = Component{
		Version:   "v3.32.0",
		Image:     "apiserver",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCSI = Component{
		Version:   "v3.32.0",
		Image:     "csi",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCSIRegistrar = Component{
		Version:   "v3.32.0",
		Image:     "node-driver-registrar",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoGoldmane = Component{
		Version:   "v3.32.0",
		Image:     "goldmane",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoWhisker = Component{
		Version:   "v3.32.0",
		Image:     "whisker",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoWhiskerBackend = Component{
		Version:   "v3.32.0",
		Image:     "whisker-backend",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyGateway = Component{
		Version:   "v3.32.0",
		Image:     "envoy-gateway",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyProxy = Component{
		Version:   "v3.32.0",
		Image:     "envoy-proxy",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyRatelimit = Component{
		Version:   "v3.32.0",
		Image:     "envoy-ratelimit",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoGuardian = Component{
		Version:   "v3.32.0",
		Image:     "guardian",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoIstioPilot = Component{
		Version:   "v3.32.0",
		Image:     "istio-pilot",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoIstioInstallCNI = Component{
		Version:   "v3.32.0",
		Image:     "istio-install-cni",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoIstioZTunnel = Component{
		Version:   "v3.32.0",
		Image:     "istio-ztunnel",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoIstioProxyv2 = Component{
		Version:   "v3.32.0",
		Image:     "istio-proxyv2",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoWebhooks = Component{
		Version:   "v3.32.0",
		Image:     "webhooks",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	// Calico OSS ships the individual per-component images rather than the
	// combined calico/calico image, so there is no ComponentCalico.
	CalicoImages = []Component{
		ComponentCalicoCNI,
		ComponentCalicoCNIWindows,
		ComponentCalicoCSRInitContainer,
		ComponentCalicoKubeControllers,
		ComponentCalicoNode,
		ComponentCalicoNodeWindows,
		ComponentCalicoTypha,
		ComponentCalicoFlexVolume,
		ComponentCalicoAPIServer,
		ComponentCalicoCSI,
		ComponentCalicoCSIRegistrar,
		ComponentCalicoGoldmane,
		ComponentCalicoWhisker,
		ComponentCalicoWhiskerBackend,
		ComponentCalicoEnvoyGateway,
		ComponentCalicoEnvoyProxy,
		ComponentCalicoEnvoyRatelimit,
		ComponentCalicoGuardian,
		ComponentCalicoIstioPilot,
		ComponentCalicoIstioInstallCNI,
		ComponentCalicoIstioZTunnel,
		ComponentCalicoIstioProxyv2,
		ComponentCalicoWebhooks,
	}
)
