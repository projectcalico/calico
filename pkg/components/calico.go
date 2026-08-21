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

import "github.com/tigera/operator/version"

var (
	CalicoRelease string = "v3.31.7"

	ComponentCalicoCNI = Component{
		Version:  "v3.31.7",
		Image:    "calico/cni",
		Registry: "",
	}

	ComponentCalicoCNIFIPS = Component{
		Version:  "v3.31.7-fips",
		Image:    "calico/cni",
		Registry: "",
	}

	ComponentCalicoCNIWindows = Component{
		Version:  "v3.31.7",
		Image:    "calico/cni-windows",
		Registry: "",
	}

	ComponentCalicoCSRInitContainer = Component{
		Version:  "v3.31.7",
		Image:    "calico/key-cert-provisioner",
		Registry: "",
	}

	ComponentCalicoKubeControllers = Component{
		Version:  "v3.31.7",
		Image:    "calico/kube-controllers",
		Registry: "",
	}

	ComponentCalicoKubeControllersFIPS = Component{
		Version:  "v3.31.7-fips",
		Image:    "calico/kube-controllers",
		Registry: "",
	}

	ComponentCalicoNode = Component{
		Version:  "v3.31.7",
		Image:    "calico/node",
		Registry: "",
	}

	ComponentCalicoNodeFIPS = Component{
		Version:  "v3.31.7-fips",
		Image:    "calico/node",
		Registry: "",
	}

	ComponentCalicoNodeWindows = Component{
		Version:  "v3.31.7",
		Image:    "calico/node-windows",
		Registry: "",
	}

	ComponentCalicoTypha = Component{
		Version:  "v3.31.7",
		Image:    "calico/typha",
		Registry: "",
	}

	ComponentCalicoTyphaFIPS = Component{
		Version:  "v3.31.7-fips",
		Image:    "calico/typha",
		Registry: "",
	}

	ComponentCalicoFlexVolume = Component{
		Version:  "v3.31.7",
		Image:    "calico/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentCalicoAPIServer = Component{
		Version:  "v3.31.7",
		Image:    "calico/apiserver",
		Registry: "",
	}

	ComponentCalicoAPIServerFIPS = Component{
		Version:  "v3.31.7-fips",
		Image:    "calico/apiserver",
		Registry: "",
	}

	ComponentCalicoCSI = Component{
		Version:  "v3.31.7",
		Image:    "calico/csi",
		Registry: "",
	}

	ComponentCalicoCSIFIPS = Component{
		Version:  "v3.31.7-fips",
		Image:    "calico/csi",
		Registry: "",
	}

	ComponentCalicoCSIRegistrar = Component{
		Version:  "v3.31.7",
		Image:    "calico/node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoCSIRegistrarFIPS = Component{
		Version:  "v3.31.7-fips",
		Image:    "calico/node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoGoldmane = Component{
		Version:  "v3.31.7",
		Image:    "calico/goldmane",
		Registry: "",
	}

	ComponentCalicoWhisker = Component{
		Version:  "v3.31.7",
		Image:    "calico/whisker",
		Registry: "",
	}

	ComponentCalicoWhiskerBackend = Component{
		Version:  "v3.31.7",
		Image:    "calico/whisker-backend",
		Registry: "",
	}

	ComponentCalicoEnvoyGateway = Component{
		Version:  "v3.31.7",
		Image:    "calico/envoy-gateway",
		Registry: "",
	}

	ComponentCalicoEnvoyProxy = Component{
		Version:  "v3.31.7",
		Image:    "calico/envoy-proxy",
		Registry: "",
	}

	ComponentCalicoEnvoyRatelimit = Component{
		Version:  "v3.31.7",
		Image:    "calico/envoy-ratelimit",
		Registry: "",
	}

	ComponentCalicoGuardian = Component{
		Version:  "v3.31.7",
		Image:    "calico/guardian",
		Registry: "",
	}
	ComponentOperatorInit = Component{
		Version: version.VERSION,
		Image:   "tigera/operator",
	}

	CalicoImages = []Component{
		ComponentCalicoCNI,
		ComponentCalicoCNIFIPS,
		ComponentCalicoCNIWindows,
		ComponentCalicoCSRInitContainer,
		ComponentCalicoKubeControllers,
		ComponentCalicoKubeControllersFIPS,
		ComponentCalicoNode,
		ComponentCalicoNodeFIPS,
		ComponentCalicoNodeWindows,
		ComponentCalicoTypha,
		ComponentCalicoTyphaFIPS,
		ComponentCalicoFlexVolume,
		ComponentCalicoAPIServer,
		ComponentCalicoAPIServerFIPS,
		ComponentCalicoCSI,
		ComponentCalicoCSIFIPS,
		ComponentCalicoCSIRegistrar,
		ComponentCalicoCSIRegistrarFIPS,
		ComponentCalicoGoldmane,
		ComponentCalicoWhisker,
		ComponentCalicoWhiskerBackend,
		ComponentCalicoEnvoyGateway,
		ComponentCalicoEnvoyProxy,
		ComponentCalicoEnvoyRatelimit,
		ComponentCalicoGuardian,
	}
)
