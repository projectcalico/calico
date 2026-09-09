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

package components

// Every Calico component is built from this repository at one version, so all three
// are stamped at link time; see CALICO_LDFLAGS in operator/Makefile. Only a dev build
// stamps the registry and image path.
var (
	// CalicoRelease is the Calico version this operator deploys.
	CalicoRelease   = "unknown"
	calicoRegistry  = ""
	calicoImagePath = ""
)

func calicoComponent(image string) Component {
	return Component{
		Version:   CalicoRelease,
		Image:     image,
		Registry:  calicoRegistry,
		imagePath: calicoImagePath,
		variant:   calicoVariant,
	}
}

var (
	ComponentCalicoCNIPlugins      = calicoComponent("third-party-cni-plugins")
	ComponentCalicoCNIWindows      = calicoComponent("cni-windows")
	ComponentCalicoNode            = calicoComponent("node")
	ComponentCalicoNodeWindows     = calicoComponent("node-windows")
	ComponentCalicoWhisker         = calicoComponent("whisker")
	ComponentCalicoEnvoyGateway    = calicoComponent("envoy-gateway")
	ComponentCalicoEnvoyProxy      = calicoComponent("envoy-proxy")
	ComponentCalicoEnvoyRatelimit  = calicoComponent("envoy-ratelimit")
	ComponentCalicoIstioPilot      = calicoComponent("istio-pilot")
	ComponentCalicoIstioInstallCNI = calicoComponent("istio-install-cni")
	ComponentCalicoIstioZTunnel    = calicoComponent("istio-ztunnel")
	ComponentCalicoIstioProxyv2    = calicoComponent("istio-proxyv2")
	ComponentCalico                = calicoComponent("calico")

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
