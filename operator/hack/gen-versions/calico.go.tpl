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
	CalicoRelease string = "{{ .Title }}"
{{ with index .Components "third-party-cni-plugins" }}
	ComponentCalicoCNIPlugins = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components "cni-windows" }}
	ComponentCalicoCNIWindows = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components.node }}
	ComponentCalicoNode = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components  "node-windows" }}
	ComponentCalicoNodeWindows = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components.whisker }}
	ComponentCalicoWhisker = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components "envoy-gateway" }}
	ComponentCalicoEnvoyGateway = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components "envoy-proxy" }}
	ComponentCalicoEnvoyProxy = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components "envoy-ratelimit" }}
	ComponentCalicoEnvoyRatelimit = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components "istio-pilot" }}
	ComponentCalicoIstioPilot = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components "istio-install-cni" }}
	ComponentCalicoIstioInstallCNI = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components "istio-ztunnel" }}
	ComponentCalicoIstioZTunnel = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components "istio-proxyv2" }}
	ComponentCalicoIstioProxyv2 = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}
{{ with index .Components.calico }}
	ComponentCalico = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   calicoVariant,
	}
{{- end }}

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
