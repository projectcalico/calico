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
// config/enterprise_versions.yml

package components

var (
	EnterpriseRelease string = "{{ .Title }}"
{{ with required .Components "calico" }}
	ComponentTigeraCalico = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "deep-packet-inspection" }}
	ComponentDeepPacketInspection = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "eck-elasticsearch" }}
	ComponentEckElasticsearch = Component{
		Version: "{{ .Version }}",
		variant: enterpriseVariant,
	}
{{- end }}
{{ with required .Components "eck-kibana" }}
	ComponentEckKibana = Component{
		Version: "{{ .Version }}",
		variant: enterpriseVariant,
	}
{{- end }}
{{ with required .Components "elastic-tsee-installer" }}
	ComponentElasticTseeInstaller = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "elasticsearch" }}
	ComponentElasticsearch = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "eck-elasticsearch-operator" }}
	ComponentECKElasticsearchOperator = Component{
		Version: "{{ .Version }}",
		variant: enterpriseVariant,
	}
{{- end }}
{{ with required .Components "elasticsearch-operator" }}
	ComponentElasticsearchOperator = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "fluent-bit" }}
	ComponentFluentBit = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "fluent-bit-windows" }}
	ComponentFluentBitWindows = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "intrusion-detection-controller" }}
	ComponentIntrusionDetectionController = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "kibana" }}
	ComponentKibana = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "manager" }}
	ComponentManager = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "dex" }}
	ComponentDex = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "egress-gateway" }}
	ComponentEgressGateway = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "gateway-l7-collector" }}
	ComponentGatewayL7Collector = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  enterpriseVariant,
	}
{{- end }}
{{ with required .Components "envoy" }}
	ComponentEnvoyProxy = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "dikastes" }}
	ComponentDikastes = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "coreos-prometheus" }}
	ComponentCoreOSPrometheus = Component{
		Version: "{{ .Version }}",
		variant: enterpriseVariant,
	}
{{- end }}
{{ with required .Components "prometheus" }}
	ComponentPrometheus = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "coreos-alertmanager" }}
	ComponentCoreOSAlertmanager = Component{
		Version: "{{ .Version }}",
		variant: enterpriseVariant,
	}
{{- end }}
{{ with required .Components "alertmanager" }}
	ComponentPrometheusAlertmanager = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "node" }}
	ComponentTigeraNode = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "node-windows" }}
	ComponentTigeraNodeWindows = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "tigera-cni-windows" }}
	ComponentTigeraCNIWindows = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "tigera-third-party-cni-plugins" }}
	ComponentTigeraCNIPlugins = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "gateway-api-envoy-gateway" }}
	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "gateway-api-envoy-proxy" }}
	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "gateway-api-envoy-ratelimit" }}
	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "{{ .Version }}",
		Image:     "{{ .Image }}",
		Registry:  "{{ .Registry }}",
		imagePath: "{{ .ImagePath }}",
		variant:   enterpriseVariant,
	}
{{- end }}
{{ with required .Components "istio-pilot" }}
	ComponentIstioPilot = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  enterpriseVariant,
	}
{{- end }}
{{ with required .Components "istio-install-cni" }}
	ComponentIstioInstallCNI = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  enterpriseVariant,
	}
{{- end }}
{{ with required .Components "istio-ztunnel" }}
	ComponentIstioZTunnel = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  enterpriseVariant,
	}
{{- end }}
{{ with required .Components "istio-proxyv2" }}
	ComponentIstioProxyv2 = Component{
		Version:  "{{ .Version }}",
		Image:    "{{ .Image }}",
		Registry: "{{ .Registry }}",
		variant:  enterpriseVariant,
	}
{{- end }}

	// Only components that correspond directly to images should be included in this list,
	// Components that are only for providing a version should be left out of this list.
	EnterpriseImages = []Component{
		ComponentTigeraCalico,
		ComponentDeepPacketInspection,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentFluentBit,
		ComponentFluentBitWindows,
		ComponentIntrusionDetectionController,
		ComponentKibana,
		ComponentManager,
		ComponentDex,
		ComponentEgressGateway,
		ComponentGatewayL7Collector,
		ComponentEnvoyProxy,
		ComponentDikastes,
		ComponentPrometheus,
		ComponentPrometheusAlertmanager,
		ComponentTigeraNode,
		ComponentTigeraNodeWindows,
		ComponentTigeraCNIWindows,
		ComponentTigeraCNIPlugins,
		ComponentGatewayAPIEnvoyGateway,
		ComponentGatewayAPIEnvoyProxy,
		ComponentGatewayAPIEnvoyRatelimit,
		ComponentIstioPilot,
		ComponentIstioInstallCNI,
		ComponentIstioZTunnel,
		ComponentIstioProxyv2,
	}
)
