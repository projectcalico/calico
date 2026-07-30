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
	EnterpriseRelease string = "v3.24.0-1.0"

	ComponentTigeraCalico = Component{
		Version:   "v3.24.0-1.0",
		Image:     "calico",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceBenchmarker = Component{
		Version:   "v3.24.0-1.0",
		Image:     "compliance-benchmarker",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDeepPacketInspection = Component{
		Version:   "v3.24.0-1.0",
		Image:     "deep-packet-inspection",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEckElasticsearch = Component{
		Version: "8.19.17",
		variant: enterpriseVariant,
	}

	ComponentEckKibana = Component{
		Version: "8.19.17",
		variant: enterpriseVariant,
	}

	ComponentElasticTseeInstaller = Component{
		Version:   "v3.24.0-1.0",
		Image:     "intrusion-detection-job-installer",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentElasticsearch = Component{
		Version:   "v3.24.0-1.0",
		Image:     "elasticsearch",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentECKElasticsearchOperator = Component{
		Version: "3.4.1",
		variant: enterpriseVariant,
	}

	ComponentElasticsearchOperator = Component{
		Version:   "v3.24.0-1.0",
		Image:     "eck-operator",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentd = Component{
		Version:   "v3.24.0-1.0",
		Image:     "fluentd",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentdWindows = Component{
		Version:   "v3.24.0-1.0",
		Image:     "fluentd-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIntrusionDetectionController = Component{
		Version:   "v3.24.0-1.0",
		Image:     "intrusion-detection-controller",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentKibana = Component{
		Version:   "v3.24.0-1.0",
		Image:     "kibana",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentManager = Component{
		Version:   "v3.24.0-1.0",
		Image:     "manager",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDex = Component{
		Version:   "v3.24.0-1.0",
		Image:     "dex",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEgressGateway = Component{
		Version:   "v3.24.0-1.0",
		Image:     "egress-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayL7Collector = Component{
		Version:  "v3.24.0-1.0",
		Image:    "gateway-l7-collector",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentEnvoyProxy = Component{
		Version:   "v3.24.0-1.0",
		Image:     "envoy",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDikastes = Component{
		Version:   "v3.24.0-1.0",
		Image:     "dikastes",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSPrometheus = Component{
		Version: "v3.12.0",
		variant: enterpriseVariant,
	}

	ComponentPrometheus = Component{
		Version:   "v3.24.0-1.0",
		Image:     "prometheus",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSAlertmanager = Component{
		Version: "v0.32.1",
		variant: enterpriseVariant,
	}

	ComponentPrometheusAlertmanager = Component{
		Version:   "v3.24.0-1.0",
		Image:     "alertmanager",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNode = Component{
		Version:   "v3.24.0-1.0",
		Image:     "node",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNodeWindows = Component{
		Version:   "v3.24.0-1.0",
		Image:     "node-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNIWindows = Component{
		Version:   "v3.24.0-1.0",
		Image:     "cni-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNIPlugins = Component{
		Version:   "v3.24.0-1.0",
		Image:     "third-party-cni-plugins",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "v3.24.0-1.0",
		Image:     "envoy-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "v3.24.0-1.0",
		Image:     "envoy-proxy",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "v3.24.0-1.0",
		Image:     "envoy-ratelimit",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIstioPilot = Component{
		Version:  "v3.24.0-1.0",
		Image:    "istio-pilot",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioInstallCNI = Component{
		Version:  "v3.24.0-1.0",
		Image:    "istio-install-cni",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioZTunnel = Component{
		Version:  "v3.24.0-1.0",
		Image:    "istio-ztunnel",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioProxyv2 = Component{
		Version:  "v3.24.0-1.0",
		Image:    "istio-proxyv2",
		Registry: "",
		variant:  enterpriseVariant,
	}

	// Only components that correspond directly to images should be included in this list,
	// Components that are only for providing a version should be left out of this list.
	EnterpriseImages = []Component{
		ComponentTigeraCalico,
		ComponentComplianceBenchmarker,
		ComponentDeepPacketInspection,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentFluentd,
		ComponentFluentdWindows,
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
