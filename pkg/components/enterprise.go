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
	EnterpriseRelease string = "v3.23.1"

	ComponentAPIServer = Component{
		Version:   "v3.23.1",
		Image:     "apiserver",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceBenchmarker = Component{
		Version:   "v3.23.1",
		Image:     "compliance-benchmarker",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceController = Component{
		Version:   "v3.23.1",
		Image:     "compliance-controller",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceReporter = Component{
		Version:   "v3.23.1",
		Image:     "compliance-reporter",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceServer = Component{
		Version:   "v3.23.1",
		Image:     "compliance-server",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentComplianceSnapshotter = Component{
		Version:   "v3.23.1",
		Image:     "compliance-snapshotter",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:   "v3.23.1",
		Image:     "key-cert-provisioner",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDeepPacketInspection = Component{
		Version:   "v3.23.1",
		Image:     "deep-packet-inspection",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEckElasticsearch = Component{
		Version: "8.19.20",
		variant: enterpriseVariant,
	}

	ComponentEckKibana = Component{
		Version: "8.19.20",
		variant: enterpriseVariant,
	}

	ComponentElasticTseeInstaller = Component{
		Version:   "v3.23.1",
		Image:     "intrusion-detection-job-installer",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentElasticsearch = Component{
		Version:   "v3.23.1",
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
		Version:   "v3.23.1",
		Image:     "eck-operator",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentUIAPIs = Component{
		Version:   "v3.23.1",
		Image:     "ui-apis",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentESGateway = Component{
		Version:   "v3.23.1",
		Image:     "es-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentLinseed = Component{
		Version:   "v3.23.1",
		Image:     "linseed",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentd = Component{
		Version:   "v3.23.1",
		Image:     "fluentd",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentFluentdWindows = Component{
		Version:   "v3.23.1",
		Image:     "fluentd-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGuardian = Component{
		Version:   "v3.23.1",
		Image:     "guardian",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIntrusionDetectionController = Component{
		Version:   "v3.23.1",
		Image:     "intrusion-detection-controller",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentWAFHTTPFilter = Component{
		Version:   "v3.23.1",
		Image:     "waf-http-filter",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:   "v3.23.1",
		Image:     "webhooks-processor",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentKibana = Component{
		Version:   "v3.23.1",
		Image:     "kibana",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentManager = Component{
		Version:   "v3.23.1",
		Image:     "manager",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDex = Component{
		Version:   "v3.23.1",
		Image:     "dex",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentManagerProxy = Component{
		Version:   "v3.23.1",
		Image:     "voltron",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentPacketCapture = Component{
		Version:   "v3.23.1",
		Image:     "packetcapture",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentPolicyRecommendation = Component{
		Version:   "v3.23.1",
		Image:     "policy-recommendation",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentEgressGateway = Component{
		Version:   "v3.23.1",
		Image:     "egress-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentL7Collector = Component{
		Version:   "v3.23.1",
		Image:     "l7-collector",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayL7Collector = Component{
		Version:  "v3.23.1",
		Image:    "gateway-l7-collector",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentEnvoyProxy = Component{
		Version:   "v3.23.1",
		Image:     "envoy",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentDikastes = Component{
		Version:   "v3.23.1",
		Image:     "dikastes",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentL7AdmissionController = Component{
		Version:   "v3.23.1",
		Image:     "l7-admission-controller",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSPrometheus = Component{
		Version: "v3.13.2",
		variant: enterpriseVariant,
	}

	ComponentPrometheus = Component{
		Version:   "v3.23.1",
		Image:     "prometheus",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraPrometheusService = Component{
		Version:   "v3.23.1",
		Image:     "prometheus-service",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentCoreOSAlertmanager = Component{
		Version: "v0.33.1",
		variant: enterpriseVariant,
	}

	ComponentPrometheusAlertmanager = Component{
		Version:   "v3.23.1",
		Image:     "alertmanager",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentQueryServer = Component{
		Version:   "v3.23.1",
		Image:     "queryserver",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraKubeControllers = Component{
		Version:   "v3.23.1",
		Image:     "kube-controllers",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNode = Component{
		Version:   "v3.23.1",
		Image:     "node",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraNodeWindows = Component{
		Version:   "v3.23.1",
		Image:     "node-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraTypha = Component{
		Version:   "v3.23.1",
		Image:     "typha",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNI = Component{
		Version:   "v3.23.1",
		Image:     "cni",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCNIWindows = Component{
		Version:   "v3.23.1",
		Image:     "cni-windows",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentElasticsearchMetrics = Component{
		Version:   "v3.23.1",
		Image:     "elasticsearch-metrics",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraFlexVolume = Component{
		Version:   "v3.23.1",
		Image:     "pod2daemon-flexvol",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSI = Component{
		Version:   "v3.23.1",
		Image:     "csi",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:   "v3.23.1",
		Image:     "node-driver-registrar",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:   "v3.23.1",
		Image:     "envoy-gateway",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:   "v3.23.1",
		Image:     "envoy-proxy",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:   "v3.23.1",
		Image:     "envoy-ratelimit",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	ComponentIstioPilot = Component{
		Version:  "v3.23.1",
		Image:    "istio-pilot",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioInstallCNI = Component{
		Version:  "v3.23.1",
		Image:    "istio-install-cni",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioZTunnel = Component{
		Version:  "v3.23.1",
		Image:    "istio-ztunnel",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentIstioProxyv2 = Component{
		Version:  "v3.23.1",
		Image:    "istio-proxyv2",
		Registry: "",
		variant:  enterpriseVariant,
	}

	ComponentTigeraWebhooks = Component{
		Version:   "v3.23.1",
		Image:     "webhooks",
		Registry:  "",
		imagePath: "",
		variant:   enterpriseVariant,
	}

	// Only components that correspond directly to images should be included in this list,
	// Components that are only for providing a version should be left out of this list.
	EnterpriseImages = []Component{
		ComponentAPIServer,
		ComponentComplianceBenchmarker,
		ComponentComplianceController,
		ComponentComplianceReporter,
		ComponentComplianceServer,
		ComponentComplianceSnapshotter,
		ComponentTigeraCSRInitContainer,
		ComponentDeepPacketInspection,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentUIAPIs,
		ComponentFluentd,
		ComponentFluentdWindows,
		ComponentGuardian,
		ComponentIntrusionDetectionController,
		ComponentWAFHTTPFilter,
		ComponentSecurityEventWebhooksProcessor,
		ComponentKibana,
		ComponentManager,
		ComponentDex,
		ComponentManagerProxy,
		ComponentPacketCapture,
		ComponentPolicyRecommendation,
		ComponentEgressGateway,
		ComponentL7Collector,
		ComponentGatewayL7Collector,
		ComponentEnvoyProxy,
		ComponentPrometheus,
		ComponentTigeraPrometheusService,
		ComponentPrometheusAlertmanager,
		ComponentQueryServer,
		ComponentTigeraKubeControllers,
		ComponentTigeraNode,
		ComponentTigeraNodeWindows,
		ComponentTigeraTypha,
		ComponentTigeraCNI,
		ComponentTigeraCNIWindows,
		ComponentElasticsearchMetrics,
		ComponentESGateway,
		ComponentLinseed,
		ComponentDikastes,
		ComponentL7AdmissionController,
		ComponentTigeraFlexVolume,
		ComponentTigeraCSI,
		ComponentTigeraCSINodeDriverRegistrar,
		ComponentGatewayAPIEnvoyGateway,
		ComponentGatewayAPIEnvoyProxy,
		ComponentGatewayAPIEnvoyRatelimit,
		ComponentIstioPilot,
		ComponentIstioInstallCNI,
		ComponentIstioZTunnel,
		ComponentIstioProxyv2,
		ComponentTigeraWebhooks,
	}
)
