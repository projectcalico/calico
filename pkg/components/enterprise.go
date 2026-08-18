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
	EnterpriseRelease string = "v3.22.7"

	ComponentAPIServer = Component{
		Version:  "v3.22.7",
		Image:    "tigera/apiserver",
		Registry: "",
	}

	ComponentComplianceBenchmarker = Component{
		Version:  "v3.22.7",
		Image:    "tigera/compliance-benchmarker",
		Registry: "",
	}

	ComponentComplianceController = Component{
		Version:  "v3.22.7",
		Image:    "tigera/compliance-controller",
		Registry: "",
	}

	ComponentComplianceReporter = Component{
		Version:  "v3.22.7",
		Image:    "tigera/compliance-reporter",
		Registry: "",
	}

	ComponentComplianceServer = Component{
		Version:  "v3.22.7",
		Image:    "tigera/compliance-server",
		Registry: "",
	}

	ComponentComplianceSnapshotter = Component{
		Version:  "v3.22.7",
		Image:    "tigera/compliance-snapshotter",
		Registry: "",
	}

	ComponentTigeraCSRInitContainer = Component{
		Version:  "v3.22.7",
		Image:    "tigera/key-cert-provisioner",
		Registry: "",
	}

	ComponentDeepPacketInspection = Component{
		Version:  "v3.22.7",
		Image:    "tigera/deep-packet-inspection",
		Registry: "",
	}

	ComponentEckElasticsearch = Component{
		Version:  "8.19.20",
		Registry: "",
	}

	ComponentEckKibana = Component{
		Version:  "8.19.20",
		Registry: "",
	}

	ComponentElasticTseeInstaller = Component{
		Version:  "v3.22.7",
		Image:    "tigera/intrusion-detection-job-installer",
		Registry: "",
	}

	ComponentElasticsearch = Component{
		Version:  "v3.22.7",
		Image:    "tigera/elasticsearch",
		Registry: "",
	}

	ComponentECKElasticsearchOperator = Component{
		Version:  "3.4.1",
		Registry: "",
	}

	ComponentElasticsearchOperator = Component{
		Version:  "v3.22.7",
		Image:    "tigera/eck-operator",
		Registry: "",
	}

	ComponentUIAPIs = Component{
		Version:  "v3.22.7",
		Image:    "tigera/ui-apis",
		Registry: "",
	}

	ComponentESGateway = Component{
		Version:  "v3.22.7",
		Image:    "tigera/es-gateway",
		Registry: "",
	}

	ComponentLinseed = Component{
		Version:  "v3.22.7",
		Image:    "tigera/linseed",
		Registry: "",
	}

	ComponentFluentd = Component{
		Version:  "v3.22.7",
		Image:    "tigera/fluentd",
		Registry: "",
	}

	ComponentFluentdWindows = Component{
		Version:  "v3.22.7",
		Image:    "tigera/fluentd-windows",
		Registry: "",
	}

	ComponentGuardian = Component{
		Version:  "v3.22.7",
		Image:    "tigera/guardian",
		Registry: "",
	}

	ComponentIntrusionDetectionController = Component{
		Version:  "v3.22.7",
		Image:    "tigera/intrusion-detection-controller",
		Registry: "",
	}

	ComponentWAFHTTPFilter = Component{
		Version:  "v3.22.7",
		Image:    "tigera/waf-http-filter",
		Registry: "",
	}

	ComponentSecurityEventWebhooksProcessor = Component{
		Version:  "v3.22.7",
		Image:    "tigera/webhooks-processor",
		Registry: "",
	}

	ComponentKibana = Component{
		Version:  "v3.22.7",
		Image:    "tigera/kibana",
		Registry: "",
	}

	ComponentManager = Component{
		Version:  "v3.22.7",
		Image:    "tigera/manager",
		Registry: "",
	}

	ComponentDex = Component{
		Version:  "v3.22.7",
		Image:    "tigera/dex",
		Registry: "",
	}

	ComponentManagerProxy = Component{
		Version:  "v3.22.7",
		Image:    "tigera/voltron",
		Registry: "",
	}

	ComponentPacketCapture = Component{
		Version:  "v3.22.7",
		Image:    "tigera/packetcapture",
		Registry: "",
	}

	ComponentPolicyRecommendation = Component{
		Version:  "v3.22.7",
		Image:    "tigera/policy-recommendation",
		Registry: "",
	}

	ComponentEgressGateway = Component{
		Version:  "v3.22.7",
		Image:    "tigera/egress-gateway",
		Registry: "",
	}

	ComponentL7Collector = Component{
		Version:  "v3.22.7",
		Image:    "tigera/l7-collector",
		Registry: "",
	}

	ComponentGatewayL7Collector = Component{
		Version:  "v3.22.7",
		Image:    "tigera/gateway-l7-collector",
		Registry: "",
	}

	ComponentEnvoyProxy = Component{
		Version:  "v3.22.7",
		Image:    "tigera/envoy",
		Registry: "",
	}

	ComponentDikastes = Component{
		Version:  "v3.22.7",
		Image:    "tigera/dikastes",
		Registry: "",
	}

	ComponentL7AdmissionController = Component{
		Version:  "v3.22.7",
		Image:    "tigera/l7-admission-controller",
		Registry: "",
	}

	ComponentCoreOSPrometheus = Component{
		Version:  "v3.13.2",
		Registry: "",
	}

	ComponentPrometheus = Component{
		Version:  "v3.22.7",
		Image:    "tigera/prometheus",
		Registry: "",
	}

	ComponentTigeraPrometheusService = Component{
		Version:  "v3.22.7",
		Image:    "tigera/prometheus-service",
		Registry: "",
	}

	ComponentCoreOSAlertmanager = Component{
		Version:  "v0.33.1",
		Registry: "",
	}

	ComponentPrometheusAlertmanager = Component{
		Version:  "v3.22.7",
		Image:    "tigera/alertmanager",
		Registry: "",
	}

	ComponentQueryServer = Component{
		Version:  "v3.22.7",
		Image:    "tigera/queryserver",
		Registry: "",
	}

	ComponentTigeraKubeControllers = Component{
		Version:  "v3.22.7",
		Image:    "tigera/kube-controllers",
		Registry: "",
	}

	ComponentTigeraNode = Component{
		Version:  "v3.22.7",
		Image:    "tigera/node",
		Registry: "",
	}

	ComponentTigeraNodeWindows = Component{
		Version:  "v3.22.7",
		Image:    "tigera/node-windows",
		Registry: "",
	}

	ComponentTigeraTypha = Component{
		Version:  "v3.22.7",
		Image:    "tigera/typha",
		Registry: "",
	}

	ComponentTigeraCNI = Component{
		Version:  "v3.22.7",
		Image:    "tigera/cni",
		Registry: "",
	}

	ComponentTigeraCNIWindows = Component{
		Version:  "v3.22.7",
		Image:    "tigera/cni-windows",
		Registry: "",
	}

	ComponentElasticsearchMetrics = Component{
		Version:  "v3.22.7",
		Image:    "tigera/elasticsearch-metrics",
		Registry: "",
	}

	ComponentTigeraFlexVolume = Component{
		Version:  "v3.22.7",
		Image:    "tigera/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentTigeraCSI = Component{
		Version:  "v3.22.7",
		Image:    "tigera/csi",
		Registry: "",
	}

	ComponentTigeraCSINodeDriverRegistrar = Component{
		Version:  "v3.22.7",
		Image:    "tigera/node-driver-registrar",
		Registry: "",
	}

	ComponentGatewayAPIEnvoyGateway = Component{
		Version:  "v3.22.7",
		Image:    "tigera/envoy-gateway",
		Registry: "",
	}

	ComponentGatewayAPIEnvoyProxy = Component{
		Version:  "v3.22.7",
		Image:    "tigera/envoy-proxy",
		Registry: "",
	}

	ComponentGatewayAPIEnvoyRatelimit = Component{
		Version:  "v3.22.7",
		Image:    "tigera/envoy-ratelimit",
		Registry: "",
	}

	ComponentCalicoIstioPilot = Component{
		Version:  "v3.22.7",
		Image:    "tigera/istio-pilot",
		Registry: "",
	}

	ComponentCalicoIstioInstallCNI = Component{
		Version:  "v3.22.7",
		Image:    "tigera/istio-install-cni",
		Registry: "",
	}

	ComponentCalicoIstioZTunnel = Component{
		Version:  "v3.22.7",
		Image:    "tigera/istio-ztunnel",
		Registry: "",
	}

	ComponentCalicoIstioProxyv2 = Component{
		Version:  "v3.22.7",
		Image:    "tigera/istio-proxyv2",
		Registry: "",
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
		ComponentCalicoIstioPilot,
		ComponentCalicoIstioInstallCNI,
		ComponentCalicoIstioZTunnel,
		ComponentCalicoIstioProxyv2,
	}
)
