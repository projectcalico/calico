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

// Every version here is stamped at link time; see ENTERPRISE_LDFLAGS in operator/Makefile.
// Only a dev build stamps the registry and image path.
var (
	// EnterpriseRelease is the Enterprise version this operator deploys.
	EnterpriseRelease   = "unknown"
	enterpriseRegistry  = ""
	enterpriseImagePath = ""

	// enterpriseCalicoRelease is the version of the combined tigera/calico image, which
	// carries most of the Enterprise control plane and so gets patched on its own.
	enterpriseCalicoRelease = "unknown"

	// The upstream versions of the third-party software our own images are built from.
	// ECK and Prometheus Operator validate a workload against the version we declare for
	// it, so these describe image contents rather than naming a tag.
	elasticVersion      = "unknown"
	kibanaVersion       = "unknown"
	prometheusVersion   = "unknown"
	alertmanagerVersion = "unknown"
)

func enterpriseComponent(image string) Component {
	return enterpriseComponentAt(image, EnterpriseRelease)
}

func enterpriseComponentAt(image, version string) Component {
	return Component{
		Version:   version,
		Image:     image,
		Registry:  enterpriseRegistry,
		imagePath: enterpriseImagePath,
		variant:   enterpriseVariant,
	}
}

// enterpriseVersionOnly is for the components the operator names a version for without
// deploying an image of its own.
func enterpriseVersionOnly(version string) Component {
	return Component{
		Version: version,
		variant: enterpriseVariant,
	}
}

var (
	ComponentEckElasticsearch   = enterpriseVersionOnly(elasticVersion)
	ComponentEckKibana          = enterpriseVersionOnly(kibanaVersion)
	ComponentCoreOSPrometheus   = enterpriseVersionOnly(prometheusVersion)
	ComponentCoreOSAlertmanager = enterpriseVersionOnly(alertmanagerVersion)
)

var (
	ComponentTigeraCalico                 = enterpriseComponentAt("calico", enterpriseCalicoRelease)
	ComponentDeepPacketInspection         = enterpriseComponent("deep-packet-inspection")
	ComponentElasticTseeInstaller         = enterpriseComponent("intrusion-detection-job-installer")
	ComponentElasticsearch                = enterpriseComponent("elasticsearch")
	ComponentElasticsearchOperator        = enterpriseComponent("eck-operator")
	ComponentFluentBit                    = enterpriseComponent("fluent-bit")
	ComponentFluentBitWindows             = enterpriseComponent("fluent-bit-windows")
	ComponentIntrusionDetectionController = enterpriseComponent("intrusion-detection-controller")
	ComponentKibana                       = enterpriseComponent("kibana")
	ComponentManager                      = enterpriseComponent("manager")
	ComponentDex                          = enterpriseComponent("dex")
	ComponentEgressGateway                = enterpriseComponent("egress-gateway")
	ComponentGatewayL7Collector           = enterpriseComponent("gateway-l7-collector")
	ComponentEnvoyProxy                   = enterpriseComponent("envoy")
	ComponentDikastes                     = enterpriseComponent("dikastes")
	ComponentPrometheus                   = enterpriseComponent("prometheus")
	ComponentPrometheusAlertmanager       = enterpriseComponent("alertmanager")
	ComponentTigeraNode                   = enterpriseComponent("node")
	ComponentTigeraNodeWindows            = enterpriseComponent("node-windows")
	ComponentTigeraCNIWindows             = enterpriseComponent("cni-windows")
	ComponentTigeraCNIPlugins             = enterpriseComponent("third-party-cni-plugins")
	ComponentGatewayAPIEnvoyGateway       = enterpriseComponent("envoy-gateway")
	ComponentGatewayAPIEnvoyProxy         = enterpriseComponent("envoy-proxy")
	ComponentGatewayAPIEnvoyRatelimit     = enterpriseComponent("envoy-ratelimit")
	ComponentIstioPilot                   = enterpriseComponent("istio-pilot")
	ComponentIstioInstallCNI              = enterpriseComponent("istio-install-cni")
	ComponentIstioZTunnel                 = enterpriseComponent("istio-ztunnel")
	ComponentIstioProxyv2                 = enterpriseComponent("istio-proxyv2")

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
