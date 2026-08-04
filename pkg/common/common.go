// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package common

const (
	CalicoNamespace               = "calico-system"
	TyphaDeploymentName           = "calico-typha"
	NodeDaemonSetName             = "calico-node"
	KubeControllersDeploymentName = "calico-kube-controllers"
	WindowsDaemonSetName          = "calico-node-windows"

	// Monitor + Prometheus related const
	TigeraPrometheusNamespace = "tigera-prometheus"

	// ThreatDefenseFeature feature name
	ThreatDefenseFeature = "threat-defense"
	// ExportLogsFeature to 3rd party systems feature name
	ExportLogsFeature = "export-logs"
	// TiersFeature enables creation/update of Tiers
	TiersFeature = "tiers"
	// EgressAccessControl enables creation/update of NetworkPolicy with Domains
	EgressAccessControlFeature = "egress-access-control"
	// PolicyRecommendation feature name
	PolicyRecommendationFeature = "policy-recommendation"
	// MultipleOwnersLabel used to indicate multiple owner references.
	// If the render code places this label on an object, the object mergeState machinery will merge owner
	// references with any that already exist on the object rather than replace the owner references. Further
	// the controller in the owner reference will not be set.
	MultipleOwnersLabel = "operator.tigera.io/multipleOwners"

	// HostNetworkedPodLabel marks pods that run with hostNetwork=true and are
	// managed by the operator. The podiprecovery controller uses this label
	// to identify pods that need their IPs re-checked after a node IP change
	// (Kubernetes does not refresh status.podIPs for existing hostNetwork pods;
	// see https://github.com/kubernetes/kubernetes/issues/93897). It is
	// applied centrally by setStandardSelectorAndLabels in pkg/controller/utils
	// to any pod template with Spec.HostNetwork == true, so render packages
	// do not need to apply it themselves.
	HostNetworkedPodLabel = "operator.tigera.io/host-networked"

	// Sidecar common names
	SidecarMutatingWebhookConfigName = "tigera-sidecar-webhook-configuration"
)
