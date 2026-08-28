// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package v1

import (
	"github.com/tigera/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IstiodDeploymentPodSpec defines the pod spec for customizing the Istiod Deployment.
type IstiodDeploymentPodSpec struct {
	// Affinity specifies the affinity for the deployment.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// NodeSelector specifies the node affinity for the deployment.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources specifies the compute resources required for the deployment.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// Tolerations specifies the tolerations for the deployment.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// IstiodDeploymentSpecTemplate defines the template for customizing the Istiod Deployment.
type IstiodDeploymentSpecTemplate struct {
	// Spec allows users to specify custom fields for the Istiod Deployment.
	// +optional
	Spec *IstiodDeploymentPodSpec `json:"spec,omitempty"`
}

// IstiodDeploymentSpec defines the spec for customizing the Istiod Deployment.
type IstiodDeploymentSpec struct {
	// Template allows users to specify custom fields for the Istiod Deployment.
	// +optional
	Template *IstiodDeploymentSpecTemplate `json:"template,omitempty"`
}

// IstiodDeployment defines customized settings for the Istio deployment.
type IstiodDeployment struct {
	// Spec allows users to specify custom fields for the Istiod Deployment.
	// +optional
	Spec *IstiodDeploymentSpec `json:"spec,omitempty"`
}

// IstioCNIDaemonsetPodSpec defines the pod spec for customizing the Istio CNI Daemonset.
type IstioCNIDaemonsetPodSpec struct {
	// Affinity specifies the affinity for the deployment.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// NodeSelector specifies the node affinity for the deployment.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources specifies the compute resources required for the deployment.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// Tolerations specifies the tolerations for the deployment.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// IstioCNIDaemonsetSpecTemplate defines the template for customizing the Istio CNI Daemonset.
type IstioCNIDaemonsetSpecTemplate struct {
	// Spec allows users to specify custom fields for the Istio CNI Daemonset.
	// +optional
	Spec *IstioCNIDaemonsetPodSpec `json:"spec,omitempty"`
}

// IstioCNIDaemonsetSpec defines the spec for customizing the Istio CNI Daemonset.
type IstioCNIDaemonsetSpec struct {
	// Template allows users to specify custom fields for the Istio CNI Daemonset.
	// +optional
	Template *IstioCNIDaemonsetSpecTemplate `json:"template,omitempty"`
}

// IstioCNIDaemonset defines customized settings for the Istio CNI plugin.
type IstioCNIDaemonset struct {
	// Spec allows users to specify custom fields for the Istio CNI Daemonset.
	// +optional
	Spec *IstioCNIDaemonsetSpec `json:"spec,omitempty"`
}

// ZTunnelDaemonsetPodSpec defines the pod spec for customizing the ZTunnel Daemonset.
type ZTunnelDaemonsetPodSpec struct {
	// Affinity specifies the affinity for the deployment.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// NodeSelector specifies the node affinity for the deployment.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources specifies the compute resources required for the deployment.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// Tolerations specifies the tolerations for the deployment.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// ZTunnelDaemonsetSpecTemplate defines the template for customizing the ZTunnel Daemonset.
type ZTunnelDaemonsetSpecTemplate struct {
	// Spec allows users to specify custom fields for the ZTunnel Daemonset.
	// +optional
	Spec *ZTunnelDaemonsetPodSpec `json:"spec,omitempty"`
}

// ZTunnelDaemonsetSpec defines the spec for customizing the ZTunnel Daemonset.
type ZTunnelDaemonsetSpec struct {
	// Template allows users to specify custom fields for the ZTunnel Daemonset.
	// +optional
	Template *ZTunnelDaemonsetSpecTemplate `json:"template,omitempty"`
}

// ZTunnelDaemonset defines customized settings for the ZTunnelDaemonset component.
type ZTunnelDaemonset struct {
	// Spec allows users to specify custom fields for the ZTunnel Daemonset.
	// +optional
	Spec *ZTunnelDaemonsetSpec `json:"spec,omitempty"`
}

// IstioSpec defines the desired state of Istio
type IstioSpec struct {
	// IstiodDeployment defines the resource requirements and node selector for the Istio deployment.
	// +optional
	IstiodDeployment *IstiodDeployment `json:"istiod,omitempty"`
	// IstioCNIDaemonset defines the resource requirements for the Istio CNI plugin.
	// +optional
	IstioCNIDaemonset *IstioCNIDaemonset `json:"istioCNI,omitempty"`
	// ZTunnelDaemonset defines the resource requirements for the ZTunnelDaemonset component.
	// +optional
	ZTunnelDaemonset *ZTunnelDaemonset `json:"ztunnel,omitempty"`
	// WaypointLogging controls whether L7 logging is enabled on every Gateway
	// using the istio-waypoint GatewayClass. When Enabled (the default), the
	// operator injects an l7-collector sidecar into each waypoint pod via
	// class-level defaults. When Disabled, no sidecar is injected and the
	// associated EnvoyFilters are not created. Allowed values are Enabled or
	// Disabled.
	// +optional
	WaypointLogging *LogCollectionStatusType `json:"waypointLogging,omitempty"`
	// DSCPMark define the value of the DSCP mark done by Felix and recognised by Istio CNI for Transparent
	// NetworkPolicies.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:validation:Type=integer
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:Pattern=`^.*`
	DSCPMark *numorstring.DSCP `json:"dscpMark,omitempty"`
}

// IstioStatus defines the observed state of Istio
type IstioStatus struct {
	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'", message="resource name must be 'default'"

// Istio is the Schema for the istios API
type Istio struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IstioSpec   `json:"spec,omitempty"`
	Status IstioStatus `json:"status,omitempty"`
}

// WaypointLoggingEnabled reports whether waypoint L7 logging should be rendered
// for this Istio CR. It defaults to true when the field is unset, and is the
// single source of truth shared by the renderer (which gates the l7-collector
// sidecar + EnvoyFilters) and the policy-sync predicate (which gates
// policySyncPathPrefix), so the two never diverge. A nil receiver reports false.
func (i *Istio) WaypointLoggingEnabled() bool {
	if i == nil {
		return false
	}
	wl := i.Spec.WaypointLogging
	return wl == nil || *wl != L7LogCollectionDisabled
}

// +kubebuilder:object:root=true

// IstioList contains a list of Istio resources.
type IstioList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Istio `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Istio{}, &IstioList{})
}
