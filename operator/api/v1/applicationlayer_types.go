// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ApplicationLayerSpec defines the desired state of ApplicationLayer
type ApplicationLayerSpec struct {
	// WebApplicationFirewall controls whether or not ModSecurity enforcement is enabled for the cluster.
	// When enabled, Services may opt-in to having ingress traffic examed by ModSecurity.
	WebApplicationFirewall *WAFStatusType `json:"webApplicationFirewall,omitempty"`
	// Specification for application layer (L7) log collection.
	LogCollection *LogCollectionSpec `json:"logCollection,omitempty"`
	// Application Layer Policy controls whether or not ALP enforcement is enabled for the cluster.
	// When enabled, NetworkPolicies with HTTP Match rules may be defined to opt-in workloads for traffic enforcement on the application layer.
	ApplicationLayerPolicy *ApplicationLayerPolicyStatusType `json:"applicationLayerPolicy,omitempty"`
	// User-configurable settings for the Envoy proxy.
	EnvoySettings *EnvoySettings `json:"envoy,omitempty"`

	// L7LogCollectorDaemonSet configures the L7LogCollector DaemonSet.
	// +optional
	L7LogCollectorDaemonSet *L7LogCollectorDaemonSet `json:"l7LogCollectorDaemonSet,omitempty"`

	// SidecarInjection controls whether or not sidecar injection is enabled for the cluster.
	// When enabled, pods with the label
	// "applicationlayer.projectcalico.org/sidecar"="true" will have their L7 functionality
	// such as WAF and ALP implemented using an injected sidecar instead of a per-host proxy.
	// The per-host proxy will continue to be used for pods without this label.
	// +optional
	SidecarInjection *SidecarStatusType `json:"sidecarInjection,omitempty"`
}

// +kubebuilder:validation:Enum=Enabled;Disabled
type LogCollectionStatusType string

// +kubebuilder:validation:Enum=Enabled;Disabled
type WAFStatusType string

// +kubebuilder:validation:Enum=Enabled;Disabled
type ApplicationLayerPolicyStatusType string

// +kubebuilder:validation:Enum=Enabled;Disabled
type SidecarStatusType string

// +kubebuilder:validation:Enum=Enabled;Disabled
type SidecarWebhookStateType string

const (
	WAFDisabled                    WAFStatusType                    = "Disabled"
	WAFEnabled                     WAFStatusType                    = "Enabled"
	L7LogCollectionDisabled        LogCollectionStatusType          = "Disabled"
	L7LogCollectionEnabled         LogCollectionStatusType          = "Enabled"
	ApplicationLayerPolicyEnabled  ApplicationLayerPolicyStatusType = "Enabled"
	ApplicationLayerPolicyDisabled ApplicationLayerPolicyStatusType = "Disabled"
	SidecarEnabled                 SidecarStatusType                = "Enabled"
	SidecarDisabled                SidecarStatusType                = "Disabled"
	SidecarWebhookStateEnabled     SidecarWebhookStateType          = "Enabled"
	SidecarWebhookStateDisabled    SidecarWebhookStateType          = "Disabled"
)

type EnvoySettings struct {
	// The number of additional ingress proxy hops from the right side of the
	// x-forwarded-for HTTP header to trust when determining the origin client’s
	// IP address. 0 is permitted, but >=1 is the typical setting.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default:=0
	// +optional
	XFFNumTrustedHops int32 `json:"xffNumTrustedHops,omitempty"`
	// If set to true, the Envoy connection manager will use the real remote address
	// of the client connection when determining internal versus external origin and
	// manipulating various headers.
	// +kubebuilder:default:=false
	// +optional
	UseRemoteAddress bool `json:"useRemoteAddress,omitempty"`
}

type LogCollectionSpec struct {
	// This setting enables or disable log collection.
	// Allowed values are Enabled or Disabled.
	// +optional
	CollectLogs *LogCollectionStatusType `json:"collectLogs,omitempty"`

	// Interval in seconds for sending L7 log information for processing.
	// +optional
	// Default: 5 sec
	LogIntervalSeconds *int64 `json:"logIntervalSeconds,omitempty"`

	// Maximum number of unique L7 logs that are sent LogIntervalSeconds.
	// Adjust this to limit the number of L7 logs sent per LogIntervalSeconds
	// to felix for further processing, use negative number to ignore limits.
	// +optional
	// Default: -1
	LogRequestsPerInterval *int64 `json:"logRequestsPerInterval,omitempty"`
}

// ApplicationLayerStatus defines the observed state of ApplicationLayer
type ApplicationLayerStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// SidecarWebhook provides the state of sidecar injection mutatinwebhookconfiguration
	SidecarWebhook *SidecarWebhookStateType `json:"sidecarWebhook,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ApplicationLayer is the Schema for the applicationlayers API
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'", message="resource name must be 'tigera-secure'"
type ApplicationLayer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApplicationLayerSpec   `json:"spec,omitempty"`
	Status ApplicationLayerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ApplicationLayerList contains a list of ApplicationLayer
type ApplicationLayerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApplicationLayer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ApplicationLayer{}, &ApplicationLayerList{})
}
