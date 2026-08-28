// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.
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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EGWDeploymentContainer is a Egress Gateway Deployment container.
type EGWDeploymentContainer struct {
	// Name is an enum which identifies the EGW Deployment container by name.
	// Supported values are: egress-gateway
	// +kubebuilder:validation:Enum=egress-gateway
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named EGW Deployment container's resources.
	// If omitted, the EGW Deployment will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`

	// ReadinessProbe allows customization of the readiness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	ReadinessProbe *ProbeOverride `json:"readinessProbe,omitempty"`

	// LivenessProbe allows customization of the liveness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	LivenessProbe *ProbeOverride `json:"livenessProbe,omitempty"`
}

// EGWDeploymentInitContainer is a Egress Gateway Deployment init container.
type EGWDeploymentInitContainer struct {
	// Name is an enum which identifies the EGW Deployment init container by name.
	// Supported values are: egress-gateway-init
	// +kubebuilder:validation:Enum=egress-gateway-init
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named EGW Deployment init container's resources.
	// If omitted, the EGW Deployment will use its default value for this init container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// EgressGatewaySpec defines the desired state of EgressGateway
type EgressGatewaySpec struct {
	// Replicas defines how many instances of the Egress Gateway pod will run.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +optional
	// +kubebuilder:default:=1
	Replicas *int32 `json:"replicas,omitempty"`

	// IPPools defines the IP Pools that the Egress Gateway pods should be using.
	// Either name or CIDR must be specified.
	// IPPools must match existing IPPools.
	// +required
	IPPools []EgressGatewayIPPool `json:"ipPools"`

	// ExternalNetworks defines the external network names this Egress Gateway is
	// associated with.
	// ExternalNetworks must match existing external networks.
	// +optional
	ExternalNetworks []string `json:"externalNetworks,omitempty"`

	// LogSeverity defines the logging level of the Egress Gateway.
	// +optional
	// +kubebuilder:default:=Info
	LogSeverity *LogSeverity `json:"logSeverity,omitempty"`

	// Template describes the EGW Deployment pod that will be created.
	// +optional
	Template *EgressGatewayDeploymentPodTemplateSpec `json:"template,omitempty"`

	// EgressGatewayFailureDetection is used to configure how Egress Gateway
	// determines readiness. If both ICMP, HTTP probes are defined, one ICMP probe and one
	// HTTP probe should succeed for Egress Gateways to become ready.
	// Otherwise one of ICMP or HTTP probe should succeed for Egress gateways to become
	// ready if configured.
	// +optional
	EgressGatewayFailureDetection *EgressGatewayFailureDetection `json:"egressGatewayFailureDetection,omitempty"`

	// AWS defines the additional configuration options for Egress Gateways on AWS.
	// +optional
	AWS *AWSEgressGateway `json:"aws,omitempty"`
}

// EgressGatewayDeploymentPodSpec is the Egress Gateway Deployment's PodSpec.
type EgressGatewayDeploymentPodSpec struct {
	// InitContainers is a list of EGW init containers.
	// If specified, this overrides the specified EGW Deployment init containers.
	// If omitted, the EGW Deployment will use its default values for its init containers.
	// +optional
	InitContainers []EGWDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of EGW containers.
	// If specified, this overrides the specified EGW Deployment containers.
	// If omitted, the EGW Deployment will use its default values for its containers.
	// +optional
	Containers []EGWDeploymentContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the EGW pods.
	// +optional
	Affinity *v1.Affinity `json:"affinity,omitempty"`

	// NodeSelector gives more control over the nodes where the Egress Gateway pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// TerminationGracePeriodSeconds defines the termination grace period of the Egress Gateway pods in seconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`

	// TopologySpreadConstraints defines how the Egress Gateway pods should be spread across different AZs.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Tolerations is the egress gateway pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the EGW Deployment.
	// If omitted, the EGW Deployment will use its default value for tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`

	// PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// EgressGatewayDeploymentPodTemplateSpec is the EGW Deployment's PodTemplateSpec
type EgressGatewayDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *EgressGatewayMetadata `json:"metadata,omitempty"`

	// Spec is the EGW Deployment's PodSpec.
	// +optional
	Spec *EgressGatewayDeploymentPodSpec `json:"spec,omitempty"`
}

// EgressGatewayMetadata contains the standard Kubernetes labels and annotations fields.
type EgressGatewayMetadata struct {
	// Labels is a map of string keys and values that may match replica set and
	// service selectors. Each of these key/value pairs are added to the
	// object's labels provided the key does not already exist in the object's labels.
	// If not specified will default to projectcalico.org/egw:[name], where [name] is
	// the name of the Egress Gateway resource.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations is a map of arbitrary non-identifying metadata. Each of these
	// key/value pairs are added to the object's annotations provided the key does not
	// already exist in the object's annotations.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

type EgressGatewayIPPool struct {
	// Name is the name of the IPPool that the Egress Gateways can use.
	// +optional
	Name string `json:"name,omitempty"`

	// CIDR is the IPPool CIDR that the Egress Gateways can use.
	// +optional
	CIDR string `json:"cidr,omitempty"`
}

// NativeIP defines if Egress Gateway pods should have AWS IPs.
// When NativeIP is enabled, the IPPools should be backed by AWS subnet.
type NativeIP string

const (
	NativeIPEnabled  NativeIP = "Enabled"
	NativeIPDisabled NativeIP = "Disabled"
)

// EgressGatewayFailureDetection defines the fields the needed for determining Egress Gateway
// readiness.
type EgressGatewayFailureDetection struct {

	// HealthTimeoutDataStoreSeconds defines how long Egress Gateway can fail to connect
	// to the datastore before reporting not ready.
	// This value must be greater than 0.
	// Default: 90
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default:=90
	// +optional
	HealthTimeoutDataStoreSeconds *int32 `json:"healthTimeoutDataStoreSeconds,omitempty"`

	// ICMPProbe define outgoing ICMP probes that Egress Gateway will use to
	// verify its upstream connection. Egress Gateway will report not ready if all
	// fail. Timeout must be greater than interval.
	// +optional
	ICMPProbe *ICMPProbe `json:"icmpProbe,omitempty"`

	// HTTPProbe define outgoing HTTP probes that Egress Gateway will use to
	// verify its upsteam connection. Egress Gateway will report not ready if all
	// fail. Timeout must be greater than interval.
	// +optional
	HTTPProbe *HTTPProbe `json:"httpProbe,omitempty"`
}

// ICMPProbe defines the ICMP probe configuration for Egress Gateway.
type ICMPProbe struct {
	// IPs define the list of ICMP probe IPs. Egress Gateway will probe each IP
	// periodically. If all probes fail, Egress Gateway will report non-ready.
	// +required
	IPs []string `json:"ips"`

	// IntervalSeconds defines the interval of ICMP probes. Used when IPs is non-empty.
	// Default: 5
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default:=5
	// +optional
	IntervalSeconds *int32 `json:"intervalSeconds,omitempty"`

	// TimeoutSeconds defines the timeout value of ICMP probes. Used when IPs is non-empty.
	// Default: 15
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default:=15
	// +optional
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`
}

// HTTPProbe defines the HTTP probe configuration for Egress Gateway.
type HTTPProbe struct {
	// URLs define the list of HTTP probe URLs. Egress Gateway will probe each URL
	// periodically.If all probes fail, Egress Gateway will report non-ready.
	// +required
	URLs []string `json:"urls"`

	// IntervalSeconds defines the interval of HTTP probes. Used when URLs is non-empty.
	// Default: 10
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default:=10
	// +optional
	IntervalSeconds *int32 `json:"intervalSeconds,omitempty"`

	// TimeoutSeconds defines the timeout value of HTTP probes. Used when URLs is non-empty.
	// Default: 30
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default:=30
	// +optional
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`
}

// AWSEgressGateway defines the configurations for deploying EgressGateway in AWS
type AWSEgressGateway struct {

	// NativeIP defines if EgressGateway is to use an AWS backed IPPool.
	// Default: Disabled
	// +kubebuilder:validation:Enum=Enabled;Disabled
	// +optional
	NativeIP *NativeIP `json:"nativeIP,omitempty"`

	// ElasticIPs defines the set of elastic IPs that can be used for Egress Gateway pods.
	// NativeIP must be Enabled if elastic IPs are set.
	// +optional
	ElasticIPs []string `json:"elasticIPs,omitempty"`
}

// EgressGatewayStatus defines the observed state of EgressGateway
type EgressGatewayStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// EgressGateway is the Schema for the egressgateways API
type EgressGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressGatewaySpec   `json:"spec,omitempty"`
	Status EgressGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EgressGatewayList contains a list of EgressGateway
type EgressGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressGateway `json:"items"`
}

func (c *EgressGateway) GetLogSeverity() string {
	return string(*c.Spec.LogSeverity)
}

func init() {
	SchemeBuilder.Register(&EgressGateway{}, &EgressGatewayList{})
}
