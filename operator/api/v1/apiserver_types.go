// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

// APIServerSpec defines the desired state of Tigera API server.
type APIServerSpec struct {
	// +optional
	Logging *APIServerPodLogging `json:"logging,omitempty"`

	// APIServerDeployment configures the calico-apiserver Deployment. If
	// used in conjunction with ControlPlaneNodeSelector or ControlPlaneTolerations, then these overrides
	// take precedence.
	APIServerDeployment *APIServerDeployment `json:"apiServerDeployment,omitempty"`

	// CalicoWebhooksDeployment configures the calico-webhooks Deployment.
	// +optional
	CalicoWebhooksDeployment *CalicoWebhooksDeployment `json:"calicoWebhooksDeployment,omitempty"`
}

// APIServerStatus defines the observed state of Tigera API server.
type APIServerStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// APIServer installs the Tigera API server and related resources. At most one instance
// of this resource is supported. It must be named "default" or "tigera-secure".
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default' || self.metadata.name == 'tigera-secure'",message="resource name must be 'default' or 'tigera-secure'"
type APIServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Tigera API server.
	Spec APIServerSpec `json:"spec,omitempty"`

	// Most recently observed status for the Tigera API server.
	Status APIServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIServerList contains a list of APIServer
type APIServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIServer{}, &APIServerList{})
}

// APIServerDeploymentContainer is an API server Deployment container.
type APIServerDeploymentContainer struct {
	// Name is an enum which identifies the API server Deployment container by name.
	// Supported values are: calico-apiserver, tigera-queryserver, calico-l7-admission-controller
	// +kubebuilder:validation:Enum=calico-apiserver;tigera-queryserver;calico-l7-admission-controller
	Name string `json:"name"`

	// Ports allows customization of container's ports.
	// If specified, this overrides the named APIServer Deployment container's ports.
	// If omitted, the API server Deployment will use its default value for this container's port.
	// +optional
	Ports []APIServerDeploymentContainerPort `json:"ports,omitempty"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named API server Deployment container's resources.
	// If omitted, the API server Deployment will use its default value for this container's resources.
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

type APIServerDeploymentContainerPort struct {
	// Name is an enum which identifies the API server Deployment Container port by name.
	// Supported values are: apiserver, queryserver, l7admctrl
	// +kubebuilder:validation:Enum=apiserver;queryserver;l7admctrl
	Name string `json:"name"`

	// Number of port to expose on the pod's IP address.
	// This must be a valid port number, 0 < x < 65536.
	ContainerPort int32 `json:"containerPort" protobuf:"varint,3,opt,name=containerPort"`
}

// APIServerDeploymentInitContainer is an API server Deployment init container.
type APIServerDeploymentInitContainer struct {
	// Name is an enum which identifies the API server Deployment init container by name.
	// Supported values are: calico-apiserver-certs-key-cert-provisioner
	// +kubebuilder:validation:Enum=calico-apiserver-certs-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named API server Deployment init container's resources.
	// If omitted, the API server Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// APIServerDeploymentDeploymentPodSpec is the API server Deployment's PodSpec.
type APIServerDeploymentPodSpec struct {
	// InitContainers is a list of API server init containers.
	// If specified, this overrides the specified API server Deployment init containers.
	// If omitted, the API server Deployment will use its default values for its init containers.
	// +optional
	InitContainers []APIServerDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of API server containers.
	// If specified, this overrides the specified API server Deployment containers.
	// If omitted, the API server Deployment will use its default values for its containers.
	// +optional
	Containers []APIServerDeploymentContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the API server pods.
	// If specified, this overrides any affinity that may be set on the API server Deployment.
	// If omitted, the API server Deployment will use its default value for affinity.
	// WARNING: Please note that this field will override the default API server Deployment affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity,omitempty"`

	// NodeSelector is the API server pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the API server Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If used in conjunction with ControlPlaneNodeSelector, that nodeSelector is set on the API server Deployment
	// and each of this field's key/value pairs are added to the API server Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the API server Deployment will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default API server Deployment nodeSelector.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Tolerations is the API server pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the API server Deployment.
	// If omitted, the API server Deployment will use its default value for tolerations.
	// WARNING: Please note that this field will override the default API server Deployment tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`

	// PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// APIServerDeploymentPodTemplateSpec is the API server Deployment's PodTemplateSpec
type APIServerDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the API server Deployment's PodSpec.
	// +optional
	Spec *APIServerDeploymentPodSpec `json:"spec,omitempty"`
}

// APIServerDeployment is the configuration for the API server Deployment.
type APIServerDeployment struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the API server Deployment.
	// +optional
	Spec *APIServerDeploymentSpec `json:"spec,omitempty"`
}

// APIServerDeploymentSpec defines configuration for the API server Deployment.
type APIServerDeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the API server Deployment.
	// If omitted, the API server Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the API server Deployment pod that will be created.
	// +optional
	Template *APIServerDeploymentPodTemplateSpec `json:"template,omitempty"`
}

type APIServerPodLogging struct {
	// +optional
	APIServerLogging *APIServerLogging `json:"apiServer,omitempty"`

	// +optional
	QueryServerLogging *QueryServerLogging `json:"queryServer,omitempty"`
}

type APIServerLogging struct {
	// LogSeverity defines log level for APIServer container.
	// +optional
	// +kubebuilder:default=Info
	LogSeverity *LogSeverity `json:"logSeverity,omitempty"`
}

type QueryServerLogging struct {
	// LogSeverity defines log level for QueryServer container.
	// +optional
	// +kubebuilder:default=Info
	LogSeverity *LogSeverity `json:"logSeverity,omitempty"`
}
