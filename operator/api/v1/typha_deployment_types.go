// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
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
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

// TyphaDeploymentContainer is a typha Deployment container.
type TyphaDeploymentContainer struct {
	// Name is an enum which identifies the typha Deployment container by name.
	// Supported values are: calico-typha
	// +kubebuilder:validation:Enum=calico-typha
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named typha Deployment container's resources.
	// If omitted, the typha Deployment will use its default value for this container's resources.
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

// TyphaDeploymentInitContainer is a typha Deployment init container.
type TyphaDeploymentInitContainer struct {
	// Name is an enum which identifies the typha Deployment init container by name.
	// Supported values are: typha-certs-key-cert-provisioner
	// +kubebuilder:validation:Enum=typha-certs-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named typha Deployment init container's resources.
	// If omitted, the typha Deployment will use its default value for this init container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// TyphaDeploymentPodSpec is the typha Deployment's PodSpec.
type TyphaDeploymentPodSpec struct {
	// InitContainers is a list of typha init containers.
	// If specified, this overrides the specified typha Deployment init containers.
	// If omitted, the typha Deployment will use its default values for its init containers.
	// +optional
	InitContainers []TyphaDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of typha containers.
	// If specified, this overrides the specified typha Deployment containers.
	// If omitted, the typha Deployment will use its default values for its containers.
	// +optional
	Containers []TyphaDeploymentContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the typha pods.
	// If specified, this overrides any affinity that may be set on the typha Deployment.
	// If omitted, the typha Deployment will use its default value for affinity.
	// If used in conjunction with the deprecated TyphaAffinity, then this value takes precedence.
	// WARNING: Please note that this field will override the default calico-typha Deployment affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity,omitempty"`

	// NodeSelector is the calico-typha pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the calico-typha Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the calico-typha Deployment will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default calico-typha Deployment nodeSelector.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Optional duration in seconds the pod needs to terminate gracefully. May be decreased in delete request.
	// Value must be non-negative integer. The value zero indicates stop immediately via
	// the kill signal (no opportunity to shut down).
	// If this value is nil, the default grace period will be used instead.
	// The grace period is the duration in seconds after the processes running in the pod are sent
	// a termination signal and the time when the processes are forcibly halted with a kill signal.
	// Set this value longer than the expected cleanup time for your process.
	// Defaults to 30 seconds.
	// +optional
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty" protobuf:"varint,4,opt,name=terminationGracePeriodSeconds"`

	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Tolerations is the typha pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the typha Deployment.
	// If omitted, the typha Deployment will use its default value for tolerations.
	// WARNING: Please note that this field will override the default calico-typha Deployment tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// TyphaDeploymentPodTemplateSpec is the typha Deployment's PodTemplateSpec
type TyphaDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the typha Deployment's PodSpec.
	// +optional
	Spec *TyphaDeploymentPodSpec `json:"spec,omitempty"`
}

// TyphaDeployment is the configuration for the typha Deployment.
type TyphaDeployment struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the typha Deployment.
	// +optional
	Spec *TyphaDeploymentSpec `json:"spec,omitempty"`
}

// TyphaDeploymentSpec defines configuration for the typha Deployment.
type TyphaDeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the typha Deployment.
	// If omitted, the typha Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the typha Deployment pod that will be created.
	// +optional
	Template *TyphaDeploymentPodTemplateSpec `json:"template,omitempty"`

	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *TyphaDeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`
}

// TyphaDeploymentStrategy describes how to replace existing pods with new ones.  Only RollingUpdate is supported
// at this time so the Type field is not exposed.
type TyphaDeploymentStrategy struct {
	// Rolling update config params. Present only if DeploymentStrategyType =
	// RollingUpdate.
	// to be.
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty" protobuf:"bytes,2,opt,name=rollingUpdate"`
}
