// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// WhiskerDeployment is the configuration for the whisker Deployment.
type WhiskerDeployment struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the specification of the whisker Deployment.
	// +optional
	Spec *WhiskerDeploymentSpec `json:"spec,omitempty"`
}

// WhiskerDeploymentSpec defines configuration for the whisker Deployment.
type WhiskerDeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the whisker Deployment.
	// If omitted, the whisker Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the whisker Deployment pod that will be created.
	// +optional
	Template *WhiskerDeploymentPodTemplateSpec `json:"template,omitempty"`
	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *WhiskerDeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`
}

// WhiskerDeploymentPodTemplateSpec is the whisker Deployment's PodTemplateSpec
type WhiskerDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the whisker Deployment's PodSpec.
	// +optional
	Spec *WhiskerDeploymentPodSpec `json:"spec,omitempty"`
}

// WhiskerDeploymentPodSpec is the whisker Deployment's PodSpec.
type WhiskerDeploymentPodSpec struct {
	// Affinity is a group of affinity scheduling rules for the whisker pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// Containers is a list of whisker containers.
	// If specified, this overrides the specified EGW Deployment containers.
	// If omitted, the whisker Deployment will use its default values for its containers.
	// +optional
	Containers []WhiskerDeploymentContainer `json:"containers,omitempty"`
	// NodeSelector gives more control over the nodes where the whisker pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// TerminationGracePeriodSeconds defines the termination grace period of the whisker pods in seconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`
	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Tolerations is the whisker pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the whisker Deployment.
	// If omitted, the whisker Deployment will use its default value for tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
	// PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}
type WhiskerDeploymentContainer struct {
	// +kubebuilder:validation:Enum=whisker;whisker-backend
	Name string `json:"name"`

	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// ReadinessProbe allows customization of the readiness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	ReadinessProbe *ProbeOverride `json:"readinessProbe,omitempty"`

	// LivenessProbe allows customization of the liveness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	LivenessProbe *ProbeOverride `json:"livenessProbe,omitempty"`
}
type WhiskerDeploymentStrategy struct {
	// Rolling update config params. Present only if DeploymentStrategyType =
	// RollingUpdate.
	// to be.
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty" protobuf:"bytes,2,opt,name=rollingUpdate"`
}
