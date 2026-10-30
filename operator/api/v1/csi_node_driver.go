/*
Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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
)

// CSINodeDriverDaemonSetContainer is a csi-node-driver DaemonSet container.
type CSINodeDriverDaemonSetContainer struct {
	// Name is an enum which identifies the csi-node-driver DaemonSet container by name.
	// Supported values are: calico-csi, csi-node-driver-registrar.
	// +kubebuilder:validation:Enum=calico-csi;csi-node-driver-registrar;csi-node-driver
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named csi-node-driver DaemonSet container's resources.
	// If omitted, the csi-node-driver DaemonSet will use its default value for this container's resources.
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

// CSINodeDriverDaemonSetPodSpec is the csi-node-driver DaemonSet's PodSpec.
type CSINodeDriverDaemonSetPodSpec struct {
	// Containers is a list of csi-node-driver containers.
	// If specified, this overrides the specified csi-node-driver DaemonSet containers.
	// If omitted, the csi-node-driver DaemonSet will use its default values for its containers.
	// +optional
	Containers []CSINodeDriverDaemonSetContainer `json:"containers,omitempty"`
	// Affinity is a group of affinity scheduling rules for the csi-node-driver pods.
	// If specified, this overrides any affinity that may be set on the csi-node-driver DaemonSet.
	// If omitted, the csi-node-driver DaemonSet will use its default value for affinity.
	// WARNING: Please note that this field will override the default csi-node-driver DaemonSet affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// NodeSelector is the csi-node-driver pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the csi-node-driver DaemonSet nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the csi-node-driver DaemonSet will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default csi-node-driver DaemonSet nodeSelector.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations is the csi-node-driver pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the csi-node-driver DaemonSet.
	// If omitted, the csi-node-driver DaemonSet will use its default value for tolerations.
	// WARNING: Please note that this field will override the default csi-node-driver DaemonSet tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// CSINodeDriverDaemonSetPodTemplateSpec is the csi-node-driver DaemonSet's PodTemplateSpec
type CSINodeDriverDaemonSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the csi-node-driver DaemonSet's PodSpec.
	// +optional
	Spec *CSINodeDriverDaemonSetPodSpec `json:"spec,omitempty"`
}

// CSINodeDriverDaemonSet is the configuration for the csi-node-driver DaemonSet.
type CSINodeDriverDaemonSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the DaemonSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the csi-node-driver DaemonSet.
	// +optional
	Spec *CSINodeDriverDaemonSetSpec `json:"spec,omitempty"`
}

// CSINodeDriverDaemonSetSpec defines configuration for the csi-node-driver DaemonSet.
type CSINodeDriverDaemonSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created DaemonSet pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the csi-node-driver DaemonSet.
	// If omitted, the csi-node-driver DaemonSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`
	// Template describes the csi-node-driver DaemonSet pod that will be created.
	// +optional
	Template *CSINodeDriverDaemonSetPodTemplateSpec `json:"template,omitempty"`
}
