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
	v1 "k8s.io/api/core/v1"
)

// CalicoWindowsUpgradeDaemonSetContainer is a calico-windows-upgrade DaemonSet container.
type CalicoWindowsUpgradeDaemonSetContainer struct {
	// Name is an enum which identifies the calico-windows-upgrade DaemonSet container by name.
	// +kubebuilder:validation:Enum=calico-windows-upgrade
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named calico-windows-upgrade DaemonSet container's resources.
	// If omitted, the calico-windows-upgrade DaemonSet will use its default value for this container's resources.
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

// CalicoWindowsUpgradeDaemonSetPodSpec is the calico-windows-upgrade DaemonSet's PodSpec.
type CalicoWindowsUpgradeDaemonSetPodSpec struct {
	// Containers is a list of calico-windows-upgrade containers.
	// If specified, this overrides the specified calico-windows-upgrade DaemonSet containers.
	// If omitted, the calico-windows-upgrade DaemonSet will use its default values for its containers.
	// +optional
	Containers []CalicoWindowsUpgradeDaemonSetContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the calico-windows-upgrade pods.
	// If specified, this overrides any affinity that may be set on the calico-windows-upgrade DaemonSet.
	// If omitted, the calico-windows-upgrade DaemonSet will use its default value for affinity.
	// WARNING: Please note that this field will override the default calico-windows-upgrade DaemonSet affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity,omitempty"`

	// NodeSelector is the calico-windows-upgrade pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the calico-windows-upgrade DaemonSet nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the calico-windows-upgrade DaemonSet will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default calico-windows-upgrade DaemonSet nodeSelector.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations is the calico-windows-upgrade pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the calico-windows-upgrade DaemonSet.
	// If omitted, the calico-windows-upgrade DaemonSet will use its default value for tolerations.
	// WARNING: Please note that this field will override the default calico-windows-upgrade DaemonSet tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// CalicoWindowsUpgradeDaemonSetPodTemplateSpec is the calico-windows-upgrade DaemonSet's PodTemplateSpec
type CalicoWindowsUpgradeDaemonSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the calico-windows-upgrade DaemonSet's PodSpec.
	// +optional
	Spec *CalicoWindowsUpgradeDaemonSetPodSpec `json:"spec,omitempty"`
}

// Deprecated. The CalicoWindowsUpgradeDaemonSet is deprecated and will be removed from the API in the future.
// CalicoWindowsUpgradeDaemonSet is the configuration for the calico-windows-upgrade DaemonSet.
type CalicoWindowsUpgradeDaemonSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the calico-windows-upgrade DaemonSet.
	// +optional
	Spec *CalicoWindowsUpgradeDaemonSetSpec `json:"spec,omitempty"`
}

// CalicoWindowsUpgradeDaemonSetSpec defines configuration for the calico-windows-upgrade DaemonSet.
type CalicoWindowsUpgradeDaemonSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the calico-windows-upgrade DaemonSet.
	// If omitted, the calico-windows-upgrade DaemonSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the calico-windows-upgrade DaemonSet pod that will be created.
	// +optional
	Template *CalicoWindowsUpgradeDaemonSetPodTemplateSpec `json:"template,omitempty"`
}
