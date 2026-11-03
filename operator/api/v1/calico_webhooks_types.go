// Copyright (c) 2026-2026 Tigera, Inc. All rights reserved.
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

// CalicoWebhooksDeploymentContainer is a calico-webhooks Deployment container.
type CalicoWebhooksDeploymentContainer struct {
	// Name is an enum which identifies the calico-webhooks Deployment container by name.
	// Supported values are: calico-webhooks
	// +kubebuilder:validation:Enum=calico-webhooks
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named calico-webhooks Deployment container's resources.
	// If omitted, the calico-webhooks Deployment will use its default value for this container's resources.
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

	// Ports allows customization of the calico-webhooks container's ports.
	// If specified, this overrides the default container port configuration.
	// If omitted, the calico-webhooks Deployment will use its default port (6443).
	// +optional
	Ports []CalicoWebhooksDeploymentContainerPort `json:"ports,omitempty"`
}

// CalicoWebhooksDeploymentContainerPort defines a port override for a calico-webhooks container.
type CalicoWebhooksDeploymentContainerPort struct {
	// Name is an enum which identifies the calico-webhooks Deployment container port by name.
	// Supported values are: calico-webhooks
	// +kubebuilder:validation:Enum=calico-webhooks
	Name string `json:"name"`

	// Number of port to expose on the pod's IP address.
	// This must be a valid port number, 0 < x < 65536.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	ContainerPort int32 `json:"containerPort"`
}

// CalicoWebhooksDeploymentPodSpec is the calico-webhooks Deployment's PodSpec.
type CalicoWebhooksDeploymentPodSpec struct {
	// Containers is a list of calico-webhooks containers.
	// If specified, this overrides the specified calico-webhooks Deployment containers.
	// If omitted, the calico-webhooks Deployment will use its default values for its containers.
	// +optional
	Containers []CalicoWebhooksDeploymentContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the calico-webhooks pods.
	// If specified, this overrides any affinity that may be set on the calico-webhooks Deployment.
	// If omitted, the calico-webhooks Deployment will use its default value for affinity.
	// WARNING: Please note that this field will override the default calico-webhooks Deployment affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// NodeSelector is the calico-webhooks pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the calico-webhooks Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If used in conjunction with ControlPlaneNodeSelector, that nodeSelector is set on the calico-webhooks Deployment
	// and each of this field's key/value pairs are added to the calico-webhooks Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the calico-webhooks Deployment will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default calico-webhooks Deployment nodeSelector.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations is the calico-webhooks pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the calico-webhooks Deployment.
	// If omitted, the calico-webhooks Deployment will use its default value for tolerations.
	// WARNING: Please note that this field will override the default calico-webhooks Deployment tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`

	// HostNetwork forces the webhook pod to use the host's network namespace.
	// When true, the webhook pod will run with hostNetwork=true and DNSPolicy=ClusterFirstWithHostNet.
	// When nil or omitted, the operator auto-detects whether host networking is required
	// (e.g., for EKS/TKG with Calico CNI).
	// +optional
	HostNetwork *bool `json:"hostNetwork,omitempty"`
}

// CalicoWebhooksDeploymentPodTemplateSpec is the calico-webhooks Deployment's PodTemplateSpec
type CalicoWebhooksDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the calico-webhooks Deployment's PodSpec.
	// +optional
	Spec *CalicoWebhooksDeploymentPodSpec `json:"spec,omitempty"`
}

// CalicoWebhooksDeployment is the configuration for the calico-webhooks Deployment.
type CalicoWebhooksDeployment struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the calico-webhooks Deployment.
	// +optional
	Spec *CalicoWebhooksDeploymentSpec `json:"spec,omitempty"`
}

// CalicoWebhooksDeploymentSpec defines configuration for the calico-webhooks Deployment.
type CalicoWebhooksDeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the calico-webhooks Deployment.
	// If omitted, the calico-webhooks Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the calico-webhooks Deployment pod that will be created.
	// +optional
	Template *CalicoWebhooksDeploymentPodTemplateSpec `json:"template,omitempty"`
}
