// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
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

// ElasticsearchMetricsDeployment is the configuration for the tigera-elasticsearch-metric Deployment.
type ElasticsearchMetricsDeployment struct {

	// Spec is the specification of the ElasticsearchMetrics Deployment.
	// +optional
	Spec *ElasticsearchMetricsDeploymentSpec `json:"spec,omitempty"`
}

// ElasticsearchMetricsDeploymentSpec defines configuration for the ElasticsearchMetricsDeployment Deployment.
type ElasticsearchMetricsDeploymentSpec struct {

	// Template describes the ElasticsearchMetrics Deployment pod that will be created.
	// +optional
	Template *ElasticsearchMetricsDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// ElasticsearchMetricsDeploymentPodTemplateSpec is the ElasticsearchMetricsDeployment's PodTemplateSpec
type ElasticsearchMetricsDeploymentPodTemplateSpec struct {

	// Spec is the ElasticsearchMetrics Deployment's PodSpec.
	// +optional
	Spec *ElasticsearchMetricsDeploymentPodSpec `json:"spec,omitempty"`
}

// ElasticsearchMetricsDeploymentPodSpec is the tElasticsearchMetricsDeployment's PodSpec.
type ElasticsearchMetricsDeploymentPodSpec struct {
	// InitContainers is a list of ElasticsearchMetricsDeployment init containers.
	// If specified, this overrides the specified ElasticsearchMetricsDeployment init containers.
	// If omitted, the ElasticsearchMetrics Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ElasticsearchMetricsDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of ElasticsearchMetricsDeployment containers.
	// If specified, this overrides the specified ElasticsearchMetricsDeployment containers.
	// If omitted, the ElasticsearchMetrics Deployment will use its default values for its containers.
	// +optional
	Containers []ElasticsearchMetricsDeploymentContainer `json:"containers,omitempty"`
}

// ElasticsearchMetricsDeploymentContainer is a ElasticsearchMetricsDeployment container.
type ElasticsearchMetricsDeploymentContainer struct {
	// Name is an enum which identifies the ElasticsearchMetricsDeployment container by name.
	// Supported values are: tigera-elasticsearch-metrics
	// +kubebuilder:validation:Enum=tigera-elasticsearch-metrics
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ElasticsearchMetricsDeployment container's resources.
	// If omitted, the ElasticsearchMetrics Deployment will use its default value for this container's resources.
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

// ElasticsearchMetricsDeploymentInitContainer is a ElasticsearchMetricsDeployment init container.
type ElasticsearchMetricsDeploymentInitContainer struct {
	// Name is an enum which identifies the ElasticsearchMetricsDeployment init container by name.
	// Supported values are: tigera-ee-elasticsearch-metrics-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-ee-elasticsearch-metrics-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ElasticsearchMetricsDeployment init container's resources.
	// If omitted, the ElasticsearchMetrics Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
