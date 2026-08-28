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
	v1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MonitorSpec defines the desired state of Tigera monitor.
type MonitorSpec struct {
	// ExternalPrometheus optionally configures integration with an external Prometheus for scraping Calico metrics. When
	// specified, the operator will render resources in the defined namespace. This option can be useful for configuring
	// scraping from git-ops tools without the need of post-installation steps.
	ExternalPrometheus *ExternalPrometheus `json:"externalPrometheus,omitempty"`

	// Prometheus is the configuration for the Prometheus.
	// +optional
	Prometheus *Prometheus `json:"prometheus,omitempty"`

	// Alertmanager is the configuration for the Alertmanager.
	// +optional
	Alertmanager *Alertmanager `json:"alertManager,omitempty"`
}

type ExternalPrometheus struct {
	// ServiceMonitor when specified, the operator will create a ServiceMonitor object in the namespace. It is recommended
	// that you configure labels if you want your prometheus instance to pick up the configuration automatically.
	// The operator will configure 1 endpoint by default:
	// - Params to scrape all metrics available in Calico Enterprise.
	// - BearerTokenSecret (If not overridden, the operator will also create corresponding RBAC that allows authz to the metrics.)
	// - TLSConfig, containing the caFile and serverName.
	// +optional
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor,omitempty"`

	// Namespace is the namespace where the operator will create resources for your Prometheus instance. The namespace
	// must be created before the operator will create Prometheus resources.
	// +required
	Namespace string `json:"namespace"`
}

type ServiceMonitor struct {
	// Labels are the metadata.labels of the ServiceMonitor. When combined with spec.serviceMonitorSelector.matchLabels
	// on your prometheus instance, the service monitor will automatically be picked up.
	// Default: k8s-app=tigera-prometheus
	Labels map[string]string `json:"labels,omitempty"`

	// The endpoints to scrape. This struct contains a subset of the Endpoint as defined in the prometheus docs. Fields
	// related to connecting to our Prometheus server are automatically set by the operator.
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

// Endpoint contains a subset of relevant fields from the Prometheus Endpoint struct.
type Endpoint struct {
	// Optional HTTP URL parameters
	// Default: scrape all metrics.
	Params map[string][]string `json:"params,omitempty"`

	// Secret to mount to read bearer token for scraping targets.
	// Recommended: when unset, the operator will create a Secret, a ClusterRole and a ClusterRoleBinding.
	BearerTokenSecret corev1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`

	// Interval at which metrics should be scraped.
	// If not specified Prometheus' global scrape interval is used.
	Interval v1.Duration `json:"interval,omitempty"`

	// Timeout after which the scrape is ended.
	// If not specified, the Prometheus global scrape timeout is used unless it is less than `Interval` in which the latter is used.
	ScrapeTimeout v1.Duration `json:"scrapeTimeout,omitempty"`

	// HonorLabels chooses the metric's labels on collisions with target labels.
	HonorLabels bool `json:"honorLabels,omitempty"`

	// HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
	HonorTimestamps *bool `json:"honorTimestamps,omitempty"`

	// MetricRelabelConfigs to apply to samples before ingestion.
	MetricRelabelConfigs []v1.RelabelConfig `json:"metricRelabelings,omitempty"`

	// RelabelConfigs to apply to samples before scraping.
	// Prometheus Operator automatically adds relabelings for a few standard Kubernetes fields.
	// The original scrape job's name is available via the `__tmp_prometheus_job_name` label.
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []v1.RelabelConfig `json:"relabelings,omitempty"`
}

// MonitorStatus defines the observed state of Tigera monitor.
type MonitorStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status

// Monitor is the Schema for the monitor API. At most one instance
// of this resource is supported. It must be named "tigera-secure".
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'",message="resource name must be 'tigera-secure'"
type Monitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MonitorSpec   `json:"spec,omitempty"`
	Status MonitorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MonitorList contains a list of Monitor
type MonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Monitor `json:"items"`
}

type Prometheus struct {
	// Spec is the specification of the Prometheus.
	// +optional
	PrometheusSpec *PrometheusSpec `json:"spec,omitempty"`
}
type PrometheusSpec struct {
	// CommonPrometheusFields are the options available to both the Prometheus server and agent.
	CommonPrometheusFields *CommonPrometheusFields `json:"commonPrometheusFields,omitempty"`
}
type CommonPrometheusFields struct {
	// Containers is a list of Prometheus containers.
	// If specified, this overrides the specified Prometheus Deployment containers.
	// If omitted, the Prometheus Deployment will use its default values for its containers.
	// +optional
	Containers []PrometheusContainer `json:"containers,omitempty"`

	// Define resources requests and limits for single Pods.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// PrometheusContainer is a Prometheus container.
type PrometheusContainer struct {
	// Name is an enum which identifies the Prometheus Deployment container by name.
	// Supported values are: authn-proxy
	// +kubebuilder:validation:Enum=authn-proxy
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Prometheus container's resources.
	// If omitted, the Prometheus will use its default value for this container's resources.
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

type Alertmanager struct {
	// Spec is the specification of the Alertmanager.
	// +optional
	AlertmanagerSpec *AlertmanagerSpec `json:"spec,omitempty"`
}
type AlertmanagerSpec struct {
	// Replicas defines the number of Alertmanager replicas. When set to 0, Alertmanager is not rendered.
	// Default: 0
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// Define resources requests and limits for single Pods.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *Prometheus) GetContainers() []corev1.Container {
	if c.PrometheusSpec != nil {
		if c.PrometheusSpec.CommonPrometheusFields != nil {
			if c.PrometheusSpec.CommonPrometheusFields.Containers != nil {
				cs := make([]corev1.Container, len(c.PrometheusSpec.CommonPrometheusFields.Containers))
				for i, v := range c.PrometheusSpec.CommonPrometheusFields.Containers {
					// Only copy and return the init container if it has resources set.
					if v.Resources == nil {
						continue
					}
					c := corev1.Container{Name: v.Name, Resources: *v.Resources}
					cs[i] = c
				}
				return cs
			}
		}
	}

	return nil
}

func (c *Prometheus) GetPrometheusResource() *corev1.ResourceRequirements {
	if c.PrometheusSpec != nil {
		if c.PrometheusSpec.CommonPrometheusFields != nil {
			return &c.PrometheusSpec.CommonPrometheusFields.Resources
		}
	}
	return nil
}

func init() {
	SchemeBuilder.Register(&Monitor{}, &MonitorList{})
}
