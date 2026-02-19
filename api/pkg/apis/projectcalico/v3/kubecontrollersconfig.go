// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindKubeControllersConfiguration     = "KubeControllersConfiguration"
	KindKubeControllersConfigurationList = "KubeControllersConfigurationList"
)

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster

// KubeControllersConfigurationList contains a list of KubeControllersConfiguration object.
type KubeControllersConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

	Items []KubeControllersConfiguration `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster,shortName={kcc,kccs}
// +kubebuilder:subresource:status

type KubeControllersConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

	Spec KubeControllersConfigurationSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`

	// +optional
	Status KubeControllersConfigurationStatus `json:"status" protobuf:"bytes,3,opt,name=status"`
}

// ControllerMode is used to enable or disable a controller.
// +kubebuilder:validation:Enum=Disabled;Enabled
type ControllerMode string

const (
	ControllerDisabled ControllerMode = "Disabled"
	ControllerEnabled  ControllerMode = "Enabled"
)

// KubeControllersConfigurationSpec contains the values of the Kubernetes controllers configuration.
type KubeControllersConfigurationSpec struct {
	// LogSeverityScreen is the log severity above which logs are sent to the stdout. [Default: Info]
	// Valid values are: "None", "Debug", "Info", "Warning", "Error", "Fatal", "Panic".
	// +kubebuilder:validation:Enum=None;Debug;Info;Warning;Error;Fatal;Panic
	LogSeverityScreen string `json:"logSeverityScreen,omitempty" validate:"omitempty,logLevel"`

	// HealthChecks enables or disables support for health checks [Default: Enabled]
	// Valid values are: "Enabled", "Disabled".
	// +kubebuilder:validation:Enum=Enabled;Disabled
	// +kubebuilder:default=Enabled
	HealthChecks string `json:"healthChecks,omitempty" validate:"omitempty,oneof=Enabled Disabled"`

	// EtcdV3CompactionPeriod is the period between etcdv3 compaction requests. Set to 0 to disable. [Default: 10m]
	EtcdV3CompactionPeriod *metav1.Duration `json:"etcdV3CompactionPeriod,omitempty" validate:"omitempty"`

	// PrometheusMetricsPort is the TCP port that the Prometheus metrics server should bind to. Set to 0 to disable. [Default: 9094]
	// Valid values are: 0-65535.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	PrometheusMetricsPort *int `json:"prometheusMetricsPort,omitempty"`

	// Controllers enables and configures individual Kubernetes controllers
	Controllers ControllersConfig `json:"controllers"`

	// DebugProfilePort configures the port to serve memory and cpu profiles on. If not specified, profiling
	// is disabled.
	// Valid values are: 0-65535.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +optional
	DebugProfilePort *int32 `json:"debugProfilePort,omitempty"`
}

// ControllersConfig enables and configures individual Kubernetes controllers
type ControllersConfig struct {
	// Node enables and configures the node controller. Enabled by default, set to nil to disable.
	Node *NodeControllerConfig `json:"node,omitempty"`

	// Policy enables and configures the policy controller. Enabled by default, set to nil to disable.
	Policy *PolicyControllerConfig `json:"policy,omitempty"`

	// WorkloadEndpoint enables and configures the workload endpoint controller. Enabled by default, set to nil to disable.
	WorkloadEndpoint *WorkloadEndpointControllerConfig `json:"workloadEndpoint,omitempty"`

	// ServiceAccount enables and configures the service account controller. Enabled by default, set to nil to disable.
	ServiceAccount *ServiceAccountControllerConfig `json:"serviceAccount,omitempty"`

	// Namespace enables and configures the namespace controller. Enabled by default, set to nil to disable.
	Namespace *NamespaceControllerConfig `json:"namespace,omitempty"`

	// LoadBalancer enables and configures the LoadBalancer controller. Enabled by default, set to nil to disable.
	LoadBalancer *LoadBalancerControllerConfig `json:"loadBalancer,omitempty"`

	// Migration enables and configures migration controllers.
	Migration *MigrationControllerConfig `json:"policyMigration,omitempty"`
}

type MigrationControllerConfig struct {
	// PolicyNameMigrator enables or disables the Policy Name Migrator, which migrates
	// old-style Calico backend policy names to use v3 style names.
	// +kubebuilder:default=Enabled
	PolicyNameMigrator ControllerMode `json:"enabled,omitempty" validate:"omitempty,oneof=Enabled Disabled"`
}

// NodeControllerConfig configures the node controller, which automatically cleans up configuration
// for nodes that no longer exist. Optionally, it can create host endpoints for all Kubernetes nodes.
type NodeControllerConfig struct {
	// ReconcilerPeriod is the period to perform reconciliation with the Calico datastore. [Default: 5m]
	ReconcilerPeriod *metav1.Duration `json:"reconcilerPeriod,omitempty" validate:"omitempty"`

	// SyncLabels controls whether to copy Kubernetes node labels to Calico nodes. [Default: Enabled]
	// Valid values are: "Enabled", "Disabled".
	// +kubebuilder:validation:Enum=Enabled;Disabled
	SyncLabels string `json:"syncLabels,omitempty" validate:"omitempty,oneof=Enabled Disabled"`

	// HostEndpoint controls syncing nodes to host endpoints. Disabled by default, set to nil to disable.
	HostEndpoint *AutoHostEndpointConfig `json:"hostEndpoint,omitempty"`

	// LeakGracePeriod is the period used by the controller to determine if an IP address has been leaked.
	// Set to 0 to disable IP garbage collection. [Default: 15m]
	// +optional
	LeakGracePeriod *metav1.Duration `json:"leakGracePeriod,omitempty"`
}

type AutoHostEndpointConfig struct {
	// AutoCreate enables automatic creation of host endpoints for every node. [Default: Disabled]
	// Valid values are: "Enabled", "Disabled".
	// +kubebuilder:validation:Enum=Enabled;Disabled
	AutoCreate string `json:"autoCreate,omitempty" validate:"omitempty,oneof=Enabled Disabled"`

	CreateDefaultHostEndpoint DefaultHostEndpointMode `json:"createDefaultHostEndpoint,omitempty" validate:"omitempty,createDefaultHostEndpoint"`

	// Templates contains definition for creating AutoHostEndpoints
	Templates []Template `json:"templates,omitempty" validate:"omitempty"`
}

// DefaultHostEndpointMode controls whether a default host endpoint is created for each node.
// Valid values are: "Enabled", "Disabled".
type DefaultHostEndpointMode string

const (
	DefaultHostEndpointsEnabled  DefaultHostEndpointMode = "Enabled"
	DefaultHostEndpointsDisabled DefaultHostEndpointMode = "Disabled"
)

type Template struct {
	// GenerateName is appended to the end of the generated AutoHostEndpoint name
	// +kubebuilder:validation:MaxLength=253
	GenerateName string `json:"generateName,omitempty" validate:"omitempty,name"`

	// InterfaceCIDRs contains a list of CIDRs used for matching nodeIPs to the AutoHostEndpoint.
	// If specified, only addresses within these CIDRs will be included in the expected IPs.
	// At least one of InterfaceCIDRs and InterfacePattern must be specified.
	// +listType=set
	InterfaceCIDRs []string `json:"interfaceCIDRs,omitempty" validate:"cidrs"`

	// InterfacePattern contains a regex string to match Node interface names. If specified, a HostEndpoint will be created for each matching interface on each selected node.
	// At least one of InterfaceCIDRs and InterfacePattern must be specified.
	InterfacePattern string `json:"interfacePattern,omitempty" validate:"omitempty,regexp"`

	// Labels adds the specified labels to the generated AutoHostEndpoint, labels from node with the same name will be overwritten by values from the template label
	Labels map[string]string `json:"labels,omitempty" validate:"omitempty,labels"`

	// NodeSelector allows the AutoHostEndpoint to be created only for specific nodes
	NodeSelector string `json:"nodeSelector,omitempty" validate:"omitempty,selector"`
}

// PolicyControllerConfig configures the network policy controller, which syncs Kubernetes policies
// to Calico policies (only used for etcdv3 datastore).
type PolicyControllerConfig struct {
	// ReconcilerPeriod is the period to perform reconciliation with the Calico datastore. [Default: 5m]
	ReconcilerPeriod *metav1.Duration `json:"reconcilerPeriod,omitempty" validate:"omitempty"`
}

// WorkloadEndpointControllerConfig configures the workload endpoint controller, which syncs Kubernetes
// labels to Calico workload endpoints (only used for etcdv3 datastore).
type WorkloadEndpointControllerConfig struct {
	// ReconcilerPeriod is the period to perform reconciliation with the Calico datastore. [Default: 5m]
	ReconcilerPeriod *metav1.Duration `json:"reconcilerPeriod,omitempty" validate:"omitempty"`
}

// ServiceAccountControllerConfig configures the service account controller, which syncs Kubernetes
// service accounts to Calico profiles (only used for etcdv3 datastore).
type ServiceAccountControllerConfig struct {
	// ReconcilerPeriod is the period to perform reconciliation with the Calico datastore. [Default: 5m]
	ReconcilerPeriod *metav1.Duration `json:"reconcilerPeriod,omitempty" validate:"omitempty"`
}

// NamespaceControllerConfig configures the service account controller, which syncs Kubernetes
// service accounts to Calico profiles (only used for etcdv3 datastore).
type NamespaceControllerConfig struct {
	// ReconcilerPeriod is the period to perform reconciliation with the Calico datastore. [Default: 5m]
	ReconcilerPeriod *metav1.Duration `json:"reconcilerPeriod,omitempty" validate:"omitempty"`
}

type LoadBalancerControllerConfig struct {
	// AssignIPs controls which LoadBalancer Service gets IP assigned from Calico IPAM.
	// +kubebuilder:default=AllServices
	AssignIPs AssignIPs `json:"assignIPs,omitempty" validate:"omitempty,assignIPs"`
}

// +kubebuilder:validation:Enum=AllServices;RequestedServicesOnly
type AssignIPs string

const (
	AllServices           AssignIPs = "AllServices"
	RequestedServicesOnly AssignIPs = "RequestedServicesOnly"
)

// KubeControllersConfigurationStatus represents the status of the configuration. It's useful for admins to
// be able to see the actual config that was applied, which can be modified by environment variables on the
// kube-controllers process.
type KubeControllersConfigurationStatus struct {
	// RunningConfig contains the effective config that is running in the kube-controllers pod, after
	// merging the API resource with any environment variables.
	// +optional
	RunningConfig *KubeControllersConfigurationSpec `json:"runningConfig,omitempty"`

	// EnvironmentVars contains the environment variables on the kube-controllers that influenced
	// the RunningConfig.
	EnvironmentVars map[string]string `json:"environmentVars,omitempty"`
}

// New KubeControllersConfiguration creates a new (zeroed) KubeControllersConfiguration struct with
// the TypeMetadata initialized to the current version.
func NewKubeControllersConfiguration() *KubeControllersConfiguration {
	return &KubeControllersConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindKubeControllersConfiguration,
			APIVersion: GroupVersionCurrent,
		},
	}
}
