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

// Metadata contains the standard Kubernetes labels and annotations fields.
type Metadata struct {
	// Labels is a map of string keys and values that may match replicaset and
	// service selectors. Each of these key/value pairs are added to the
	// object's labels provided the key does not already exist in the object's labels.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations is a map of arbitrary non-identifying metadata. Each of these
	// key/value pairs are added to the object's annotations provided the key does not
	// already exist in the object's annotations.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// +kubebuilder:validation:Enum=Error;Warning;Info;Debug
type LogLevel string

const (
	LogLevelError LogLevel = "Error"
	LogLevelWarn  LogLevel = "Warn"
	LogLevelInfo  LogLevel = "Info"
	LogLevelDebug LogLevel = "Debug"
)

// +kubebuilder:validation:Enum=Fatal;Error;Warn;Info;Debug;Trace
type LogSeverity string

const (
	LogSeverityFatal LogSeverity = "Fatal"
	LogSeverityError LogSeverity = "Error"
	LogSeverityWarn  LogSeverity = "Warn"
	LogSeverityInfo  LogSeverity = "Info"
	LogSeverityDebug LogSeverity = "Debug"
	LogSeverityTrace LogSeverity = "Trace"
)

// +kubebuilder:validation:Enum=Reconcile;PreferExisting
type CRDManagement string

const (
	CRDManagementReconcile      CRDManagement = "Reconcile"
	CRDManagementPreferExisting CRDManagement = "PreferExisting"
)

// NamespacedName references an object of a known type in any namespace.
type NamespacedName struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// NetworkPolicySpec configures how the operator manages the NetworkPolicies it installs.
type NetworkPolicySpec struct {
	// ManagePolicies controls whether the operator creates and reconciles the NetworkPolicies and
	// GlobalNetworkPolicies it uses to protect the Calico components it installs. When set to
	// Disabled, the operator stops creating or updating these policies and deletes any it has
	// already created, leaving policy management to the user. Defaults to Enabled.
	// +kubebuilder:default=Enabled
	// +optional
	ManagePolicies *NetworkPolicyManagement `json:"managePolicies,omitempty"`
}

// NetworkPolicyManagement specifies whether the operator manages the NetworkPolicies it installs to
// protect the Calico components it manages.
// +kubebuilder:validation:Enum=Enabled;Disabled
type NetworkPolicyManagement string

const (
	NetworkPolicyManagementEnabled  NetworkPolicyManagement = "Enabled"
	NetworkPolicyManagementDisabled NetworkPolicyManagement = "Disabled"
)
