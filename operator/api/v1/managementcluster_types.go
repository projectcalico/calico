// Copyright (c) 2012,2015-2026 Tigera, Inc. All rights reserved.
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ManagementClusterSpec defines the desired state of a ManagementCluster
type ManagementClusterSpec struct {
	// This field specifies the externally reachable address to which your managed cluster will connect. When a managed
	// cluster is added, this field is used to populate an easy-to-apply manifest that will connect both clusters.
	// Valid examples are: "0.0.0.0:31000", "example.com:32000", "[::1]:32500"
	// +optional
	Address string `json:"address,omitempty"`

	// TLS provides options for configuring how Managed Clusters can establish an mTLS connection with the Management Cluster.
	// +optional
	TLS *TLS `json:"tls,omitempty"`
}

type TLS struct {
	// SecretName indicates the name of the secret in the tigera-operator namespace that contains the private key and certificate that the management cluster uses when it listens for incoming connections.
	//
	// When set to calico-management-cluster-connection voltron will use the same cert bundle which Guardian client certs are signed with.
	//
	// When set to manager-tls, voltron will use the same cert bundle which Manager UI is served with.
	// This cert bundle must be a publicly signed cert created by the user.
	// Note that Tigera Operator will generate a self-signed manager-tls cert if one does not exist,
	// and use of that cert will result in Guardian being unable to verify Voltron's identity.
	//
	// If changed on a running cluster with connected managed clusters, all managed clusters will disconnect as they will no longer be able to verify Voltron's identity.
	// To reconnect existing managed clusters, change the tls.ca of the  managed clusters' ManagementClusterConnection resource.
	//
	// One of: calico-management-cluster-connection, manager-tls, tigera-management-cluster-connection (deprecated)
	//
	// Default: calico-management-cluster-connection
	//
	// +kubebuilder:validation:Enum=calico-management-cluster-connection;manager-tls;tigera-management-cluster-connection
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// The presence of ManagementCluster in your cluster, will configure it to be the management plane to which managed
// clusters can connect. At most one instance of this resource is supported. It must be named "tigera-secure".
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'",message="resource name must be 'tigera-secure'"
type ManagementCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ManagementClusterSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ManagementClusterList contains a list of ManagementCluster
type ManagementClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManagementCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ManagementCluster{}, &ManagementClusterList{})
}
