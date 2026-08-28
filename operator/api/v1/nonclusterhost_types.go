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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NonClusterHostSpec enables non-cluster hosts to connect to a cluster.
type NonClusterHostSpec struct {
	// Location of the log ingestion point for non-cluster hosts. For example: https://1.2.3.4:443
	// +kubebuilder:validation:Pattern=`^https://.+$`
	Endpoint string `json:"endpoint"`

	// Location of the Typha endpoint for non-cluster host Felix and Typha communication. For example: 5.6.7.8:5473
	TyphaEndpoint string `json:"typhaEndpoint,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// NonClusterHost installs the components required for non-cluster host log collection.
// At most one instance of this resource is supported. It must be named "tigera-secure".
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'",message="resource name must be 'tigera-secure'"
type NonClusterHost struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for non-cluster host log collection.
	Spec NonClusterHostSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// NonClusterHostList contains a list of NonClusterHost
type NonClusterHostList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NonClusterHost `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NonClusterHost{}, &NonClusterHostList{})
}
