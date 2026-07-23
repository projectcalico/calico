// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:name="ID",type=string,JSONPath=".spec.handleID",description="The handle ID"

// +k8s:openapi-gen=true
// +kubebuilder:resource:scope=Cluster
type IPAMHandle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              IPAMHandleSpec `json:"spec"`
}

// IPAMHandleSpec contains the specification for an IPAMHandle resource.
// This resource is managed internally by Calico IPAM and should not be modified manually.
type IPAMHandleSpec struct {
	// HandleID is the unique identifier for this allocation handle.
	HandleID string `json:"handleID"`

	// Block maps block CIDRs to the number of allocations from that block held by this handle.
	Block map[string]int `json:"block"`

	// Deleted is an internal flag used to prevent races during handle cleanup. Should not be set manually.
	// +optional
	Deleted bool `json:"deleted"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPAMHandleList contains a list of IPAMHandle resources.
type IPAMHandleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []IPAMHandle `json:"items"`
}
