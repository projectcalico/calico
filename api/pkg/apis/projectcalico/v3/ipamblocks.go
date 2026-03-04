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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="CIDR",type=string,JSONPath=".spec.cidr",description="The block CIDR"
// +kubebuilder:printcolumn:name="Affinity",type=string,JSONPath=".spec.affinity",description="The block affinity"
// +kubebuilder:printcolumn:name="ClaimTime",type=date,JSONPath=".spec.affinityClaimTime",description="The time at which affinity was claimed"

// +k8s:openapi-gen=true
type IPAMBlock struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              IPAMBlockSpec `json:"spec"`
}

// IPAMBlockSpec contains the specification for an IPAMBlock resource.
type IPAMBlockSpec struct {
	// The block's CIDR.
	// +kubebuilder:validation:Format=cidr
	CIDR string `json:"cidr"`

	// Affinity of the block, if this block has one. If set, it will be of the form
	// "host:<hostname>" or "virtual:<hostname>". If not set, this block is not affine to a host.
	// +kubebuilder:validation:Pattern=`^(host|virtual):[a-zA-Z0-9\.\-_]+$`
	// +optional
	Affinity *string `json:"affinity,omitempty"`

	// Time at which affinity was claimed.
	// +optional
	AffinityClaimTime *metav1.Time `json:"affinityClaimTime,omitempty"`

	// Array of allocations in-use within this block. nil entries mean the allocation is free.
	// For non-nil entries at index i, the index is the ordinal of the allocation within this block
	// and the value is the index of the associated attributes in the Attributes array.
	Allocations []*int `json:"allocations"`

	// Unallocated is an ordered list of allocations which are free in the block.
	Unallocated []int `json:"unallocated"`

	// Attributes is an array of arbitrary metadata associated with allocations in the block. To find
	// attributes for a given allocation, use the value of the allocation's entry in the Allocations array
	// as the index of the element in this array.
	Attributes []AllocationAttribute `json:"attributes"`

	// We store a sequence number that is updated each time the block is written.
	// Each allocation will also store the sequence number of the block at the time of its creation.
	// When releasing an IP, passing the sequence number associated with the allocation allows us
	// to protect against a race condition and ensure the IP hasn't been released and re-allocated
	// since the release request.
	//
	// +kubebuilder:default=0
	// +optional
	SequenceNumber uint64 `json:"sequenceNumber"`

	// Map of allocated ordinal within the block to sequence number of the block at
	// the time of allocation. Kubernetes does not allow numerical keys for maps, so
	// the key is cast to a string.
	// +optional
	SequenceNumberForAllocation map[string]uint64 `json:"sequenceNumberForAllocation"`

	// Deleted is an internal boolean used to workaround a limitation in the Kubernetes API whereby
	// deletion will not return a conflict error if the block has been updated. It should not be set manually.
	// +optional
	Deleted bool `json:"deleted"`

	// StrictAffinity on the IPAMBlock is deprecated and no longer used by the code. Use IPAMConfig StrictAffinity instead.
	DeprecatedStrictAffinity bool `json:"strictAffinity"`
}

type AllocationAttribute struct {
	HandleID            *string           `json:"handle_id,omitempty"`
	ActiveOwnerAttrs    map[string]string `json:"secondary,omitempty"`
	AlternateOwnerAttrs map[string]string `json:"alternate,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPAMBlockList contains a list of IPAMBlock resources.
type IPAMBlockList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []IPAMBlock `json:"items"`
}
