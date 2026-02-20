// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package internalapi

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	KindLiveMigration     = "LiveMigration"
	KindLiveMigrationList = "LiveMigrationList"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LiveMigration describes a live-migration operation in progress. It is
// orchestrator-independent and holds the fields that Calico needs for
// optimal live migration processing.
type LiveMigration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              LiveMigrationSpec `json:"spec"`
}

// LiveMigrationSpec contains the specification for a LiveMigration resource.
type LiveMigrationSpec struct {
	// Source identifies the WorkloadEndpoint that this live migration operation is moving from.
	Source *types.NamespacedName

	// Destination identifies the WorkloadEndpoint that this live migration operation is moving
	// to.
	Destination *WorkloadEndpointIdentifier
}

// +kubebuilder:validation:ExactlyOneOf
type WorkloadEndpointIdentifier struct {
	// NamespacedName is used when the WorkloadEndpoint can be identified directly by its
	// name and namespace.
	// +optional
	NamespacedName *types.NamespacedName

	// Selector is used when the WorkloadEndpoint must be identified by a selector expression.
	// +optional
	Selector *string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LiveMigrationList contains a list of LiveMigration resources.
type LiveMigrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []LiveMigration `json:"items"`
}

// NewLiveMigration creates a new (zeroed) LiveMigration struct with the
// TypeMetadata initialised to the current version.
func NewLiveMigration() *LiveMigration {
	return &LiveMigration{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindLiveMigration,
			APIVersion: apiv3.GroupVersionCurrent,
		},
	}
}

// NewLiveMigrationList creates a new (zeroed) LiveMigrationList struct with the
// TypeMetadata initialised to the current version.
func NewLiveMigrationList() *LiveMigrationList {
	return &LiveMigrationList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindLiveMigrationList,
			APIVersion: apiv3.GroupVersionCurrent,
		},
	}
}
