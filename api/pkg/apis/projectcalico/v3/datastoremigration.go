// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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
	KindDatastoreMigration     = "DatastoreMigration"
	KindDatastoreMigrationList = "DatastoreMigrationList"
)

// DatastoreMigrationPhase represents the current phase of a datastore migration.
type DatastoreMigrationPhase string

const (
	DatastoreMigrationPhasePending   DatastoreMigrationPhase = "Pending"
	DatastoreMigrationPhaseMigrating DatastoreMigrationPhase = "Migrating"
	DatastoreMigrationPhaseConverged DatastoreMigrationPhase = "Converged"
	DatastoreMigrationPhaseComplete  DatastoreMigrationPhase = "Complete"
	DatastoreMigrationPhaseFailed    DatastoreMigrationPhase = "Failed"
)

// DatastoreMigrationType represents the type of migration to perform.
type DatastoreMigrationType string

const (
	DatastoreMigrationTypeV1ToV3 DatastoreMigrationType = "V1ToV3"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Total",type="integer",JSONPath=".status.progress.total"
// +kubebuilder:printcolumn:name="Migrated",type="integer",JSONPath=".status.progress.migrated"
// +kubebuilder:printcolumn:name="Conflicts",type="integer",JSONPath=".status.progress.conflicts"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// DatastoreMigration triggers and tracks the migration of Calico resources
// from crd.projectcalico.org/v1 CRDs to projectcalico.org/v3 CRDs.
type DatastoreMigration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   DatastoreMigrationSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status DatastoreMigrationStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// DatastoreMigrationSpec contains the desired state for the migration.
type DatastoreMigrationSpec struct {
	// Type is the direction of migration. Only V1ToV3 is supported.
	// +kubebuilder:validation:Enum=V1ToV3
	Type DatastoreMigrationType `json:"type" protobuf:"bytes,1,opt,name=type"`
}

// DatastoreMigrationStatus contains the observed state of the migration.
type DatastoreMigrationStatus struct {
	// Phase is the current phase of the migration.
	Phase DatastoreMigrationPhase `json:"phase,omitempty" protobuf:"bytes,1,opt,name=phase"`

	// StartedAt is the time the migration started.
	StartedAt *metav1.Time `json:"startedAt,omitempty" protobuf:"bytes,2,opt,name=startedAt"`

	// CompletedAt is the time the migration completed.
	CompletedAt *metav1.Time `json:"completedAt,omitempty" protobuf:"bytes,3,opt,name=completedAt"`

	// Progress tracks the overall migration progress.
	Progress DatastoreMigrationProgress `json:"progress,omitempty" protobuf:"bytes,4,opt,name=progress"`

	// Conditions represent the latest available observations of the migration's state.
	Conditions []metav1.Condition `json:"conditions,omitempty" protobuf:"bytes,5,rep,name=conditions"`
}

// DatastoreMigrationProgress tracks the number of resources migrated.
type DatastoreMigrationProgress struct {
	// Total is the total number of v1 resources found.
	Total int `json:"total,omitempty" protobuf:"varint,1,opt,name=total"`

	// Migrated is the number of resources successfully migrated to v3.
	Migrated int `json:"migrated,omitempty" protobuf:"varint,2,opt,name=migrated"`

	// Skipped is the number of resources skipped (already exist with matching spec).
	Skipped int `json:"skipped,omitempty" protobuf:"varint,3,opt,name=skipped"`

	// Conflicts is the number of resources with spec mismatches.
	Conflicts int `json:"conflicts,omitempty" protobuf:"varint,4,opt,name=conflicts"`
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DatastoreMigrationList contains a list of DatastoreMigration resources.
type DatastoreMigrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []DatastoreMigration `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// NewDatastoreMigration creates a new (zeroed) DatastoreMigration struct with the TypeMetadata
// initialized to the current version.
func NewDatastoreMigration() *DatastoreMigration {
	return &DatastoreMigration{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindDatastoreMigration,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// NewDatastoreMigrationList creates a new (zeroed) DatastoreMigrationList struct with the
// TypeMetadata initialized to the current version.
func NewDatastoreMigrationList() *DatastoreMigrationList {
	return &DatastoreMigrationList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindDatastoreMigrationList,
			APIVersion: GroupVersionCurrent,
		},
	}
}
