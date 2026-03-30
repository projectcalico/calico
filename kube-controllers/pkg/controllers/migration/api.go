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

package migration

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	Group   = "migration.projectcalico.org"
	Version = "v1beta1"
)

var DatastoreMigrationGVR = schema.GroupVersionResource{
	Group:    Group,
	Version:  Version,
	Resource: "datastoremigrations",
}

// DatastoreMigrationPhase represents the current state of a datastore migration.
type DatastoreMigrationPhase string

const (
	// DatastoreMigrationPhasePending indicates the migration CR has been created but
	// prerequisites have not yet been validated and migration has not started.
	DatastoreMigrationPhasePending DatastoreMigrationPhase = "Pending"

	// DatastoreMigrationPhaseMigrating indicates the controller is actively copying
	// resources from v1 CRDs to v3 CRDs. The datastore is locked (DatastoreReady=false)
	// during this phase.
	DatastoreMigrationPhaseMigrating DatastoreMigrationPhase = "Migrating"

	// DatastoreMigrationPhaseWaitingForConflictResolution indicates the migration
	// encountered resource conflicts (v3 resources exist with different content).
	// The datastore remains locked (DatastoreReady=false) in this phase. The
	// controller periodically re-checks and transitions back to Migrating once
	// all conflicts are resolved.
	DatastoreMigrationPhaseWaitingForConflictResolution DatastoreMigrationPhase = "WaitingForConflictResolution"

	// DatastoreMigrationPhaseConverged indicates all resources have been migrated
	// successfully with no conflicts and the datastore has been unlocked.
	DatastoreMigrationPhaseConverged DatastoreMigrationPhase = "Converged"

	// DatastoreMigrationPhaseComplete indicates the migration is fully finished.
	// Deleting the CR in this phase triggers cleanup of v1 CRDs.
	DatastoreMigrationPhaseComplete DatastoreMigrationPhase = "Complete"

	// DatastoreMigrationPhaseFailed indicates the migration encountered an
	// unrecoverable error. The CR must be deleted (triggering rollback) and
	// recreated to retry.
	DatastoreMigrationPhaseFailed DatastoreMigrationPhase = "Failed"
)

// DatastoreMigrationType identifies the type of migration to perform.
// +kubebuilder:validation:Enum=APIServerToCRDs
type DatastoreMigrationType string

const (
	// DatastoreMigrationTypeAPIServerToCRDs migrates resources from the aggregated
	// API server (crd.projectcalico.org/v1) to native CRDs (projectcalico.org/v3).
	DatastoreMigrationTypeAPIServerToCRDs DatastoreMigrationType = "APIServerToCRDs"
)

// DatastoreMigration triggers and tracks the migration of Calico resources
// from crd.projectcalico.org/v1 CRDs to projectcalico.org/v3 CRDs.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Types",type=string,JSONPath=`.status.progress.typeProgress`
// +kubebuilder:printcolumn:name="Message",type=string,JSONPath=`.status.message`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Current Type",type=string,JSONPath=`.status.progress.currentType`,priority=1
// +kubebuilder:printcolumn:name="Migrated",type=integer,JSONPath=`.status.progress.migrated`,priority=1
// +kubebuilder:printcolumn:name="Skipped",type=integer,JSONPath=`.status.progress.skipped`,priority=1
// +kubebuilder:printcolumn:name="Conflicts",type=integer,JSONPath=`.status.progress.conflicts`,priority=1
type DatastoreMigration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired migration behavior.
	Spec DatastoreMigrationSpec `json:"spec"`
	// Status reports the observed state of the migration.
	Status DatastoreMigrationStatus `json:"status"`
}

// DatastoreMigrationList contains a list of DatastoreMigration resources.
//
// +kubebuilder:object:root=true
type DatastoreMigrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DatastoreMigration `json:"items"`
}

// DatastoreMigrationSpec defines the desired migration behavior. Rollback is
// triggered by deleting the CR while in a non-Complete phase; the finalizer
// handles cleanup and APIService restoration.
type DatastoreMigrationSpec struct {
	// Type specifies the migration to perform (e.g., APIServerToCRDs).
	// +kubebuilder:validation:Required
	Type DatastoreMigrationType `json:"type"`
}

// DatastoreMigrationStatus reports the observed state of the migration.
type DatastoreMigrationStatus struct {
	// Phase is the current phase of the migration state machine.
	Phase DatastoreMigrationPhase `json:"phase,omitempty"`
	// Message is a human-readable status message describing what the controller
	// is currently doing or waiting on.
	Message string `json:"message,omitempty"`
	// StartedAt is the timestamp when the migration transitioned to Migrating.
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// CompletedAt is the timestamp when the migration transitioned to Complete.
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
	// Progress tracks per-type and aggregate migration counters.
	Progress DatastoreMigrationProgress `json:"progress,omitempty"`
	// Conditions report conflicts and errors encountered during migration.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DatastoreMigrationProgress tracks aggregate and per-type migration counters.
type DatastoreMigrationProgress struct {
	// TotalTypes is the number of resource types to migrate.
	TotalTypes int `json:"totalTypes,omitempty"`
	// CompletedTypes is the number of resource types that have been fully processed.
	CompletedTypes int `json:"completedTypes,omitempty"`
	// TypeProgress is a human-readable summary like "5 / 21" for printer columns.
	TypeProgress string `json:"typeProgress,omitempty"`
	// CurrentType is the resource kind currently being migrated, or empty if done.
	CurrentType string `json:"currentType,omitempty"`

	// Total is the total number of resources processed across all types.
	Total int `json:"total,omitempty"`
	// Migrated is the number of resources successfully copied to v3.
	Migrated int `json:"migrated,omitempty"`
	// Skipped is the number of resources that already existed in v3 with matching content.
	Skipped int `json:"skipped,omitempty"`
	// Conflicts is the number of resources that existed in v3 with different content.
	Conflicts int `json:"conflicts,omitempty"`

	// TypeDetails contains per-resource-type migration results.
	TypeDetails []TypeMigrationProgress `json:"typeDetails,omitempty"`
}

// TypeMigrationProgress tracks the migration result for a single resource kind.
type TypeMigrationProgress struct {
	// Kind is the Calico resource kind (e.g., "NetworkPolicy", "GlobalNetworkPolicy").
	Kind string `json:"kind"`
	// Migrated is the number of resources of this kind successfully copied to v3.
	Migrated int `json:"migrated,omitempty"`
	// Skipped is the number of resources of this kind that already existed in v3 with matching content.
	Skipped int `json:"skipped,omitempty"`
	// Conflicts is the number of resources of this kind that existed in v3 with different content.
	Conflicts int `json:"conflicts,omitempty"`
}
