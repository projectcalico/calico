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
	Version = "v1"
)

var DatastoreMigrationGVR = schema.GroupVersionResource{
	Group:    Group,
	Version:  Version,
	Resource: "datastoremigrations",
}

type DatastoreMigrationPhase string

const (
	DatastoreMigrationPhasePending   DatastoreMigrationPhase = "Pending"
	DatastoreMigrationPhaseMigrating DatastoreMigrationPhase = "Migrating"
	DatastoreMigrationPhaseConverged DatastoreMigrationPhase = "Converged"
	DatastoreMigrationPhaseComplete  DatastoreMigrationPhase = "Complete"
	DatastoreMigrationPhaseFailed    DatastoreMigrationPhase = "Failed"
)

type DatastoreMigrationType string

const (
	DatastoreMigrationTypeV1ToV3 DatastoreMigrationType = "V1ToV3"
)

// DatastoreMigration triggers and tracks the migration of Calico resources
// from crd.projectcalico.org/v1 CRDs to projectcalico.org/v3 CRDs.
type DatastoreMigration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DatastoreMigrationSpec   `json:"spec,omitempty"`
	Status DatastoreMigrationStatus `json:"status,omitempty"`
}

type DatastoreMigrationSpec struct {
	Type DatastoreMigrationType `json:"type"`
}

type DatastoreMigrationStatus struct {
	Phase       DatastoreMigrationPhase    `json:"phase,omitempty"`
	StartedAt   *metav1.Time               `json:"startedAt,omitempty"`
	CompletedAt *metav1.Time               `json:"completedAt,omitempty"`
	Progress    DatastoreMigrationProgress `json:"progress,omitempty"`
	Conditions  []metav1.Condition         `json:"conditions,omitempty"`
}

type DatastoreMigrationProgress struct {
	TotalTypes     int    `json:"totalTypes,omitempty"`
	CompletedTypes int    `json:"completedTypes,omitempty"`
	CurrentType    string `json:"currentType,omitempty"`

	Total     int `json:"total,omitempty"`
	Migrated  int `json:"migrated,omitempty"`
	Skipped   int `json:"skipped,omitempty"`
	Conflicts int `json:"conflicts,omitempty"`

	TypeDetails []TypeMigrationProgress `json:"typeDetails,omitempty"`
}

// TypeMigrationProgress tracks the result for a single resource type.
type TypeMigrationProgress struct {
	Kind      string `json:"kind"`
	Migrated  int    `json:"migrated,omitempty"`
	Skipped   int    `json:"skipped,omitempty"`
	Conflicts int    `json:"conflicts,omitempty"`
}
