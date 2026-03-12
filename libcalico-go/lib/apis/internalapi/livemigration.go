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
	// Source identifies the Workload or WorkloadEndpoint that this live migration operation is
	// moving from.
	Source *LiveMigrationSource

	// Target identifies the Workload or WorkloadEndpoint that this live migration operation is
	// moving to.
	Target *LiveMigrationTarget
}

// +kubebuilder:validation:ExactlyOneOf
type LiveMigrationSource struct {
	// Workload identifies the live migration source pod or VM in clusters where the
	// orchestrator uses a single LiveMigration object to describe all of that pod/VM's
	// interfaces.  This is what happens with KubeVirt.
	// +optional
	Workload *WorkloadIdentifier

	// WorkloadEndpoint identifies the live migration source WorkloadEndpoint in clusters where
	// the orchestrator uses different LiveMigration objects to describe each of a migrating
	// pod/VM's interfaces.  This is what happens with OpenStack.
	// +optional
	WorkloadEndpoint *WorkloadEndpointIdentifier
}

// +kubebuilder:validation:ExactlyOneOf
type LiveMigrationTarget struct {
	// Selector identifies the live migration target pod or VM in clusters where the
	// orchestrator uses a single LiveMigration object to describe all of that pod/VM's
	// interfaces.  This is what happens with KubeVirt.
	// +optional
	Selector *string

	// WorkloadEndpoint identifies the live migration target WorkloadEndpoint in clusters where
	// the orchestrator uses different LiveMigration objects to describe each of a migrating
	// pod/VM's interfaces.  This is what happens with OpenStack.
	// +optional
	WorkloadEndpoint *WorkloadEndpointIdentifier
}

// WorkloadIdentifier identifies a workload, i.e. a pod or VM, possibly with multiple interfaces.
// When OrchestratorID is "k8s" the Hostname field is ignored because a Kubernetes pod is already
// uniquely identified by WorkloadID.
type WorkloadIdentifier struct {
	Hostname       string
	OrchestratorID string
	WorkloadID     string
}

// WorkloadIdentifier identifies a workload endpoint, i.e. a specific pod or VM interface.  When
// OrchestratorID is "k8s" the Hostname field is ignored because a Kubernetes pod is already
// uniquely identified by WorkloadID.
type WorkloadEndpointIdentifier struct {
	Hostname       string
	OrchestratorID string
	WorkloadID     string
	EndpointID     string
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
