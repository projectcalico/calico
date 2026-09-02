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

// Package datastoremigration provides utilities for checking DatastoreMigration
// CR state from the operator's controllers.
package datastoremigration

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Phase constants for DatastoreMigration status.
const (
	PhasePending                      = "Pending"
	PhaseMigrating                    = "Migrating"
	PhaseWaitingForConflictResolution = "WaitingForConflictResolution"
	PhaseConverged                    = "Converged"
	PhaseComplete                     = "Complete"
	PhaseFailed                       = "Failed"
)

// get fetches the first DatastoreMigration CR and returns its phase and
// whether it exists. Returns ("", false) if no CR exists.
func get(c client.Client) (string, bool) {
	if c == nil {
		return "", false
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(ServedVersion().WithKind(ListKind))
	if err := c.List(context.Background(), list, client.Limit(1)); err != nil {
		log.V(1).Info("Failed to list DatastoreMigrations", "error", err)
		return "", false
	}
	if len(list.Items) == 0 {
		return "", false
	}

	phase, _, err := unstructured.NestedString(list.Items[0].Object, "status", "phase")
	if err != nil {
		log.V(1).Info("DatastoreMigration has a malformed phase", "error", err)
		return "", true
	}
	return phase, true
}

// GetPhase returns the phase of the first DatastoreMigration CR, or empty
// string if none exists or the CRD is not installed.
func GetPhase(c client.Client) string {
	phase, _ := get(c)
	return phase
}

// Exists returns true if at least one DatastoreMigration CR exists.
func Exists(c client.Client) bool {
	_, exists := get(c)
	return exists
}
