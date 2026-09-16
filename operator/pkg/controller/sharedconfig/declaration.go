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

package sharedconfig

import (
	"fmt"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// ConflictPolicy resolves a field that both the operator and someone else set.
type ConflictPolicy string

const (
	// ConflictError reports the conflict to the caller, which should degrade.
	ConflictError ConflictPolicy = "Error"

	// ConflictDefer leaves the other writer's value in place.
	ConflictDefer ConflictPolicy = "Defer"

	// ConflictOverride takes the field back and writes the operator's value.
	ConflictOverride ConflictPolicy = "Override"
)

// FelixConfigurationDeclaration is one field manager's statement of what it owns.
type FelixConfigurationDeclaration struct {
	// Manager is the field manager name, and has to stay the same across reconciles.
	Manager string

	// Owned carries the declared fields and nothing else. Fields left nil are not owned.
	Owned *v3.FelixConfiguration

	// Policies is keyed by field path, e.g. "spec.healthPort". Every declared field needs an entry.
	Policies map[string]ConflictPolicy
}

// policyFor returns the policy governing path, which may name a field below a declared one.
func (d *FelixConfigurationDeclaration) policyFor(path string) (string, ConflictPolicy, bool) {
	best := ""
	for declared := range d.Policies {
		if path != declared && !strings.HasPrefix(path, declared+".") {
			continue
		}
		if len(declared) > len(best) {
			best = declared
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, d.Policies[best], true
}

// ConflictingFieldsError reports fields the operator declares that someone else owns.
type ConflictingFieldsError struct {
	Paths []string
}

func (e *ConflictingFieldsError) Error() string {
	return fmt.Sprintf("FelixConfiguration fields modified outside the operator: %s", strings.Join(e.Paths, ", "))
}
