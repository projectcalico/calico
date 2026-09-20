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

package managedfields

import (
	"bytes"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"
)

// legacyFieldManager is what the API server derives from the /usr/bin/operator user agent,
// so it records the operator's pre-apply writes.
const legacyFieldManager = "operator"

// reclaimablePaths lists fields a plain update owns that the operator wrote itself.
// An apply must force ownership across once.
func reclaimablePaths(obj client.Object, manager string) (map[string]bool, error) {
	reclaimable, _, err := updateOwnedPaths(obj)
	if err != nil || appliedBy(obj, manager) {
		return reclaimable, err
	}

	// Ownership also moves on a plain update, and on another manager's apply, so fall back to the
	// values the operator recorded.
	lastWritten, err := lastWrittenValues(obj)
	if err != nil || len(lastWritten) == 0 {
		return reclaimable, err
	}
	content, err := toUnstructured(obj)
	if err != nil {
		return nil, err
	}
	for path := range lastWritten {
		if reclaimable[path] {
			continue
		}

		// Legacy ownership is beside the point here: these paths belong to another manager.
		changed, err := changedByOther(content, lastWritten, nil, path)
		if err != nil {
			return nil, err
		}
		if !changed {
			reclaimable[path] = true
		}
	}
	return reclaimable, nil
}

// appliedBy reports whether manager has already applied to fc. The operator's records only speak
// for the writes that came before its first apply, so they stop counting once it has one.
func appliedBy(obj client.Object, manager string) bool {
	for _, entry := range obj.GetManagedFields() {
		if entry.Operation == metav1.ManagedFieldsOperationApply && entry.Manager == manager {
			return true
		}
	}
	return false
}

// updateOwnedPaths splits the fields owned through a plain update by whether the operator's own
// legacy field manager holds them.
func updateOwnedPaths(obj client.Object) (legacy, others map[string]bool, err error) {
	legacy, others = map[string]bool{}, map[string]bool{}
	for _, entry := range obj.GetManagedFields() {
		if entry.Operation != metav1.ManagedFieldsOperationUpdate || entry.FieldsV1 == nil {
			continue
		}
		owned := &fieldpath.Set{}
		if err := owned.FromJSON(bytes.NewReader(entry.FieldsV1.GetRawBytes())); err != nil {
			return nil, nil, fmt.Errorf("unable to parse the fields managed by %q: %w", entry.Manager, err)
		}

		out := others
		if entry.Manager == legacyFieldManager {
			out = legacy
		}
		owned.Iterate(func(p fieldpath.Path) {
			if path, ok := dottedPath(p); ok {
				out[path] = true
			}
		})
	}
	return legacy, others, nil
}

// dottedPath renders a field path as "spec.field". Ownership of a single list item has no such
// form, and no declaration governs a list item by item, so those paths are reported as unusable.
func dottedPath(p fieldpath.Path) (string, bool) {
	names := make([]string, 0, len(p))
	for _, element := range p {
		if element.FieldName == nil {
			return "", false
		}
		names = append(names, *element.FieldName)
	}
	return strings.Join(names, "."), true
}
