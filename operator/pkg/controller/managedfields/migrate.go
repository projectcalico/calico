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

// The operator wrote these fields through plain updates before it applied them, and this file is
// what recognizes that. All of it goes away once upgrades from those versions are out of support.

package managedfields

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"

	"github.com/projectcalico/calico/operator/pkg/render"
)

// ownedFieldsAnnotation records the values an operator that wrote through update left behind.
const ownedFieldsAnnotation = "operator.tigera.io/owned-fields"

// bpfEnabledPath was tracked by its own annotation, which predates ownedFieldsAnnotation.
const bpfEnabledPath = "spec.bpfEnabled"

// lastWrittenValues reads back the values an older operator recorded, from when it wrote through
// update instead of apply.
func lastWrittenValues(obj client.Object) (map[string]any, error) {
	annotations := obj.GetAnnotations()
	values := map[string]any{}
	if raw := annotations[ownedFieldsAnnotation]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, fmt.Errorf("unable to parse %s annotation: %w", ownedFieldsAnnotation, err)
		}
	}

	// Clusters last written by an older operator only have the legacy annotation.
	if _, ok := values[bpfEnabledPath]; !ok {
		if raw := annotations[render.BPFOperatorAnnotation]; raw != "" {
			enabled, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, fmt.Errorf("unable to parse %s annotation: %w", render.BPFOperatorAnnotation, err)
			}
			values[bpfEnabledPath] = enabled
		}
	}
	return values, nil
}

// changedByOther reports whether path holds a value the operator did not write. Fields the
// operator wrote before it kept records are still its own, marked by its pre-apply field manager.
func changedByOther(currentContent map[string]any, lastWritten map[string]any, legacyOwned map[string]bool, path string) (bool, error) {
	current, found, err := unstructured.NestedFieldNoCopy(currentContent, strings.Split(path, ".")...)
	if err != nil {
		return false, fmt.Errorf("unable to read %s: %w", path, err)
	}
	if !found {
		return false, nil
	}

	written, recorded := lastWritten[path]
	if !recorded {
		return !legacyOwned[path], nil
	}
	canonical, err := canonicalize(current)
	if err != nil {
		return false, err
	}
	return !reflect.DeepEqual(canonical, written), nil
}

// canonicalize renders a value the way it will read back out of the annotation.
func canonicalize(value any) (any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("unable to encode field value: %w", err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unable to decode field value: %w", err)
	}
	return decoded, nil
}

// legacyFieldManager is what the API server derives from the /usr/bin/operator user agent, so it
// is what managed fields show for the fields older operators set.
const legacyFieldManager = "operator"

// reclaimablePaths lists the fields the operator wrote itself through a plain update. The first
// apply forces ownership of those across to its own field manager.
func reclaimablePaths(obj client.Object, manager string) (map[string]bool, error) {
	reclaimable, err := legacyOwnedPaths(obj)
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

// legacyOwnedPaths lists the fields the operator's pre-apply field manager holds.
func legacyOwnedPaths(obj client.Object) (map[string]bool, error) {
	return ownedPaths(obj, func(entry metav1.ManagedFieldsEntry) bool {
		return entry.Operation == metav1.ManagedFieldsOperationUpdate && entry.Manager == legacyFieldManager
	})
}

// ownedPaths lists the fields held by the managed-fields entries want selects.
func ownedPaths(obj client.Object, want func(metav1.ManagedFieldsEntry) bool) (map[string]bool, error) {
	paths := map[string]bool{}
	for _, entry := range obj.GetManagedFields() {
		if entry.FieldsV1 == nil || !want(entry) {
			continue
		}
		owned := &fieldpath.Set{}
		if err := owned.FromJSON(bytes.NewReader(entry.FieldsV1.GetRawBytes())); err != nil {
			return nil, fmt.Errorf("unable to parse the fields managed by %q: %w", entry.Manager, err)
		}
		owned.Iterate(func(p fieldpath.Path) {
			if path, ok := dottedPath(p); ok {
				paths[path] = true
			}
		})
	}
	return paths, nil
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

// clearSpentRecords deletes the annotations an operator that wrote through update left behind,
// once no declared field still needs them. Their values freeze at the upgrade, so anyone who
// finds them later reads them as current.
func (m *FieldManager) clearSpentRecords(ctx context.Context, obj client.Object, gvk schema.GroupVersionKind) error {
	annotations := obj.GetAnnotations()
	_, recordPresent := annotations[ownedFieldsAnnotation]
	_, legacyPresent := annotations[render.BPFOperatorAnnotation]
	if !recordPresent && !legacyPresent {
		return nil
	}

	recorded, err := lastWrittenValues(obj)
	if err != nil {
		return err
	}
	content, err := toUnstructured(obj)
	if err != nil {
		return err
	}
	applied, err := operatorAppliedPaths(obj)
	if err != nil {
		return err
	}
	for path := range recorded {
		if applied[path] {
			continue
		}
		changed, err := changedByOther(content, recorded, nil, path)
		if err != nil {
			return err
		}
		if !changed {
			// The record still speaks for this field, so a manager that has not applied yet
			// can use it to reclaim the field.
			return nil
		}
	}

	log.Info("Clearing the field records an earlier operator left behind", "kind", kindOf(obj))
	return m.clearFields(ctx, gvk, map[string]any{"metadata": map[string]any{"annotations": map[string]any{
		ownedFieldsAnnotation:        nil,
		render.BPFOperatorAnnotation: nil,
	}}})
}

// operatorAppliedPaths lists the fields the operator's own field managers hold through an apply.
func operatorAppliedPaths(obj client.Object) (map[string]bool, error) {
	return ownedPaths(obj, func(entry metav1.ManagedFieldsEntry) bool {
		return entry.Operation == metav1.ManagedFieldsOperationApply && strings.HasPrefix(entry.Manager, fieldManagerPrefix)
	})
}
