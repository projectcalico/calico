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
	"context"
	"errors"
	"reflect"
	"sort"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/controller/utils"
)

// ownedFieldsAnnotation records the values the operator last wrote, so it can spot changes by others.
const ownedFieldsAnnotation = "operator.tigera.io/owned-fields"

// bpfEnabledPath is tracked by its own legacy annotation, which predates ownedFieldsAnnotation.
const bpfEnabledPath = "spec.bpfEnabled"

// applyCRDV1 writes through crd.projectcalico.org/v1, the API group used in aggregated apiserver
// mode, where the operator tracks its own fields.
func (m *FieldManager) applyCRDV1(ctx context.Context, current client.Object, declare declareFn) (client.Object, error) {
	if err := utils.RestoreV3Metadata(current); err != nil {
		return nil, err
	}

	// Diff against the restored object, so the patch leaves the v3 metadata stash alone.
	patchFrom := client.MergeFrom(current.DeepCopyObject().(client.Object))

	d, err := declare(current)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return current, nil
	}

	payload, err := declaredPayload(d.Owned, d.Policies)
	if err != nil {
		return nil, err
	}

	// Fields the operator's pre-apply manager still owns are its own, whether or not it kept a
	// record of writing them.
	legacyOwned, _, err := updateOwnedPaths(current)
	if err != nil {
		return nil, err
	}
	deferred, conflict := resolveTrackedConflicts(current, d, payload, legacyOwned)
	var refused *ConflictingFieldsError
	if conflict != nil && !errors.As(conflict, &refused) {
		return nil, conflict
	}

	merged := current.DeepCopyObject().(client.Object)
	if err := mergeInto(merged, payload); err != nil {
		return nil, err
	}
	removed, dropped, err := removeUndeclared(merged, current, d, payload, legacyOwned)
	if err != nil {
		return nil, err
	}
	conflict = joinConflicts(current, conflict, dropped)
	if err := recordWrittenValues(merged, payload, d, append(deferred, removed...)); err != nil {
		return nil, err
	}
	if equality.Semantic.DeepEqual(current, merged) {
		return current, conflict
	}
	if current.GetResourceVersion() == "" && !declaresSpec(payload) {
		// The declaration holds nothing to write, so don't create an object carrying only a record.
		return current, conflict
	}

	logResolution(current, d.Manager, deferred, removed, nil)
	persisted, err := m.persist(ctx, merged, patchFrom)
	if err != nil {
		return nil, err
	}
	return persisted, conflict
}

// resolveTrackedConflicts drops deferred fields from payload and returns the paths it dropped.
func resolveTrackedConflicts(current client.Object, d *Declaration, payload *unstructured.Unstructured, legacyOwned map[string]bool) ([]string, error) {
	currentContent, err := toUnstructured(current)
	if err != nil {
		return nil, err
	}
	lastWritten, err := lastWrittenValues(current)
	if err != nil {
		return nil, err
	}

	var deferred, refused []string
	for path := range d.Policies {
		if !pathSet(payload.Object, path) {
			continue
		}
		changed, err := changedByOther(currentContent, lastWritten, legacyOwned, path)
		if err != nil {
			return nil, err
		}
		if !changed {
			continue
		}

		switch d.Policies[path] {
		case ConflictDefer:
			// Agreeing on the value is not ownership. Recording it here would delete the other
			// writer's setting the moment the operator stops declaring it.
			removePath(payload.Object, path)
			deferred = append(deferred, path)
		case ConflictOverride:
		default:
			// Writing the value that is already there needs no arbitration, whoever put it there.
			agree, err := valuesAgree(currentContent, payload.Object, path)
			if err != nil {
				return nil, err
			}
			if !agree {
				// Leave the other writer's value alone and let the caller report it.
				removePath(payload.Object, path)
				refused = append(refused, path)
			}
		}
	}

	if len(refused) > 0 {
		sort.Strings(refused)
		return deferred, &ConflictingFieldsError{Kind: kindOf(current), Paths: refused}
	}
	return deferred, nil
}

// joinConflicts folds newly refused paths into an existing refusal, or reports them on their own.
func joinConflicts(current client.Object, conflict error, paths []string) error {
	if len(paths) == 0 {
		return conflict
	}
	var refused *ConflictingFieldsError
	if errors.As(conflict, &refused) {
		refused.Paths = append(refused.Paths, paths...)
		sort.Strings(refused.Paths)
		return refused
	}
	sort.Strings(paths)
	return &ConflictingFieldsError{Kind: kindOf(current), Paths: paths}
}

// removeUndeclared deletes governed fields the declaration left out, matching the way a sole
// apply owner drops them.
func removeUndeclared(merged, current client.Object, d *Declaration, payload *unstructured.Unstructured, legacyOwned map[string]bool) (remove, refused []string, err error) {
	currentContent, err := toUnstructured(current)
	if err != nil {
		return nil, nil, err
	}
	lastWritten, err := lastWrittenValues(current)
	if err != nil {
		return nil, nil, err
	}

	for path := range d.Policies {
		if pathSet(payload.Object, path) || !pathSet(currentContent, path) {
			continue
		}
		if _, recorded := lastWritten[path]; !recorded && !legacyOwned[path] {
			// The operator has no sign of writing this, so it belongs to someone else.
			continue
		}
		changed, err := changedByOther(currentContent, lastWritten, legacyOwned, path)
		if err != nil {
			return nil, nil, err
		}
		if changed {
			switch d.Policies[path] {
			case ConflictDefer:
				continue
			case ConflictOverride:
			default:
				refused = append(refused, path)
				continue
			}
		}
		remove = append(remove, path)
	}

	return remove, refused, deletePaths(merged, remove)
}

// deletePaths clears the named fields on obj.
func deletePaths(obj client.Object, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	content, err := toUnstructured(obj)
	if err != nil {
		return err
	}
	for _, path := range paths {
		removePath(content, path)
	}
	return runtime.DefaultUnstructuredConverter.FromUnstructured(content, obj)
}

// kindOf names a governed resource for error messages.
func kindOf(obj client.Object) string {
	t := reflect.TypeOf(obj)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Name()
}

func (m *FieldManager) persist(ctx context.Context, obj client.Object, patchFrom client.Patch) (client.Object, error) {
	if obj.GetResourceVersion() == "" {
		obj.SetName(defaultResourceName)
		if err := m.client.Create(ctx, obj); err != nil {
			return nil, err
		}
		return obj, nil
	}
	if err := m.client.Patch(ctx, obj, patchFrom); err != nil {
		return nil, err
	}
	return obj, nil
}
