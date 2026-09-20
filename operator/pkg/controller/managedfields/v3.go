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
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// fieldManagerPrefix namespaces the operator's field managers away from other writers.
const fieldManagerPrefix = "tigera-operator/"

// applyV3 writes through projectcalico.org/v3, where the API server tracks the operator's fields.
func (m *FieldManager) applyV3(ctx context.Context, current client.Object, declare declareFn) (client.Object, error) {
	d, err := declare(current)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return current, nil
	}

	gvk, err := apiutil.GVKForObject(current, m.client.Scheme())
	if err != nil {
		return nil, err
	}

	payload, err := declaredPayload(d.Owned, d.Policies)
	if err != nil {
		return nil, err
	}
	if current.GetResourceVersion() == "" && !declaresSpec(payload) {
		// The declaration holds nothing to write, so don't create an empty object.
		return current, nil
	}
	if err := m.clearLegacyOwned(ctx, current, gvk, d, payload); err != nil {
		return nil, err
	}

	applied, err := m.serverSideApply(ctx, gvk, payload, d.Manager, false)
	if err == nil {
		return applied, nil
	}
	if !apierrors.IsConflict(err) {
		return nil, err
	}

	force, conflict := resolveConflicts(err, current, d, payload)
	var refused *ConflictingFieldsError
	if conflict != nil && !errors.As(conflict, &refused) {
		return nil, conflict
	}

	// A refused field is dropped from the payload rather than fought over, so the rest of the
	// declaration still lands. The caller degrades on the error it gets back.
	applied, err = m.serverSideApply(ctx, gvk, payload, d.Manager, force)
	if err != nil {
		return nil, err
	}
	return applied, conflict
}

// resolveConflicts drops deferred fields from payload and reports whether the retry must force.
func resolveConflicts(applyErr error, current client.Object, d *Declaration, payload *unstructured.Unstructured) (bool, error) {
	paths := conflictPaths(applyErr)
	if len(paths) == 0 {
		return false, applyErr
	}

	currentContent, err := toUnstructured(current)
	if err != nil {
		return false, err
	}
	reclaimable, err := reclaimablePaths(current, fieldManagerPrefix+d.Manager)
	if err != nil {
		return false, err
	}

	var undeclared, refused, deferred, forced []string
	for _, path := range paths {
		declared, policy, ok := d.policyFor(path)
		if !ok {
			undeclared = append(undeclared, path)
			continue
		}
		if reclaimable[declared] || reclaimable[path] {
			// The operator wrote this before it applied, so take the field rather than arbitrate.
			forced = append(forced, declared)
			continue
		}

		switch policy {
		case ConflictDefer:
			// Agreeing on the value is not ownership. Taking the field here would delete the
			// other writer's setting the moment the operator stops declaring it.
			removePath(payload.Object, declared)
			deferred = append(deferred, declared)
		case ConflictOverride:
			forced = append(forced, declared)
		default:
			agree, err := valuesAgree(currentContent, payload.Object, declared)
			if err != nil {
				return false, err
			}
			if agree {
				// Both writers want the same value, so there is nothing to arbitrate.
				forced = append(forced, declared)
			} else {
				// Leave the other writer's value alone and let the caller report it.
				removePath(payload.Object, declared)
				refused = append(refused, declared)
			}
		}
	}

	if len(undeclared) > 0 {
		return false, fmt.Errorf("conflict on fields with no declared policy %v: %w", undeclared, applyErr)
	}
	logResolution(current, d.Manager, deferred, nil, forced)
	if len(refused) > 0 {
		sort.Strings(refused)
		return len(forced) > 0, &ConflictingFieldsError{Kind: kindOf(current), Paths: refused}
	}
	return len(forced) > 0, nil
}

// clearLegacyOwned deletes governed fields the operator's pre-apply field manager still holds and
// the declaration does not set. An apply cannot drop a field it does not own.
func (m *FieldManager) clearLegacyOwned(ctx context.Context, current client.Object, gvk schema.GroupVersionKind, d *Declaration, payload *unstructured.Unstructured) error {
	legacyOwned, _, err := updateOwnedPaths(current)
	if err != nil || len(legacyOwned) == 0 {
		return err
	}

	remove := map[string]any{}
	for path := range d.Policies {
		if !legacyOwned[path] || pathSet(payload.Object, path) {
			continue
		}
		if err := unstructured.SetNestedField(remove, nil, strings.Split(path, ".")...); err != nil {
			return err
		}
	}
	if len(remove) == 0 {
		return nil
	}

	encoded, err := json.Marshal(remove)
	if err != nil {
		return fmt.Errorf("unable to render the fields to clear: %w", err)
	}
	log.Info("Clearing shared configuration fields the operator no longer declares", "kind", kindOf(current), "manager", d.Manager, "fields", string(encoded))
	target := &unstructured.Unstructured{}
	target.SetGroupVersionKind(gvk)
	target.SetName(defaultResourceName)
	return m.client.Patch(ctx, target, client.RawPatch(types.MergePatchType, encoded))
}

func (m *FieldManager) serverSideApply(ctx context.Context, gvk schema.GroupVersionKind, payload *unstructured.Unstructured, manager string, force bool) (client.Object, error) {
	opts := []client.ApplyOption{client.FieldOwner(fieldManagerPrefix + manager)}
	if force {
		opts = append(opts, client.ForceOwnership)
	}

	applied := payload.DeepCopy()
	applied.SetGroupVersionKind(gvk)
	if err := m.client.Apply(ctx, client.ApplyConfigurationFromUnstructured(applied), opts...); err != nil {
		return nil, err
	}

	out, err := m.client.Scheme().New(gvk)
	if err != nil {
		return nil, err
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(applied.Object, out); err != nil {
		return nil, fmt.Errorf("unable to read back the applied %s: %w", gvk.Kind, err)
	}
	return out.(client.Object), nil
}
