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

// Package managedfields owns a declared set of fields on Calico resources that
// users also modify, through server-side apply.
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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// FieldManager owns a declared set of fields on shared Calico configuration resources.
type FieldManager struct {
	client client.Client
}

// New returns a FieldManager that writes through the API group the client is configured for.
func New(c client.Client) *FieldManager {
	return &FieldManager{client: c}
}

// DeclareFn states which fields the caller owns, given the current object.
type DeclareFn[T client.Object] func(current T) (*Declaration, error)

// object constrains a declaration to a pointer type, so the write path can make one to read into.
type object[U any] interface {
	*U
	client.Object
}

// Apply writes the fields the declaration asks for on the governed resource, and returns the
// whole resulting object.
func (m *FieldManager) Apply[U any, T object[U]](ctx context.Context, declare DeclareFn[T]) (T, error) {
	// Read the object the declaration governs, so the caller can decide from its current state.
	current := T(new(U))
	if err := m.client.Get(ctx, types.NamespacedName{Name: defaultResourceName}, current); err != nil && !apierrors.IsNotFound(err) {
		var zero T
		return zero, fmt.Errorf("unable to read %T: %w", current, err)
	}
	return m.applyDeclared[U](ctx, current, declare)
}

// fieldManagerPrefix namespaces the operator's field managers away from other writers.
const fieldManagerPrefix = "operator.tigera.io/"

var log = logf.Log.WithName("managedfields")

// applyDeclared writes the declared fields, letting the API server track who owns each one.
func (m *FieldManager) applyDeclared[U any, T object[U]](ctx context.Context, current T, declare DeclareFn[T]) (T, error) {
	var zero T
	d, err := declare(current)
	if err != nil {
		return zero, err
	}
	if d == nil {
		return current, nil
	}
	if _, ok := d.Owned.(T); !ok {
		return zero, fmt.Errorf("a %T declaration cannot own %T", current, d.Owned)
	}

	gvk, err := apiutil.GVKForObject(current, m.client.Scheme())
	if err != nil {
		return zero, err
	}

	payload, err := declaredPayload(d.Owned, d.Policies)
	if err != nil {
		return zero, err
	}
	declared, err := declaresSpec(payload)
	if err != nil {
		return zero, err
	}
	if current.GetResourceVersion() == "" && !declared {
		// The declaration holds nothing to write, so don't create an empty object.
		return current, nil
	}

	// Fields an older operator wrote through update have to go before the apply, which cannot
	// drop a field it does not own.
	if err := m.clearLegacyOwned(ctx, current, gvk, d, payload); err != nil {
		return zero, err
	}

	var conflict error
	applied := T(new(U))
	if err := m.serverSideApply(ctx, gvk, payload, d.Manager, false, applied); err != nil {
		if !apierrors.IsConflict(err) {
			return zero, err
		}

		var force bool
		force, conflict = resolveConflicts(err, current, d, payload)
		var refused *ConflictingFieldsError
		if conflict != nil && !errors.As(conflict, &refused) {
			return zero, conflict
		}

		// A refused field is dropped from the payload rather than fought over, so the rest of
		// the declaration still lands. The caller degrades on the error it gets back.
		applied = T(new(U))
		if err := m.serverSideApply(ctx, gvk, payload, d.Manager, force, applied); err != nil {
			return zero, err
		}
	}

	if err := m.clearLegacyAnnotationTracking(ctx, applied, gvk); err != nil {
		// The declaration landed, so leftover records wait for a later reconcile rather
		// than failing this write.
		log.Error(err, "Unable to clear the field records an earlier operator left behind", "kind", kindOf(applied))
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
			// Agreeing on the value with another field manager doesn't mean we own the field.
			// Taking it here would delete the other writer's setting the moment the operator
			// stops declaring it.
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
	logResolution(current, d.Manager, deferred, forced)
	if len(refused) > 0 {
		sort.Strings(refused)
		return len(forced) > 0, &ConflictingFieldsError{Kind: kindOf(current), Paths: refused}
	}
	return len(forced) > 0, nil
}

// clearLegacyOwned deletes governed fields the operator's pre-apply field manager still holds and
// the declaration does not set. It takes its own request, because an apply cannot drop a field it
// does not own.
func (m *FieldManager) clearLegacyOwned(ctx context.Context, current client.Object, gvk schema.GroupVersionKind, d *Declaration, payload *unstructured.Unstructured) error {
	legacyOwned, err := legacyOwnedPaths(current)
	if err != nil || len(legacyOwned) == 0 {
		return err
	}

	remove := map[string]any{}
	for path := range d.Policies {
		set, err := pathSet(payload.Object, path)
		if err != nil {
			return err
		}
		if !legacyOwned[path] || set {
			continue
		}
		if err := unstructured.SetNestedField(remove, nil, strings.Split(path, ".")...); err != nil {
			return err
		}
	}
	if len(remove) == 0 {
		return nil
	}

	log.Info("Clearing shared configuration fields the operator no longer declares", "kind", kindOf(current), "manager", d.Manager, "fields", remove)
	return m.clearFields(ctx, gvk, remove)
}

// clearFields deletes the fields remove names, through a patch request. remove is an unstructured
// form of that request, with every field to clear set to nil.
func (m *FieldManager) clearFields(ctx context.Context, gvk schema.GroupVersionKind, remove map[string]any) error {
	encoded, err := json.Marshal(remove)
	if err != nil {
		return fmt.Errorf("unable to render the fields to clear: %w", err)
	}
	target := &unstructured.Unstructured{}
	target.SetGroupVersionKind(gvk)
	target.SetName(defaultResourceName)
	return m.client.Patch(ctx, target, client.RawPatch(types.MergePatchType, encoded))
}

// serverSideApply applies payload and reads the result back into out.
func (m *FieldManager) serverSideApply(ctx context.Context, gvk schema.GroupVersionKind, payload *unstructured.Unstructured, manager string, force bool, out client.Object) error {
	opts := []client.ApplyOption{client.FieldOwner(fieldManagerPrefix + manager)}
	if force {
		opts = append(opts, client.ForceOwnership)
	}

	applied := payload.DeepCopy()
	applied.SetGroupVersionKind(gvk)
	if err := m.client.Apply(ctx, client.ApplyConfigurationFromUnstructured(applied), opts...); err != nil {
		return err
	}

	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(applied.Object, out); err != nil {
		return fmt.Errorf("unable to read back the applied %s: %w", gvk.Kind, err)
	}
	return nil
}

// logResolution records what the write path did with fields it does not simply own. Reconciles
// that only rewrite the operator's own values say nothing, so the log carries the surprises.
func logResolution(obj client.Object, manager string, deferred, forced []string) {
	if len(deferred) == 0 && len(forced) == 0 {
		return
	}
	log.Info("Resolved shared configuration ownership",
		"kind", kindOf(obj),
		"manager", manager,
		"deferred", deferred,
		"forced", forced,
	)
}
