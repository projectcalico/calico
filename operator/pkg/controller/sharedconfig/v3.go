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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/projectcalico/calico/operator/pkg/controller/utils"
)

// fieldManagerPrefix namespaces the operator's field managers away from other writers.
const fieldManagerPrefix = "tigera-operator/"

// v3Writer writes through projectcalico.org/v3, where the API server tracks the operator's fields.
type v3Writer struct {
	crdV1Writer
}

var _ Writer = &v3Writer{}

func (w *v3Writer) ApplyFelixConfiguration(ctx context.Context, declare DeclareFelixConfiguration) (*v3.FelixConfiguration, error) {
	current, err := utils.GetFelixConfiguration(ctx, w.client)
	if err != nil {
		return nil, err
	}

	declaration, err := declare(current)
	if err != nil {
		return nil, err
	}
	if declaration == nil {
		return current, nil
	}

	payload, err := declaredPayload(declaration.Owned, declaration.Policies)
	if err != nil {
		return nil, err
	}
	if err := w.clearLegacyOwned(ctx, current, declaration, payload); err != nil {
		return nil, err
	}

	applied, err := w.apply(ctx, payload, declaration.Manager, false)
	if err == nil {
		return applied, nil
	}
	if !apierrors.IsConflict(err) {
		return nil, err
	}

	force, err := w.resolveConflicts(err, current, declaration, payload)
	if err != nil {
		return nil, err
	}
	return w.apply(ctx, payload, declaration.Manager, force)
}

// resolveConflicts drops deferred fields from payload and reports whether the retry must force.
func (w *v3Writer) resolveConflicts(applyErr error, current *v3.FelixConfiguration, d *FelixConfigurationDeclaration, payload *unstructured.Unstructured) (bool, error) {
	paths := conflictPaths(applyErr)
	if len(paths) == 0 {
		return false, applyErr
	}

	currentContent, err := runtime.DefaultUnstructuredConverter.ToUnstructured(current)
	if err != nil {
		return false, fmt.Errorf("unable to read FelixConfiguration fields: %w", err)
	}
	reclaimable, err := reclaimablePaths(current, fieldManagerPrefix+d.Manager)
	if err != nil {
		return false, err
	}

	force := false
	var undeclared, refused []string
	for _, path := range paths {
		declared, policy, ok := d.policyFor(path)
		if !ok {
			undeclared = append(undeclared, path)
			continue
		}
		// An apply conflicts on ownership, not on value. Taking a field that already holds the
		// declared value changes nothing, so there is nothing to arbitrate.
		agree, err := valuesAgree(currentContent, payload.Object, declared)
		if err != nil {
			return false, err
		}
		if agree {
			force = true
			continue
		}
		if reclaimable[declared] || reclaimable[path] {
			// The operator wrote this before it applied, so take the field rather than arbitrate.
			force = true
			continue
		}
		switch policy {
		case ConflictDefer:
			removePath(payload.Object, declared)
		case ConflictOverride:
			force = true
		default:
			refused = append(refused, declared)
		}
	}

	if len(undeclared) > 0 {
		return false, fmt.Errorf("conflict on fields with no declared policy %v: %w", undeclared, applyErr)
	}
	if len(refused) > 0 {
		return false, &ConflictingFieldsError{Paths: refused}
	}
	return force, nil
}

// clearLegacyOwned deletes governed fields the operator's pre-apply field manager still holds and
// the declaration does not set. An apply cannot drop a field it does not own.
func (w *v3Writer) clearLegacyOwned(ctx context.Context, current *v3.FelixConfiguration, d *FelixConfigurationDeclaration, payload *unstructured.Unstructured) error {
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
	fc := &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{Name: defaultFelixConfigName}}
	return w.client.Patch(ctx, fc, client.RawPatch(types.MergePatchType, encoded))
}

func (w *v3Writer) apply(ctx context.Context, payload *unstructured.Unstructured, manager string, force bool) (*v3.FelixConfiguration, error) {
	opts := []client.ApplyOption{client.FieldOwner(fieldManagerPrefix + manager)}
	if force {
		opts = append(opts, client.ForceOwnership)
	}

	gvk, err := apiutil.GVKForObject(&v3.FelixConfiguration{}, w.client.Scheme())
	if err != nil {
		return nil, err
	}

	applied := payload.DeepCopy()
	applied.SetGroupVersionKind(gvk)
	if err := w.client.Apply(ctx, client.ApplyConfigurationFromUnstructured(applied), opts...); err != nil {
		return nil, err
	}

	fc := &v3.FelixConfiguration{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(applied.Object, fc); err != nil {
		return nil, fmt.Errorf("unable to read back applied FelixConfiguration: %w", err)
	}
	return fc, nil
}
