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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	applied, err := w.applyDeclared(ctx, current, felixDeclareFn(declare))
	if err != nil {
		return nil, err
	}
	return applied.(*v3.FelixConfiguration), nil
}

func (w *v3Writer) ApplyBGPConfiguration(ctx context.Context, declare DeclareBGPConfiguration) (*v3.BGPConfiguration, error) {
	current, err := utils.GetBGPConfiguration(ctx, w.client)
	if err != nil {
		return nil, err
	}
	applied, err := w.applyDeclared(ctx, current, bgpDeclareFn(declare))
	if err != nil {
		return nil, err
	}
	return applied.(*v3.BGPConfiguration), nil
}

func (w *v3Writer) applyDeclared(ctx context.Context, current client.Object, declare declareFn) (client.Object, error) {
	d, err := declare(current)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return current, nil
	}

	gvk, err := apiutil.GVKForObject(current, w.client.Scheme())
	if err != nil {
		return nil, err
	}

	payload, err := declaredPayload(d.owned, d.policies)
	if err != nil {
		return nil, err
	}
	if current.GetResourceVersion() == "" && !declaresSpec(payload) {
		// The declaration holds nothing to write, so don't create an empty object.
		return current, nil
	}
	if err := w.clearLegacyOwned(ctx, current, gvk, d, payload); err != nil {
		return nil, err
	}

	applied, err := w.apply(ctx, gvk, payload, d.manager, false)
	if err == nil {
		return applied, nil
	}
	if !apierrors.IsConflict(err) {
		return nil, err
	}

	force, err := w.resolveConflicts(err, current, d, payload)
	if err != nil {
		return nil, err
	}
	return w.apply(ctx, gvk, payload, d.manager, force)
}

// resolveConflicts drops deferred fields from payload and reports whether the retry must force.
func (w *v3Writer) resolveConflicts(applyErr error, current client.Object, d *declaration, payload *unstructured.Unstructured) (bool, error) {
	paths := conflictPaths(applyErr)
	if len(paths) == 0 {
		return false, applyErr
	}

	currentContent, err := toUnstructured(current)
	if err != nil {
		return false, err
	}
	reclaimable, err := reclaimablePaths(current, fieldManagerPrefix+d.manager)
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
		return false, &ConflictingFieldsError{Kind: kindOf(current), Paths: refused}
	}
	return force, nil
}

// clearLegacyOwned deletes governed fields the operator's pre-apply field manager still holds and
// the declaration does not set. An apply cannot drop a field it does not own.
func (w *v3Writer) clearLegacyOwned(ctx context.Context, current client.Object, gvk schema.GroupVersionKind, d *declaration, payload *unstructured.Unstructured) error {
	legacyOwned, _, err := updateOwnedPaths(current)
	if err != nil || len(legacyOwned) == 0 {
		return err
	}

	remove := map[string]any{}
	for path := range d.policies {
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
	target := &unstructured.Unstructured{}
	target.SetGroupVersionKind(gvk)
	target.SetName(defaultResourceName)
	return w.client.Patch(ctx, target, client.RawPatch(types.MergePatchType, encoded))
}

func (w *v3Writer) apply(ctx context.Context, gvk schema.GroupVersionKind, payload *unstructured.Unstructured, manager string, force bool) (client.Object, error) {
	opts := []client.ApplyOption{client.FieldOwner(fieldManagerPrefix + manager)}
	if force {
		opts = append(opts, client.ForceOwnership)
	}

	applied := payload.DeepCopy()
	applied.SetGroupVersionKind(gvk)
	if err := w.client.Apply(ctx, client.ApplyConfigurationFromUnstructured(applied), opts...); err != nil {
		return nil, err
	}

	out, err := w.client.Scheme().New(gvk)
	if err != nil {
		return nil, err
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(applied.Object, out); err != nil {
		return nil, fmt.Errorf("unable to read back the applied %s: %w", gvk.Kind, err)
	}
	return out.(client.Object), nil
}
