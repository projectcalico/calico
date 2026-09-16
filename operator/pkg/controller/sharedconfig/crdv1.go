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
	"fmt"
	"sort"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/controller/utils"
)

// ownedFieldsAnnotation records the values the operator last wrote, so it can spot changes by others.
const ownedFieldsAnnotation = "operator.tigera.io/owned-fields"

// bpfEnabledPath is tracked by its own legacy annotation, which predates ownedFieldsAnnotation.
const bpfEnabledPath = "spec.bpfEnabled"

// crdV1Writer writes through crd.projectcalico.org/v1, the API group used in aggregated apiserver mode.
type crdV1Writer struct {
	client client.Client
}

var _ Writer = &crdV1Writer{}

// ApplyFelixConfiguration writes the declared fields, comparing each against the value the operator
// last wrote to spot changes made by others.
func (w *crdV1Writer) ApplyFelixConfiguration(ctx context.Context, declare DeclareFelixConfiguration) (*v3.FelixConfiguration, error) {
	current, err := utils.GetFelixConfiguration(ctx, w.client)
	if err != nil {
		return nil, err
	}
	if err := utils.RestoreV3Metadata(current); err != nil {
		return nil, err
	}
	// Diff against the restored object, so the patch leaves the v3 metadata stash alone.
	patchFrom := client.MergeFrom(current.DeepCopy())

	declaration, err := declare(current)
	if err != nil {
		return nil, err
	}
	if declaration == nil {
		return current, nil
	}

	payload, err := declaredPayload(declaration.Owned)
	if err != nil {
		return nil, err
	}
	// Fields the operator's pre-apply manager still owns are its own, whether or not it kept a
	// record of writing them.
	legacyOwned, _, err := updateOwnedPaths(current)
	if err != nil {
		return nil, err
	}
	deferred, err := resolveTrackedConflicts(current, declaration, payload, legacyOwned)
	if err != nil {
		return nil, err
	}

	merged := current.DeepCopy()
	if err := mergeInto(merged, payload); err != nil {
		return nil, err
	}
	removed, err := removeUndeclared(merged, current, declaration, payload, legacyOwned)
	if err != nil {
		return nil, err
	}
	if err := recordWrittenValues(merged, payload, declaration, append(deferred, removed...)); err != nil {
		return nil, err
	}
	if equality.Semantic.DeepEqual(current, merged) {
		return current, nil
	}
	if current.ResourceVersion == "" && !declaresSpec(payload) {
		// The declaration holds nothing to write, so don't create an object carrying only a record.
		return current, nil
	}
	return w.persist(ctx, merged, patchFrom)
}

// resolveTrackedConflicts drops deferred fields from payload and returns the paths it dropped.
func resolveTrackedConflicts(current *v3.FelixConfiguration, d *FelixConfigurationDeclaration, payload *unstructured.Unstructured, legacyOwned map[string]bool) ([]string, error) {
	currentContent, err := runtime.DefaultUnstructuredConverter.ToUnstructured(current)
	if err != nil {
		return nil, fmt.Errorf("unable to read FelixConfiguration fields: %w", err)
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
		// Writing the value that is already there needs no arbitration, whoever put it there.
		agree, err := valuesAgree(currentContent, payload.Object, path)
		if err != nil {
			return nil, err
		}
		if agree {
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
			removePath(payload.Object, path)
			deferred = append(deferred, path)
		case ConflictOverride:
		default:
			refused = append(refused, path)
		}
	}

	if len(refused) > 0 {
		sort.Strings(refused)
		return nil, &ConflictingFieldsError{Paths: refused}
	}
	return deferred, nil
}

// removeUndeclared deletes governed fields the declaration left out, matching the way a sole
// apply owner drops them.
func removeUndeclared(merged, current *v3.FelixConfiguration, d *FelixConfigurationDeclaration, payload *unstructured.Unstructured, legacyOwned map[string]bool) ([]string, error) {
	currentContent, err := runtime.DefaultUnstructuredConverter.ToUnstructured(current)
	if err != nil {
		return nil, fmt.Errorf("unable to read FelixConfiguration fields: %w", err)
	}
	lastWritten, err := lastWrittenValues(current)
	if err != nil {
		return nil, err
	}

	var remove, refused []string
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
			return nil, err
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

	if len(refused) > 0 {
		sort.Strings(refused)
		return nil, &ConflictingFieldsError{Paths: refused}
	}
	return remove, deletePaths(merged, remove)
}

// deletePaths clears the named fields on fc.
func deletePaths(fc *v3.FelixConfiguration, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(fc)
	if err != nil {
		return fmt.Errorf("unable to read FelixConfiguration fields: %w", err)
	}
	for _, path := range paths {
		removePath(content, path)
	}
	return runtime.DefaultUnstructuredConverter.FromUnstructured(content, fc)
}

func (w *crdV1Writer) persist(ctx context.Context, fc *v3.FelixConfiguration, patchFrom client.Patch) (*v3.FelixConfiguration, error) {
	if fc.ResourceVersion == "" {
		fc.Name = defaultFelixConfigName
		if err := w.client.Create(ctx, fc); err != nil {
			return nil, err
		}
		return fc, nil
	}
	if err := w.client.Patch(ctx, fc, patchFrom); err != nil {
		return nil, err
	}
	return fc, nil
}

func (w *crdV1Writer) UpdateFelixConfiguration(ctx context.Context, updateFn func(fc *v3.FelixConfiguration) (bool, error)) (*v3.FelixConfiguration, error) {
	// Fetch any existing default FelixConfiguration object.
	fc := &v3.FelixConfiguration{}
	err := w.client.Get(ctx, types.NamespacedName{Name: "default"}, fc)
	if err != nil && !errors.IsNotFound(err) {
		return nil, fmt.Errorf("unable to read FelixConfiguration: %w", err)
	}

	if err = utils.RestoreV3Metadata(fc); err != nil {
		return nil, err
	}

	// Create a base state for the upcoming patch operation, diffing against the restored object so
	// the patch leaves the v3 metadata stash alone.
	patchFrom := client.MergeFrom(fc.DeepCopy())

	// Apply desired changes to the FelixConfiguration.
	updated, err := updateFn(fc)
	if err != nil {
		return nil, err
	}
	if updated {
		// Apply the patch.
		if fc.ResourceVersion == "" {
			fc.Name = "default"
			if err := w.client.Create(ctx, fc); err != nil {
				return nil, err
			}
		} else {
			if err := w.client.Patch(ctx, fc, patchFrom); err != nil {
				return nil, err
			}
		}
	}

	return fc, nil
}
