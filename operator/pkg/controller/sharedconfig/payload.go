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
	"errors"
	"fmt"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// defaultFelixConfigName is the only FelixConfiguration the operator writes.
const defaultFelixConfigName = "default"

// declaredPayload renders the governed fields as an object carrying no other state.  It is built
// from the policy paths rather than the struct, which serializes some fields unconditionally.
func declaredPayload(owned *v3.FelixConfiguration, policies map[string]ConflictPolicy) (*unstructured.Unstructured, error) {
	if owned == nil {
		owned = &v3.FelixConfiguration{}
	}
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(owned)
	if err != nil {
		return nil, fmt.Errorf("unable to render FelixConfiguration fields: %w", err)
	}

	declared := map[string]any{}
	for path := range policies {
		keys := strings.Split(path, ".")
		value, found, err := unstructured.NestedFieldCopy(content, keys...)
		if err != nil {
			return nil, fmt.Errorf("unable to read declared field %s: %w", path, err)
		}

		// A governed path with no value is how a declaration gives the field up.
		if !found {
			continue
		}
		if err := unstructured.SetNestedField(declared, value, keys...); err != nil {
			return nil, fmt.Errorf("unable to render declared field %s: %w", path, err)
		}
	}

	u := &unstructured.Unstructured{Object: declared}
	u.SetName(defaultFelixConfigName)
	return u, nil
}

// declaresSpec reports whether the payload sets any field at all.
func declaresSpec(payload *unstructured.Unstructured) bool {
	spec, found, err := unstructured.NestedMap(payload.Object, "spec")
	return err == nil && found && len(spec) > 0
}

// pathSet reports whether path holds a value in obj.
func pathSet(obj map[string]any, path string) bool {
	_, found, err := unstructured.NestedFieldNoCopy(obj, strings.Split(path, ".")...)
	return err == nil && found
}

// removePath drops path from obj, so the operator stops claiming it.
func removePath(obj map[string]any, path string) {
	unstructured.RemoveNestedField(obj, strings.Split(path, ".")...)
}

// conflictPaths lists the fields an apply was rejected for, normalized to "spec.field" form.
func conflictPaths(err error) []string {
	var status apierrors.APIStatus
	if !errors.As(err, &status) || status.Status().Details == nil {
		return nil
	}

	var paths []string
	for _, cause := range status.Status().Details.Causes {
		if cause.Type != metav1.CauseTypeFieldManagerConflict {
			continue
		}
		paths = append(paths, strings.TrimPrefix(cause.Field, "."))
	}
	return paths
}
