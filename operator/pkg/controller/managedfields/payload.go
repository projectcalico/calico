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
	"errors"
	"fmt"
	"reflect"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// defaultResourceName is the only FelixConfiguration or BGPConfiguration the operator writes.
const defaultResourceName = "default"

// declaredPayload renders the governed fields as an object carrying no other state. It reads the
// policy paths, so a field the declaration sets without governing stays out, where the resolver
// could not classify it.
func declaredPayload(owned client.Object, policies map[string]ConflictPolicy) (*unstructured.Unstructured, error) {
	content, err := toUnstructured(owned)
	if err != nil {
		return nil, err
	}

	declared := map[string]any{}
	for path := range policies {
		keys := strings.Split(path, ".")
		value, found, err := unstructured.NestedFieldCopy(content, keys...)
		if err != nil {
			return nil, fmt.Errorf("unable to read declared field %s: %w", path, err)
		}

		// A governed path with no value is how a declaration gives the field up, which
		// relies on the field carrying omitempty.
		if !found {
			continue
		}
		if err := unstructured.SetNestedField(declared, value, keys...); err != nil {
			return nil, fmt.Errorf("unable to render declared field %s: %w", path, err)
		}
	}

	u := &unstructured.Unstructured{Object: declared}
	u.SetName(defaultResourceName)
	return u, nil
}

// toUnstructured renders an object as a field map.
func toUnstructured(obj client.Object) (map[string]any, error) {
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, fmt.Errorf("unable to render %T fields: %w", obj, err)
	}
	return content, nil
}

// declaresSpec reports whether the payload sets any field at all.
func declaresSpec(payload *unstructured.Unstructured) (bool, error) {
	spec, found, err := unstructured.NestedMap(payload.Object, "spec")
	if err != nil {
		return false, fmt.Errorf("unable to read the declared fields: %w", err)
	}
	return found && len(spec) > 0, nil
}

// pathSet reports whether path holds a value in obj.
func pathSet(obj map[string]any, path string) (bool, error) {
	_, found, err := unstructured.NestedFieldNoCopy(obj, strings.Split(path, ".")...)
	if err != nil {
		return false, fmt.Errorf("unable to read %s: %w", path, err)
	}
	return found, nil
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

// kindOf names a governed resource for error messages.
func kindOf(obj client.Object) string {
	t := reflect.TypeOf(obj)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Name()
}

// valuesAgree reports whether the value about to be written is already there.
func valuesAgree(currentContent, payloadObj map[string]any, path string) (bool, error) {
	keys := strings.Split(path, ".")
	current, found, err := unstructured.NestedFieldNoCopy(currentContent, keys...)
	if err != nil || !found {
		return false, err
	}
	written, found, err := unstructured.NestedFieldNoCopy(payloadObj, keys...)
	if err != nil || !found {
		return false, err
	}
	return reflect.DeepEqual(current, written), nil
}
