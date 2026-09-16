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

// declaredPayload renders the declared fields as an object carrying no other state.
func declaredPayload(owned *v3.FelixConfiguration) (*unstructured.Unstructured, error) {
	if owned == nil {
		owned = &v3.FelixConfiguration{}
	}
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(owned)
	if err != nil {
		return nil, fmt.Errorf("unable to render FelixConfiguration fields: %w", err)
	}

	u := &unstructured.Unstructured{Object: content}
	unstructured.RemoveNestedField(u.Object, "metadata")
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
