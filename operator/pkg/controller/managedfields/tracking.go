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
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/render"
)

// lastWrittenValues reads back the values the operator recorded on its previous write.
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

// recordWrittenValues stores the values being written so the next reconcile can compare against them.
func recordWrittenValues(obj client.Object, payload *unstructured.Unstructured, d *Declaration, deferred []string) error {
	values, err := lastWrittenValues(obj)
	if err != nil {
		return err
	}
	for _, path := range deferred {
		delete(values, path)
	}

	for path := range d.Policies {
		written, found, err := unstructured.NestedFieldNoCopy(payload.Object, strings.Split(path, ".")...)
		if err != nil {
			return fmt.Errorf("unable to read %s: %w", path, err)
		}
		if !found {
			continue
		}
		if values[path], err = canonicalize(written); err != nil {
			return err
		}
	}

	encoded, err := json.Marshal(values)
	if err != nil {
		return fmt.Errorf("unable to record written fields: %w", err)
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[ownedFieldsAnnotation] = string(encoded)

	// Keep the legacy annotation in step, so a rollback to an older operator still reads it.
	if enabled, ok := values[bpfEnabledPath].(bool); ok {
		annotations[render.BPFOperatorAnnotation] = strconv.FormatBool(enabled)
	} else {
		delete(annotations, render.BPFOperatorAnnotation)
	}
	obj.SetAnnotations(annotations)
	return nil
}

// mergeInto overlays the declared fields onto fc, leaving every other field alone.
func mergeInto(obj client.Object, payload *unstructured.Unstructured) error {
	declared, _, err := unstructured.NestedMap(payload.Object, "spec")
	if err != nil {
		return fmt.Errorf("unable to read declared fields: %w", err)
	}
	if len(declared) == 0 {
		return nil
	}

	content, err := toUnstructured(obj)
	if err != nil {
		return err
	}
	spec, _, err := unstructured.NestedMap(content, "spec")
	if err != nil {
		return fmt.Errorf("unable to read %T fields: %w", obj, err)
	}
	if spec == nil {
		spec = map[string]any{}
	}
	// Overlay whole fields rather than merging into them, so a struct field lands the way an
	// apply would place it.
	for field, value := range declared {
		spec[field] = value
	}
	if err := unstructured.SetNestedMap(content, spec, "spec"); err != nil {
		return err
	}
	return runtime.DefaultUnstructuredConverter.FromUnstructured(content, obj)
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
