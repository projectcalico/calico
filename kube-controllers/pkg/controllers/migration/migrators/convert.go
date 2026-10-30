// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package migrators

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// internalMetadataAnnotation is the annotation used by the v1 backend to store
// internal metadata. It is filtered out during conversion.
const internalMetadataAnnotation = "projectcalico.org/metadata"

// defaultConvert performs a deep copy of the v1 resource and cleans server-side
// metadata fields. The UID and OwnerReferences are preserved so callers can
// use them for UID mapping and OwnerRef remapping before creation.
func defaultConvert[T any](kvp *model.KVPair) (*T, error) {
	v1, ok := kvp.Value.(*T)
	if !ok {
		return nil, fmt.Errorf("unexpected type for value: %T", kvp.Value)
	}

	rtObj, ok := any(v1).(runtime.Object)
	if !ok {
		return nil, fmt.Errorf("type %T does not implement runtime.Object", v1)
	}
	copied := rtObj.DeepCopyObject()

	// Type-assert through any — the direct assertion from runtime.Object
	// to *T is not allowed by the Go compiler for type parameters.
	v3, ok := any(copied).(*T)
	if !ok {
		return nil, fmt.Errorf("deep copy returned unexpected type: %T", copied)
	}

	metaObj, ok := any(v3).(metav1.Object)
	if !ok {
		return nil, fmt.Errorf("type %T does not implement metav1.Object", v3)
	}

	// Clear server-side metadata that should not be carried to the new resource.
	// UID and OwnerReferences are intentionally preserved: MigrateResourceType
	// extracts the v1 UID for mapping and copies OwnerRefs before creation.
	metaObj.SetResourceVersion("")
	metaObj.SetCreationTimestamp(metav1.Time{})
	metaObj.SetManagedFields(nil)
	metaObj.SetGeneration(0)
	metaObj.SetSelfLink("")

	// Filter internal annotations.
	if annotations := metaObj.GetAnnotations(); len(annotations) > 0 {
		cleaned := make(map[string]string)
		for k, v := range annotations {
			if k == internalMetadataAnnotation {
				continue
			}
			cleaned[k] = v
		}
		if len(cleaned) > 0 {
			metaObj.SetAnnotations(cleaned)
		} else {
			metaObj.SetAnnotations(nil)
		}
	}

	return v3, nil
}
