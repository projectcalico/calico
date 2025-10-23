// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

// Package optimize provides functions to optimize Calico API resources.
package optimize

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

// Objects takes a slice of runtime.Object and returns a new slice containing
// the optimized objects. List objects are preserved (not flattened) and contain
// the optimized versions of their items. Non-list objects may expand into
// multiple objects.
func Objects(in []runtime.Object) []runtime.Object {
	out := make([]runtime.Object, 0, len(in))
	for _, obj := range in {
		out = append(out, optimizeOne(obj)...)
	}
	return out
}

func optimizeOne(obj runtime.Object) []runtime.Object {
	// If this is a List type, optimize each item and return a List object of the
	// same type containing the optimized items. Items are assumed to be non-list
	// resources; each may expand into multiple objects which are all included.
	if items, err := meta.ExtractList(obj); err == nil {
		optimizedItems := make([]runtime.Object, 0, len(items))
		for _, it := range items {
			optimizedItems = append(optimizedItems, optimizeNonList(it)...)
		}

		// Create a copy of the input list object and set the Items field.
		listCopy := obj.DeepCopyObject()
		if err := meta.SetList(listCopy, optimizedItems); err == nil {
			return []runtime.Object{listCopy}
		}
		// If we couldn't set the list (unexpected), return the original object as-is.
		return []runtime.Object{obj}
	}

	return optimizeNonList(obj)
}

// optimizeNonList optimizes a single non-list object and may return multiple objects.
func optimizeNonList(obj runtime.Object) (out []runtime.Object) {
	switch t := obj.(type) {
	case *apiv3.GlobalNetworkPolicy:
		pols := GlobalNetworkPolicy(t)
		return typedSliceToObjectSlice(pols)
	default:
		// No-op for unhandled resource types.
		return []runtime.Object{obj}
	}
}

func typedSliceToObjectSlice[T runtime.Object](in []T) (out []runtime.Object) {
	for _, obj := range in {
		out = append(out, obj)
	}
	return
}
