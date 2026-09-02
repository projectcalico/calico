// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package common

import (
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MergeMaps merges current and desired maps. If both current and desired maps contain the same key, the
// desired map's value is used.
// MergeMaps does not copy operator-managed annotations from the current map.
func MergeMaps(current, desired map[string]string) map[string]string {
	for k, v := range current {
		if _, ok := desired[k]; !ok && !isOperatorManaged(k) {
			desired[k] = v
		}
	}
	return desired
}

// isOperatorManaged returns true if the given annotation key is managed by the operator
// and should not be copied from the current map during merges.
func isOperatorManaged(key string) bool {
	return strings.Contains(key, "operator.tigera.io")
}

// MapExistsOrInitialize returns the given map if non-nil or returns an empty map.
func MapExistsOrInitialize(m map[string]string) map[string]string {
	if m != nil {
		return m
	}
	return make(map[string]string)
}

// MergeOwnerReferences merges desired and current owner references, removing the duplicates.
// A UID identifies an owner, so desired's version of a reference wins over current's.
//
// The result is sorted by UID, which keeps the merge convergent when more than one controller
// writes the object. Each caller passes its own reference in desired, so an order that followed
// the arguments would put a different reference first depending on who wrote last, and the two
// controllers would rewrite the object in turn for as long as both keep reconciling. Order carries
// no meaning to Kubernetes: owner references are a set, and the controller reference is identified
// by its Controller field rather than its position.
func MergeOwnerReferences(desired, current []metav1.OwnerReference) []metav1.OwnerReference {
	refList := make([]metav1.OwnerReference, 0, len(desired)+len(current))
	seen := make(map[string]bool, len(desired)+len(current))
	for _, item := range slices.Concat(desired, current) {
		if !seen[string(item.UID)] {
			refList = append(refList, item)
			seen[string(item.UID)] = true
		}
	}
	slices.SortFunc(refList, func(a, b metav1.OwnerReference) int {
		return strings.Compare(string(a.UID), string(b.UID))
	})
	return refList
}
