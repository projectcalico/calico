// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package informerutil holds helpers for working with client-go informer
// event handlers.
package informerutil

import (
	"fmt"
	"reflect"

	"k8s.io/client-go/tools/cache"
)

// DeletedObject returns the object carried by an informer delete event.
//
// A DeleteFunc handler usually receives the deleted object itself, but the
// informer substitutes a cache.DeletedFinalStateUnknown tombstone whenever it
// loses track of an object's final state - for example when a watch drops and
// the object is already gone by the time the informer relists. A handler that
// type-asserts the event object directly panics on that tombstone; one that
// asserts with the two-value form silently skips the delete, leaving whatever
// the handler was meant to clean up behind.
//
// Use this only when the handler needs the object itself. A handler that needs
// only the namespace/name should use cache.DeletionHandlingObjectToName, or
// cache.DeletionHandlingMetaNamespaceKeyFunc where the "namespace/name" key is
// itself what the handler wants. A tombstone may carry a key but no object:
// that case returns an error here, because there is no T to return, while both
// of those still yield the name.
//
// The error names the types involved so the caller can log it with its own
// logger and skip the event.
func DeletedObject[T any](obj any) (T, error) {
	if typed, ok := obj.(T); ok {
		return typed, nil
	}

	var zero T
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return zero, fmt.Errorf("delete event carried %T, want %s or a tombstone", obj, reflect.TypeFor[T]())
	}
	typed, ok := tombstone.Obj.(T)
	if !ok {
		return zero, fmt.Errorf("tombstone for key %q carried %T, want %s", tombstone.Key, tombstone.Obj, reflect.TypeFor[T]())
	}
	return typed, nil
}
