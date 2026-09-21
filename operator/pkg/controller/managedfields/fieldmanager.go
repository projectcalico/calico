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

// Package managedfields owns a declared set of fields on Calico resources that
// users also modify, through server-side apply.
package managedfields

import (
	"context"
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FieldManager owns a declared set of fields on shared Calico configuration resources.
type FieldManager struct {
	client client.Client
}

// New returns a FieldManager that writes through the API group the client is configured for.
func New(c client.Client) *FieldManager {
	return &FieldManager{client: c}
}

// DeclareFn states which fields the caller owns, given the current object.
type DeclareFn[T client.Object] func(current T) (*Declaration, error)

// Apply writes the fields the declaration asks for on the governed resource, and returns the
// whole resulting object.
func (d DeclareFn[T]) Apply(ctx context.Context, m *FieldManager) (T, error) {
	var zero T
	governed := reflect.TypeOf(zero)
	if governed == nil || governed.Kind() != reflect.Pointer {
		return zero, fmt.Errorf("a declaration governs a pointer type, not %T", zero)
	}

	// Read the object the declaration governs, so the caller can decide from its current state.
	current := reflect.New(governed.Elem()).Interface().(T)
	if err := m.client.Get(ctx, types.NamespacedName{Name: defaultResourceName}, current); err != nil && !apierrors.IsNotFound(err) {
		return zero, fmt.Errorf("unable to read %T: %w", current, err)
	}

	applied, err := applyDeclared(ctx, m, current, d)
	if applied == nil {
		return zero, err
	}
	typed, ok := applied.(T)
	if !ok {
		return zero, err
	}
	return typed, err
}
