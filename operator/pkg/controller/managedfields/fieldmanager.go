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
// users also modify. One write path per API group.
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
	useV3  bool
}

// New returns a FieldManager for the API group the operator writes through.
func New(c client.Client, useV3CRDs bool) *FieldManager {
	return &FieldManager{client: c, useV3: useV3CRDs}
}

// Declare states which fields the caller owns, given the current object.
type Declare[T client.Object] func(current T) (*Declaration, error)

// Apply writes the fields the declaration asks for on the governed resource, and returns the
// whole resulting object.
func (d Declare[T]) Apply(ctx context.Context, m *FieldManager) (T, error) {
	var zero T
	governed := reflect.TypeOf(zero)
	if governed == nil || governed.Kind() != reflect.Pointer {
		return zero, fmt.Errorf("a declaration governs a pointer type, not %T", zero)
	}

	current := reflect.New(governed.Elem()).Interface().(T)
	if err := m.client.Get(ctx, types.NamespacedName{Name: defaultResourceName}, current); err != nil && !apierrors.IsNotFound(err) {
		return zero, fmt.Errorf("unable to read %T: %w", current, err)
	}

	applied, err := m.applyDeclared(ctx, current, untypedDeclare(d))
	if applied == nil {
		return zero, err
	}
	typed, ok := applied.(T)
	if !ok {
		return zero, err
	}
	return typed, err
}

// applyDeclared persists a declaration through the API group the operator writes.
func (m *FieldManager) applyDeclared(ctx context.Context, current client.Object, declare declareFn) (client.Object, error) {
	if m.useV3 {
		return m.applyV3(ctx, current, declare)
	}
	return m.applyCRDV1(ctx, current, declare)
}

// declareFn is the untyped declaration callback the writers share.
type declareFn func(current client.Object) (*Declaration, error)

// untypedDeclare adapts a caller's typed declaration to the form the writers work in.
func untypedDeclare[T client.Object](declare Declare[T]) declareFn {
	return func(current client.Object) (*Declaration, error) {
		d, err := declare(current.(T))
		if err != nil || d == nil {
			return nil, err
		}
		if _, ok := d.Owned.(T); !ok {
			return nil, fmt.Errorf("a %T declaration cannot own %T", current, d.Owned)
		}
		return d, nil
	}
}
