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
// users also modify. One implementation per API group.
package managedfields

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FieldManager owns a declared set of fields on shared Calico configuration resources.
type FieldManager struct {
	client client.Client
	writer writer
}

// New returns a FieldManager for the API group the operator writes through.
func New(c client.Client, useV3CRDs bool) *FieldManager {
	crdV1 := crdV1FieldManager{client: c}
	if useV3CRDs {
		return &FieldManager{client: c, writer: &v3FieldManager{crdV1}}
	}
	return &FieldManager{client: c, writer: &crdV1}
}

// Declare states which fields the caller owns, given the current object.
type Declare[T client.Object] func(current T) (*Declaration[T], error)

// object constrains Apply to a pointer type, so it can make one to read into.
type object[U any] interface {
	*U
	client.Object
}

// Apply writes the fields declare asks for on the governed resource, and returns the whole
// resulting object.
func Apply[U any, T object[U]](ctx context.Context, m *FieldManager, declare Declare[T]) (T, error) {
	var zero T
	current := T(new(U))
	if err := m.client.Get(ctx, types.NamespacedName{Name: defaultResourceName}, current); err != nil && !apierrors.IsNotFound(err) {
		return zero, fmt.Errorf("unable to read %T: %w", current, err)
	}

	applied, err := m.writer.applyDeclared(ctx, current, untypedDeclare(declare))
	if applied == nil {
		return zero, err
	}
	typed, ok := applied.(T)
	if !ok {
		return zero, err
	}
	return typed, err
}

// writer persists a declaration through one API group.
type writer interface {
	applyDeclared(ctx context.Context, current client.Object, declare declareFn) (client.Object, error)
}

// declareFn is the untyped declaration callback the writers share.
type declareFn func(current client.Object) (*declaration, error)

// untypedDeclare adapts a caller's typed declaration to the form the writers work in.
func untypedDeclare[T client.Object](declare Declare[T]) declareFn {
	return func(current client.Object) (*declaration, error) {
		typed, ok := current.(T)
		if !ok {
			return nil, nil
		}
		d, err := declare(typed)
		if err != nil || d == nil {
			return nil, err
		}
		return d.untyped(), nil
	}
}
