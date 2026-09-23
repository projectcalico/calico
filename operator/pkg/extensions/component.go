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

package extensions

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/render"
)

// Modifier post-processes the objects a render component produced. Appending to
// delete cleans up what a prior variant left behind.
type Modifier func(create, delete []client.Object) (newCreate, newDelete []client.Object)

// Decorate wraps base so modify runs over its rendered objects. An Installation
// asking for a different variant gets base untouched.
func Decorate(base render.Component, ri render.Inputs, variant operatorv1.ProductVariant, modify Modifier) render.Component {
	if ri.Installation == nil || !sameProduct(ri.Installation.Variant, variant) {
		return base
	}
	return &decoratedComponent{Component: base, modify: modify}
}

// sameProduct reports whether two variant values name the same product. Enterprise has
// two spellings: TigeraSecureEnterprise is a deprecated alias for CalicoEnterprise, and
// an Installation using either has to reach the same extension.
func sameProduct(a, b operatorv1.ProductVariant) bool {
	return a == b || (a.IsEnterprise() && b.IsEnterprise())
}

// decoratedComponent renders its base component and runs the modifier over the result.
type decoratedComponent struct {
	render.Component

	modify Modifier
}

func (d *decoratedComponent) Objects() ([]client.Object, []client.Object) {
	return d.modify(d.Component.Objects())
}

// FindObject returns the first object of type T with the given name.
func FindObject[T client.Object](objs []client.Object, name string) (T, bool) {
	var zero T
	for _, o := range objs {
		if t, ok := o.(T); ok && o.GetName() == name {
			return t, true
		}
	}
	return zero, false
}

// MustFindObject returns the first object of type T with the given name, panicking
// if the base render did not produce it.
func MustFindObject[T client.Object](objs []client.Object, name string) T {
	t, ok := FindObject[T](objs, name)
	if !ok {
		panic(fmt.Sprintf("BUG: no object named %q to modify", name))
	}
	return t
}
