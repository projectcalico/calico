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

// Package imageoverride is a leaf package (no render/operator dependencies)
// that holds the image override table. The render package imports it to resolve
// a component's image without depending on pkg/extensions, which would cycle.
package imageoverride

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
)

type overrideKey struct {
	variant operatorv1.ProductVariant
	key     string
}

// Overrides maps a component (keyed by variant) to the image it should resolve
// to, letting a variant swap a component's image without the render package
// branching on variant. The render component holds one and resolves through it.
// Registry, image path, and FIPS handling are applied downstream in the render
// package, so an override only picks which component.
type Overrides struct {
	m map[overrideKey]components.Component
}

// New returns an empty Overrides.
func New() *Overrides {
	return &Overrides{m: map[overrideKey]components.Component{}}
}

// Register stores image under key for the given variant. The key is the render
// component's image identifier (e.g. "node").
func (o *Overrides) Register(variant operatorv1.ProductVariant, key string, image components.Component) {
	o.m[overrideKey{variant, key}] = image
}

// Resolve returns the override registered for key under the installation's
// variant, otherwise def. It is safe to call on a nil *Overrides (the core
// operator hands render no overrides), which always returns def.
func (o *Overrides) Resolve(key string, def components.Component, in *operatorv1.InstallationSpec) components.Component {
	if o == nil || in == nil {
		return def
	}
	if image, ok := o.m[overrideKey{in.Variant, key}]; ok {
		return image
	}
	return def
}
