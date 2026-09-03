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

// Package daemon is the operator itself, so that a build serving another product
// variant can supply its own main and pass what only it knows.
package daemon

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatortigeraiov1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/extensions"
)

// Options are what a build of the operator supplies beyond the core behavior. The
// zero value runs Calico.
type Options struct {
	// Variants are the values the -variant flag accepts, for the CRDs installed before
	// an Installation exists. Empty accepts Calico alone.
	Variants []operatortigeraiov1.ProductVariant

	// Versions are extra lines -version prints after the operator's own, in name order.
	Versions map[string]string

	// Images are the component sets -print-images prints, keyed by the flag value. An
	// entry replaces the core set of the same name.
	Images map[string][]components.Component

	// Extensions builds the extensions the variant supplies, once the variant resolves.
	Extensions extensions.Builder

	// UncachedObjects are read straight from the apiserver rather than through the
	// manager's cache, for a kind whose cached copy goes stale.
	UncachedObjects []client.Object

	// AfterParse runs once the flags are parsed, so a caller that registered its own
	// flag on flag.CommandLine can act on it. Returning true exits zero, like the
	// operator's own print-and-exit flags.
	AfterParse func() (handled bool, err error)
}

// acceptsVariant reports whether the -variant flag may name v.
func (o Options) acceptsVariant(v operatortigeraiov1.ProductVariant) bool {
	if len(o.Variants) == 0 {
		return v == operatortigeraiov1.Calico
	}
	for _, accepted := range o.Variants {
		if v == accepted {
			return true
		}
	}
	return false
}

// imageSet returns the components -print-images was asked for.
func (o Options) imageSet(name string) ([]components.Component, bool) {
	if cmpnts, ok := o.Images[name]; ok {
		return cmpnts, true
	}
	switch name {
	case "list", "listcalico":
		return components.CalicoImages, true
	}
	return nil, false
}

// afterParse runs the caller's flag handling, if it registered any.
func (o Options) afterParse() (bool, error) {
	if o.AfterParse == nil {
		return false, nil
	}
	return o.AfterParse()
}
