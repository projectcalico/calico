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

// Package sharedconfig writes operator-owned fields to Calico resources that
// users also modify. One implementation per API group.
package sharedconfig

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DeclareFelixConfiguration states which FelixConfiguration fields the caller owns, given the current object.
type DeclareFelixConfiguration func(current *v3.FelixConfiguration) (*FelixConfigurationDeclaration, error)

// Writer persists operator-owned fields on shared Calico configuration resources.
type Writer interface {
	// UpdateFelixConfiguration applies updateFn to the default FelixConfiguration and persists the result.
	UpdateFelixConfiguration(ctx context.Context, updateFn func(fc *v3.FelixConfiguration) (bool, error)) (*v3.FelixConfiguration, error)

	// ApplyFelixConfiguration writes the declared fields and returns the whole resulting object.
	ApplyFelixConfiguration(ctx context.Context, declare DeclareFelixConfiguration) (*v3.FelixConfiguration, error)
}

// NewWriter returns a Writer for the API group the operator writes through.
func NewWriter(c client.Client, useV3CRDs bool) Writer {
	if useV3CRDs {
		return &v3Writer{crdV1Writer{client: c}}
	}
	return &crdV1Writer{client: c}
}
