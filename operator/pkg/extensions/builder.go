// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package extensions

import (
	"context"

	"k8s.io/client-go/kubernetes"

	opv1 "github.com/projectcalico/calico/operator/api/v1"
)

// BuildOptions is what a variant needs from startup beyond the cluster connection.
type BuildOptions struct {
	ManageCRDs bool
	UseV3CRDs  bool
}

// Builder returns the extensions a variant supplies. It runs once the variant is
// resolved, so it can query the cluster for anything else the variant needs.
type Builder func(ctx context.Context, variant opv1.ProductVariant, clientset kubernetes.Interface, opts BuildOptions) (Extensions, error)

// Build returns the extensions the operator runs with. A build that supplies no
// builder extends nothing.
func Build(ctx context.Context, b Builder, variant opv1.ProductVariant, clientset kubernetes.Interface, opts BuildOptions) (Extensions, error) {
	if b == nil {
		return Extensions{}, nil
	}
	return b(ctx, variant, clientset, opts)
}
