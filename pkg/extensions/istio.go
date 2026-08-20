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
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IstioExtension is the variant's hook into the istio controller.
type IstioExtension interface {
	// PolicySyncRequired reports whether a variant feature needs Felix's policy-sync
	// socket, which the istio controller shares the FelixConfiguration field with.
	PolicySyncRequired(ctx context.Context, c client.Client) (bool, error)
}

// noopIstio needs nothing of the shared FelixConfiguration field.
type noopIstio struct{}

func (noopIstio) PolicySyncRequired(context.Context, client.Client) (bool, error) {
	return false, nil
}
