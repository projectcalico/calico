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

package istio

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/enterprise/policysync"
	"github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/extensions"
)

// Extension is the Calico Enterprise behavior for the istio controller.
type Extension struct{}

var _ extensions.IstioExtension = &Extension{}

// New returns the istio extension.
func New() *Extension {
	return &Extension{}
}

// PolicySyncRequired reports whether the ApplicationLayer flow needs the policy-sync
// socket, so deleting the Istio CR does not strand it.
func (e *Extension) PolicySyncRequired(ctx context.Context, c client.Client) (bool, error) {
	al, err := utils.GetApplicationLayer(ctx, c)
	if err != nil {
		return false, err
	}
	return policysync.ApplicationLayerRequires(al), nil
}
