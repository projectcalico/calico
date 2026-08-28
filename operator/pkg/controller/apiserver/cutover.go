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

package apiserver

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/render"
)

// holdAPIServiceCutover reports whether the projectcalico.org/v3 APIService is still served from a
// previous location whose API server has to keep serving, because the one that would replace it is
// not ready. Errors hold too, since failing to read the state is not evidence the cutover is safe.
func holdAPIServiceCutover(ctx context.Context, reader client.Reader) (bool, error) {
	apiService := &apiregv1.APIService{}
	if err := reader.Get(ctx, client.ObjectKey{Name: render.APIServiceName}, apiService); err != nil {
		if errors.IsNotFound(err) {
			// A fresh install. There is no API server in service to protect.
			return false, nil
		}
		return true, err
	}

	if apiService.Spec.Service == nil || apiService.Spec.Service.Namespace == render.APIServerNamespace {
		return false, nil
	}

	deployment := &appsv1.Deployment{}
	key := client.ObjectKey{Name: render.APIServerName, Namespace: render.APIServerNamespace}
	if err := reader.Get(ctx, key, deployment); err != nil {
		if errors.IsNotFound(err) {
			return true, nil
		}
		return true, err
	}

	// /readyz is deliberately excluded from the API server's always-allow paths, so a passing probe
	// means the pod authorized a request against the kube-apiserver - the connectivity the cutover
	// depends on, and exactly what a leftover deny policy takes away.
	return deployment.Status.ReadyReplicas == 0, nil
}
