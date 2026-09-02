// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ResolveClusterIP uses the Kubernetes API to resolve a Service to its ClusterIP.
func ResolveClusterIP(ctx context.Context, c client.Client, name, namespace string) (string, error) {
	svc := &corev1.Service{}
	k := types.NamespacedName{Name: name, Namespace: namespace}
	if err := c.Get(ctx, k, svc); err != nil {
		return "", err
	}
	return svc.Spec.ClusterIP, nil
}
