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

package discovery

import (
	"context"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

// IsOperatorManaged returns true if the cluster is managed by the Tigera operator.
// It checks both that the operator.tigera.io API group is registered and that an
// Installation CR exists. The CRDs alone are not sufficient since they may be
// installed as part of the Calico CRD charts without the operator actually running.
func IsOperatorManaged(ctx context.Context, discoveryClient discovery.DiscoveryInterface, dynamicClient dynamic.Interface) (bool, error) {
	_, err := discoveryClient.ServerResourcesForGroupVersion("operator.tigera.io/v1")
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	// The API group exists - check if an actual Installation CR is present.
	installationGVR := schema.GroupVersionResource{
		Group:    "operator.tigera.io",
		Version:  "v1",
		Resource: "installations",
	}
	list, err := dynamicClient.Resource(installationGVR).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		if kerrors.IsNotFound(err) || kerrors.IsForbidden(err) {
			// CRD doesn't exist or no RBAC - operator CRDs are present
			// but no Installation, so not operator-managed.
			return false, nil
		}
		return false, err
	}
	return len(list.Items) > 0, nil
}
