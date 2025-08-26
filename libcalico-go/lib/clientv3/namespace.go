// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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

package clientv3

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// NamespaceInterface has methods to work with Kubernetes Namespace resources.
// This is a simplified interface for accessing namespace information, primarily
// used for namespaceSelector functionality in IPAM.
type NamespaceInterface interface {
	Get(ctx context.Context, name string, opts options.GetOptions) (*corev1.Namespace, error)
	List(ctx context.Context, opts options.ListOptions) (*corev1.NamespaceList, error)
}

// namespaces implements NamespaceInterface
type namespaces struct {
	client client
}

// Get takes name of the Namespace, and returns the corresponding Namespace object,
// and an error if there is any.
func (r namespaces) Get(ctx context.Context, name string, opts options.GetOptions) (*corev1.Namespace, error) {
	// Get the backend from Calico client
	backend := r.client.backend

	// Type assert to KubeClient to access the Kubernetes clientset
	if kubeClient, ok := backend.(*k8s.KubeClient); ok {
		// Use the Kubernetes clientset from Calico's backend
		return kubeClient.ClientSet.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	}

	// If not using Kubernetes backend, return an error
	return nil, fmt.Errorf("namespace access is only available when using Kubernetes datastore")
}

// List returns the list of Namespace objects that match the supplied options.
func (r namespaces) List(ctx context.Context, opts options.ListOptions) (*corev1.NamespaceList, error) {
	// Get the backend from Calico client
	backend := r.client.backend

	// Type assert to KubeClient to access the Kubernetes clientset
	if kubeClient, ok := backend.(*k8s.KubeClient); ok {
		// Convert Calico ListOptions to Kubernetes ListOptions
		listOpts := metav1.ListOptions{}
		if opts.Name != "" {
			listOpts.FieldSelector = "metadata.name=" + opts.Name
		}

		// Use the Kubernetes clientset from Calico's backend
		return kubeClient.ClientSet.CoreV1().Namespaces().List(ctx, listOpts)
	}

	// If not using Kubernetes backend, return an error
	return nil, fmt.Errorf("namespace access is only available when using Kubernetes datastore")
}
