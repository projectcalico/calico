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

// NamespaceInterface provides methods to work with Kubernetes Namespace resources.
// Used for namespaceSelector functionality in IPAM.
type NamespaceInterface interface {
	Create(ctx context.Context, res *corev1.Namespace, opts options.SetOptions) (*corev1.Namespace, error)
	Update(ctx context.Context, res *corev1.Namespace, opts options.SetOptions) (*corev1.Namespace, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*corev1.Namespace, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*corev1.Namespace, error)
	List(ctx context.Context, opts options.ListOptions) (*corev1.NamespaceList, error)
}

// namespaces implements NamespaceInterface
type namespaces struct {
	client client
}

func (r namespaces) Create(ctx context.Context, res *corev1.Namespace, opts options.SetOptions) (*corev1.Namespace, error) {
	backend := r.client.backend

	if kubeClient, ok := backend.(*k8s.KubeClient); ok {
		return kubeClient.ClientSet.CoreV1().Namespaces().Create(ctx, res, metav1.CreateOptions{})
	}

	return nil, fmt.Errorf("namespace access is only available when using Kubernetes datastore")
}

func (r namespaces) Update(ctx context.Context, res *corev1.Namespace, opts options.SetOptions) (*corev1.Namespace, error) {
	backend := r.client.backend

	if kubeClient, ok := backend.(*k8s.KubeClient); ok {
		return kubeClient.ClientSet.CoreV1().Namespaces().Update(ctx, res, metav1.UpdateOptions{})
	}

	return nil, fmt.Errorf("namespace access is only available when using Kubernetes datastore")
}

func (r namespaces) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*corev1.Namespace, error) {
	backend := r.client.backend

	if kubeClient, ok := backend.(*k8s.KubeClient); ok {
		deleteOpts := metav1.DeleteOptions{}
		if opts.ResourceVersion != "" {
			deleteOpts.Preconditions = &metav1.Preconditions{
				ResourceVersion: &opts.ResourceVersion,
			}
		}
		if opts.UID != nil {
			if deleteOpts.Preconditions == nil {
				deleteOpts.Preconditions = &metav1.Preconditions{}
			}
			deleteOpts.Preconditions.UID = opts.UID
		}

		// Get object first, then delete it to return the deleted object
		namespace, err := kubeClient.ClientSet.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		err = kubeClient.ClientSet.CoreV1().Namespaces().Delete(ctx, name, deleteOpts)
		if err != nil {
			return nil, err
		}

		return namespace, nil
	}

	return nil, fmt.Errorf("namespace access is only available when using Kubernetes datastore")
}

func (r namespaces) Get(ctx context.Context, name string, opts options.GetOptions) (*corev1.Namespace, error) {
	backend := r.client.backend

	if kubeClient, ok := backend.(*k8s.KubeClient); ok {
		return kubeClient.ClientSet.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	}

	return nil, fmt.Errorf("namespace access is only available when using Kubernetes datastore")
}

func (r namespaces) List(ctx context.Context, opts options.ListOptions) (*corev1.NamespaceList, error) {
	backend := r.client.backend

	if kubeClient, ok := backend.(*k8s.KubeClient); ok {
		listOpts := metav1.ListOptions{}
		if opts.Name != "" {
			listOpts.FieldSelector = "metadata.name=" + opts.Name
		}

		return kubeClient.ClientSet.CoreV1().Namespaces().List(ctx, listOpts)
	}

	return nil, fmt.Errorf("namespace access is only available when using Kubernetes datastore")
}
