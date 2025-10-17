// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	operatorv1 "github.com/tigera/operator/api/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// New returns a new controller-runtime client configured to use the projectcalico.org/v3 API group.
func New(cfg *rest.Config) (client.Client, error) {
	// Use the API client if the Calico v3 API is available, otherwise fall back to the calicoctl exec client.
	c, err := NewAPIClient(cfg)
	if err != nil {
		return nil, err
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Checks to see if the projectcalico.org/v3 API is available.
	available, err := calicoV3APIAvailable(discoveryClient)
	if err != nil {
		return nil, err
	}

	if available {
		// API is available, we can return the calicoclient
		logrus.Infof("Using API server client for projectcalico.org/v3 API")
		return c, nil
	}

	// If the projectcalico.org/v3 apigroup is not found,
	// then we can assume that the API server is not present and default to calicoctl.
	logrus.Infof("projectcalico.org/v3 API not available, falling back to calicoctl exec client")
	return NewCalicoctlExecClient(c)
}

// NewAPIClient returns a new controller-runtime client configured to use the projectcalico.org/v3 API group.
func NewAPIClient(cfg *rest.Config) (client.Client, error) {
	scheme, err := newScheme()
	if err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{Scheme: scheme})
}

// NewCalicoctlExecClient returns a new controller-runtime client that uses exec commands into a calicoctl pod to interact with the projectcalico.org/v3 API.
// This is useful for testing purposes when the Calico API server is not running, however it requires that the cluster has a
// calicoctl pod running in the kube-system namespace.
//
// Additionally, this client does not support all operations that a normal controller-runtime client would support. For example, it cannot
// interact with API groups other than projectcalico.org/v3.
func NewCalicoctlExecClient(base client.Client) (client.Client, error) {
	return &calicoctlExecClient{
		base:      base,
		scheme:    base.Scheme(),
		name:      "calicoctl",
		namespace: "kube-system",
	}, nil
}

func newScheme() (*runtime.Scheme, error) {
	// Create a new Scheme and add the projectcalico.org/v3 API group to it.
	scheme := runtime.NewScheme()
	if err := v3.AddToScheme(scheme); err != nil {
		return nil, err
	}

	// Add operator APIs.
	if err := operatorv1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	// Add core k8s APIs.
	if err := networkingv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return scheme, nil
}

func calicoV3APIAvailable(discoveryClient discovery.DiscoveryInterface) (bool, error) {
	groups, err := discoveryClient.ServerGroups()
	if err != nil {
		return false, err
	}
	for _, group := range groups.Groups {
		if group.Name == "projectcalico.org" {
			for _, version := range group.Versions {
				if version.Version == "v3" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
