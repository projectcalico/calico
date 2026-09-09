// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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
	"context"
	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
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
	available, err := calicoV3APIAvailable(context.Background(), discoveryClient, c)
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

// NewAPIClient returns a client that always talks to the aggregated apiserver, with no
// discovery wait and no calicoctl fallback. Prefer New unless the request identity
// matters, as it does for an impersonating client.
func NewAPIClient(cfg *rest.Config) (client.Client, error) {
	scheme, err := newScheme()
	if err != nil {
		return nil, err
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	return WithRetry(c), nil
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
	if err := rbacv1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	// APIServices tell us a rolling calico-apiserver is still registered.
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	// KubeVirt VM/VMI/VMIM types: register so KubeVirt e2e tests share this
	// client instead of a parallel typed clientset.
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return scheme, nil
}

// calicoV3APIServiceName is the APIService registered for projectcalico.org/v3, either
// by calico-apiserver or by the CRD registration controller.
const calicoV3APIServiceName = "v3.projectcalico.org"

// serverGroupLister is the slice of discovery this package needs.
type serverGroupLister interface {
	ServerGroups() (*metav1.APIGroupList, error)
}

// calicoV3APIAvailable reports whether projectcalico.org/v3 is served, waiting out an
// apiserver that is still rolling rather than falling back to calicoctl.
func calicoV3APIAvailable(ctx context.Context, d serverGroupLister, c client.Client) (bool, error) {
	served, err := v3InDiscovery(d)
	if err != nil {
		return false, err
	}
	if served {
		return true, nil
	}

	// A rolling calico-apiserver leaves discovery but keeps its APIService, so a
	// registered APIService means wait rather than fall back.
	registered, err := v3APIServiceRegistered(ctx, c)
	if err != nil || !registered {
		return false, err
	}

	logrus.Infof("APIService %s is registered but projectcalico.org/v3 is not in discovery, waiting", calicoV3APIServiceName)
	if err := waitForV3InDiscovery(d); err != nil {
		return false, err
	}
	return true, nil
}

// v3InDiscovery retries transient discovery failures, but reports a clean answer
// of "not served" straight away.
func v3InDiscovery(d serverGroupLister) (bool, error) {
	var served bool
	err := retry.OnError(apiRetry, RetriableAPIError, func() error {
		var err error
		served, err = queryV3InDiscovery(d)
		return err
	})
	return served, err
}

func queryV3InDiscovery(d serverGroupLister) (bool, error) {
	groups, err := d.ServerGroups()
	if err != nil {
		return false, err
	}
	for _, group := range groups.Groups {
		if group.Name != v3.SchemeGroupVersion.Group {
			continue
		}
		for _, version := range group.Versions {
			if version.Version == v3.SchemeGroupVersion.Version {
				return true, nil
			}
		}
	}
	return false, nil
}

func v3APIServiceRegistered(ctx context.Context, c client.Client) (bool, error) {
	apiService := &apiregistrationv1.APIService{}
	err := c.Get(ctx, client.ObjectKey{Name: calicoV3APIServiceName}, apiService)
	if apierrors.IsNotFound(err) {
		return false, nil
	}

	// An RBAC-restricted client can't read APIServices, so trust discovery on its own.
	if apierrors.IsForbidden(err) {
		logrus.WithError(err).Warn("Cannot read APIServices, relying on discovery alone")
		return false, nil
	}
	return err == nil, err
}

func waitForV3InDiscovery(d serverGroupLister) error {
	alwaysRetry := func(error) bool {
		return true
	}
	return retry.OnError(apiRetry, alwaysRetry, func() error {
		served, err := queryV3InDiscovery(d)
		if err != nil {
			return err
		}
		if !served {
			return fmt.Errorf("%s is not served yet", v3.SchemeGroupVersion.String())
		}
		return nil
	})
}
