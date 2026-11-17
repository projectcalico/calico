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

package capability

import (
	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
)

// Cluster is the API access the probes read through. Probes only read, and
// never start a workload.
type Cluster struct {
	client    ctrlclient.Client
	discovery apiDiscovery
	extNodeIP string
}

// apiDiscovery is the slice of API discovery the probes need, to tell which
// API groups and resources the cluster serves.
type apiDiscovery interface {
	ServerGroups() (*metav1.APIGroupList, error)
	ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error)
}

// NewCluster connects to the cluster at cfg. The client deliberately doesn't
// retry an unserved API group, as the specs' client does, since to a probe
// that's the answer. The lane passes the external node's address in.
func NewCluster(cfg *rest.Config, extNodeIP string) (*Cluster, error) {
	scheme, err := newScheme()
	if err != nil {
		return nil, err
	}
	c, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create API client: %w", err)
	}
	d, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create discovery client: %w", err)
	}
	return &Cluster{client: c, discovery: d, extNodeIP: extNodeIP}, nil
}

// newScheme registers the typed APIs the probes read. KubeVirt is read
// unstructured, so it isn't here.
func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		v3.AddToScheme,
		operatorv1.AddToScheme,
		corev1.AddToScheme,
		apiregistrationv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			return nil, fmt.Errorf("build scheme: %w", err)
		}
	}
	return scheme, nil
}
